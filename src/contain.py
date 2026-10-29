"""Run one shell-skill command and leave no process behind.

Usage: python3 -I contain.py <timeout-seconds> -- <command> [args...]

The process makes itself a child subreaper (PR_SET_CHILD_SUBREAPER), so
descendants that detach with setsid, nohup or a double fork are re-parented
to it instead of to init. When the command exits, or the timeout expires,
every remaining descendant is killed. A command therefore cannot leave a
reverse shell or any other process running after the skill returns.

The command runs as the same user, so it could kill this supervisor
(`kill -9 $PPID`) before cleanup. The agent process is therefore a subreaper
too (agent_init): anything orphaned that way lands on the agent, and the
shell skill calls agent_sweep() after every command to kill it. The only
process left to kill is the agent itself, which stops the container.

Exit status: the command's own status, 124 when the timeout expired (the
same convention as coreutils `timeout`, which the shell skill maps to
`timeout_error`), or 125 when cleanup could not stop every process.
"""

import ctypes
import logging
import os
import signal
import subprocess
import sys
import time

PR_SET_CHILD_SUBREAPER = 36
TIMEOUT_EXIT_CODE = 124
CONTAINMENT_FAILURE_EXIT_CODE = 125
AGENT_TEARDOWN_EXIT_CODE = 70  # EX_SOFTWARE
KILL_ROUNDS = 50

logger = logging.getLogger(__name__)


def become_subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, f"prctl(PR_SET_CHILD_SUBREAPER) failed: {os.strerror(error)}")


def _parent_pids():
    parents = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", "rb") as stat:
                # Field 4 is the parent pid; the command name in field 2 may
                # itself contain spaces or parentheses, so split after it.
                fields = stat.read().rsplit(b")", 1)[1].split()
            parents[int(entry)] = int(fields[1])
        except (OSError, IndexError, ValueError):
            continue
    return parents


def descendants(root):
    children = {}
    for pid, parent in _parent_pids().items():
        children.setdefault(parent, []).append(pid)
    found, stack = [], list(children.get(root, ()))
    while stack:
        pid = stack.pop()
        found.append(pid)
        stack.extend(children.get(pid, ()))
    return found


def _reap():
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def kill_descendants(root=None):
    """SIGKILL every descendant until none is left. Processes forked while
    a round runs are re-parented to this subreaper and caught next round."""
    root = os.getpid() if root is None else root
    for _ in range(KILL_ROUNDS):
        remaining = descendants(root)
        if not remaining:
            return True
        for pid in remaining:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        _reap()
        time.sleep(0.01)
    return not descendants(root)


def run(timeout, command):
    become_subreaper()
    process = subprocess.Popen(command, start_new_session=True)
    try:
        status = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        status = TIMEOUT_EXIT_CODE
    if not kill_descendants():
        print("contain: some processes could not be stopped", file=sys.stderr)
        return CONTAINMENT_FAILURE_EXIT_CODE
    if status < 0:  # killed by a signal
        status = 128 - status
    return status


# -- the agent side ----------------------------------------------------------

def agent_init():
    """Make the calling (agent) process a subreaper. Idempotent."""
    become_subreaper()
    return True


def agent_sweep():
    """Kill every descendant of the agent process. Called by the shell skill
    after each command. If they cannot all be stopped, the agent exits:
    in Docker that ends the container and every process in it."""
    if kill_descendants(os.getpid()):
        return True
    logger.critical("shell containment failed: processes outlived cleanup; stopping the agent")
    os._exit(AGENT_TEARDOWN_EXIT_CODE)


def main(argv):
    if len(argv) < 3 or argv[1] != "--":
        print(__doc__, file=sys.stderr)
        return 2
    return run(float(argv[0]), argv[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
