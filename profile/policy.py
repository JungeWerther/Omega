"""Landlock filesystem sandbox for the agent process.

The sandbox is the boundary between an LLM that can run shell commands and
the rest of the container, so it fails closed: if the policy is missing, if
Landlock is unavailable, or if a self-test shows the rules are not enforced,
the process exits (status 78, EX_CONFIG) instead of running unsandboxed.
`allowUnsandboxed=True` is the explicit, logged escape hatch for hosts
without Landlock.
"""

import functools
import os
import enum
import subprocess
import yaml
import json
from py_landlock import Landlock, AccessFs
from pathlib import Path
from glob import glob
from src.logger import get_logger

logger = get_logger(__name__)

_applied_paths = {}

SANDBOX_FAILURE_EXIT_CODE = 78  # EX_CONFIG
_TRUTHY = {"1", "true", "yes", "on"}


class SandboxNotEnforced(RuntimeError):
    pass


def _allow_unsandboxed():
    try:
        from config import config_get_by_key
    except ImportError:
        return False
    value = config_get_by_key("allowUnsandboxed", False)
    return value is True or str(value).strip().lower() in _TRUTHY


def _exit_process(code):
    os._exit(code)


def sandbox_required(apply):
    """Turn any failure to establish the sandbox into process exit.

    os._exit is used on purpose: the caller is MeTTa code whose handling of a
    Python exception cannot be relied on to stop the agent loop.
    """

    @functools.wraps(apply)
    def guarded(*args, **kwargs):
        try:
            return apply(*args, **kwargs)
        except Exception as exc:
            if _allow_unsandboxed():
                logger.critical(f"Sandbox NOT applied ({exc}); continuing because allowUnsandboxed=True. "
                                "The agent can read and write every file this user can.")
                return None
            logger.critical(f"Sandbox could not be applied, refusing to run unsandboxed: {exc}. "
                            "Fix the policy or the host (Landlock must be enabled), or pass "
                            "allowUnsandboxed=True to run without it.")
            _exit_process(SANDBOX_FAILURE_EXIT_CODE)

    return guarded


def _policy_key(path) -> str:
    return str(path or "").strip().strip('"')


def _is_covered(path: Path, policy_paths) -> bool:
    return any(path == granted or granted in path.parents or path in granted.parents
               for granted in policy_paths)


def canary_directory(policy_paths, root=Path("/")):
    """A readable directory the policy does not grant, used to prove the
    rules are enforced. Must be chosen before the policy is applied."""
    granted = [Path(p) for p in policy_paths]
    for candidate in sorted(root.iterdir()):
        try:
            if (candidate.is_dir() and not candidate.is_symlink()
                    and not _is_covered(candidate, granted)
                    and os.access(candidate, os.R_OK | os.X_OK)):
                return candidate
        except OSError:
            continue
    return None


def verify_enforced(canary):
    """Raise SandboxNotEnforced unless listing `canary` is denied, both in
    this process and in a child process (the path the shell skill uses)."""
    if canary is None:
        raise SandboxNotEnforced("no directory outside the policy to test enforcement with")
    try:
        os.listdir(canary)
    except PermissionError:
        pass
    else:
        raise SandboxNotEnforced(f"{canary} is still readable after applying the policy")
    child = subprocess.run(["ls", str(canary)], capture_output=True, check=False)
    if child.returncode == 0:
        raise SandboxNotEnforced(f"a child process can still read {canary}")


@sandbox_required
def apply_security_policy(path):
    if not _policy_key(path):
        raise SandboxNotEnforced("securityPolicyPath is not set")
    policy = FileSystemPolicy()
    policy.load_file(_policy_key(path))
    policy.validate()
    ro = policy._resolve_paths(policy._read_only, logging=False)
    rw = policy._resolve_paths(policy._read_write, logging=False)
    canary = canary_directory(ro + rw)
    policy.apply()
    verify_enforced(canary)
    _applied_paths[_policy_key(path)] = policy.resolved_paths
    logger.info(f"Sandbox enforced (verified: {canary} is not readable)")

def get_allowed_policy_paths(path) -> str:
    """
    Retrieves and serializes the allowed filesystem paths from the security policy.

    This function is exposed to the agent as a skill (`get-io-policy`). It reads the 
    Landlock security policy configuration and returns the permitted base paths 
    for read-only and read-write operations in JSON format. This allows the LLM 
    to proactively check path permissions before attempting File I/O operations.

    Args:
        path (str | Any): The file path to the security policy YAML file. 
                          Can be a raw string or a MeTTa symbol (which will be parsed to a string).

    Returns:
        str: A JSON-formatted string containing two keys: 'read_only' and 'read_write', 
             with lists of allowed directory paths.
             If the path is missing or an error occurs, returns a descriptive error string.
    """
    try:
        path = _policy_key(path)
        if path:
            resolved = _applied_paths.get(path)
            if resolved is None:
                policy = FileSystemPolicy()
                policy.load_file(path)
                resolved = (policy._resolve_paths(policy._read_only, logging=False),
                            policy._resolve_paths(policy._read_write, logging=False))
            read_only, read_write = resolved
            return json.dumps({
                'read_only': [str(p) for p in read_only],
                'read_write': [str(p) for p in read_write]
            })
        else:
            logger.warning("SecurityPolicyPath is not set")
            return "Could not retrieve policy: policy is not set"
    except Exception as e:
        logger.exception(
            f"Could not retrieve a policy due to unexpected exception: {e}"
        )
        return "Could not retrieve a policy: unexpected exception"

class LandLockCompatibility(enum.Enum):
    BEST_EFFORT = 0
    HARD_REQUIREMENT = 1

class FileSystemPolicy:

    READ_ONLY_DIR_ACCESS = AccessFs.READ_DIR | AccessFs.READ_FILE
    READ_ONLY_FILE_ACCESS = AccessFs.READ_FILE
    READ_WRITE_DIR_ACCESS = (AccessFs.READ_FILE | AccessFs.READ_DIR
                             | AccessFs.WRITE_FILE | AccessFs.TRUNCATE
                             | AccessFs.MAKE_REG | AccessFs.MAKE_DIR
                             | AccessFs.MAKE_SYM | AccessFs.REMOVE_FILE
                             | AccessFs.REMOVE_DIR | AccessFs.MAKE_FIFO
                             | AccessFs.MAKE_SOCK)
    READ_WRITE_FILE_ACCESS = (AccessFs.READ_FILE | AccessFs.WRITE_FILE |
                              AccessFs.TRUNCATE | AccessFs.IOCTL_DEV)
    # GPU paths are platform specific: /dev/dxg and /usr/lib/wsl exist on
    # WSL2 only, the NVIDIA device nodes and the PCI topology on native Linux
    # only. The policy lists all of them, so these are the only paths allowed
    # to be missing on a host machine.
    OPTIONAL_PATH_PREFIXES = ('/dev/dxg', '/dev/nvidia', '/sys/bus/pci',
                              '/sys/class/drm', '/sys/devices/pci',
                              '/usr/lib/wsl', '/run/nvidia-persistenced')

    def __init__(self):
        self._compatibility = LandLockCompatibility.BEST_EFFORT
        self._read_only = []
        self._read_write = []
        self.resolved_paths = ([], [])

    def load_file(self, path: str|Path):
        logger.info(f"Loading policy from file {path}")
        policy = None
        with open(path, "r") as f:
            policy = yaml.safe_load(f)
        self.load_dict(policy)

    def load_str(self, policy: str):
        policy = yaml.safe_load(policy)
        self.load_dict(policy)

    def load_dict(self, policy: dict):
        version = policy.get('version')
        assert version == 1

        self._compatibility = LandLockCompatibility.BEST_EFFORT
        ll = policy.get('landlock')
        if ll:
            comp = ll.get('compatibility')
            if comp:
                self._compatibility = LandLockCompatibility[comp.upper()]

        fs = policy.get('filesystem_policy')

        ro = []
        rw = []
        if fs:
            ro = fs.get('read_only', [])
            if ro is None:
                ro = []
            rw = fs.get('read_write', [])
            if rw is None:
                rw = []
            if fs.get('include_workdir'):
                rw.append(os.getcwd())
        self._read_only = [Path(f'{p}') for p in ro]
        self._read_write = [Path(f'{p}') for p in rw]

    @staticmethod
    def _resolve_paths(paths: list[Path], logging: bool = True) -> list[Path]:
        """Expand glob patterns and drop paths missing on a host machine.

        Landlock cannot add a rule for a missing path, and the policy lists
        platform-specific paths such as GPU device nodes that exist only on
        some host machines.

        Args:
            paths: Paths and glob patterns listed in the policy.
            logging: Whether to log missing paths.

        Returns:
            Existing paths the patterns resolve to.
        """
        resolved = set()
        missing = []
        for path in paths:
            matches = glob(str(path))
            if not matches:
                missing.append(str(path))
            for match in matches:
                resolved.add(Path(match))
        if missing and logging:
            logger.info(f"Skipped missing optional policy paths: {missing}")
        return sorted(resolved)

    @classmethod
    def _is_optional(cls, path: Path) -> bool:
        """Check whether the policy may list a path a host machine lacks.

        Args:
            path: Path listed in the policy.

        Returns:
            True for the platform specific GPU paths.
        """
        return str(path).startswith(cls.OPTIONAL_PATH_PREFIXES)

    def validate(self):
        """Check that the policy lists no path missing on a host machine.

        A missing path gets no Landlock rule, so a path mistyped in the
        policy is denied silently and shows up much later as a runtime
        error.

        Raises:
            ValueError: If a path which is not optional is missing.
        """
        missing = [str(p) for p in self._read_only + self._read_write
                   if not self._is_optional(p) and not glob(str(p))]
        if missing:
            raise ValueError(f"Policy paths missing on a host machine: {missing}")

    def apply(self):
        ro = self._resolve_paths(self._read_only, logging=False)
        rw = self._resolve_paths(self._read_write, logging=False)
        missing = [str(p) for p in self._read_only + self._read_write
                   if not glob(str(p))]
        if missing:
            logger.info(f"Skipped missing optional policy paths: {missing}")
        self.resolved_paths = (ro, rw)
        rod = list(filter(lambda p: p.is_dir(), ro))
        rof = list(filter(lambda p: not p.is_dir(), ro))
        rwd = list(filter(lambda p: p.is_dir(), rw))
        rwf = list(filter(lambda p: not p.is_dir(), rw))

        strict = self._compatibility == LandLockCompatibility.HARD_REQUIREMENT
        Landlock(strict=strict) \
            .allow_all_scope() \
            .allow_all_network() \
            .add_path_rule('/', access=AccessFs.EXECUTE) \
            .add_path_rule(*rwd, access=FileSystemPolicy.READ_WRITE_DIR_ACCESS) \
            .add_path_rule(*rwf, access=FileSystemPolicy.READ_WRITE_FILE_ACCESS) \
            .add_path_rule(*rod, access=FileSystemPolicy.READ_ONLY_DIR_ACCESS) \
            .add_path_rule(*rof, access=FileSystemPolicy.READ_ONLY_FILE_ACCESS) \
            .apply()

        logger.info("Policy applied")
