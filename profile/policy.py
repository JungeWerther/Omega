"""Landlock filesystem sandbox for the agent process.

The sandbox is the boundary between an LLM that can run shell commands and
the rest of the container, so it fails closed: if the policy is missing, if
Landlock is unavailable, or if a self-test shows the rules are not enforced,
the process exits (status 78, EX_CONFIG) instead of running unsandboxed.
`allowUnsandboxed=True` is the explicit, logged escape hatch for hosts
without Landlock.
"""

import errno
import functools
import os
import socket
import enum
import shutil
import site
import subprocess
import sys
import tempfile
import yaml
import json
from dataclasses import dataclass
from py_landlock import Landlock, AccessFs, AccessNet, get_abi_version
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


# Landlock ABI 3 (Linux 6.2) is the first that can deny truncate(2); with an
# older ABI files outside the policy could still be emptied, so the sandbox
# would not be what the policy says.
MINIMUM_LANDLOCK_ABI = 3

# Places where a write probe directory may be created when the policy grants
# read access everywhere (so no read probe exists).
_WRITE_PROBE_PARENTS = ("/var/tmp", "/tmp", "/dev/shm")

_DENIED = 13


def _beneath(path: Path, granted: Path) -> bool:
    return path == granted or granted in path.parents


def _is_covered(path: Path, policy_paths) -> bool:
    return any(_beneath(path, granted) or path in granted.parents for granted in policy_paths)


@dataclass(frozen=True)
class Probe:
    """An access the policy must deny, chosen before the policy is applied.

    `read` lists a directory; `write` creates a file in a directory. A probe
    is valid only if the access worked before applying the policy, so a
    later denial can only come from the new rules.
    """

    kind: str
    path: Path

    _CHILD = {
        "read": "import os, sys\ntry:\n    os.listdir(sys.argv[1])\nexcept PermissionError:\n    sys.exit(13)\n",
        "write": ("import os, sys\ntry:\n    open(os.path.join(sys.argv[1], 'child-probe'), 'x').close()\n"
                  "except PermissionError:\n    sys.exit(13)\n"),
    }

    def attempt(self):
        """True if denied in this process."""
        try:
            if self.kind == "read":
                os.listdir(self.path)
            else:
                open(self.path / "probe", "x").close()
        except PermissionError:
            return True
        return False

    def attempt_in_child(self):
        """True only if a child process ran and was denied (exit 13); any
        other outcome, including a child that could not start, is not proof."""
        child = subprocess.run([python_interpreter(), "-I", "-c", self._CHILD[self.kind], str(self.path)],
                               capture_output=True, check=False)
        return child.returncode == _DENIED


def python_interpreter():
    """A Python executable for child probes. Inside the agent, Python is
    embedded in SWI-Prolog and sys.executable is the swipl binary."""
    if os.path.basename(sys.executable or "").startswith("python"):
        return sys.executable
    return shutil.which("python3") or "/usr/bin/python3"


def read_probe(granted_paths, root=Path("/")):
    """A top-level directory outside every granted path that can be listed now."""
    granted = [Path(p) for p in granted_paths]
    for candidate in sorted(root.iterdir()):
        try:
            if not candidate.is_dir() or candidate.is_symlink() or _is_covered(candidate, granted):
                continue
            os.listdir(candidate)
        except OSError:
            continue
        return Probe("read", candidate)
    return None


def write_probe(writable_paths, parents=_WRITE_PROBE_PARENTS):
    """A fresh directory outside every writable path that can be written now."""
    writable = [Path(p) for p in writable_paths]
    for parent in map(Path, parents):
        if not parent.is_dir() or any(_beneath(parent, granted) for granted in writable):
            continue
        try:
            directory = Path(tempfile.mkdtemp(prefix=".omega-sandbox-probe-", dir=parent))
        except OSError:
            continue
        return Probe("write", directory)
    return None


def choose_probe(read_only, read_write):
    return read_probe(read_only + read_write) or write_probe(read_write)


def canary_directory(policy_paths, root=Path("/")):
    """Backwards-compatible helper: the read probe's directory, or None."""
    probe = read_probe(policy_paths, root=root)
    return probe.path if probe else None


def verify_enforced(probe):
    """Raise SandboxNotEnforced unless `probe` is denied both here and in a
    child process (the path the shell skill uses)."""
    if probe is None:
        raise SandboxNotEnforced("no access outside the policy is available to test enforcement with")
    if not probe.attempt():
        raise SandboxNotEnforced(f"{probe.kind} access to {probe.path} still works after applying the policy")
    if not probe.attempt_in_child():
        raise SandboxNotEnforced(f"a child process was not shown to be denied {probe.kind} access to {probe.path}")


def require_minimum_abi():
    abi = get_abi_version()
    if abi < MINIMUM_LANDLOCK_ABI:
        raise SandboxNotEnforced(
            f"Landlock ABI {abi} cannot restrict truncation; ABI {MINIMUM_LANDLOCK_ABI} "
            "(Linux 6.2 or newer) is required for the policy to hold")
    return abi


# A TEST-NET-1 address: never a real host, used to check that UDP is refused.
_UNROUTABLE = ("192.0.2.1", 9)
MINIMUM_NETWORK_ABI = 4


def _local_address():
    """A non-loopback IPv4 address of this host, or None."""
    candidates = []
    try:
        candidates.append(socket.gethostbyname(socket.gethostname()))
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.connect(_UNROUTABLE)
            candidates.append(udp.getsockname()[0])
    except OSError:
        pass
    return next((a for a in candidates if a and not a.startswith("127.") and a != "0.0.0.0"), None)


def _listen(address, port=0):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((address, port))
    listener.listen(1)
    return listener


@dataclass
class NetworkProbes:
    """Prepared before the policy is applied.

    * `other_port`: a listener on loopback, on a port outside the policy.
      After applying, connecting to it must fail.
    * `same_port`: this host's non-loopback address with a port the policy
      allows, and nothing listening there. This is what an attacker's server
      on port 8080 looks like to Landlock, which only checks ports. Without
      the per-user firewall the kernel answers with a reset
      (ECONNREFUSED); with it the connection is refused as prohibited
      (EHOSTUNREACH) before it leaves the host.
    """

    other_port: socket.socket
    same_port: tuple

    @classmethod
    def open(cls, allowed_ports):
        address = _local_address() or _UNROUTABLE[0]
        return cls(other_port=_listen("127.0.0.1"), same_port=(address, min(allowed_ports)))

    def close(self):
        self.other_port.close()


_PROHIBITED = {errno.EHOSTUNREACH, errno.EACCES, errno.EPERM, errno.ENETUNREACH}


def _connect_error(address, timeout=3):
    """None if the connection succeeded, else the errno (ETIMEDOUT on timeout)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(timeout)
    try:
        probe.connect(address)
        return None
    except socket.timeout:
        return errno.ETIMEDOUT
    except OSError as exc:
        return exc.errno
    finally:
        probe.close()


def verify_network_enforced(probes):
    """Raise SandboxNotEnforced unless the agent can reach nothing but the
    allowed loopback ports."""
    try:
        loopback = probes.other_port.getsockname()
        if _connect_error(loopback) is None:
            raise SandboxNotEnforced(f"a loopback port outside the policy ({loopback[1]}) is reachable")
        outcome = _connect_error(probes.same_port)
        if outcome not in _PROHIBITED:
            seen = "connected" if outcome is None else errno.errorcode.get(outcome, str(outcome))
            raise SandboxNotEnforced(
                f"{probes.same_port[0]}:{probes.same_port[1]} (an allowed port on a non-loopback "
                f"address) was not refused by the firewall ({seen}). The per-user firewall "
                "(profile/firewall.py, needs CAP_NET_ADMIN) is not in place; pass "
                "allowUnrestrictedNetwork=True to run without it.")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            try:
                udp.sendto(b"probe", _UNROUTABLE)
            except OSError:
                pass
            else:
                raise SandboxNotEnforced("UDP to non-loopback addresses is not refused: the per-user "
                                         "firewall is not in place")
    finally:
        probes.close()


def _config_ports(key):
    try:
        from config import config_get_by_key
    except ImportError:
        return []
    value = config_get_by_key(key, "")
    return [int(p) for p in str(value or "").split(",") if str(p).strip()]


def _allow_unrestricted_network():
    try:
        from config import config_get_by_key
    except ImportError:
        return False
    value = config_get_by_key("allowUnrestrictedNetwork", False)
    return value is True or str(value).strip().lower() in _TRUTHY


@sandbox_required
def apply_security_policy(path):
    if not _policy_key(path):
        raise SandboxNotEnforced("securityPolicyPath is not set")
    abi = require_minimum_abi()
    policy = FileSystemPolicy()
    policy.load_file(_policy_key(path))
    policy.prepare()
    policy.validate()
    if policy.connect_ports is not None:
        if _allow_unrestricted_network():
            logger.critical("Network NOT restricted (allowUnrestrictedNetwork=True): "
                            "the agent can open TCP connections to any host.")
            policy.connect_ports = None
        else:
            policy.add_connect_ports(_config_ports("egressExtraPorts"))
    ro = policy._resolve_paths(policy._read_only, logging=False)
    rw = policy._resolve_paths(policy._read_write, logging=False)
    probe = choose_probe(ro, rw)
    network_probes = (NetworkProbes.open(policy.loopback_ports)
                      if policy.connect_ports is not None else None)
    policy.apply()
    verify_enforced(probe)
    if network_probes is not None:
        verify_network_enforced(network_probes)
    _applied_paths[_policy_key(path)] = policy.resolved_paths
    network = ("unrestricted" if policy.connect_ports is None
               else f"TCP connect only to ports {policy.connect_ports}")
    logger.info(f"Sandbox enforced (Landlock ABI {abi}; verified: {probe.kind} of {probe.path} is denied; "
                f"network: {network})")

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
        self._optional = set()
        self._create = set()
        self.resolved_paths = ([], [])
        # None: no network rules. A list: the only TCP ports that may be
        # connected to; binding is denied.
        self.connect_ports = None
        self._loopback_ports = []

    @property
    def loopback_ports(self):
        """Ports the policy itself lists: reachable on loopback only."""
        return list(self._loopback_ports)

    def add_connect_ports(self, ports):
        if self.connect_ports is not None:
            self.connect_ports = sorted(set(self.connect_ports) | {int(p) for p in ports})

    def _entries(self, items):
        """Paths from policy entries. An entry is a path string or a mapping
        {path, optional, create}. `~` and $VARIABLES are expanded; a path
        whose variables are unset is skipped when optional."""
        paths = []
        for item in items or []:
            spec = item if isinstance(item, dict) else {"path": item}
            raw = os.path.expandvars(os.path.expanduser(str(spec["path"])))
            if "$" in raw:
                if spec.get("optional"):
                    continue
                raise ValueError(f"Policy path {spec['path']!r} uses an unset variable")
            path = Path(raw)
            if spec.get("optional"):
                self._optional.add(path)
            if spec.get("create"):
                self._create.add(path)
            paths.append(path)
        return paths

    @staticmethod
    def _python_runtime_paths():
        """Directories the running interpreters load code from: Python's
        prefixes and site-packages, and, when Python is embedded in
        SWI-Prolog (the agent), the SWI-Prolog home, whose libraries are
        autoloaded lazily long after the sandbox is applied."""
        candidates = {sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix,
                      *site.getsitepackages(), site.getusersitepackages()}
        candidates.update(p for p in sys.path if p and os.path.isabs(p))
        candidates.update(FileSystemPolicy._prolog_home())
        return sorted(Path(p) for p in candidates if os.path.isdir(p))

    @staticmethod
    def _prolog_home():
        homes = set()
        if os.environ.get("SWI_HOME_DIR"):
            homes.add(os.environ["SWI_HOME_DIR"])
        executable = Path(sys.executable or "").resolve()
        if executable.name.startswith("swipl"):
            # <home>/bin/<arch>/swipl
            homes.add(str(executable.parents[2]))
        return homes

    def prepare(self):
        """Create the directories the policy marks with `create: true`."""
        for path in self._create:
            path.mkdir(parents=True, exist_ok=True)

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

        self._optional = set()
        self._create = set()
        ro = []
        rw = []
        if fs:
            ro = self._entries(fs.get('read_only'))
            rw = self._entries(fs.get('read_write'))
            if fs.get('include_workdir'):
                rw.append(Path(os.getcwd()))
            if fs.get('include_python_runtime'):
                runtime = self._python_runtime_paths()
                self._optional.update(runtime)
                ro.extend(runtime)
        self._read_only = ro
        self._read_write = rw

        net = policy.get('network_policy')
        self.connect_ports = None
        self._loopback_ports = []
        if net is not None:
            self.connect_ports = sorted({int(p) for p in (net.get('connect_tcp') or [])})
            self._loopback_ports = list(self.connect_ports)

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

    def _may_be_missing(self, path: Path) -> bool:
        return self._is_optional(path) or path in self._optional

    def validate(self):
        """Check that the policy lists no path missing on a host machine.

        A missing path gets no Landlock rule, so a path mistyped in the
        policy is denied silently and shows up much later as a runtime
        error.

        Raises:
            ValueError: If a path which is not optional is missing.
        """
        missing = [str(p) for p in self._read_only + self._read_write
                   if not self._may_be_missing(p) and not glob(str(p))]
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
        ruleset = Landlock(strict=strict).allow_all_scope()
        if self.connect_ports is None:
            ruleset.allow_all_network()
        elif get_abi_version() < MINIMUM_NETWORK_ABI:
            # No Landlock network rules on this kernel; the per-user
            # firewall is the boundary (checked by verify_network_enforced).
            logger.info("Landlock has no network rules on this kernel; relying on the firewall")
            ruleset.allow_all_network()
        elif self.connect_ports:
            ruleset.add_net_rule(*self.connect_ports, access=AccessNet.CONNECT_TCP)
        ruleset \
            .add_path_rule('/', access=AccessFs.EXECUTE) \
            .add_path_rule(*rwd, access=FileSystemPolicy.READ_WRITE_DIR_ACCESS) \
            .add_path_rule(*rwf, access=FileSystemPolicy.READ_WRITE_FILE_ACCESS) \
            .add_path_rule(*rod, access=FileSystemPolicy.READ_ONLY_DIR_ACCESS) \
            .add_path_rule(*rof, access=FileSystemPolicy.READ_ONLY_FILE_ACCESS) \
            .apply()

        logger.info("Policy applied")
