"""Landlock sandbox: fails closed and proves itself enforced.

Each scenario runs in a fresh interpreter because Landlock restrictions
cannot be lifted once applied.
"""

import json
import os
import shutil
import subprocess
import tempfile
import sys
import textwrap
from pathlib import Path

import pytest

pytest.importorskip("py_landlock")

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "profile"))
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

import policy  # noqa: E402

def _landlock_abi():
    probe = subprocess.run(
        [sys.executable, "-c", "from py_landlock import get_abi_version; print(get_abi_version())"],
        capture_output=True, text=True,
    )
    return int(probe.stdout.strip()) if probe.returncode == 0 else 0


needs_landlock = pytest.mark.skipif(_landlock_abi() < 1, reason="Landlock is not available on this kernel")

SYSTEM_PATHS = ["/bin", "/usr", "/lib", "/lib64", "/etc", "/proc", "/dev/urandom"]


def _policy_file(tmp_path, read_only=None, read_write=None, extra=""):
    read_only = [p for p in (read_only or SYSTEM_PATHS) if os.path.exists(p)]
    read_write = read_write or [str(tmp_path), "/dev/null"]
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\nfilesystem_policy:\n"
        + "  read_only:\n" + "".join(f"  - {p}\n" for p in read_only)
        + "  read_write:\n" + "".join(f"  - {p}\n" for p in read_write)
        + extra
    )
    return path


def _run(tmp_path, body, *config):
    """Run `body` in a fresh interpreter with the repository importable and
    the given key=value configuration. Returns the CompletedProcess."""
    script = textwrap.dedent(f"""
        import sys
        sys.path[:0] = {[str(REPO_ROOT / 'profile'), str(REPO_ROOT / 'src'), str(REPO_ROOT)]!r}
        import logging
        logging.basicConfig(level=logging.INFO)
        from config import init_config
        init_config({list(config)!r})
        import policy
    """) + textwrap.dedent(body)
    return subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                          cwd=tmp_path, timeout=60)


# -- loader bugs -------------------------------------------------------------

def test_include_workdir_is_read_from_the_filesystem_policy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    loaded = policy.FileSystemPolicy()
    loaded.load_str("version: 1\nfilesystem_policy:\n  include_workdir: true\n  read_write: [/tmp]\n")

    assert Path(tmp_path) in loaded._read_write


def test_include_workdir_defaults_off(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    loaded = policy.FileSystemPolicy()
    loaded.load_str("version: 1\ninclude_workdir: true\nfilesystem_policy:\n  read_write: [/tmp]\n")

    assert loaded._read_write == [Path("/tmp")]


def test_empty_read_write_list_is_allowed():
    loaded = policy.FileSystemPolicy()
    loaded.load_str("version: 1\nfilesystem_policy:\n  read_only: [/usr]\n  read_write:\n")

    assert loaded._read_write == []
    assert loaded._read_only == [Path("/usr")]


# -- canary ------------------------------------------------------------------

def test_canary_is_outside_every_granted_path(tmp_path):
    for name in ("granted", "parent_of_granted", "free"):
        (tmp_path / name).mkdir()
    (tmp_path / "parent_of_granted" / "inner").mkdir()
    granted = [tmp_path / "granted", tmp_path / "parent_of_granted" / "inner"]

    assert policy.canary_directory(granted, root=tmp_path) == tmp_path / "free"


def test_no_canary_when_everything_is_granted(tmp_path):
    (tmp_path / "only").mkdir()

    assert policy.canary_directory([tmp_path], root=tmp_path) is None


def test_production_policy_leaves_a_canary_in_the_image_layout():
    loaded = policy.FileSystemPolicy()
    loaded.load_file(REPO_ROOT / "profile" / "policy.yaml")
    granted = loaded._read_only + loaded._read_write
    image_top_level = {"bin", "boot", "dev", "etc", "home", "lib", "media", "mnt", "opt",
                       "PeTTa", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"}

    uncovered = {name for name in image_top_level
                 if not policy._is_covered(Path("/") / name, granted)}

    assert {"home", "root", "srv"} <= uncovered


# -- fail closed -------------------------------------------------------------

def test_missing_policy_path_exits(tmp_path):
    result = _run(tmp_path, "policy.apply_security_policy('')\nprint('STILL RUNNING')")

    assert result.returncode == policy.SANDBOX_FAILURE_EXIT_CODE
    assert "STILL RUNNING" not in result.stdout
    assert "refusing to run unsandboxed" in result.stderr


def test_unreadable_policy_exits(tmp_path):
    result = _run(tmp_path, f"policy.apply_security_policy({str(tmp_path / 'nope.yaml')!r})\nprint('STILL RUNNING')")

    assert result.returncode == policy.SANDBOX_FAILURE_EXIT_CODE
    assert "STILL RUNNING" not in result.stdout


def test_landlock_that_silently_does_nothing_is_caught(tmp_path):
    """If apply() returned without restricting anything, the self-test must
    notice and stop the process."""
    path = _policy_file(tmp_path)
    result = _run(tmp_path, f"""
        policy.FileSystemPolicy.apply = lambda self: None
        policy.apply_security_policy({str(path)!r})
        print('STILL RUNNING')
    """)

    assert result.returncode == policy.SANDBOX_FAILURE_EXIT_CODE
    assert "STILL RUNNING" not in result.stdout
    assert "still works after applying the policy" in result.stderr


def test_unavailable_landlock_exits(tmp_path):
    path = _policy_file(tmp_path)
    result = _run(tmp_path, f"""
        from py_landlock import LandlockNotAvailableError
        def unavailable(self):
            raise LandlockNotAvailableError()
        policy.FileSystemPolicy.apply = unavailable
        policy.apply_security_policy({str(path)!r})
        print('STILL RUNNING')
    """)

    assert result.returncode == policy.SANDBOX_FAILURE_EXIT_CODE
    assert "STILL RUNNING" not in result.stdout


def test_explicit_opt_out_continues_with_a_warning(tmp_path):
    result = _run(tmp_path, "policy.apply_security_policy('')\nprint('STILL RUNNING')",
                  "allowUnsandboxed=True")

    assert result.returncode == 0
    assert "STILL RUNNING" in result.stdout
    assert "Sandbox NOT applied" in result.stderr


@needs_landlock
def test_real_policy_is_enforced_in_process_and_children(tmp_path):
    path = _policy_file(tmp_path)
    outside = Path(policy.canary_directory(
        [Path(p) for p in SYSTEM_PATHS] + [tmp_path, Path("/dev/null")]))
    result = _run(tmp_path, f"""
        import json, os, subprocess
        policy.apply_security_policy({str(path)!r})
        outcome = {{}}
        try:
            os.listdir({str(outside)!r}); outcome['read_outside'] = 'allowed'
        except PermissionError:
            outcome['read_outside'] = 'denied'
        try:
            open({str(tmp_path / 'inside.txt')!r}, 'w').write('ok'); outcome['write_inside'] = 'allowed'
        except PermissionError:
            outcome['write_inside'] = 'denied'
        shell = subprocess.run(['sh', '-c', 'echo x > {tmp_path.parent}/escape.txt'], capture_output=True)
        outcome['shell_write_outside'] = 'allowed' if shell.returncode == 0 else 'denied'
        print(json.dumps(outcome))
    """)

    assert result.returncode == 0, result.stderr
    outcome = json.loads(result.stdout.strip().splitlines()[-1])
    assert outcome == {"read_outside": "denied", "write_inside": "allowed", "shell_write_outside": "denied"}
    assert "Sandbox enforced (Landlock ABI" in result.stderr
    assert not (tmp_path.parent / "escape.txt").exists()


# -- probes ------------------------------------------------------------------

def test_read_probe_skips_directories_that_are_already_unreadable(tmp_path, monkeypatch):
    for name in ("a_inherited_denial", "b_free"):
        (tmp_path / name).mkdir()
    real_listdir = os.listdir

    def listdir(path):
        if Path(path).name == "a_inherited_denial":
            raise PermissionError("denied by an outer sandbox")
        return real_listdir(path)

    monkeypatch.setattr(policy.os, "listdir", listdir)

    assert policy.read_probe([], root=tmp_path) == policy.Probe("read", tmp_path / "b_free")


def test_write_probe_is_created_outside_writable_paths(tmp_path):
    allowed, other = tmp_path / "allowed", tmp_path / "other"
    allowed.mkdir()
    other.mkdir()

    probe = policy.write_probe([allowed], parents=[str(allowed), str(other)])

    assert probe.kind == "write"
    assert probe.path.parent == other


def test_child_that_cannot_run_is_not_proof(tmp_path, monkeypatch):
    monkeypatch.setattr(policy.sys, "executable", "/bin/false")

    assert policy.Probe("read", tmp_path).attempt_in_child() is False


def test_old_landlock_abi_stops_the_agent(tmp_path):
    path = _policy_file(tmp_path)
    result = _run(tmp_path, f"""
        policy.get_abi_version = lambda: 2
        policy.apply_security_policy({str(path)!r})
        print('STILL RUNNING')
    """)

    assert result.returncode == policy.SANDBOX_FAILURE_EXIT_CODE
    assert "STILL RUNNING" not in result.stdout
    assert "cannot restrict truncation" in result.stderr


@needs_landlock
def test_read_everything_policy_is_verified_with_a_write_probe(tmp_path):
    path = _policy_file(tmp_path, read_only=["/"], read_write=[str(tmp_path), "/dev/null"])
    result = _run(tmp_path, f"""
        policy.apply_security_policy({str(path)!r})
        print('RUNNING')
    """)

    assert result.returncode == 0, result.stderr
    assert "verified: write of" in result.stderr


# -- policy entries ----------------------------------------------------------

def test_entries_expand_home_and_variables(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MODEL_CACHE", str(tmp_path / "models"))
    monkeypatch.delenv("UNSET_CACHE", raising=False)
    loaded = policy.FileSystemPolicy()
    loaded.load_str(
        "version: 1\nfilesystem_policy:\n"
        "  read_only:\n  - ~/code\n  - $MODEL_CACHE\n  - {path: $UNSET_CACHE, optional: true}\n"
        "  read_write:\n  - {path: ~/state, create: true}\n"
    )

    assert loaded._read_only == [tmp_path / "code", tmp_path / "models"]
    assert loaded._read_write == [tmp_path / "state"]
    loaded.prepare()
    assert (tmp_path / "state").is_dir()


def test_required_entry_with_unset_variable_is_an_error(monkeypatch):
    monkeypatch.delenv("UNSET_CACHE", raising=False)
    loaded = policy.FileSystemPolicy()

    with pytest.raises(ValueError, match="unset variable"):
        loaded.load_str("version: 1\nfilesystem_policy:\n  read_only:\n  - $UNSET_CACHE\n")


def test_optional_entries_may_be_missing(tmp_path):
    loaded = policy.FileSystemPolicy()
    loaded.load_str("version: 1\nfilesystem_policy:\n  read_only:\n"
                    f"  - {{path: {tmp_path / 'absent'}, optional: true}}\n")

    loaded.validate()


def test_python_runtime_paths_are_included_when_requested():
    loaded = policy.FileSystemPolicy()
    loaded.load_str("version: 1\nfilesystem_policy:\n  include_python_runtime: true\n")

    assert Path(sys.prefix) in loaded._read_only


# -- running without Docker --------------------------------------------------

@needs_landlock
def test_native_policy_works_from_a_petta_checkout():
    # Outside /tmp, which the native policy makes writable.
    tmp_path = Path(tempfile.mkdtemp(dir=Path.home()))
    petta = tmp_path / "PeTTa"
    (petta / "repos" / "Omega" / "src").mkdir(parents=True)
    (petta / "repos" / "Omega" / "src" / "code.metta").write_text("(code)")
    native = REPO_ROOT / "profile" / "policy-native.yaml"
    result = _run(petta, f"""
        import json, os
        policy.apply_security_policy({str(native)!r})
        def attempt(fn):
            try:
                fn(); return "allowed"
            except PermissionError:
                return "denied"
        outcome = {{
            "read code": attempt(lambda: open("repos/Omega/src/code.metta").read()),
            "write memory": attempt(lambda: open("repos/Omega/memory/history.metta", "a").write("x")),
            "write chroma": attempt(lambda: open("chroma_db/probe", "w").write("x")),
            "write code": attempt(lambda: open("repos/Omega/src/code.metta", "a").write("x")),
            "read outside": attempt(lambda: os.listdir({str(tmp_path)!r})),
            "import": attempt(lambda: __import__("decimal")),
        }}
        print(json.dumps(outcome))
    """)

    shutil.rmtree(tmp_path)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.strip().splitlines()[-1]) == {
        "read code": "allowed", "write memory": "allowed", "write chroma": "allowed",
        "write code": "denied", "read outside": "denied", "import": "allowed",
    }


def test_child_probe_uses_a_python_interpreter_when_embedded(monkeypatch, tmp_path):
    """Inside the agent, Python runs embedded in SWI-Prolog."""
    monkeypatch.setattr(policy.sys, "executable", "/usr/lib/swipl/bin/x86_64-linux/swipl")

    assert Path(policy.python_interpreter()).name.startswith("python")
    assert policy.Probe("read", tmp_path).attempt_in_child() is False  # readable, so not denied


def test_native_policy_is_the_configured_default():
    import yaml

    config = yaml.safe_load((REPO_ROOT / "config" / "config.yaml").read_text())

    assert config["securityPolicyPath"].endswith("profile/policy-native.yaml")


def test_docker_entrypoint_selects_the_docker_policy():
    entrypoint = (REPO_ROOT / "entrypoint.sh").read_text()

    assert "securityPolicyPath=${OMEGA_DIR}/profile/policy.yaml $*" in entrypoint
