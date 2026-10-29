"""Landlock sandbox: fails closed and proves itself enforced.

Each scenario runs in a fresh interpreter because Landlock restrictions
cannot be lifted once applied.
"""

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

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
    assert "still readable" in result.stderr


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
    assert "Sandbox enforced (verified:" in result.stderr
    assert not (tmp_path.parent / "escape.txt").exists()
