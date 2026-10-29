"""The shell skill must not leave processes running after it returns."""

import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTAIN = REPO_ROOT / "src" / "contain.py"
SKILLS = REPO_ROOT / "src" / "skills.pl"


def contain(timeout, script):
    return subprocess.run(
        [sys.executable, "-I", str(CONTAIN), str(timeout), "--", "sh", "-c", script],
        capture_output=True, text=True, timeout=60,
    )


def survives(marker, wait=2.5):
    """True if a background process managed to write `marker` later."""
    time.sleep(wait)
    return marker.exists()


def test_output_and_status_pass_through():
    result = contain(5, "echo out; echo err >&2; exit 3")

    assert result.returncode == 3
    assert result.stdout == "out\n"
    assert result.stderr == "err\n"


def test_timeout_exits_124_and_stops_the_command(tmp_path):
    marker = tmp_path / "late"
    started = time.monotonic()
    result = contain(1, f"sleep 2; touch {marker}")

    assert result.returncode == 124
    assert time.monotonic() - started < 3
    assert not survives(marker)


@pytest.mark.parametrize("escape", [
    "setsid sh -c 'sleep 1; touch {m}' &",
    "nohup sh -c 'sleep 1; touch {m}' >/dev/null 2>&1 &",
    "( ( sleep 1; touch {m} ) & ) &",                       # double fork
    "setsid sh -c '( setsid sh -c \"sleep 1; touch {m}\" & )' &",  # nested setsid
])
def test_detached_processes_are_killed_when_the_command_returns(tmp_path, escape):
    marker = tmp_path / "escaped"
    result = contain(5, escape.format(m=marker) + " echo started")

    assert result.returncode == 0
    assert "started" in result.stdout
    assert not survives(marker)


def test_detached_processes_are_killed_on_timeout(tmp_path):
    marker = tmp_path / "escaped"
    result = contain(1, f"setsid sh -c 'sleep 2; touch {marker}' & sleep 5")

    assert result.returncode == 124
    assert not survives(marker, wait=3)


def test_signal_death_is_reported_like_a_shell():
    assert contain(5, "kill -9 $$").returncode == 137


def test_usage_error():
    result = subprocess.run([sys.executable, "-I", str(CONTAIN), "5", "sh"], capture_output=True)

    assert result.returncode == 2


# -- the Prolog skill itself -------------------------------------------------

needs_swipl = pytest.mark.skipif(shutil.which("swipl") is None, reason="swipl is not installed")


def prolog_shell(command, tmp_path):
    goal = (
        "use_module(library(process)), use_module(library(readutil)), "
        f"consult('{SKILLS}'), getenv('SHELL_SKILL_COMMAND', Command), shell(Command, Out), "
        "( Out == timeout_error -> write('TIMEOUT') ; write(Out) ), halt."
    )
    return subprocess.run(["swipl", "-q", "-g", goal, "-t", "halt(1)"],
                          capture_output=True, text=True, cwd=tmp_path, timeout=60,
                          env={"PATH": "/usr/local/bin:/usr/bin:/bin", "SHELL_SKILL_COMMAND": command})


@needs_swipl
def test_skill_returns_command_output(tmp_path):
    result = prolog_shell("echo hello; echo err >&2", tmp_path)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "hello\nerr\n"


@needs_swipl
def test_skill_reports_timeout(tmp_path):
    result = prolog_shell("sleep 30", tmp_path)

    assert result.stdout == "TIMEOUT"


@needs_swipl
def test_skill_does_not_leave_a_detached_process(tmp_path):
    marker = tmp_path / "escaped"
    result = prolog_shell(f"setsid sh -c 'sleep 1; touch {marker}' > /dev/null 2>&1 & echo ok", tmp_path)

    assert result.stdout == "ok\n", result.stderr
    assert not survives(marker)
