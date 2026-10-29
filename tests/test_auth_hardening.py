"""Regression tests for the fail-closed channel authentication."""

import importlib.util
import os
import stat
import sys
import types
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
AUTH_MODULE_PATH = REPO_ROOT / "channels" / "auth.py"
GUARDS_MODULE_PATH = REPO_ROOT / "channels" / "guards.py"


def _load(monkeypatch, path, name, **config):
    monkeypatch.syspath_prepend(str(REPO_ROOT))
    config_module = types.ModuleType("config")
    config_module.config_get_by_key = lambda key, default=None: config.get(key, default)
    monkeypatch.setitem(sys.modules, "config", config_module)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def auth_factory(monkeypatch, tmp_path):
    def load(**config):
        config.setdefault("authStateDir", str(tmp_path / "gate-state"))
        return _load(monkeypatch, AUTH_MODULE_PATH, "auth_hardening_under_test", **config)

    return load


@pytest.fixture
def guards(monkeypatch):
    return _load(monkeypatch, GUARDS_MODULE_PATH, "guards_under_test")


# -- secret guessing ---------------------------------------------------------

def test_wrong_secrets_lock_out_the_sender(monkeypatch, auth_factory):
    monkeypatch.setenv("OMEGA_AUTH_SECRET", "123456")
    auth = auth_factory()

    for guess in range(auth.SECRET_ATTEMPTS_PER_SENDER):
        assert auth.authenticate_channel_user("IRC", "mallory", f"{guess:06}") == "ignore"

    # Locked out: even the right secret is refused during the window.
    assert auth.authenticate_channel_user("IRC", "mallory", "123456") == "ignore"
    assert auth.get_channel_authenticated_user_id("IRC") is None


def test_lockout_of_one_sender_does_not_block_another(monkeypatch, auth_factory):
    monkeypatch.setenv("OMEGA_AUTH_SECRET", "123456")
    auth = auth_factory()

    for guess in range(auth.SECRET_ATTEMPTS_PER_SENDER):
        auth.authenticate_channel_user("IRC", "mallory", f"{guess:06}")

    assert auth.authenticate_channel_user("IRC", "owner", "123456") == "auth_bound"


def test_global_limit_stops_guessing_from_many_identities(monkeypatch, auth_factory):
    monkeypatch.setenv("OMEGA_AUTH_SECRET", "123456")
    auth = auth_factory()

    for attempt in range(auth.SECRET_ATTEMPTS_TOTAL):
        auth.authenticate_channel_user("IRC", f"sock{attempt}", "000000")

    assert auth.authenticate_channel_user("IRC", "fresh-nick", "123456") == "ignore"


def test_throttle_window_expires(guards):
    now = [0.0]
    calls = []

    @guards.throttle_failures(limit=2, window=60, key=lambda value: "k", clock=lambda: now[0])
    def check(value):
        calls.append(value)
        return value == "right"

    assert check("a") is False
    assert check("b") is False
    assert check("right") is False  # locked, predicate not evaluated
    assert calls == ["a", "b"]

    now[0] = 61.0
    assert check("right") is True


def test_rotating_keys_do_not_grow_the_ledger_without_bound(guards):
    now = [0.0]

    @guards.throttle_failures(limit=5, global_limit=20, window=60,
                              key=lambda value: value, clock=lambda: now[0])
    def check(value):
        return False

    for attempt in range(10_000):
        now[0] = attempt * 0.01
        check(f"nick{attempt}")

    # Lookups past the global limit create nothing; recorded keys are capped
    # by the failures that fit in one window.
    assert check.failures.tracked_keys() <= 20

    now[0] += 61
    check("after-window")
    assert check.failures.tracked_keys() == 1


def test_fail_closed_turns_errors_into_denial(guards):
    @guards.fail_closed("ignore")
    def decide():
        raise OSError("disk gone")

    assert decide() == "ignore"


# -- unauthenticated mode ----------------------------------------------------

@pytest.mark.parametrize("value", ["", "False", "0", "no", None])
def test_only_explicit_truthy_values_disable_auth(monkeypatch, auth_factory, value):
    monkeypatch.delenv("OMEGA_AUTH_SECRET", raising=False)
    auth = auth_factory(allowUnauthenticated=value)

    assert auth.is_auth_enabled() is True


def test_weak_secret_detection(auth_factory):
    auth = auth_factory()

    assert auth.is_weak_secret("0000")
    assert auth.is_weak_secret("123456")
    assert not auth.is_weak_secret("x" * auth.WEAK_SECRET_LENGTH)


# -- record storage ----------------------------------------------------------

def test_records_live_in_the_configured_state_directory(monkeypatch, tmp_path, auth_factory):
    monkeypatch.setenv("OMEGA_AUTH_SECRET", "a-long-enough-owner-secret")
    auth = auth_factory(authStateDir=str(tmp_path / "gate-state"))

    assert auth.authenticate_channel_user("TELEGRAM", "42", "a-long-enough-owner-secret") == "auth_bound"

    user_file = tmp_path / "gate-state" / "authenticated-user.json"
    assert user_file.exists()
    assert stat.S_IMODE(user_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(user_file.parent.stat().st_mode) == 0o700


def test_group_records_are_private(monkeypatch, tmp_path, auth_factory):
    monkeypatch.setenv("OMEGA_AUTH_SECRET", "a-long-enough-owner-secret")
    auth = auth_factory()
    auth.authenticate_channel_user("TELEGRAM", "42", "a-long-enough-owner-secret")

    assert auth.authorize_channel_group("TELEGRAM", "-100", "42") == "group_bound"

    group_file = tmp_path / "gate-state" / "authenticated-group.json"
    assert stat.S_IMODE(group_file.stat().st_mode) == 0o600


def test_planted_symlink_is_not_followed(monkeypatch, tmp_path, auth_factory):
    monkeypatch.setenv("OMEGA_AUTH_SECRET", "a-long-enough-owner-secret")
    state = tmp_path / "gate-state"
    state.mkdir(mode=0o700)
    target = tmp_path / "elsewhere.json"
    os.symlink(target, state / "authenticated-user.json")
    auth = auth_factory()

    with pytest.raises(RuntimeError):
        auth.authenticate_channel_user("IRC", "owner", "a-long-enough-owner-secret")
    assert not target.exists()


def test_legacy_location_is_used_without_state_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("OMEGA_AUTH_SECRET", "a-long-enough-owner-secret")
    auth = _load(monkeypatch, AUTH_MODULE_PATH, "auth_legacy_under_test")
    monkeypatch.setattr(auth, "_MEMORY_DIRECTORY", str(tmp_path))

    assert auth.auth_state_directory() == str(tmp_path / ".channel")
