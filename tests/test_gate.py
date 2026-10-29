"""Gate process: agent-facing surface, client behaviour, isolation."""

import importlib
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
for entry in (REPO_ROOT, REPO_ROOT / "src", REPO_ROOT / "channels"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import channels  # noqa: E402 - src/channels.py
from gate import server as gate_server  # noqa: E402


class FakeChannels(types.SimpleNamespace):
    """Stands in for src/channels.py with a started channel behind it."""

    def __init__(self):
        super().__init__(inbox=["owner: hello"], sent=[])

    def commChannelReceiveRaw(self):
        return self.inbox.pop(0) if self.inbox else ""

    def commChannelSend(self, message):
        self.sent.append(message)

    def local_export_principal(self, commchannel_id):
        return f"{commchannel_id}:owner-id"


@pytest.fixture
def running_gate():
    gate_server.ROUTES.clear()
    fake = FakeChannels()
    fake.sender = gate_server.bind_channel_routes(fake, "telegram")
    httpd = gate_server.serve("127.0.0.1", 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield fake, url
    httpd.shutdown()
    httpd.server_close()
    gate_server.ROUTES.clear()


def test_client_round_trip_through_gate(running_gate):
    fake, url = running_gate
    client = channels.GateChannel(url)

    client.start()
    assert client.receive() == "owner: hello"
    assert client.receive() == ""
    client.send("reply")
    fake.sender.join()
    assert fake.sent == ["reply"]
    assert client.principal() == "telegram:owner-id"


def test_gate_exposes_no_auth_management_endpoints(running_gate):
    _, url = running_gate
    client = channels.GateChannel(url)

    for path in ("/v1/bind", "/v1/owner", "/auth/verify", "/v1/authorize"):
        with pytest.raises(Exception):
            client._call("POST", path, {"user": "mallory"})
    assert set(gate_server.ROUTES) == {
        ("GET", "/v1/health"),
        ("GET", "/v1/receive"),
        ("POST", "/v1/send"),
        ("GET", "/v1/principal"),
    }


def test_send_rejects_non_string_message(running_gate):
    fake, url = running_gate
    client = channels.GateChannel(url)

    with pytest.raises(Exception):
        client._call("POST", "/v1/send", {"message": {"chat_id": "anyone"}})
    assert fake.sent == []


def test_oversized_body_is_refused(running_gate):
    fake, url = running_gate
    client = channels.GateChannel(url)

    with pytest.raises(Exception):
        client.send("x" * (gate_server.MAX_BODY_BYTES + 1))
    assert fake.sent == []


def test_send_is_acknowledged_before_slow_delivery_and_keeps_order(running_gate):
    fake, url = running_gate
    release = threading.Event()
    original = fake.commChannelSend

    def slow_send(message):
        release.wait(5)
        original(message)

    fake.sender._deliver = slow_send
    client = channels.GateChannel(url)
    started = time.monotonic()
    for index in range(3):
        client.send(f"part {index}")
    assert time.monotonic() - started < 2
    release.set()
    fake.sender.join()

    assert fake.sent == ["part 0", "part 1", "part 2"]


@pytest.mark.parametrize("length", ["-1", "abc", "1e3", " 12x"])
def test_malformed_content_length_is_rejected(running_gate, length):
    fake, url = running_gate
    host, port = url.removeprefix("http://").split(":")
    with socket.create_connection((host, int(port)), timeout=5) as connection:
        connection.sendall(
            f"POST /v1/send HTTP/1.1\r\nHost: x\r\nContent-Length: {length}\r\n\r\n".encode()
            + b'{"message": "' + b"x" * 100 + b'"}'
        )
        status_line = connection.recv(1024).split(b"\r\n", 1)[0]

    assert b" 400 " in status_line
    assert fake.sent == []


def test_unreachable_gate_means_no_message_and_no_principal():
    client = channels.GateChannel("http://127.0.0.1:9")

    assert client.receive() == ""
    assert client.principal() is None


def test_gate_refuses_non_loopback_bind():
    with pytest.raises(ValueError):
        gate_server.serve("0.0.0.0", 0)


def test_commchannel_start_uses_gate_when_configured(monkeypatch, running_gate):
    _, url = running_gate
    config_module = types.ModuleType("config")
    config_module.config_get_by_key = lambda key, default=None: url if key == "GATE_URL" else default
    monkeypatch.setitem(sys.modules, "config", config_module)
    monkeypatch.setattr(channels, "_commChannelRegistry", {})

    channels.commChannelStart("telegram")

    assert isinstance(channels._commchannel, channels.GateChannel)
    assert channels._authenticated_export_principal() == "telegram:owner-id"


# -- gate/main.py ------------------------------------------------------------

@pytest.fixture
def gate_main(monkeypatch):
    module = importlib.import_module("gate.main")
    return module


def _config(monkeypatch, **settings):
    import config

    monkeypatch.setattr(config, "_COMMAND_LINE", {k: str(v) for k, v in settings.items()})
    monkeypatch.setattr(config, "_CONFIG", {})
    monkeypatch.setattr(config, "_CONFIG_FILE", {})


def test_gate_refuses_to_run_as_a_gate_client(monkeypatch, tmp_path, gate_main):
    _config(monkeypatch, GATE_URL="http://127.0.0.1:8090", authStateDir=tmp_path)

    with pytest.raises(SystemExit, match="GATE_URL"):
        gate_main.check_configuration()


def test_gate_requires_its_own_state_directory(monkeypatch, gate_main):
    _config(monkeypatch)

    with pytest.raises(SystemExit, match="authStateDir"):
        gate_main.check_configuration()


def test_gate_creates_private_state_directory(monkeypatch, tmp_path, gate_main):
    state = tmp_path / "gate-state"
    _config(monkeypatch, authStateDir=state)
    monkeypatch.setenv("OMEGA_AUTH_SECRET", "a-long-enough-owner-secret")

    gate_main.check_configuration()

    assert state.is_dir()
    assert (state.stat().st_mode & 0o777) == 0o700


def test_secrets_are_masked_in_log_records(gate_main, caplog):
    original = logging.getLogRecordFactory()
    try:
        gate_main.redact_secrets(["k3y-value"])
        with caplog.at_level(logging.INFO):
            logging.getLogger("gate-test").info("GET http://127.0.0.1:8080/gate/%s/telegram/x", "k3y-value")
        assert "k3y-value" not in caplog.text
        assert "/gate/***/telegram/x" in caplog.text
    finally:
        logging.setLogRecordFactory(original)


# -- uid isolation (the exploit from the audit) ------------------------------

AGENT_UID = 65534
GATE_UID = 65533


@pytest.mark.skipif(os.geteuid() != 0 or shutil.which("setpriv") is None,
                    reason="needs root and setpriv to switch users")
def test_agent_user_cannot_plant_auth_records():
    # A directory whose every ancestor the agent can traverse, so a denial
    # can only come from the gate directory itself.
    parent = Path(tempfile.mkdtemp(dir="/tmp"))
    try:
        parent.chmod(0o755)
        public = parent / "public.txt"
        public.write_text("readable")
        public.chmod(0o644)
        state = parent / "omega-gate"
        state.mkdir(mode=0o700)
        os.chown(state, GATE_UID, GATE_UID)
        record = (
            '{"channel_identifier":"TELEGRAM","group_id":"-100attacker",'
            '"authorized_by":"42"}'
        )

        def as_agent(code):
            return subprocess.run(
                ["setpriv", f"--reuid={AGENT_UID}", f"--regid={AGENT_UID}", "--clear-groups",
                 sys.executable, "-I", "-c", code],
                capture_output=True, text=True,
            )

        control = as_agent(f"print(open({str(public)!r}).read())")
        assert control.returncode == 0, control.stderr
        assert control.stdout.strip() == "readable"

        attack = as_agent(f"open({str(state / 'authenticated-group.json')!r}, 'a').write({record!r})")

        assert attack.returncode != 0
        assert "PermissionError" in attack.stderr
        assert not (state / "authenticated-group.json").exists()
    finally:
        shutil.rmtree(parent)
