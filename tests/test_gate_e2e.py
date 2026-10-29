"""End to end: a real gate process relays a websocket chat to the agent."""

import asyncio
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

websockets = pytest.importorskip("websockets")

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

import channels  # noqa: E402


def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class ChatServer:
    """Speaks wschat's JSON frames; records what the agent sends."""

    def __init__(self):
        self.port = _free_port()
        self.received = []
        self.authorization = None
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    async def _handler(self, ws):
        self.authorization = ws.request.headers.get("Authorization")
        await ws.send(json.dumps({"type": "user_message", "seq": 1, "text": "ping from owner"}))
        async for raw in ws:
            frame = json.loads(raw)
            if frame.get("type") == "agent_message":
                self.received.append(frame["text"])

    async def _main(self):
        async with websockets.serve(self._handler, "127.0.0.1", self.port):
            self._ready.set()
            await asyncio.Future()

    def _run(self):
        self._loop.run_until_complete(self._main())

    def start(self):
        self._thread.start()
        assert self._ready.wait(10)


def _wait_for(predicate, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.2)
    raise AssertionError("condition not met in time")


@pytest.fixture
def gate_process(tmp_path):
    server = ChatServer()
    server.start()
    gate_port = _free_port()
    environment = {
        "PATH": os.environ["PATH"],
        "OMEGA_AUTH_SECRET": "a-long-enough-owner-secret",
        "OMEGA_WS_TOKEN": "ws-bearer-token",
    }
    process = subprocess.Popen(
        [sys.executable, "-I", str(REPO_ROOT / "gate" / "main.py"),
         "commchannel=websocket",
         f"WS_URL=ws://127.0.0.1:{server.port}",
         f"authStateDir={tmp_path / 'state'}",
         f"gatePort={gate_port}"],
        env=environment,
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    client = channels.GateChannel(f"http://127.0.0.1:{gate_port}")
    try:
        _wait_for(lambda: _healthy(client))
        yield server, client, process
    finally:
        process.terminate()
        process.wait(timeout=10)


def _healthy(client):
    try:
        client.start()
        return True
    except Exception:
        return False


def test_message_flows_from_chat_through_gate_to_agent_and_back(gate_process):
    server, client, _ = gate_process

    message = _wait_for(client.receive)
    assert message == "ping from owner"

    client.send("pong from agent")
    _wait_for(lambda: server.received)
    assert server.received == ["pong from agent"]


def test_channel_token_comes_from_gate_environment_not_argv(gate_process):
    server, client, process = gate_process
    _wait_for(client.receive)

    assert server.authorization == "Bearer ws-bearer-token"
    cmdline = Path(f"/proc/{process.pid}/cmdline").read_bytes().decode()
    assert "ws-bearer-token" not in cmdline
    assert client.principal() == "websocket:" + hashlib.sha256(b"ws-bearer-token").hexdigest()
