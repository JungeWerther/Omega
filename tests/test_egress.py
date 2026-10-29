"""Egress: the agent reaches the internet only through the allowlisting proxy."""

import asyncio
import json
import socket
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from egress import proxy as egress  # noqa: E402


# -- policy ------------------------------------------------------------------

def test_default_allowlist_covers_search_engines_only():
    policy = egress.EgressPolicy.from_config()

    assert policy.allows("html.duckduckgo.com", 443)
    assert policy.allows("en.wikipedia.org", 443)
    assert not policy.allows("github.com", 443)
    assert not policy.allows("attacker.example", 443)


@pytest.mark.parametrize(("host", "allowed"), [
    ("duckduckgo.com", True),
    ("DuckDuckGo.com.", True),
    ("links.duckduckgo.com", True),
    ("evilduckduckgo.com", False),
    ("duckduckgo.com.attacker.example", False),
    ("93.184.216.34", False),
    ("[::1]", False),
    ("", False),
])
def test_domain_matching(host, allowed):
    assert egress.EgressPolicy.from_config(allowlist="duckduckgo.com").allows(host, 443) is allowed


def test_ports_are_restricted():
    policy = egress.EgressPolicy.from_config(allowlist="example.org")

    assert policy.allows("example.org", 443)
    assert not policy.allows("example.org", 22)
    assert not policy.allows("example.org", 80)


def test_extra_domains_extend_and_allowlist_replaces_defaults():
    extended = egress.EgressPolicy.from_config(extra_domains="github.com")
    replaced = egress.EgressPolicy.from_config(allowlist="github.com")

    assert extended.allows("github.com", 443) and extended.allows("duckduckgo.com", 443)
    assert replaced.allows("github.com", 443) and not replaced.allows("duckduckgo.com", 443)


@pytest.mark.parametrize(("address", "public"), [
    ("8.8.8.8", True),
    ("2606:4700:4700::1111", True),
    ("127.0.0.1", False),
    ("10.0.0.5", False),
    ("172.17.0.1", False),
    ("192.168.1.1", False),
    ("169.254.169.254", False),  # cloud metadata
    ("100.64.0.1", False),
    ("::1", False),
    ("::ffff:127.0.0.1", False),
    ("fd00::1", False),
    ("fe80::1", False),
    ("224.0.0.1", False),
    ("0.0.0.0", False),
])
def test_only_public_addresses_are_reachable(address, public):
    assert egress.is_public_address(address) is public


def test_name_resolving_to_a_private_address_is_refused():
    with pytest.raises(PermissionError, match="non-public"):
        asyncio.run(egress.resolve_public("localhost", 443))


@pytest.mark.parametrize("head", [b"GET http://x/ HTTP/1.1\r\n\r\n", b"CONNECT nohost HTTP/1.1\r\n\r\n", b"\xff\r\n\r\n"])
def test_parse_connect_rejects_everything_but_connect(head):
    with pytest.raises(egress._Refused):
        egress.parse_connect(head)


# -- proxy behaviour ---------------------------------------------------------

class Echo:
    """Upstream stand-in that echoes bytes back."""

    def __init__(self):
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn):
        with conn:
            while data := conn.recv(4096):
                conn.sendall(data)


@pytest.fixture
def running_proxy():
    echo = Echo()
    policy = egress.EgressPolicy.from_config(allowlist="allowed.test,private.test")

    async def fake_resolve(host, port):
        if host == "private.test":
            raise PermissionError("private.test resolves to non-public address 10.0.0.1")
        return ["203.0.113.10"]

    async def to_echo(address, port):
        assert address == "203.0.113.10"
        return await asyncio.open_connection("127.0.0.1", echo.port)

    loop = asyncio.new_event_loop()
    ready = threading.Event()
    holder = {}

    async def start():
        holder["server"] = await egress.serve(policy, port=0, resolve=fake_resolve, open_connection=to_echo)
        ready.set()

    threading.Thread(target=lambda: (loop.run_until_complete(start()), loop.run_forever()), daemon=True).start()
    assert ready.wait(5)
    port = holder["server"].sockets[0].getsockname()[1]
    yield port

    async def stop():
        holder["server"].close()
        await holder["server"].wait_closed()

    asyncio.run_coroutine_threadsafe(stop(), loop).result(5)
    loop.call_soon_threadsafe(loop.stop)


def _request(port, head):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall(head)
        response = conn.recv(4096)
        if response.startswith(b"HTTP/1.1 200"):
            conn.sendall(b"ping")
            return response, conn.recv(4096)
        return response, None


def test_allowed_host_gets_a_tunnel(running_proxy):
    response, echoed = _request(running_proxy, b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test\r\n\r\n")

    assert response.startswith(b"HTTP/1.1 200")
    assert echoed == b"ping"


@pytest.mark.parametrize(("head", "status"), [
    (b"CONNECT attacker.example:443 HTTP/1.1\r\n\r\n", b"403"),
    (b"CONNECT allowed.test:22 HTTP/1.1\r\n\r\n", b"403"),
    (b"CONNECT 203.0.113.10:443 HTTP/1.1\r\n\r\n", b"403"),
    (b"CONNECT private.test:443 HTTP/1.1\r\n\r\n", b"403"),
    (b"GET http://allowed.test/ HTTP/1.1\r\n\r\n", b"405"),
    (b"CONNECT " + b"a" * 9000 + b".test:443 HTTP/1.1\r\n\r\n", b"431"),
])
def test_refusals(running_proxy, head, status):
    response, _ = _request(running_proxy, head)

    assert response.split(b" ", 2)[1] == status


def test_proxy_refuses_non_loopback_listen():
    with pytest.raises(ValueError):
        asyncio.run(egress.serve(egress.EgressPolicy.from_config(), host="0.0.0.0", port=0))


# -- Landlock network rules for the agent ------------------------------------

def _landlock_abi():
    probe = subprocess.run([sys.executable, "-c", "from py_landlock import get_abi_version; print(get_abi_version())"],
                           capture_output=True, text=True)
    return int(probe.stdout.strip()) if probe.returncode == 0 else 0


needs_network_landlock = pytest.mark.skipif(_landlock_abi() < 4, reason="needs Landlock ABI 4 (Linux 6.7+)")

SYSTEM_PATHS = ["/bin", "/usr", "/lib", "/lib64", "/etc", "/proc", "/dev/urandom"]


def _policy_file(tmp_path, ports):
    read_only = [p for p in SYSTEM_PATHS if Path(p).exists()] + [str(REPO_ROOT)]
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\nfilesystem_policy:\n  read_only:\n" + "".join(f"  - {p}\n" for p in read_only)
        + f"  read_write:\n  - {tmp_path}\n  - /dev/null\n"
        + "network_policy:\n  connect_tcp:\n" + "".join(f"  - {p}\n" for p in ports)
    )
    return path


def _run_agent(tmp_path, body, *config):
    script = textwrap.dedent(f"""
        import json, socket, sys
        sys.path[:0] = {[str(REPO_ROOT / 'profile'), str(REPO_ROOT / 'src'), str(REPO_ROOT)]!r}
        import logging; logging.basicConfig(level=logging.INFO)
        from config import init_config
        init_config({list(config)!r})
        import policy
    """) + textwrap.dedent(body)
    return subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, cwd=tmp_path, timeout=60)


def _connect_outcome(port):
    return f"""
        def connect(port):
            s = socket.socket(); s.settimeout(3)
            try:
                s.connect(("127.0.0.1", port)); return "connected"
            except PermissionError:
                return "denied"
            except OSError as e:
                return type(e).__name__
            finally:
                s.close()
    """


@needs_network_landlock
def test_agent_can_only_connect_to_listed_ports(tmp_path, running_proxy):
    other = Echo()
    path = _policy_file(tmp_path, [running_proxy])
    result = _run_agent(tmp_path, _connect_outcome(0) + f"""
        policy.apply_security_policy({str(path)!r})
        outcome = {{"proxy": connect({running_proxy}), "direct": connect({other.port})}}
        s = socket.create_connection(("127.0.0.1", {running_proxy}), timeout=5)
        s.sendall(b"CONNECT allowed.test:443 HTTP/1.1\\r\\n\\r\\n")
        outcome["tunnel"] = s.recv(100).split(b"\\r\\n")[0].decode()
        print(json.dumps(outcome))
    """)

    assert result.returncode == 0, result.stderr
    outcome = json.loads(result.stdout.strip().splitlines()[-1])
    assert outcome == {"proxy": "connected", "direct": "denied",
                       "tunnel": "HTTP/1.1 200 Connection established"}
    assert "network: TCP connect only to ports" in result.stderr


@needs_network_landlock
def test_extra_ports_come_from_configuration(tmp_path):
    other = Echo()
    path = _policy_file(tmp_path, [8080])
    result = _run_agent(tmp_path, _connect_outcome(0) + f"""
        policy.apply_security_policy({str(path)!r})
        print(connect({other.port}))
    """, f"egressExtraPorts={other.port}")

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == "connected"


def test_kernel_without_network_rules_stops_the_agent(tmp_path):
    path = _policy_file(tmp_path, [8080])
    result = _run_agent(tmp_path, f"""
        original = policy.FileSystemPolicy.apply
        def without_network(self):
            ports, self.connect_ports = self.connect_ports, None
            original(self)
            self.connect_ports = ports
        policy.FileSystemPolicy.apply = without_network
        policy.apply_security_policy({str(path)!r})
        print("STILL RUNNING")
    """)

    assert result.returncode == policy_exit_code()
    assert "STILL RUNNING" not in result.stdout
    assert "needs ABI 4" in result.stderr


def test_unrestricted_network_needs_explicit_opt_in(tmp_path):
    other = Echo()
    path = _policy_file(tmp_path, [8080])
    result = _run_agent(tmp_path, _connect_outcome(0) + f"""
        policy.apply_security_policy({str(path)!r})
        print(connect({other.port}))
    """, "allowUnrestrictedNetwork=True")

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == "connected"
    assert "Network NOT restricted" in result.stderr


def policy_exit_code():
    sys.path.insert(0, str(REPO_ROOT / "profile"))
    sys.path.insert(0, str(REPO_ROOT / "src"))
    import policy

    return policy.SANDBOX_FAILURE_EXIT_CODE


# -- agent clients bypass the proxy for local services -----------------------

def test_local_services_are_not_sent_through_the_egress_proxy(monkeypatch):
    """The agent's environment points every HTTP client at the proxy; the
    gate and nginx on 127.0.0.1 must still be reached directly."""
    sys.path.insert(0, str(REPO_ROOT / "src"))
    import http.server
    import channels

    class Gate(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b'{"message": "direct"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    gate = http.server.HTTPServer(("127.0.0.1", 0), Gate)
    threading.Thread(target=gate.serve_forever, daemon=True).start()
    # A proxy that does not exist: anything sent there fails.
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost,::1")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost,::1")
    try:
        assert channels.GateChannel(f"http://127.0.0.1:{gate.server_address[1]}").receive() == "direct"
    finally:
        gate.shutdown()


# -- the proxy as a process --------------------------------------------------

def test_proxy_process_applies_configuration(tmp_path):
    port = Echo().port  # any free port number for the proxy to take over
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    process = subprocess.Popen(
        [sys.executable, "-I", str(REPO_ROOT / "egress" / "proxy.py"),
         f"egressPort={port}", "egressAllowlist=only.example"],
        cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1) as conn:
                    conn.sendall(b"CONNECT duckduckgo.com:443 HTTP/1.1\r\n\r\n")
                    response = conn.recv(200)
                break
            except OSError:
                import time
                time.sleep(0.1)
        assert response.startswith(b"HTTP/1.1 403")
        assert b"not on the egress allowlist" in response
    finally:
        process.terminate()
        output = process.communicate(timeout=10)[0]
    assert "allowing ['only.example']" in output
