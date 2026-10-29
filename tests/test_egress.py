"""Egress: the agent reaches the internet only through the allowlisting proxy."""

import asyncio
import json
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from egress import proxy as egress  # noqa: E402


# -- policy ------------------------------------------------------------------

def test_default_allowlist_covers_exact_search_hosts_only():
    policy = egress.EgressPolicy.from_config()

    assert policy.allows("html.duckduckgo.com", 443)
    assert policy.allows("www.google.com", 443)
    # Same parent domains, but services an agent could post data to.
    assert not policy.allows("docs.google.com", 443)
    assert not policy.allows("en.wikipedia.org", 443)
    assert not policy.allows("github.com", 443)
    assert not policy.allows("attacker.example", 443)


@pytest.mark.parametrize(("entry", "host", "allowed"), [
    ("duckduckgo.com", "duckduckgo.com", True),
    ("duckduckgo.com", "DuckDuckGo.com.", True),
    ("duckduckgo.com", "links.duckduckgo.com", False),
    ("*.duckduckgo.com", "links.duckduckgo.com", True),
    ("*.duckduckgo.com", "duckduckgo.com", False),
    ("*.duckduckgo.com", "evilduckduckgo.com", False),
    ("duckduckgo.com", "duckduckgo.com.attacker.example", False),
    ("duckduckgo.com", "93.184.216.34", False),
    ("duckduckgo.com", "[::1]", False),
    ("duckduckgo.com", "", False),
])
def test_host_matching(entry, host, allowed):
    assert egress.EgressPolicy.from_config(allowlist=entry).allows(host, 443) is allowed


@pytest.mark.parametrize("host", [
    "8.8.8.8\x00.www.google.com",   # resolver would stop at the NUL
    "www.google.com\x00",
    "www.google.com\t",
    "www google.com",
    "www.goo_gle.com",
    "-www.google.com",
    "a" * 64 + ".google.com",
])
def test_invalid_hostnames_are_refused(host):
    policy = egress.EgressPolicy.from_config(allowlist="*.google.com,www.google.com")

    assert not policy.allows(host, 443)


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


@pytest.mark.parametrize("head", [
    b"CONNECT 8.8.8.8\x00.www.google.com:443 HTTP/1.1\r\n\r\n",
    b"CONNECT www.google.com:0 HTTP/1.1\r\n\r\n",
    b"CONNECT www.google.com:70000 HTTP/1.1\r\n\r\n",
])
def test_connect_targets_with_control_characters_or_bad_ports_are_malformed(head):
    with pytest.raises(egress._Refused) as refused:
        egress.parse_connect(head)
    assert refused.value.status == 400


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


# -- the agent's network boundary: Landlock ports + per-user firewall ---------

import os  # noqa: E402
import shutil  # noqa: E402

sys.path.insert(0, str(REPO_ROOT / "profile"))
import firewall  # noqa: E402

AGENT_UID = 65534
needs_root_firewall = pytest.mark.skipif(
    os.geteuid() != 0 or shutil.which("iptables") is None or shutil.which("setpriv") is None,
    reason="needs root, iptables and setpriv")
SYSTEM_PATHS = ["/bin", "/usr", "/lib", "/lib64", "/etc", "/proc", "/dev/urandom"]


def test_firewall_plan_allows_only_listed_loopback_ports():
    plan = firewall.AgentFirewall(uid=65534, loopback_ports=(3128, 8080, 8090), extra_ports=(9765,)).plan()
    commands = [" ".join(command) for command, _ in plan]

    assert ("iptables -A OMEGA_AGENT -o lo -d 127.0.0.1/32 -p tcp -m multiport "
            "--dports 3128,8080,8090 -j RETURN") in commands
    assert "iptables -A OMEGA_AGENT -p tcp -m multiport --dports 9765 -j RETURN" in commands
    assert "iptables -A OMEGA_AGENT -p tcp -j REJECT --reject-with icmp-admin-prohibited" in commands
    assert "ip6tables -A OMEGA_AGENT -p tcp -j REJECT --reject-with icmp6-adm-prohibited" in commands
    assert "iptables -A OMEGA_AGENT -j DROP" in commands
    assert "ip6tables -A OMEGA_AGENT -j DROP" in commands
    assert "iptables -I OUTPUT 1 -m owner --uid-owner 65534 -j OMEGA_AGENT" in commands
    # Nothing allows UDP, so the agent cannot use DNS.
    assert not any("udp" in command for command in commands)


def test_firewall_reads_ports_from_the_production_policy():
    loaded = firewall.load(REPO_ROOT / "profile" / "policy.yaml", 65534, [9765])

    assert loaded.loopback_ports == (3128, 8080, 8090)
    assert loaded.extra_ports == (9765,)


def test_firewall_failure_stops_the_entrypoint_step():
    failures = []

    def run(command, **kwargs):
        failures.append(command)
        return subprocess.CompletedProcess(command, 1, "", "Permission denied (you must be root)")

    with pytest.raises(SystemExit, match="Permission denied"):
        firewall.apply(firewall.AgentFirewall(uid=1, loopback_ports=(8080,)), run=run)


@pytest.fixture
def installed_firewall():
    loaded = firewall.AgentFirewall(uid=AGENT_UID, loopback_ports=(3128, 8080, 8090))
    firewall.apply(loaded)
    yield loaded
    for tool in ("iptables", "ip6tables"):
        subprocess.run([tool, "-D", "OUTPUT", "-m", "owner", "--uid-owner", str(AGENT_UID), "-j", firewall.CHAIN],
                       capture_output=True)
        subprocess.run([tool, "-F", firewall.CHAIN], capture_output=True)
        subprocess.run([tool, "-X", firewall.CHAIN], capture_output=True)


def _agent_dir():
    directory = Path(tempfile.mkdtemp(dir="/tmp"))
    directory.chmod(0o777)
    return directory


def _policy_file(directory, ports):
    read_only = [p for p in SYSTEM_PATHS if Path(p).exists()] + [str(REPO_ROOT)]
    path = directory / "policy.yaml"
    path.write_text(
        "version: 1\nfilesystem_policy:\n  read_only:\n" + "".join(f"  - {p}\n" for p in read_only)
        + f"  read_write:\n  - {directory}\n  - /dev/null\n"
        + "network_policy:\n  connect_tcp:\n" + "".join(f"  - {p}\n" for p in ports)
    )
    path.chmod(0o644)
    return path


def _run_as_agent(directory, body, *config):
    script = textwrap.dedent(f"""
        import json, socket, sys
        sys.path[:0] = {[str(REPO_ROOT / 'profile'), str(REPO_ROOT / 'src'), str(REPO_ROOT)]!r}
        import logging; logging.basicConfig(level=logging.INFO)
        from config import init_config
        init_config({list(config)!r})
        import policy
        def connect(host, port):
            s = socket.socket(); s.settimeout(3)
            try:
                s.connect((host, port)); return "connected"
            except OSError as e:
                return "refused"
            finally:
                s.close()
    """) + textwrap.dedent(body)
    return subprocess.run(["setpriv", f"--reuid={AGENT_UID}", f"--regid={AGENT_UID}", "--clear-groups",
                           sys.executable, "-I", "-c", script],
                          capture_output=True, text=True, cwd=directory, timeout=60)


def _local_ip():
    sys.path.insert(0, str(REPO_ROOT / "profile"))
    import policy
    return policy._local_address()


@needs_root_firewall
def test_agent_reaches_only_listed_loopback_ports(installed_firewall, running_proxy):
    directory = _agent_dir()
    path = _policy_file(directory, [3128, 8080, 8090])
    # A server owned by another user on an *allowed* port of a non-loopback
    # address: what an attacker's server on port 8090 looks like to Landlock.
    local_ip = _local_ip()
    remote_like = socket.create_server((local_ip, 8090)) if local_ip else None
    try:
        result = _run_as_agent(directory, f"""
            policy.apply_security_policy({str(path)!r})
            print(json.dumps({{
                "same port, non-loopback": connect({local_ip!r}, 8090) if {local_ip!r} else "n/a",
                "remote 1.1.1.1:3128": connect("1.1.1.1", 3128),
            }}))
        """)
    finally:
        if remote_like:
            remote_like.close()
        shutil.rmtree(directory)

    assert result.returncode == 0, result.stderr
    outcome = json.loads(result.stdout.strip().splitlines()[-1])
    assert outcome["remote 1.1.1.1:3128"] == "refused"
    assert outcome["same port, non-loopback"] in ("refused", "n/a")
    assert "Sandbox enforced" in result.stderr


@pytest.fixture
def port_only_firewall():
    """The bug Copilot found: ports allowed to any address."""
    rules = [["-p", "tcp", "-m", "multiport", "--dports", "3128,8080,8090", "-j", "RETURN"],
             ["-p", "tcp", "-j", "REJECT", "--reject-with", "icmp-admin-prohibited"], ["-j", "DROP"]]
    subprocess.run(["iptables", "-N", "OMEGA_BUGGY"], check=True)
    for rule in rules:
        subprocess.run(["iptables", "-A", "OMEGA_BUGGY", *rule], check=True)
    jump = ["-m", "owner", "--uid-owner", str(AGENT_UID), "-j", "OMEGA_BUGGY"]
    subprocess.run(["iptables", "-I", "OUTPUT", "1", *jump], check=True)
    yield
    subprocess.run(["iptables", "-D", "OUTPUT", *jump])
    subprocess.run(["iptables", "-F", "OMEGA_BUGGY"])
    subprocess.run(["iptables", "-X", "OMEGA_BUGGY"])


@needs_root_firewall
def test_port_only_firewall_is_detected(port_only_firewall):
    directory = _agent_dir()
    path = _policy_file(directory, [3128, 8080, 8090])
    try:
        result = _run_as_agent(directory, f"""
            policy.apply_security_policy({str(path)!r})
            print("STILL RUNNING")
        """)
    finally:
        shutil.rmtree(directory)

    assert result.returncode == policy_exit_code()
    assert "STILL RUNNING" not in result.stdout
    assert "was not refused by the firewall (ECONNREFUSED)" in result.stderr


@needs_root_firewall
def test_agent_without_firewall_refuses_to_run():
    directory = _agent_dir()
    path = _policy_file(directory, [3128, 8080, 8090])
    try:
        result = _run_as_agent(directory, f"""
            policy.apply_security_policy({str(path)!r})
            print("STILL RUNNING")
        """)
    finally:
        shutil.rmtree(directory)

    assert result.returncode == policy_exit_code()
    assert "STILL RUNNING" not in result.stdout
    assert "firewall" in result.stderr


@needs_root_firewall
def test_unrestricted_network_needs_explicit_opt_in():
    directory = _agent_dir()
    path = _policy_file(directory, [8080])
    try:
        result = _run_as_agent(directory, f"""
            policy.apply_security_policy({str(path)!r})
            print("RUNNING")
        """, "allowUnrestrictedNetwork=True")
    finally:
        shutil.rmtree(directory)

    assert result.returncode == 0, result.stderr
    assert "RUNNING" in result.stdout
    assert "Network NOT restricted" in result.stderr


def test_probes_work_for_any_allowed_port_list():
    sys.path.insert(0, str(REPO_ROOT / "profile"))
    import policy

    probes = policy.NetworkProbes.open([1, 7, 9, 13])
    try:
        assert probes.other_port.getsockname()[1] not in (1, 7, 9, 13)
        assert probes.same_port[1] == 1
        assert not probes.same_port[0].startswith("127.")
    finally:
        probes.close()


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
