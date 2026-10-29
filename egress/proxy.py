"""Allowlisting HTTPS egress proxy for the agent.

The agent may only open TCP connections to local services (Landlock port
rules plus the per-user firewall in profile/firewall.py): nginx (LLM
providers), the gate (chat) and this proxy. Everything else it fetches (web
search, git, curl) goes through here as an HTTP CONNECT tunnel, and the
tunnel is opened only when

* the host is a valid DNS name (letters, digits, hyphens and dots; no NUL
  or other control characters a resolver might truncate at),
* the host is on the allowlist: `example.com` matches that host exactly,
  `*.example.com` matches its subdomains,
* the port is allowed (443 by default),
* the host is a name, not an IP literal, and
* every address it resolves to is public: loopback, private, link-local
  (cloud metadata), multicast and reserved ranges are refused, so the
  proxy cannot be used to reach internal services. The connection goes to
  an address checked here, so a second DNS answer cannot redirect it.

The proxy holds no credentials and runs as its own user.

Run: python3 -I egress/proxy.py [egressAllowlist=a.com,b.org] [egressExtraDomains=...]
"""

import asyncio
import ipaddress
import logging
import pathlib
import re
import socket
import sys
from dataclasses import dataclass

logger = logging.getLogger("egress")

DEFAULT_PORT = 3128
MAX_HEADER_BYTES = 8 * 1024
MAX_CONNECTIONS = 64
CONNECT_TIMEOUT_SECONDS = 10
IDLE_TIMEOUT_SECONDS = 300

# The exact hosts the search skill (ddgs) queries. Exact hosts, not parent
# domains: google.com would include docs.google.com (public forms an agent
# could post data to), and wikipedia.org accepts anonymous edits, so
# neither is allowed by default. An attacker cannot read a search engine's
# query log, so these hosts are not an exfiltration channel.
DEFAULT_ALLOWLIST = (
    "duckduckgo.com",
    "html.duckduckgo.com",
    "www.bing.com",
    "search.brave.com",
    "www.google.com",
    "www.mojeek.com",
    "www.startpage.com",
    "yandex.com",
    "search.yahoo.com",
    "news.search.yahoo.com",
)

_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


def valid_hostname(host):
    return bool(_HOSTNAME.match(host))


@dataclass(frozen=True)
class EgressPolicy:
    domains: frozenset
    ports: frozenset = frozenset({443})

    @classmethod
    def from_config(cls, allowlist="", extra_domains="", ports="443"):
        def names(text):
            return {d.strip().lower().rstrip(".") for d in str(text or "").split(",") if d.strip()}

        base = names(allowlist) or set(DEFAULT_ALLOWLIST)
        port_set = {int(p) for p in str(ports or "443").split(",") if p.strip()}
        return cls(domains=frozenset(base | names(extra_domains)), ports=frozenset(port_set))

    def allows_name(self, host):
        host = host.lower()
        if host.endswith("."):
            host = host[:-1]
        if not valid_hostname(host) or _is_ip_literal(host):
            return False
        return any(_matches(host, entry) for entry in self.domains)

    def allows(self, host, port):
        return port in self.ports and self.allows_name(host)


def _matches(host, entry):
    if entry.startswith("*."):
        return host.endswith(entry[1:])
    return host == entry


def _is_ip_literal(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_public_address(address):
    ip = ipaddress.ip_address(address)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def resolve_public(host, port):
    """Addresses for host:port, only if every one of them is public."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = [info[4][0] for info in infos]
    if not addresses:
        raise PermissionError(f"{host} did not resolve")
    blocked = [a for a in addresses if not is_public_address(a)]
    if blocked:
        raise PermissionError(f"{host} resolves to non-public address {blocked[0]}")
    return addresses


class _Refused(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def parse_connect(head):
    """('host', port) from a CONNECT request head, or raise _Refused."""
    try:
        request_line = head.split(b"\r\n", 1)[0].decode("ascii")
        method, target, _version = request_line.split(" ", 2)
    except (UnicodeDecodeError, ValueError) as exc:
        raise _Refused(400, "malformed request") from exc
    if any(ord(char) < 0x21 or ord(char) == 0x7F for char in target):
        raise _Refused(400, "control characters in CONNECT target")
    if method.upper() != "CONNECT":
        raise _Refused(405, "only CONNECT (https) is supported")
    host, sep, port = target.rpartition(":")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536:
        raise _Refused(400, "CONNECT target must be host:port")
    return host.strip("[]"), int(port)


class EgressProxy:
    def __init__(self, policy, resolve=resolve_public, open_connection=asyncio.open_connection):
        self.policy = policy
        self._resolve = resolve
        self._open_connection = open_connection
        self._slots = asyncio.Semaphore(MAX_CONNECTIONS)

    async def handle(self, reader, writer):
        async with self._slots:
            try:
                await self._handle(reader, writer)
            except Exception as exc:
                logger.warning(f"egress: connection failed: {exc}")
            finally:
                writer.close()

    async def _handle(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), CONNECT_TIMEOUT_SECONDS)
        except asyncio.LimitOverrunError:
            return await self._refuse(writer, _Refused(431, "request head too large"))
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return
        try:
            host, port = parse_connect(head)
            if not self.policy.allows(host, port):
                raise _Refused(403, f"{host}:{port} is not on the egress allowlist")
            try:
                addresses = await self._resolve(host, port)
            except PermissionError as exc:
                raise _Refused(403, str(exc)) from exc
            except OSError as exc:
                raise _Refused(502, f"cannot resolve {host}: {exc}") from exc
            upstream = await self._connect(addresses, port)
        except _Refused as refused:
            return await self._refuse(writer, refused)

        logger.info(f"egress: allowed {host}:{port}")
        up_reader, up_writer = upstream
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        try:
            await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer))
        finally:
            up_writer.close()

    async def _connect(self, addresses, port):
        last_error = None
        for address in addresses:
            try:
                return await asyncio.wait_for(self._open_connection(address, port), CONNECT_TIMEOUT_SECONDS)
            except (OSError, asyncio.TimeoutError) as exc:
                last_error = exc
        raise _Refused(502, f"cannot connect: {last_error}")

    async def _refuse(self, writer, refused):
        logger.warning(f"egress: refused ({refused.status}): {refused.reason}")
        body = f"{refused.reason}\n".encode()
        writer.write(
            f"HTTP/1.1 {refused.status} Refused\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
        )
        await writer.drain()


async def _pipe(source, sink):
    try:
        while True:
            chunk = await asyncio.wait_for(source.read(65536), IDLE_TIMEOUT_SECONDS)
            if not chunk:
                break
            sink.write(chunk)
            await sink.drain()
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        try:
            sink.write_eof()
        except (OSError, RuntimeError):
            pass


async def serve(policy, host="127.0.0.1", port=DEFAULT_PORT, **kwargs):
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError(f"egress proxy must listen on loopback only, got {host!r}")
    proxy = EgressProxy(policy, **kwargs)
    server = await asyncio.start_server(proxy.handle, host, port, limit=MAX_HEADER_BYTES)
    logger.info(f"egress proxy on {host}:{port}, allowing {sorted(policy.domains)} on ports {sorted(policy.ports)}")
    return server


def main(argv):
    repo = pathlib.Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo / "src"))
    from config import config_get_by_key, init_config
    from logger import setup_logging

    init_config(argv)
    setup_logging(config_get_by_key("logConfigPath", ""))
    policy = EgressPolicy.from_config(
        allowlist=config_get_by_key("egressAllowlist", ""),
        extra_domains=config_get_by_key("egressExtraDomains", ""),
        ports=config_get_by_key("egressAllowPorts", "443"),
    )

    async def run():
        server = await serve(policy, port=int(config_get_by_key("egressPort", DEFAULT_PORT)))
        async with server:
            await server.serve_forever()

    asyncio.run(run())


if __name__ == "__main__":
    main(sys.argv[1:])
