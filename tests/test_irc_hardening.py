"""IRC adapter: TLS, private-only auth, account-bound owner."""

import importlib
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
for entry in (REPO_ROOT, REPO_ROOT / "src", REPO_ROOT / "channels"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

SECRET = "a-long-enough-owner-secret"


@pytest.fixture
def irc(monkeypatch, tmp_path):
    import config

    monkeypatch.setattr(config, "_COMMAND_LINE", {"authStateDir": str(tmp_path / "gate")})
    monkeypatch.setattr(config, "_CONFIG", {})
    monkeypatch.setattr(config, "_CONFIG_FILE", {})
    monkeypatch.setenv("OMEGA_AUTH_SECRET", SECRET)
    for name in ("irc", "auth"):
        sys.modules.pop(name, None)
    module = importlib.import_module("irc")
    module._sent = []
    monkeypatch.setattr(module, "_send", module._sent.append)
    module._state = module._State(nick="omega1234", require_account=True, registered=True)
    module._outbox.clear()
    module.getLastMessage()
    return module


def privmsg(irc, text, target=None, nick="alice", account="alice", ident="~al", host="example.org"):
    tags = f"@account={account} " if account else ""
    return irc.parse_line(f"{tags}:{nick}!{ident}@{host} PRIVMSG {target or irc._state.nick} :{text}")


# -- parsing -----------------------------------------------------------------

def test_parse_line_with_tags_prefix_and_trailing(irc):
    line = irc.parse_line(r"@account=Al\sice;time=2026 :alice!~al@host PRIVMSG #chan :hello there :)")

    assert line.command == "PRIVMSG"
    assert line.params == ("#chan", "hello there :)")
    assert line.tags == {"account": "Al ice", "time": "2026"}
    assert (line.nick, line.ident, line.host) == ("alice", "~al", "host")


def test_parse_line_without_prefix(irc):
    line = irc.parse_line("PING :irc.example.org")

    assert line.command == "PING"
    assert line.params == ("irc.example.org",)


@pytest.mark.parametrize(("raw", "require_account", "identity"), [
    ("@account=Alice :alice!~a@h PRIVMSG x :m", True, "account:alice"),
    ("@account=* :alice!~a@h PRIVMSG x :m", True, None),
    (":alice!~a@h PRIVMSG x :m", True, None),
    (":alice!~a@Host PRIVMSG x :m", False, "mask:~a@host"),
    ("@account=Alice :alice!~a@h PRIVMSG x :m", False, "account:alice"),
])
def test_sender_identity(irc, raw, require_account, identity):
    assert irc.sender_identity(irc.parse_line(raw), require_account) == identity


# -- authentication ----------------------------------------------------------

def test_secret_in_a_channel_is_never_evaluated(irc, monkeypatch):
    calls = []
    monkeypatch.setattr(irc.auth, "authenticate_channel_user", lambda *a: calls.append(a) or "auth_bound")

    forward, reply = irc.handle_privmsg(privmsg(irc, f"auth {SECRET}", target="#chan"))

    assert forward is None
    assert calls == []
    assert "Never send the secret in a channel" in reply
    assert irc._state.owner is None


def test_public_auth_warning_is_sent_once_per_nick(irc):
    irc.handle_privmsg(privmsg(irc, "auth one", target="#chan"))

    assert irc.handle_privmsg(privmsg(irc, "auth two", target="#chan")) == (None, None)


def test_private_auth_requires_a_services_account(irc):
    forward, reply = irc.handle_privmsg(privmsg(irc, f"auth {SECRET}", account=None))

    assert forward is None
    assert "Identify with the network's services" in reply
    assert irc._state.owner is None


def test_private_auth_binds_the_account(irc):
    forward, reply = irc.handle_privmsg(privmsg(irc, f"auth {SECRET}"))

    assert forward is None  # the secret never reaches the agent
    assert reply == "Authentication successful."
    assert irc._state.owner == "account:alice"
    assert irc.auth.get_channel_authenticated_user_id("IRC_IDENTITY") == "account:alice"


def test_wrong_secret_does_not_bind(irc):
    assert irc.handle_privmsg(privmsg(irc, "auth wrong")) == (None, None)
    assert irc._state.owner is None


def test_owner_messages_reach_the_agent_and_replies_follow(irc):
    irc.handle_privmsg(privmsg(irc, f"auth {SECRET}"))

    assert irc.handle_privmsg(privmsg(irc, "hi in private")) == ("alice: hi in private", None)
    assert irc._state.reply_target == "alice"

    assert irc.handle_privmsg(privmsg(irc, "hi in public", target="#chan")) == ("alice: hi in public", None)
    assert irc._state.reply_target == "#chan"


def test_taking_the_owners_nick_gives_nothing(irc):
    irc.handle_privmsg(privmsg(irc, f"auth {SECRET}"))

    assert irc.handle_privmsg(privmsg(irc, "rm -rf /", account=None)) == (None, None)
    assert irc.handle_privmsg(privmsg(irc, "rm -rf /", account="mallory")) == (None, None)


def test_mask_binding_when_accounts_are_not_required(irc):
    irc._state.require_account = False
    irc.handle_privmsg(privmsg(irc, f"auth {SECRET}", account=None, ident="~al", host="1.2.3.4"))

    assert irc._state.owner == "mask:~al@1.2.3.4"
    assert irc.handle_privmsg(privmsg(irc, "hi", account=None, ident="~al", host="1.2.3.4"))[0] == "alice: hi"
    assert irc.handle_privmsg(privmsg(irc, "hi", account=None, ident="~al", host="6.6.6.6")) == (None, None)


def test_legacy_nick_record_is_not_trusted(irc, tmp_path):
    state = tmp_path / "gate"
    state.mkdir(mode=0o700)
    (state / "authenticated-user.json").write_text(
        '{"time":"t","channel_identifier":"IRC","user_id":"alice"}\n')

    assert irc.handle_privmsg(privmsg(irc, "hello", account=None)) == (None, None)


def test_outbound_lines_cannot_inject_commands(irc):
    importlib.reload(irc)  # restore the real _send

    with pytest.raises(ValueError):
        irc._send("PRIVMSG #c :hi\r\nQUIT")


def test_agent_text_is_wrapped_into_single_lines(irc):
    irc.handle_privmsg(privmsg(irc, f"auth {SECRET}"))
    irc._sent.clear()

    irc.send_message("hello\nQUIT :bye")

    assert irc._sent == ["PRIVMSG alice :hello QUIT :bye"]


# -- delivery safety ---------------------------------------------------------

def _privmsgs(irc):
    return [line for line in irc._sent if line.startswith("PRIVMSG")]


def _owner_authenticated(irc, monitor=True):
    irc._state.monitor = monitor
    irc._on_line(privmsg(irc, f"auth {SECRET}"))


def test_queued_output_is_flushed_once_the_owner_authenticates(irc):
    irc.send_message("Omega v1.2.3")  # e.g. the startup version, before any owner
    assert _privmsgs(irc) == []

    _owner_authenticated(irc)

    assert "PRIVMSG alice :Omega v1.2.3" in _privmsgs(irc)


def test_owner_nick_is_monitored(irc):
    _owner_authenticated(irc)

    assert "MONITOR + alice" in irc._sent


def test_reply_is_held_when_the_owner_goes_offline_and_the_nick_is_reused(irc):
    _owner_authenticated(irc)
    irc._sent.clear()

    irc._on_line(irc.parse_line(":srv 731 omega1234 :alice"))       # owner left
    irc._on_line(irc.parse_line(":srv 730 omega1234 :alice!~m@evil"))  # someone took the nick
    irc._on_line(privmsg(irc, "hi", account=None, ident="~m", host="evil"))
    irc.send_message("secret result")

    assert _privmsgs(irc) == []

    irc._on_line(privmsg(irc, "back again", nick="alice_"))  # owner, new nick, same account

    assert _privmsgs(irc) == ["PRIVMSG alice_ :secret result"]


def test_without_monitor_private_replies_expire(irc, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(irc.time, "monotonic", lambda: clock[0])
    irc._state.private_reply_ttl = 600
    _owner_authenticated(irc, monitor=False)
    irc._sent.clear()

    clock[0] += 601
    irc.send_message("late reply")
    assert _privmsgs(irc) == []

    irc._on_line(privmsg(irc, "still here"))
    assert _privmsgs(irc) == ["PRIVMSG alice :late reply"]


def test_private_replies_work_when_the_channel_join_failed(irc):
    irc._state.channel = "#closed"
    irc._on_line(irc.parse_line(":srv 474 omega1234 #closed :Cannot join channel (+b)"))
    _owner_authenticated(irc)
    irc._sent.clear()

    irc.send_message("private answer")

    assert _privmsgs(irc) == ["PRIVMSG alice :private answer"]


def test_channel_replies_wait_for_the_join(irc):
    irc._state.channel = "#chan"
    _owner_authenticated(irc)
    irc._on_line(privmsg(irc, "say it in public", target="#chan"))
    irc._sent.clear()

    irc.send_message("public answer")
    assert _privmsgs(irc) == []

    irc._on_line(irc.parse_line(":srv 366 omega1234 #chan :End of /NAMES list."))
    assert _privmsgs(irc) == ["PRIVMSG #chan :public answer"]


def test_isupport_monitor_is_detected(irc):
    irc._on_line(irc.parse_line(":srv 005 omega1234 CHANTYPES=# MONITOR=100 :are supported"))

    assert irc._state.monitor is True


def test_export_principal_uses_the_irc_identity_records(irc, tmp_path):
    import channels as channel_api

    state = tmp_path / "gate"
    state.mkdir(mode=0o700, exist_ok=True)
    (state / "authenticated-user.json").write_text(
        '{"time":"t","channel_identifier":"IRC","user_id":"legacy-nick"}\n')

    assert channel_api.auth_channel_id("irc") == "IRC_IDENTITY"
    assert channel_api.local_export_principal("irc") is None

    irc.handle_privmsg(privmsg(irc, f"auth {SECRET}"))
    assert channel_api.local_export_principal("irc") == "account:alice"


# -- transport ---------------------------------------------------------------

def test_plaintext_needs_explicit_opt_in(irc):
    with pytest.raises(ValueError, match="IRC_allowPlaintext"):
        irc.start_irc(tls=False)


@pytest.fixture
def self_signed_tls_server(tmp_path):
    if subprocess.run(["which", "openssl"], capture_output=True).returncode:
        pytest.skip("openssl is not installed")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    listener = socket.create_server(("127.0.0.1", 0))

    def accept():
        try:
            conn, _ = listener.accept()
            with context.wrap_socket(conn, server_side=True):
                pass
        except Exception:
            pass

    threading.Thread(target=accept, daemon=True).start()
    yield listener.getsockname()[1]
    listener.close()


def test_tls_certificate_is_verified(irc, self_signed_tls_server):
    with pytest.raises(ssl.SSLCertVerificationError):
        irc.open_connection("localhost", self_signed_tls_server, tls=True, timeout=5)


# -- end to end against a fake server ----------------------------------------

class FakeIrcServer:
    def __init__(self, script):
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.script = script
        self.received = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        conn, _ = self.listener.accept()
        conn.settimeout(10)
        buffer = b""
        nick = None
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                buffer += data
                while b"\r\n" in buffer:
                    raw, buffer = buffer.split(b"\r\n", 1)
                    line = raw.decode()
                    self.received.append(line)
                    if line.startswith("NICK "):
                        nick = line.split()[1]
                    if line == "CAP REQ :account-tag":
                        conn.sendall(b":srv CAP * ACK :account-tag\r\n")
                    if line.startswith("USER "):
                        conn.sendall(f":srv 001 {nick} :Welcome\r\n".encode())
                        for scripted in self.script:
                            conn.sendall(scripted.format(nick=nick).encode() + b"\r\n")
        except OSError:
            return


def test_session_end_to_end(irc, monkeypatch):
    importlib.reload(irc)  # restore the real _send
    monkeypatch.setattr(irc.time, "sleep", lambda seconds: None)
    server = FakeIrcServer([
        f"@account=mallory :mallory!~m@evil PRIVMSG {{nick}} :auth {SECRET}x",
        f"@account=alice :alice!~a@home PRIVMSG {{nick}} :auth {SECRET}",
        "@account=mallory :alice!~m@evil PRIVMSG {nick} :impersonation",
        "@account=alice :alice!~a@home PRIVMSG {nick} :hello agent",
    ])
    irc.start_irc(server="127.0.0.1", port=server.port, tls=False, allow_plaintext=True)
    try:
        deadline = time.monotonic() + 10
        message = ""
        while time.monotonic() < deadline and not message:
            message = irc.getLastMessage()
            time.sleep(0.05) if not message else None
        assert message == "alice: hello agent"

        irc.send_message("hi owner")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not any(l.startswith("PRIVMSG alice :hi owner") for l in server.received):
            pass
        assert "PRIVMSG alice :hi owner" in server.received
        assert any(l.startswith("NOTICE alice :Authentication successful") for l in server.received)
        assert not any("impersonation" in l for l in server.received)
        assert not any(l.startswith("JOIN") for l in server.received)  # no channel configured
    finally:
        irc.stop_irc()
