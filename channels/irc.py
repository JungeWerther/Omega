"""IRC channel adapter.

Security model
--------------
IRC nicknames are first come, first served, and channel messages are public,
so the adapter does not trust either:

* The connection uses TLS with certificate verification. Plain TCP needs an
  explicit IRC_allowPlaintext=True.
* `auth <secret>` is accepted only in a private message to the bot. A secret
  posted in a channel is never evaluated (so the channel cannot be used to
  test guesses) and the sender is told to rotate it.
* The owner is bound to a services account (IRCv3 `account-tag`, e.g.
  Libera.Chat NickServ), not to a nickname, so whoever takes the nick after a
  disconnect gets nothing. Servers without account tags (QuakeNet) need
  IRC_requireAccount=False, which binds the owner to `ident@host` instead.
* Replies go back where the owner spoke: a private message when the owner
  wrote privately, the channel otherwise. Without IRC_channel the bot joins
  no channel at all and talks to the owner privately only.
"""

import random
import socket
import ssl
import textwrap
import threading
import time
from dataclasses import dataclass, field

import auth
import channels
from config import config_get_by_key
from delivery_queue import PendingMessages
from src.logger import get_logger

logger = get_logger(__name__)

# Owner records written by this adapter. Older versions stored bare
# nicknames under "IRC"; those are deliberately not trusted any more, so the
# owner authenticates once again after upgrading.
AUTH_CHANNEL_ID = "IRC_IDENTITY"

DEFAULT_SERVER = "irc.libera.chat"
TLS_PORT = 6697
PLAINTEXT_PORT = 6667
MAX_LINE_CHARS = 400

_TRUTHY = {"1", "true", "yes", "on"}


def _flag(key, default):
    value = config_get_by_key(key, default)
    return value is True or str(value).strip().lower() in _TRUTHY


# -- parsing -----------------------------------------------------------------

_TAG_ESCAPES = {":": ";", "s": " ", "\\": "\\", "r": "\r", "n": "\n"}


def _unescape_tag_value(value):
    out, chars = [], iter(value)
    for char in chars:
        if char == "\\":
            escaped = next(chars, "")
            out.append(_TAG_ESCAPES.get(escaped, escaped))
        else:
            out.append(char)
    return "".join(out)


@dataclass(frozen=True)
class IrcLine:
    """One parsed IRC protocol line (RFC 1459 with IRCv3 message tags)."""

    command: str
    params: tuple = ()
    tags: dict = field(default_factory=dict)
    nick: str = ""
    ident: str = ""
    host: str = ""


def parse_line(raw):
    rest = raw
    tags = {}
    if rest.startswith("@"):
        tag_text, _, rest = rest[1:].partition(" ")
        for item in filter(None, tag_text.split(";")):
            key, _, value = item.partition("=")
            tags[key] = _unescape_tag_value(value)
    nick = ident = host = ""
    if rest.startswith(":"):
        prefix, _, rest = rest[1:].partition(" ")
        nick, _, user_host = prefix.partition("!")
        ident, _, host = user_host.partition("@")
    middle, _, trailing = rest.partition(" :")
    words = middle.split()
    if not words:
        return IrcLine(command="")
    params = tuple(words[1:]) + ((trailing,) if " :" in rest else ())
    return IrcLine(command=words[0].upper(), params=params, tags=tags,
                   nick=nick, ident=ident, host=host)


def sender_identity(line, require_account):
    """Stable identity of a message's sender, or None when it has none.

    A services account wins. Without one, `ident@host` is used only when the
    operator accepted that weaker binding (IRC_requireAccount=False).
    """
    account = line.tags.get("account", "")
    if account and account != "*":
        return f"account:{account.lower()}"
    if require_account:
        return None
    if line.ident and line.host:
        return f"mask:{line.ident}@{line.host}".lower()
    return None


def _parse_auth_candidate(msg):
    text = msg.strip()
    lower = text.lower()
    if lower.startswith("auth "):
        return text[5:].strip()
    if lower.startswith("/auth "):
        return text[6:].strip()
    return text


def _is_auth_command(msg):
    lower = msg.strip().lower()
    return lower.startswith("auth ") or lower.startswith("/auth ")


# -- state -------------------------------------------------------------------

@dataclass
class _State:
    channel: str = ""
    nick: str = ""
    require_account: bool = True
    owner: str | None = None
    owner_nick: str = ""
    reply_target: str = ""
    connected: bool = False
    account_tags: bool = False
    warned_public_auth: set = field(default_factory=set)


_state = _State()
_state_lock = threading.Lock()
_running = False
_sock = None
_sock_lock = threading.Lock()
_last_message = ""
_msg_lock = threading.Lock()
_outbox = PendingMessages()


def _send(cmd):
    if "\r" in cmd or "\n" in cmd:
        raise ValueError("IRC command must be a single line")
    with _sock_lock:
        if _sock is None:
            raise RuntimeError("IRC channel is not connected")
        _sock.sendall((cmd + "\r\n").encode())
    time.sleep(1)


def _set_last(msg):
    global _last_message
    with _msg_lock:
        _last_message = msg if not _last_message else f"{_last_message} | {msg}"


def getLastMessage():
    global _last_message
    with _msg_lock:
        tmp, _last_message = _last_message, ""
        return tmp


def _notice(target, text):
    try:
        _send(f"NOTICE {target} :{text}")
    except Exception as exc:
        logger.warning(f"IRC notice to {target} failed: {exc}")


# -- message handling --------------------------------------------------------

def _handle_auth(line, private, text):
    """Returns the reply for an auth attempt. Never forwards it to the agent."""
    if not private:
        with _state_lock:
            first_warning = line.nick not in _state.warned_public_auth
            _state.warned_public_auth.add(line.nick)
        if first_warning:
            return ("Never send the secret in a channel. Send it privately "
                    f"(/msg {_state.nick} auth <secret>). If that was the real secret, "
                    "restart Omega with a new one.")
        return None

    identity = sender_identity(line, _state.require_account)
    if identity is None:
        return ("Identify with the network's services first (for example "
                "/msg NickServ IDENTIFY), then send auth again.")

    result = auth.authenticate_channel_user(AUTH_CHANNEL_ID, identity, _parse_auth_candidate(text))
    if result in ("auth_bound", "allow"):
        with _state_lock:
            _state.owner = identity
            _state.owner_nick = line.nick
            _state.reply_target = line.nick
        return "Authentication successful."
    return None


def handle_privmsg(line):
    """Process one PRIVMSG; returns (forward_to_agent, notice_text)."""
    if len(line.params) < 2:
        return None, None
    target, text = line.params[0], line.params[1]
    private = target.lower() == _state.nick.lower()

    if _is_auth_command(text):
        return None, _handle_auth(line, private, text)

    if not auth.is_auth_enabled():
        allowed = True
    else:
        identity = sender_identity(line, _state.require_account)
        allowed = identity is not None and identity == _state.owner
    if not allowed:
        return None, None

    with _state_lock:
        _state.owner_nick = line.nick
        _state.reply_target = line.nick if private else target
    return f"{line.nick}: {text}", None


def _on_line(line):
    if line.command == "PING":
        _send(f"PONG :{line.params[0] if line.params else ''}")
    elif line.command == "CAP" and len(line.params) >= 3:
        _on_cap(line.params[1].upper(), line.params[2])
    elif line.command == "001":
        with _state_lock:
            if line.params:
                _state.nick = line.params[0]
            channel = _state.channel
        if not _state.account_tags and _state.require_account:
            logger.error("IRC server does not provide account tags: nobody can authenticate. "
                         "Use a network with services accounts (e.g. Libera.Chat) or set "
                         "IRC_requireAccount=False to bind the owner to ident@host.")
        if channel:
            _send(f"JOIN {channel}")
        else:
            _mark_connected()
    elif line.command == "366" and len(line.params) > 1 and line.params[1].lower() == _state.channel.lower():
        logger.info(f"Joined {_state.channel}")
        _mark_connected()
    elif line.command in {"403", "405", "471", "473", "474", "475"}:
        logger.error(f"Join failed: {line.command} {' '.join(line.params)}")
    elif line.command == "433":
        raise NickInUse("Nickname in use")
    elif line.command == "PRIVMSG":
        forward, reply = handle_privmsg(line)
        if forward:
            _set_last(forward)
        if reply:
            _notice(line.nick, reply)


def _on_cap(subcommand, capabilities):
    if subcommand == "ACK" and "account-tag" in capabilities.split():
        _state.account_tags = True
        _send("CAP END")
    elif subcommand == "NAK":
        _send("CAP END")


def _mark_connected():
    with _state_lock:
        _state.connected = True
    _flush_outbox()


# -- delivery ----------------------------------------------------------------

def _ready_to_send():
    with _state_lock:
        return _state.connected and bool(_state.reply_target)


def _deliver_outbound(chunk):
    with _state_lock:
        target = _state.reply_target
    _send(f"PRIVMSG {target} :{chunk}")


def _flush_outbox():
    try:
        _outbox.flush(_deliver_outbound, _ready_to_send)
    except Exception as exc:
        logger.warning(f"IRC send failed; retaining queued message: {exc}")


def send_message(text):
    segments = str(text).replace("\r", "").split("\\n")
    lines = []
    for segment in segments:
        lines.extend(textwrap.wrap(segment, width=MAX_LINE_CHARS,
                                   break_long_words=True, break_on_hyphens=False))
    _outbox.extend(lines)
    _flush_outbox()


# -- connection --------------------------------------------------------------

def open_connection(server, port, tls, timeout=15):
    sock = socket.create_connection((server, int(port)), timeout=timeout)
    if not tls:
        return sock
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        return context.wrap_socket(sock, server_hostname=server)
    except Exception:
        sock.close()
        raise


class NickInUse(ConnectionError):
    pass


def _irc_session(server, port, tls, nick):
    global _sock
    logger.info(f"Connecting to {server}:{port} ({'TLS' if tls else 'PLAINTEXT'}) as {nick}")
    try:
        sock = open_connection(server, port, tls)
        sock.settimeout(60)
    except OSError as exc:
        raise ConnectionError(f"IRC connect failed: {exc}") from exc

    with _sock_lock:
        _sock = sock
    with _state_lock:
        _state.nick = nick
        _state.account_tags = False
        _state.connected = False

    try:
        _send("CAP REQ :account-tag")
        _send(f"NICK {nick}")
        _send(f"USER {nick} 0 * :{nick}")
        buffer = b""
        while _running:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                _flush_outbox()
                continue
            if not data:
                raise ConnectionError("IRC server closed the connection")
            buffer += data
            while b"\r\n" in buffer:
                raw, buffer = buffer.split(b"\r\n", 1)
                if raw:
                    try:
                        _on_line(parse_line(raw.decode("utf-8", errors="replace")))
                    except ConnectionError:
                        raise
                    except Exception as exc:
                        logger.exception(f"Failed to handle IRC line: {exc}")
    finally:
        with _state_lock:
            _state.connected = False
        with _sock_lock:
            if _sock is sock:
                _sock = None
        sock.close()
        logger.info("Disconnected")


def _irc_loop(server, port, tls, base_nick):
    backoff_seconds = 1
    nick = base_nick
    while _running:
        try:
            _irc_session(server, port, tls, nick)
            backoff_seconds = 1
        except NickInUse:
            nick = f"{base_nick[:12]}{random.randint(1000, 9999)}"
            logger.warning(f"IRC nick {base_nick} is taken; retrying as {nick}. "
                           f"Send private messages to {nick} instead.")
        except Exception as exc:
            if _running:
                logger.warning(f"IRC connection error: {exc}")
        if not _running:
            break
        logger.info(f"Reconnecting IRC in {backoff_seconds}s")
        time.sleep(backoff_seconds)
        backoff_seconds = min(backoff_seconds * 2, 30)


def start_irc(channel="", server=DEFAULT_SERVER, port=None, nick="omega",
              tls=True, require_account=True, allow_plaintext=False):
    global _running
    if not tls and not allow_plaintext:
        raise ValueError("IRC without TLS sends the secret and every message in clear text; "
                         "set IRC_allowPlaintext=True to accept that")
    channel = str(channel or "").strip()
    if channel and not channel.startswith("#"):
        channel = f"#{channel}"
    port = int(port or (TLS_PORT if tls else PLAINTEXT_PORT))

    owner = auth.get_channel_authenticated_user_id(AUTH_CHANNEL_ID) if auth.is_auth_enabled() else None
    with _state_lock:
        _state.channel = channel
        _state.require_account = require_account
        _state.owner = owner
        _state.reply_target = channel
        _state.warned_public_auth = set()

    _running = True
    thread = threading.Thread(target=_irc_loop, args=(server, port, tls, nick), daemon=True)
    thread.start()
    return thread


def stop_irc():
    global _running
    _running = False
    with _sock_lock:
        sock = _sock
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


class IRCChannel(channels.CommChannel):

    def start(self) -> None:
        start_irc(
            channel=config_get_by_key("IRC_channel", ""),
            server=config_get_by_key("IRC_server", DEFAULT_SERVER),
            port=config_get_by_key("IRC_port", None),
            nick=config_get_by_key("IRC_user", "omega"),
            tls=_flag("IRC_tls", True),
            require_account=_flag("IRC_requireAccount", True),
            allow_plaintext=_flag("IRC_allowPlaintext", False),
        )

    def stop(self) -> None:
        stop_irc()

    def receive(self) -> str:
        return getLastMessage()

    def send(self, message: str) -> None:
        send_message(message)


def loadOmegaPlugin():
    channels.registerCommChannel("irc", IRCChannel())
