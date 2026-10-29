import hashlib
import json
import logging
import urllib.request

logger = logging.getLogger(__name__)

_commChannelRegistry = {}


# Identifier each channel stores its owner records under, when it differs
# from the upper-cased channel name. IRC owners are services accounts stored
# under IRC_IDENTITY; old nickname records under "IRC" are not trusted.
AUTH_CHANNEL_IDS = {"irc": "IRC_IDENTITY"}


def auth_channel_id(commchannel_id: str) -> str:
    return AUTH_CHANNEL_IDS.get(commchannel_id.lower(), commchannel_id.upper())


def local_export_principal(commchannel_id: str) -> str | None:
    """Principal allowed to export memory, computed where the channel runs."""
    if commchannel_id == "websocket":
        from config import config_get_by_key

        token = str(config_get_by_key("WS_TOKEN", "")).strip()
        if not token:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return f"websocket:{digest}"

    from auth import get_channel_authenticated_user_id, is_auth_enabled

    if not is_auth_enabled():
        return None
    return get_channel_authenticated_user_id(auth_channel_id(commchannel_id))


def _authenticated_export_principal() -> str | None:
    principal = getattr(_commchannel, "principal", None)
    if callable(principal):
        return principal()
    return local_export_principal(_commchannel_id)


def handle_control_message(message: str) -> bool:
    from src.memory_export import handle_export_command, is_export_command

    _, separator, command = message.rpartition(": ")
    if not separator:
        command = message
    if not is_export_command(command):
        return False

    try:
        authenticated_principal = _authenticated_export_principal()
    except Exception as exc:
        logger.exception("Failed to resolve memory-export principal: %s", exc)
        authenticated_principal = None

    reply = handle_export_command(command, authenticated_principal)
    if reply is not None:
        try:
            _commchannel.send(reply)
        except Exception as exc:
            logger.exception("Failed to deliver control-message response: %s", exc)
    return True


class CommChannel:
    """Communication channel implementation"""

    def start(self) -> None:
        """Configure and start communication channel"""
        pass

    def stop(self) -> None:
        """Stop communication channel and free resources"""
        pass

    def receive(self) -> str:
        """Receive message from the communication channel"""
        raise NotImplementedError()

    def send(self, message: str) -> None:
        """Send message via the communication channel"""
        raise NotImplementedError()

def registerCommChannel(id: str, channel: CommChannel) -> None:
    """
    Register communication channel in the registry.

    Arguments:
    id: the identifier of the plugin which is used to load it
    channel: the implementation of the channel
    """
    global _commChannelRegistry
    logger.info(f"registerCommChannel: registering communication channel {id}")
    _commChannelRegistry[id] = channel

_commchannel: CommChannel = None
_commchannel_id = ""

class GateChannel(CommChannel):
    """Agent-side client of the gate process (see gate/).

    In Docker the real channel plugin runs in the gate under its own user,
    which authenticates senders and keeps the owner records out of the
    agent's reach. The agent only receives messages that passed that check
    and can only send through the gate. Every failure is treated as "no
    message", never as permission.
    """

    TIMEOUT_SECONDS = 10

    def __init__(self, url: str):
        self._url = url.rstrip("/")

    def _call(self, method: str, path: str, payload: dict | None = None) -> dict:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self._url}{path}",
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=self.TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))

    def start(self) -> None:
        self._call("GET", "/v1/health")

    def receive(self) -> str:
        try:
            return str(self._call("GET", "/v1/receive").get("message") or "")
        except Exception as exc:
            logger.warning(f"Gate receive failed, treating as no message: {exc}")
            return ""

    def send(self, message: str) -> None:
        self._call("POST", "/v1/send", {"message": str(message)})

    def principal(self) -> str | None:
        try:
            return self._call("GET", "/v1/principal").get("principal")
        except Exception as exc:
            logger.warning(f"Gate principal lookup failed, denying export: {exc}")
            return None


def _gate_url() -> str:
    from config import config_get_by_key

    return str(config_get_by_key("GATE_URL", "") or "").strip()


def commChannelStart(commchannel):
    """Select and start one of the communication channels registered by
    plugins, or the gate client when GATE_URL is configured"""
    global _commchannel, _commchannel_id
    gate_url = _gate_url()
    if gate_url:
        logger.info(f"commChannelStart: using gate at {gate_url} for channel {commchannel}")
        _commchannel = GateChannel(gate_url)
        _commchannel_id = str(commchannel).lower()
        _commchannel.start()
        return
    _commchannel = _commChannelRegistry.get(commchannel, None)
    if _commchannel is None:
        error = f"commChannelStart: Communication channel plugin {commchannel} is not registered"
        logger.error(error)
        raise RuntimeError(error)
    _commchannel_id = str(commchannel).lower()
    _commchannel.start()

def commChannelReceiveRaw():
    """Receive from the selected channel without control-message handling.
    Used by the gate, which leaves control messages to the agent."""
    return _commchannel.receive()


def _command_text(message: str) -> str:
    _, separator, command = message.rpartition(": ")
    return command if separator else message


def commChannelReceive():
    """Receive the owner's messages for the agent.

    /memory-export is answered here and dropped. /approve and /deny are
    answered by the injection guard and replaced by a note for the agent.
    Any other message is a genuine new turn from the owner, which ends the
    taint left by untrusted tool output.
    """
    import guard

    raw = _commchannel.receive()
    forwarded, genuine = [], False
    for message in raw.split(" | ") if raw else []:
        if handle_control_message(message):
            continue
        note = guard.handle_owner_command(_command_text(message))
        if note is not None:
            forwarded.append(note)
            continue
        forwarded.append(message)
        genuine = genuine or bool(message.strip())
    if genuine:
        guard.guard().human_turn()
    return " | ".join(forwarded)

def commChannelSend(message):
    """Send message via selected communication channel"""
    global _commchannel
    _commchannel.send(message)
