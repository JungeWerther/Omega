"""Gate process: runs the communication channel on behalf of the agent.

Started by entrypoint.sh as the dedicated `omegagate` user with:

* OMEGA_AUTH_SECRET and the channel credentials the agent must never see,
* OMEGA_authStateDir pointing at a directory only this user can write,
* GATEWAY_URL carrying the key that unlocks nginx's channel routes.

Run with `python3 -I gate/main.py key=value ...` so neither the working
directory nor PYTHON* variables can inject modules.
"""

import logging
import os
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
for entry in (REPO / "channels", REPO / "src", REPO):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import channels  # noqa: E402 - src/channels.py, after sys.path setup
import plugin  # noqa: E402
from config import config_get_by_key, init_config  # noqa: E402
from logger import setup_logging  # noqa: E402

from gate.server import bind_channel_routes, serve  # noqa: E402

logger = logging.getLogger("gate")

DEFAULT_PORT = 8090
_SECRET_ENVIRONMENT = ("OMEGA_AUTH_SECRET", "OMEGA_GATE_KEY")


def redact_secrets(secrets):
    """Install a log-record factory that masks the given values everywhere,
    so a URL carrying the gate key never reaches a log line verbatim."""
    secrets = [value for value in secrets if value]
    original_factory = logging.getLogRecordFactory()

    def factory(*args, **kwargs):
        record = original_factory(*args, **kwargs)
        message = record.getMessage()
        masked = message
        for value in secrets:
            masked = masked.replace(value, "***")
        if masked != message:
            record.msg, record.args = masked, ()
        return record

    logging.setLogRecordFactory(factory)


def load_channel_plugins():
    """Load the Python channel plugins only; providers and MeTTa plugins
    belong to the agent."""
    channels_dir = str((REPO / "channels").resolve())
    for loader, name, location in plugin.listPlugins():
        if loader == "python" and location == channels_dir:
            plugin.loadPythonPlugin(name, location)


def check_configuration():
    import auth

    if str(config_get_by_key("GATE_URL", "") or "").strip():
        raise SystemExit("gate: GATE_URL must not be set for the gate itself")

    state_dir = str(config_get_by_key("authStateDir", "") or "").strip()
    if not state_dir:
        raise SystemExit("gate: authStateDir must be set to a directory owned by the gate user")
    pathlib.Path(state_dir).mkdir(mode=0o700, parents=True, exist_ok=True)
    if not os.access(state_dir, os.W_OK):
        raise SystemExit(f"gate: authStateDir {state_dir} is not writable")

    secret = os.environ.get("OMEGA_AUTH_SECRET", "")
    if secret and auth.is_weak_secret(secret):
        logger.warning(
            "OMEGA_AUTH_SECRET is shorter than %d characters. It is rate limited, "
            "but a long random secret is strongly recommended.",
            auth.WEAK_SECRET_LENGTH,
        )
    auth.is_auth_enabled()  # logs once when nobody can authenticate


def main(argv):
    init_config(argv)
    setup_logging(config_get_by_key("logConfigPath", ""))
    redact_secrets([os.environ.get(name, "") for name in _SECRET_ENVIRONMENT])
    check_configuration()

    commchannel = str(config_get_by_key("commchannel", "irc"))
    load_channel_plugins()
    channels.commChannelStart(commchannel)
    bind_channel_routes(channels, commchannel)

    port = int(config_get_by_key("gatePort", DEFAULT_PORT))
    serve("127.0.0.1", port).serve_forever()


if __name__ == "__main__":
    main(sys.argv[1:])
