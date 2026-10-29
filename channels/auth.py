"""Channel owner and group authorization.

The owner secret and the persisted owner/group records are trust anchors, so
everything here fails closed:

* The secret is only ever read from this process's environment. In Docker
  this module runs inside the gate process (see gate/), which is the only
  process holding OMEGA_AUTH_SECRET; the agent never sees it.
* Missing secret means "nobody can authenticate", not "everybody is allowed".
  Running without authentication needs an explicit allowUnauthenticated=True.
* Repeated wrong secrets lock the sender out (see guards.throttle_failures).
* Records live in authStateDir. In Docker that is a volume owned by the gate
  user, outside every path the agent can write.
"""

import hmac
import json
import os
import time
from pathlib import Path
import sys
from config import config_get_by_key

try:
    from guards import fail_closed, throttle_failures
except ModuleNotFoundError:  # loaded by file path, e.g. from tests
    sys.path.append(str(Path(__file__).resolve().parent))
    from guards import fail_closed, throttle_failures
from src.logger import get_logger

logger = get_logger(__name__)

_proxy_url = None
_CHANNEL_DIR_NAME = ".channel"
_CHANNEL_AUTH_USER_FILE = "authenticated-user.json"
_CHANNEL_AUTH_GROUP_FILE = "authenticated-group.json"
_REPO_ROOT = Path(__file__).resolve().parents[1]
_MEMORY_DIRECTORY = str(_REPO_ROOT / "memory")
_user_ID_processed = False
_unauthenticated_warning_logged = False

# A 6-digit secret has 10^6 values; at 5 guesses per sender per 15 minutes
# and 20 guesses in total per 15 minutes, exhausting it takes about 1.4 years.
SECRET_ATTEMPTS_PER_SENDER = 5
SECRET_ATTEMPTS_TOTAL = 20
SECRET_ATTEMPT_WINDOW_SECONDS = 15 * 60
WEAK_SECRET_LENGTH = 16

_TRUTHY = {"1", "true", "yes", "on"}


def get_proxy_url():
    global _proxy_url
    if _proxy_url is None:
        configured_url = config_get_by_key("GATEWAY_URL", "")
        _proxy_url = str(configured_url or "").strip().rstrip("/")
    return _proxy_url


def _local_auth_secret():
    return os.environ.get("OMEGA_AUTH_SECRET", "").strip()


def _allow_unauthenticated():
    value = config_get_by_key("allowUnauthenticated", False)
    return value is True or str(value).strip().lower() in _TRUTHY


def is_auth_enabled():
    """Whether channel senders must authenticate.

    Only an explicit allowUnauthenticated=True without a secret turns
    authentication off. A missing secret otherwise keeps it on, so no one can
    authenticate and every unbound sender is ignored.
    """
    global _unauthenticated_warning_logged
    if _local_auth_secret():
        return True
    if _allow_unauthenticated():
        return False
    if not _unauthenticated_warning_logged:
        logger.error(
            "OMEGA_AUTH_SECRET is not set: no one can authenticate. Set a secret, "
            "or pass allowUnauthenticated=True to accept messages from anyone."
        )
        _unauthenticated_warning_logged = True
    return True


def is_weak_secret(secret):
    return len(str(secret or "")) < WEAK_SECRET_LENGTH


def verify_token(candidate):
    secret = _local_auth_secret()
    return bool(secret) and hmac.compare_digest(
        str(candidate).encode("utf-8"), secret.encode("utf-8")
    )


@throttle_failures(
    limit=SECRET_ATTEMPTS_PER_SENDER,
    global_limit=SECRET_ATTEMPTS_TOTAL,
    window=SECRET_ATTEMPT_WINDOW_SECONDS,
    key=lambda channel_identifier, user_id, candidate: (channel_identifier, user_id),
)
@fail_closed(False)
def _sender_presented_secret(channel_identifier, user_id, candidate):
    return verify_token(candidate)


def auth_state_directory():
    """Directory holding the owner and group records.

    authStateDir wins when configured (the gate's own volume in Docker);
    otherwise the legacy memory/.channel location is used.
    """
    configured = str(config_get_by_key("authStateDir", "") or "").strip()
    if configured:
        return configured
    return os.path.join(_MEMORY_DIRECTORY, _CHANNEL_DIR_NAME)


def _open_private_append(path):
    """Append to a record file readable by its owner only, refusing symlinks
    so a planted link cannot redirect the write."""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "a", encoding="utf-8")


def _channel_auth_user_path():
    return os.path.join(auth_state_directory(), _CHANNEL_AUTH_USER_FILE)


# ---------------------------------------------------------------------------
# Single-user (owner) authentication.

def store_channel_authenticated_user_id(channel_identifier, user_id):
    # For any single run of Omega, allow only a single save of a user-id or verification    
    global _user_ID_processed
    if _user_ID_processed:
        logger.warning(f"[{channel_identifier}] Warning: a user already was validated, ignoring")
        return False
    channel_identifier = str(channel_identifier or "").strip()
    if not channel_identifier:
        raise ValueError("channel_identifier is required")
    user_id = str(user_id or "").strip()
    if not user_id:
        raise ValueError("user_id is required")

    """Record an authenticated channel user ID in the memory directory."""
    payload = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "channel_identifier": channel_identifier,
        "user_id": user_id,
    }
    path = _channel_auth_user_path()
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    try:
        with _open_private_append(path) as f:
            json.dump(payload, f, separators=(",", ":"))
            f.write("\n")
    except OSError as e:
        raise RuntimeError("Failed to write channel authenticated user record") from e
    _user_ID_processed = True
    return True


def get_channel_saved_user_id(channel_identifier, user_id):
    # For any single run of OmegaClaw, allow only a single save of a user-id or verification
    global _user_ID_processed
    if _user_ID_processed:
        logger.warning(f"[{channel_identifier}] Warning: a user was already validated, ignoring")
        return False

    # The first persisted record is the owner.  Do not scan later records
    saved_user_id = get_channel_authenticated_user_id(channel_identifier)
    if saved_user_id != str(user_id or "").strip():
        return False

    _user_ID_processed = True
    return True


def authenticate_channel_user(channel_identifier, user_id, auth_candidate=None):
    channel_identifier = str(channel_identifier or "").strip()
    user_id = str(user_id or "").strip()

    # A persisted owner always wins over a reusable secret.
    saved_user_id = get_channel_authenticated_user_id(channel_identifier)
    if saved_user_id is not None:
        return "allow" if saved_user_id == user_id else "ignore"

    # The secret can establish an owner only before an owner has been saved.
    if auth_candidate is not None and _sender_presented_secret(
        channel_identifier, user_id, auth_candidate
    ):
        label = channel_identifier.upper()
        if store_channel_authenticated_user_id(channel_identifier, user_id):
            logger.info(f"[{label}] Saved authenticated user ID")
            return "auth_bound"
        logger.error(f"[{label}] ERROR -- Unable to save user ID")

    return "ignore"


def get_channel_authenticated_user_id(channel_identifier):
    """
    Read-only owner lookup. Returns the persisted owner user_id for a
    channel, or None if no owner has authenticated yet.
    """
    channel_identifier = str(channel_identifier or "").strip()
    if not channel_identifier:
        return None
    try:
        path = _channel_auth_user_path()
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    record = json.loads(line)
                    saved_channel_identifier = str(record.get("channel_identifier", "")).strip()
                    saved_user_id = str(record.get("user_id", "")).strip()
                except (AttributeError, json.JSONDecodeError) as e:
                    logger.warning(f"Skipping malformed channel authenticated user record: {e}")
                    continue
                if saved_channel_identifier == channel_identifier and saved_user_id:
                    return saved_user_id
    except FileNotFoundError:
        return None
    except Exception as e:
        raise RuntimeError("Failed to read channel authenticated user records") from e
    return None


# ---------------------------------------------------------------------------
# Owner-managed group authorization.

def _channel_auth_group_path():
    return os.path.join(auth_state_directory(), _CHANNEL_AUTH_GROUP_FILE)


def _append_json_line(path, payload):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    prefix = ""
    try:
        with open(path, "rb") as probe:
            probe.seek(0, os.SEEK_END)
            if probe.tell():
                probe.seek(-1, os.SEEK_END)
                if probe.read(1) != b"\n":
                    prefix = "\n"
    except FileNotFoundError:
        pass
    with _open_private_append(path) as f:
        f.write(prefix + json.dumps(payload, separators=(",", ":")) + "\n")


def load_channel_auth_state(channel_identifier):
    """Validate and load one channel's persisted owner and active groups."""
    channel_identifier = str(channel_identifier or "").strip()
    if not channel_identifier:
        raise ValueError("channel_identifier is required")

    def read_records(path, label):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as source:
                records = []
                for line_number, line in enumerate(source, 1):
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as exc:
                        logger.warning(
                            f"Skipping malformed {label} record at line "
                            f"{line_number}: {exc}"
                        )
                        continue
                    if not isinstance(record, dict):
                        logger.warning(
                            f"Skipping malformed {label} record at line "
                            f"{line_number}: expected a JSON object"
                        )
                        continue
                    records.append(record)
                return records
        except FileNotFoundError:
            return []
        except (OSError, UnicodeError) as exc:
            raise RuntimeError(f"Failed to read {label} records") from exc

    owner_id = None
    for record in read_records(_channel_auth_user_path(), "channel authenticated user"):
        saved_channel = str(record.get("channel_identifier", "")).strip()
        saved_user = str(record.get("user_id", "")).strip()
        if saved_channel == channel_identifier and saved_user and owner_id is None:
            owner_id = saved_user

    group_states = {}
    for record in read_records(_channel_auth_group_path(), "channel authenticated group"):
        saved_channel = str(record.get("channel_identifier", "")).strip()
        saved_group = str(record.get("group_id", "")).strip()
        authorized_by = str(record.get("authorized_by", "")).strip()
        if (
            saved_channel == channel_identifier
            and saved_group
            and owner_id is not None
            and authorized_by == owner_id
        ):
            group_states[saved_group] = not bool(record.get("revoked", False))
        elif saved_channel == channel_identifier and saved_group:
            logger.warning(
                f"[{channel_identifier.upper()}] Skipping group authorization "
                f"for {saved_group}: record is not owned by the authenticated user"
            )

    authorized_groups = {
        group_id for group_id, authorized in group_states.items() if authorized
    }
    return owner_id, authorized_groups


# Group tiers. In a "chat" group, members can talk to the agent, but what
# they write is handled as untrusted input: it cannot approve held actions,
# and actions it leads to need the owner's approval. A "tools" group's
# members act with the owner's authority. Records written before tiers
# existed count as "chat".
TIER_CHAT = "chat"
TIER_TOOLS = "tools"
TIERS = (TIER_CHAT, TIER_TOOLS)


def store_channel_authenticated_group_id(channel_identifier, group_id, authorized_by_user_id,
                                         tier=TIER_CHAT):
    """Persist a trusted group. Never touches the single-user auth file."""
    channel_identifier = str(channel_identifier or "").strip()
    group_id = str(group_id or "").strip()
    authorized_by_user_id = str(authorized_by_user_id or "").strip()
    if not channel_identifier:
        raise ValueError("channel_identifier is required")
    if not group_id:
        raise ValueError("group_id is required")
    if not authorized_by_user_id:
        raise ValueError("authorized_by_user_id is required")
    if tier not in TIERS:
        raise ValueError(f"tier must be one of {TIERS}")

    payload = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "channel_identifier": channel_identifier,
        "group_id": group_id,
        "authorized_by": authorized_by_user_id,
        "tier": tier,
    }
    path = _channel_auth_group_path()
    try:
        _append_json_line(path, payload)
    except OSError as e:
        raise RuntimeError("Failed to write channel authenticated group record") from e
    return True


def get_channel_saved_group_id(channel_identifier, group_id):
    """Return whether a group has already been authorized for this channel."""
    channel_identifier = str(channel_identifier or "").strip()
    group_id = str(group_id or "").strip()
    if not channel_identifier or not group_id:
        return False
    owner_id = get_channel_authenticated_user_id(channel_identifier)
    if owner_id is None:
        return False

    authorized = False
    try:
        with open(_channel_auth_group_path(), "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    record = json.loads(line)
                    saved_channel = str(record.get("channel_identifier", "")).strip()
                    saved_group = str(record.get("group_id", "")).strip()
                    authorized_by = str(record.get("authorized_by", "")).strip()
                except (AttributeError, json.JSONDecodeError) as e:
                    logger.warning(f"Skipping malformed channel authenticated group record: {e}")
                    continue
                if (
                    saved_channel == channel_identifier
                    and saved_group == group_id
                    and authorized_by == owner_id
                ):
                    authorized = not bool(record.get("revoked", False))
    except FileNotFoundError:
        return False
    except Exception as e:
        raise RuntimeError("Failed to read channel authenticated group records") from e
    return authorized


def get_channel_group_tier(channel_identifier, group_id):
    """The tier of an authorized group (latest record wins), or None."""
    channel_identifier = str(channel_identifier or "").strip()
    group_id = str(group_id or "").strip()
    owner_id = get_channel_authenticated_user_id(channel_identifier)
    if owner_id is None or not group_id:
        return None
    tier = None
    try:
        with open(_channel_auth_group_path(), "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (not isinstance(record, dict)
                        or str(record.get("channel_identifier", "")).strip() != channel_identifier
                        or str(record.get("group_id", "")).strip() != group_id
                        or str(record.get("authorized_by", "")).strip() != owner_id):
                    continue
                if record.get("revoked"):
                    tier = None
                else:
                    recorded = record.get("tier")
                    tier = recorded if recorded in TIERS else TIER_CHAT
    except FileNotFoundError:
        return None
    return tier


def load_channel_group_tiers(channel_identifier):
    """{group_id: tier} for every authorized group of the channel."""
    _, groups = load_channel_auth_state(channel_identifier)
    return {group: get_channel_group_tier(channel_identifier, group) or TIER_CHAT for group in groups}


def authorize_channel_group(channel_identifier, group_id, requester_user_id, tier=TIER_CHAT):
    """
    Open a group chat to all its members -- but ONLY when requester_user_id
    matches the persisted owner for this channel. Binding an authorized group
    again with another tier changes its tier (owner only).
    """
    current = get_channel_group_tier(channel_identifier, group_id)
    if current is not None and (current == tier or str(requester_user_id or "").strip()
                                != get_channel_authenticated_user_id(channel_identifier)):
        return "allow"

    owner_id = get_channel_authenticated_user_id(channel_identifier)
    if owner_id is None:
        # No owner has authenticated yet -- nobody can open groups.
        return "ignore"

    if str(requester_user_id or "").strip() != owner_id:
        return "ignore"

    if store_channel_authenticated_group_id(channel_identifier, group_id, owner_id, tier):
        logger.info(f"[{str(channel_identifier).upper()}] Saved authorized group ID (tier {tier})")
        return "group_bound"

    logger.error(f"[{str(channel_identifier).upper()}] ERROR -- Unable to save group ID")
    return "ignore"


def revoke_channel_group(channel_identifier, group_id, requester_user_id):
    """Remove a trusted group when requested by the persisted channel owner."""
    channel_identifier = str(channel_identifier or "").strip()
    group_id = str(group_id or "").strip()
    requester_user_id = str(requester_user_id or "").strip()
    if not channel_identifier or not group_id:
        return "ignore"

    owner_id = get_channel_authenticated_user_id(channel_identifier)
    if owner_id is None or requester_user_id != owner_id:
        return "ignore"

    if not get_channel_saved_group_id(channel_identifier, group_id):
        return "ignore"

    payload = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "channel_identifier": channel_identifier,
        "group_id": group_id,
        "authorized_by": owner_id,
        "revoked": True,
    }
    path = _channel_auth_group_path()
    try:
        _append_json_line(path, payload)
    except OSError as e:
        raise RuntimeError("Failed to write channel group revocation record") from e

    logger.info(f"[{channel_identifier.upper()}] Removed authorized group ID {group_id}")
    return "group_unbound"
