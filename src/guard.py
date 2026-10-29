"""Prompt-injection containment for the agent loop.

Anything a tool returns from outside the owner's control (web pages, files,
command output, recalled memories, other agents) may contain instructions
written by an attacker. This module does three things with it:

1. Labels it. Results of skills not in TRUSTED_OUTPUT are wrapped in
   <untrusted_data source="..."> ... </untrusted_data> before the LLM sees
   them, and the system prompt says such content is data, never
   instructions.

2. Remembers that it was read. From then on the turn is "tainted" until the
   owner sends a new message.

3. Holds consequential actions while tainted. A skill outside
   SAFE_WHILE_TAINTED (shell, file writes, remember, delegation, plugins
   unknown to this list) is not run. The owner is asked through the chat
   channel and answers /approve <id> or /deny <id>. An approval lets that
   exact call run once.

Tool calls arrive as the repr of a quoted MeTTa expression such as
`(quote (shell "ls -la"))`; the skill is the first symbol inside. The loop
quotes the call so that building its repr never evaluates it.

Taint is cleared by the agent-side channel receive (src/channels.py) when a
genuine owner message arrives; /approve and /deny replies do not count, so
approving one held action does not wave through the next one.
"""

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass, field

# Skills whose results are produced by Omega itself (status lines, read-back
# verification) rather than copied from outside.
TRUSTED_OUTPUT = frozenset({
    "send", "pin", "nop", "version", "get-io-policy",
    "write-file", "write-file-b64", "append-file", "delete-file", "remember",
    "Error",  # loop-generated error results
})

# Skills that may run while tainted: they only read, or talk to the owner.
SAFE_WHILE_TAINTED = frozenset({
    "send", "pin", "nop", "version", "get-io-policy",
    "query", "episodes", "websearch", "read-file",
})

PENDING_LIMIT = 20
PENDING_TTL_SECONDS = 3600
PREVIEW_CHARS = 300

_OPEN, _CLOSE = "<untrusted_data", "</untrusted_data>"


def unquote(call_repr):
    """`(quote X)` -> `X`; anything else unchanged."""
    text = str(call_repr).strip()
    if text.startswith("(quote ") and text.endswith(")"):
        return text[len("(quote "):-1].strip()
    return text


def skill_of(call_repr):
    text = unquote(call_repr)
    if text.startswith("("):
        text = text[1:]
    words = text.split(None, 1)
    return words[0].rstrip(")") if words else ""


def _fingerprint(call_repr):
    return hashlib.sha256(unquote(call_repr).encode("utf-8")).hexdigest()


_EMPTY_RESULTS = {"", "SUCCESS, RETURN: ['']", 'SUCCESS, RETURN: [""]', "SUCCESS, RETURN: []",
                  "SUCCESS, RETURN: ()"}


def carries_content(text):
    """Whether a result holds any text an attacker could have written. An
    empty result (e.g. from `mkdir`) cannot carry instructions."""
    return str(text).strip() not in _EMPTY_RESULTS


def _neutralize(text):
    """Keep untrusted text from closing or faking the wrapper."""
    return str(text).replace(_CLOSE, "</untrusted_data_>").replace(_OPEN, "<untrusted_data_")


@dataclass
class Pending:
    call: str
    skill: str
    created: float
    approved: bool = False


@dataclass
class Guard:
    clock: object = time.monotonic
    notify: object = None  # callable(str): message to the owner
    tainted_by: set = field(default_factory=set)
    pending: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # -- the loop ------------------------------------------------------------

    def decide(self, call_repr):
        """True to run the call, or the result to give the LLM instead.
        (A boolean, because PeTTa hands Python strings back as atoms that
        do not compare equal to MeTTa string literals.)"""
        skill = skill_of(call_repr)
        with self._lock:
            self._expire()
            if not self.tainted_by or skill in SAFE_WHILE_TAINTED:
                return True
            fingerprint = _fingerprint(call_repr)
            for request_id, item in list(self.pending.items()):
                if _fingerprint(item.call) != fingerprint:
                    continue
                if item.approved:
                    del self.pending[request_id]
                    return True
                # Already waiting for the owner: do not ask again.
                return self._held_result(request_id, skill)
            request_id = self._hold(call_repr, skill)
            sources = ", ".join(sorted(self.tainted_by))
        self._tell_owner(
            f"Approval needed [{request_id}]: after reading untrusted content ({sources}) "
            f"the agent wants to run: {_preview(call_repr)}\n"
            f"Reply /approve {request_id} to allow it once, or /deny {request_id}."
        )
        return self._held_result(request_id, skill)

    @staticmethod
    def _held_result(request_id, skill):
        return (f"HELD_FOR_OWNER_APPROVAL id={request_id}: {skill} was not run because untrusted "
                "content was read in this turn. The owner has been asked. Do not retry it until "
                "you are told it was approved.")

    def present(self, call_repr, result):
        """The tool result as the LLM should see it; marks the turn tainted
        when the result came from outside."""
        skill = skill_of(call_repr)
        text = str(result)
        if skill in TRUSTED_OUTPUT or text.startswith("HELD_FOR_OWNER_APPROVAL") or not carries_content(text):
            return text
        with self._lock:
            self.tainted_by.add(skill)
        return f'{_OPEN} source="{skill}">\n{_neutralize(text)}\n{_CLOSE}'

    def human_turn(self):
        """A new message from the owner starts a new, untainted turn."""
        with self._lock:
            self.tainted_by.clear()

    # -- the owner -----------------------------------------------------------

    def approve(self, request_id):
        with self._lock:
            self._expire()
            item = self.pending.get(request_id)
            if item is None:
                return f"[No pending action {request_id}]"
            item.approved = True
            return (f"[OWNER APPROVED {request_id}] You may now run this exactly once: "
                    f"{item.call}")

    def deny(self, request_id):
        with self._lock:
            item = self.pending.pop(request_id, None)
        if item is None:
            return f"[No pending action {request_id}]"
        return f"[OWNER DENIED {request_id}] Do not run: {_preview(item.call)}"

    # -- internals -----------------------------------------------------------

    def _hold(self, call_repr, skill):
        if len(self.pending) >= PENDING_LIMIT:
            oldest = min(self.pending, key=lambda k: self.pending[k].created)
            del self.pending[oldest]
        request_id = secrets.token_hex(3)
        self.pending[request_id] = Pending(call=unquote(call_repr), skill=skill, created=self.clock())
        return request_id

    def _expire(self):
        now = self.clock()
        for request_id in [k for k, v in self.pending.items() if now - v.created > PENDING_TTL_SECONDS]:
            del self.pending[request_id]

    def _tell_owner(self, message):
        if self.notify is None:
            return
        try:
            self.notify(message)
        except Exception:  # the hold stands even if the notice fails
            pass


def _preview(call_repr):
    text = unquote(call_repr)
    return text if len(text) <= PREVIEW_CHARS else text[:PREVIEW_CHARS] + "…"


# -- control messages from the owner -----------------------------------------

def parse_control(text):
    """('approve'|'deny', id) for '/approve <id>' or '/deny <id>', else None."""
    parts = str(text).strip().split()
    if len(parts) != 2:
        return None
    command = parts[0].lower().split("@", 1)[0]
    if command not in ("/approve", "/deny"):
        return None
    return command[1:], parts[1].strip()


# -- module-level instance used from MeTTa ------------------------------------

def _owner_notifier(message):
    import channels

    channels.commChannelSend(message)


_GUARD = Guard(notify=_owner_notifier)


def guard():
    return _GUARD


def decide(call_repr):
    return _GUARD.decide(call_repr)


def present(call_repr, result):
    return _GUARD.present(call_repr, result)


def handle_owner_command(text):
    """Synthetic message for the agent if `text` is /approve or /deny."""
    parsed = parse_control(text)
    if parsed is None:
        return None
    action, request_id = parsed
    return _GUARD.approve(request_id) if action == "approve" else _GUARD.deny(request_id)
