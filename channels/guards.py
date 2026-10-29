"""Reusable decorators that keep authentication checks fail-closed.

Both are plain function wrappers so they compose with any predicate:

    @throttle_failures(limit=5, window=900, key=lambda channel, user, _: (channel, user))
    def check_secret(channel, user, candidate): ...

    @fail_closed(False)
    def remote_check(...): ...
"""

import functools
import threading
import time
from collections import deque

from src.logger import get_logger

logger = get_logger(__name__)


def fail_closed(denial):
    """Return `denial` instead of propagating any exception from the wrapped
    check. An error while deciding access must never grant it."""

    def decorate(check):
        @functools.wraps(check)
        def guarded(*args, **kwargs):
            try:
                return check(*args, **kwargs)
            except Exception as exc:
                logger.error(f"{check.__name__} failed, denying: {exc}")
                return denial

        return guarded

    return decorate


class _FailureLedger:
    """Sliding-window record of recent failures, per key and globally.

    Lookups never create entries and every record() drops keys whose
    failures have all expired, so memory stays bounded by the number of
    failures inside one window however many keys an attacker rotates
    through.
    """

    def __init__(self, window, clock):
        self._window = window
        self._clock = clock
        self._lock = threading.Lock()
        self._per_key = {}
        self._all = deque()

    def _expire(self, events, now):
        while events and now - events[0] >= self._window:
            events.popleft()

    def _prune(self, now):
        for key in list(self._per_key):
            self._expire(self._per_key[key], now)
            if not self._per_key[key]:
                del self._per_key[key]

    def counts(self, key):
        now = self._clock()
        with self._lock:
            self._expire(self._all, now)
            events = self._per_key.get(key)
            if events is None:
                return 0, len(self._all)
            self._expire(events, now)
            if not events:
                del self._per_key[key]
            return len(events), len(self._all)

    def record(self, key):
        now = self._clock()
        with self._lock:
            self._prune(now)
            self._per_key.setdefault(key, deque()).append(now)
            self._all.append(now)

    def tracked_keys(self):
        with self._lock:
            return len(self._per_key)

    def clear(self):
        with self._lock:
            self._per_key.clear()
            self._all.clear()


def throttle_failures(*, limit, window, key, global_limit=None, clock=time.monotonic):
    """Lock out a boolean predicate after repeated False results.

    Once `limit` failures for one key (or `global_limit` failures in total)
    happened within `window` seconds, the predicate is not evaluated at all
    and False is returned, so even the right answer is refused during the
    lockout. That turns guessing a short secret into years of work instead of
    minutes. The ledger is exposed as `predicate.failures` for tests.
    """

    def decorate(predicate):
        ledger = _FailureLedger(window, clock)

        @functools.wraps(predicate)
        def throttled(*args, **kwargs):
            bucket = key(*args, **kwargs)
            per_key, total = ledger.counts(bucket)
            if per_key >= limit or (global_limit is not None and total >= global_limit):
                logger.warning(f"{predicate.__name__}: too many failed attempts, locked out")
                return False
            ok = bool(predicate(*args, **kwargs))
            if not ok:
                ledger.record(bucket)
            return ok

        throttled.failures = ledger
        return throttled

    return decorate
