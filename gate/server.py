"""HTTP surface the gate exposes to the agent on the loopback interface.

The agent is untrusted from the gate's point of view: an LLM with a shell can
call these endpoints directly. So the surface is deliberately small and only
offers what the agent may do anyway: take the next message that already
passed authentication, send a reply through the channel's own target checks,
and read which principal may export memory. Nothing here reads or writes
owner or group records on the agent's say-so.
"""

import json
import logging
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 64 * 1024

ROUTES = {}


def route(method, path):
    """Register a handler for one method and path. Handlers take the decoded
    JSON body (or None) and return a JSON-serialisable dict."""

    def register(handler):
        ROUTES[(method, path)] = handler
        return handler

    return register


class GateError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class _Handler(BaseHTTPRequestHandler):
    server_version = "omega-gate"
    sys_version = ""

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        logger.debug("gate %s", format % args)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            raise GateError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body too large")
        if not length:
            return None
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GateError(HTTPStatus.BAD_REQUEST, f"invalid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise GateError(HTTPStatus.BAD_REQUEST, "body must be a JSON object")
        return payload

    def _reply(self, status, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _dispatch(self, method):
        handler = ROUTES.get((method, self.path))
        try:
            if handler is None:
                raise GateError(HTTPStatus.NOT_FOUND, "no such endpoint")
            self._reply(HTTPStatus.OK, handler(self._body()))
        except GateError as exc:
            self._reply(exc.status, {"error": str(exc)})
        except Exception as exc:
            logger.exception(f"gate handler {method} {self.path} failed: {exc}")
            self._reply(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})

    def do_GET(self):  # noqa: N802 - stdlib naming
        self._dispatch("GET")

    def do_POST(self):  # noqa: N802 - stdlib naming
        self._dispatch("POST")


def bind_channel_routes(channels_module, commchannel_id):
    """Register the agent-facing endpoints against a started channel."""

    @route("GET", "/v1/health")
    def health(_body):
        return {"ok": True, "channel": commchannel_id}

    @route("GET", "/v1/receive")
    def receive(_body):
        return {"message": channels_module.commChannelReceiveRaw() or ""}

    @route("POST", "/v1/send")
    def send(body):
        message = (body or {}).get("message")
        if not isinstance(message, str):
            raise GateError(HTTPStatus.BAD_REQUEST, "message must be a string")
        channels_module.commChannelSend(message)
        return {"ok": True}

    @route("GET", "/v1/principal")
    def principal(_body):
        return {"principal": channels_module.local_export_principal(commchannel_id)}


def serve(host, port):
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError(f"gate must listen on loopback only, got {host!r}")
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.daemon_threads = True
    logger.info(f"gate listening on {host}:{port}")
    return httpd
