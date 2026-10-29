"""nginx credential proxy: loopback only, channel routes behind the gate key."""

import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
NGINX_SCRIPT = REPO_ROOT / "proxy" / "nginx.sh"
TEMPLATE = REPO_ROOT / "proxy" / "nginx.conf.template"
GATE_KEY = "0123456789abcdef0123456789abcdef"

pytestmark = pytest.mark.skipif(shutil.which("envsubst") is None, reason="envsubst is not installed")


def _render(tmp_path, nginx_binary=None, template=TEMPLATE, **environment_overrides):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    if nginx_binary is None:
        fake = bin_dir / "nginx"
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o755)
    config = tmp_path / "nginx.conf"
    environment = {name: value for name, value in os.environ.items()
                   if not name.endswith(("AUTH_SECRET", "GATE_KEY"))}
    environment.update(
        PATH=f"{bin_dir}{os.pathsep}{environment['PATH']}",
        NGINX_TEMPLATE=str(template),
        NGINX_CONFIG=str(config),
        TG_BOT_TOKEN="123:telegram-bot-token",
        OPENAIAPI_URL="http://127.0.0.1:9/",
        MM_URL="http://127.0.0.1:9/",
        OPENCLAW_URL="http://127.0.0.1:9/",
    )
    environment.update(environment_overrides)
    # A real nginx daemonizes and would keep captured pipes open, so its
    # output goes to a file instead.
    stderr_path = tmp_path / "nginx.sh.stderr"
    with open(stderr_path, "w") as stderr:
        result = subprocess.run(["sh", str(NGINX_SCRIPT)], env=environment,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=stderr, text=True, check=False)
    result.stderr = stderr_path.read_text()
    return result, config.read_text() if config.exists() else None


@pytest.mark.parametrize("key", ["", "short", "0123456789ABCDEF0123456789ABCDEF", "../" * 12])
def test_nginx_refuses_missing_or_unsafe_gate_key(tmp_path, key):
    result, _ = _render(tmp_path, OMEGA_GATE_KEY=key)

    assert result.returncode != 0
    assert "OMEGA_GATE_KEY" in result.stderr


def test_channel_routes_are_only_under_the_gate_key(tmp_path):
    result, config = _render(tmp_path, OMEGA_GATE_KEY=GATE_KEY)

    assert result.returncode == 0, result.stderr
    for route in ("telegram", "telegram-file", "mattermost", "slack", "slack-files"):
        assert f"location /gate/{GATE_KEY}/{route}/ {{" in config
        assert f"location /{route}/ {{" not in config


def test_listens_on_loopback_only(tmp_path):
    _, config = _render(tmp_path, OMEGA_GATE_KEY=GATE_KEY)

    assert "listen 127.0.0.1:8080;" in config
    assert "listen 8080;" not in config


def test_auth_oracle_endpoints_are_gone(tmp_path):
    _, config = _render(tmp_path, OMEGA_GATE_KEY=GATE_KEY, OMEGA_AUTH_SECRET="s3cr3t-owner")

    assert "/auth/verify" not in config
    assert "/auth/status" not in config
    assert "s3cr3t-owner" not in config


def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _status(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url), timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


@pytest.mark.skipif(shutil.which("nginx") is None, reason="nginx is not installed")
def test_real_nginx_hides_bot_routes_without_the_key(tmp_path):
    import http.server
    import threading

    seen_paths = []

    class Upstream(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen_paths.append(self.path)
            self.send_response(299)
            self.end_headers()

        def log_message(self, *args):
            pass

    upstream = http.server.HTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    port = _free_port()
    template = tmp_path / "nginx.conf.template"
    template.write_text(
        TEMPLATE.read_text()
        .replace("listen 127.0.0.1:8080;", f"listen 127.0.0.1:{port};")
        .replace(" /tmp/", f" {tmp_path}/")
        # Point the Telegram upstream at a local stub.
        .replace("proxy_pass https://api.telegram.org;",
                 f"proxy_pass http://127.0.0.1:{upstream.server_address[1]};")
    )
    result, _ = _render(tmp_path, nginx_binary="real", template=template, OMEGA_GATE_KEY=GATE_KEY)
    assert result.returncode == 0, result.stderr
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(50):
            if _status(f"{base}/health") == 200:
                break
            time.sleep(0.1)

        assert _status(f"{base}/telegram/getUpdates") == 404
        assert _status(f"{base}/gate/{'f' * 32}/telegram/getUpdates") == 404
        assert _status(f"{base}/gate/{GATE_KEY}/telegram/getUpdates") == 299
        assert _status(f"{base}/auth/verify") == 404
        # The bot token is injected on the way out and never needed by the caller.
        assert seen_paths == ["/bot123:telegram-bot-token/getUpdates"]
    finally:
        upstream.shutdown()
        pid_file = tmp_path / "nginx.pid"
        if pid_file.exists():
            os.kill(int(pid_file.read_text()), 15)
