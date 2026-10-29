"""The entrypoint's gate supervisor: clean environment, correct command.

run_gate() is extracted from entrypoint.sh and run under `set -euo
pipefail` like the real script, with setpriv and sleep replaced by shell
functions that record what would have been executed.
"""

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = (REPO_ROOT / "entrypoint.sh").read_text()


def _function(name):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", ENTRYPOINT, re.S | re.M)
    assert match, f"{name} not found in entrypoint.sh"
    return match.group(0)


def run_supervisor(name, tmp_path, environment, variables):
    record = tmp_path / "record"
    harness = f"""
set -euo pipefail
{variables}
setpriv() {{
  {{ echo "ARGS $*"; echo "PWD $(pwd)"; env | sort | sed 's/^/ENV /'; }} > {record}
}}
sleep() {{ exit 0; }}
{_function(name)}
{name} commchannel=websocket
"""
    result = subprocess.run(["bash", "-c", harness], env=environment, capture_output=True, text=True, timeout=30)
    return result, record.read_text() if record.exists() else ""


def test_gate_supervisor_starts_the_gate_with_only_its_secrets(tmp_path):
    omega_dir = tmp_path / "Omega"
    omega_dir.mkdir()
    environment = {
        "PATH": "/usr/bin:/bin",
        "OMEGA_DIR": str(omega_dir),
        "OMEGA_AUTH_SECRET": "owner-secret",
        "OMEGA_GATE_KEY": "f" * 48,
        "OMEGA_WS_TOKEN": "ws-token",
        "ANTHROPIC_API_KEY": "must-not-reach-the-gate",
        "TG_BOT_TOKEN": "must-not-reach-the-gate-either",
    }
    variables = 'GATE_USER=omegagate\nGATE_PORT=8090\nGATE_STATE_DIR=/var/lib/omega-gate'

    result, record = run_supervisor("run_gate", tmp_path, environment, variables)

    assert result.returncode == 0, result.stderr
    assert f"ARGS --reuid=omegagate --regid=omegagate --init-groups --no-new-privs python3 -I {omega_dir}/gate/main.py commchannel=websocket" in record
    assert f"PWD {omega_dir}" in record
    assert "ENV OMEGA_AUTH_SECRET=owner-secret" in record
    assert "ENV OMEGA_WS_TOKEN=ws-token" in record
    assert f"ENV OMEGA_GATEWAY_URL=http://127.0.0.1:8080/gate/{'f' * 48}" in record
    assert "ENV OMEGA_authStateDir=/var/lib/omega-gate" in record
    assert "must-not-reach" not in record
    assert "ENV OMEGA_DIR=" not in record
    # No secret is ever passed as an argument.
    args = next(line for line in record.splitlines() if line.startswith("ARGS"))
    assert "owner-secret" not in args and "ws-token" not in args and "f" * 48 not in args


def test_egress_supervisor_gets_no_secrets(tmp_path):
    omega_dir = tmp_path / "Omega"
    omega_dir.mkdir()
    environment = {
        "PATH": "/usr/bin:/bin",
        "OMEGA_DIR": str(omega_dir),
        "OMEGA_AUTH_SECRET": "owner-secret",
        "OMEGA_GATE_KEY": "f" * 48,
        "ANTHROPIC_API_KEY": "provider-key",
    }

    result, record = run_supervisor("run_egress", tmp_path, environment, "EGRESS_USER=omegaegress\nEGRESS_PORT=3128")

    assert result.returncode == 0, result.stderr
    assert f"python3 -I {omega_dir}/egress/proxy.py commchannel=websocket" in record
    assert f"PWD {omega_dir}" in record
    assert "ENV OMEGA_egressPort=3128" in record
    for secret in ("owner-secret", "f" * 48, "provider-key"):
        assert secret not in record
