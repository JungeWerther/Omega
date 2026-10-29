#!/usr/bin/env bash
set -euo pipefail

# Adds slash at the end which is critical to Nginx configuration work properly
nginx_url() {
    text=$1
    [[ ${text} != */ ]] && text="${text}/"
    echo "${text}"
}

cd /PeTTa

EMBEDDING_PROVIDER="${EMBEDDING_PROVIDER:-Local}"
EMBEDDING_MODEL="${EMBEDDING_MODEL:-}"
OPENAIAPI_URL="http://localhost:8080/" # dummy value
MM_URL="http://localhost:8080/" # dummy value
OPENCLAW_URL="http://localhost:8080/" # dummy value
for arg in "$@"; do
  if [[ "$arg" == embeddingprovider=* ]]; then
    EMBEDDING_PROVIDER="${arg#*=}"
  fi
  if [[ "$arg" == embeddingModel=* ]]; then
    EMBEDDING_MODEL="${arg#*=}"
  fi
  # URL to redirect OpenAIAPI provider requests
  if [[ "$arg" == openaiapi_url=* ]]; then
    OPENAIAPI_URL=$(nginx_url "${arg#*=}")
  fi
  # URL to redirect Mattermost communication channel requests
  if [[ "$arg" == MM_URL=* ]]; then
    MM_URL=$(nginx_url "${arg#*=}")
  fi
  # URL to redirect OpenClaw Gateway requests
  if [[ "$arg" == openclaw_url=* ]]; then
    OPENCLAW_URL=$(nginx_url "${arg#*=}")
  fi
done
export EMBEDDING_PROVIDER EMBEDDING_MODEL OPENAIAPI_URL MM_URL OPENCLAW_URL

agent_su=(su --group nogroup nobody)

# --- Gate --------------------------------------------------------------------
# The gate runs the communication channel as its own user, checks who sent
# each message and keeps the owner/group records where the agent cannot
# write. The agent only talks to it on 127.0.0.1:${GATE_PORT}.
GATE_USER=omegagate
GATE_PORT=8090
GATE_STATE_DIR=${GATE_STATE_DIR:-/var/lib/omega-gate}

if [ -z "${OMEGA_AUTH_SECRET:-}" ] && [ -n "${OMEGACLAW_AUTH_SECRET:-}" ]; then
  echo "OMEGACLAW_AUTH_SECRET is deprecated, rename it to OMEGA_AUTH_SECRET" >&2
  OMEGA_AUTH_SECRET=${OMEGACLAW_AUTH_SECRET}
fi
unset OMEGACLAW_AUTH_SECRET

for arg in "$@"; do
  case "$arg" in
    WS_TOKEN=*)
      echo "WARNING: WS_TOKEN passed as a container argument is readable by every process" \
           "in the container (/proc/1/cmdline). Pass it as -e OMEGA_WS_TOKEN instead." >&2
      ;;
  esac
done

# Random key that unlocks nginx's channel routes; shared by nginx and the
# gate only, and passed through the environment, never through argv.
OMEGA_GATE_KEY=$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')
export OMEGA_GATE_KEY

install -d -o "${GATE_USER}" -g "${GATE_USER}" -m 0700 "${GATE_STATE_DIR}"
# One-time move of records written by older versions, which kept them in
# the agent-writable memory volume. The marker is written even when there was
# nothing to move, so records the agent plants there later are never imported.
legacy_auth_dir="${MEMORY_DIR}/.channel"
migration_marker="${GATE_STATE_DIR}/.legacy-migration-done"
if [ ! -e "${migration_marker}" ]; then
  for record in authenticated-user.json authenticated-group.json; do
    if [ -f "${legacy_auth_dir}/${record}" ] && [ ! -L "${legacy_auth_dir}/${record}" ] \
       && [ ! -e "${GATE_STATE_DIR}/${record}" ]; then
      install -o "${GATE_USER}" -g "${GATE_USER}" -m 0600 \
        "${legacy_auth_dir}/${record}" "${GATE_STATE_DIR}/${record}"
      echo "gate: migrated ${record} from the memory volume; review it if the agent may have been compromised" >&2
    fi
  done
  install -o "${GATE_USER}" -g "${GATE_USER}" -m 0600 /dev/null "${migration_marker}"
fi

# The system prompt is read from the image (prompts/, root-owned, read-only)
# so a compromised agent cannot rewrite its own instructions. Copies left in
# the memory volume by older versions are ignored.
for legacy_prompt in "${MEMORY_DIR}"/prompt*.txt "${MEMORY_DIR}"/tg_prompt.txt; do
  [ -f "${legacy_prompt}" ] || continue
  image_prompt="${OMEGA_DIR}/prompts/$(basename "${legacy_prompt}")"
  if ! cmp -s "${legacy_prompt}" "${image_prompt}"; then
    echo "WARNING: ${legacy_prompt} differs from ${image_prompt} and is ignored." \
         "Prompts are read only from the image now; rebuild the image to customize them." >&2
  fi
done

su www-data -s /bin/sh -c "sh /opt/nginx/nginx.sh"

# Supervise the gate. The environment is rebuilt with shell builtins inside
# this subshell, so secrets are only ever inherited as environment variables
# and never appear in any process's argv (/proc/<pid>/cmdline is readable by
# every user, including the agent).
run_gate() {
  # Capture what the supervisor needs before the environment is cleared.
  local name omega_dir="${OMEGA_DIR}"
  for name in $(compgen -e); do
    case "${name}" in
      OMEGA_AUTH_SECRET|OMEGA_GATE_KEY|OMEGA_WS_TOKEN|TEST_SERVER_IP|LANG) ;;
      *) unset "${name}" 2>/dev/null || true ;;
    esac
  done
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  export HOME="${GATE_STATE_DIR}" LANG="${LANG:-C.UTF-8}"
  export PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
  export OMEGA_GATEWAY_URL="http://127.0.0.1:8080/gate/${OMEGA_GATE_KEY}"
  export OMEGA_authStateDir="${GATE_STATE_DIR}" OMEGA_gatePort="${GATE_PORT}"
  cd "${omega_dir}"
  while :; do
    setpriv --reuid="${GATE_USER}" --regid="${GATE_USER}" --init-groups --no-new-privs \
      python3 -I "${omega_dir}/gate/main.py" "$@" \
      || echo "gate exited with status $?, restarting" >&2
    sleep 1
  done
}
( run_gate "$@" ) &
unset OMEGA_AUTH_SECRET OMEGA_WS_TOKEN OMEGA_GATE_KEY

for _ in $(seq 1 120); do
  if curl -fsS "http://127.0.0.1:${GATE_PORT}/v1/health" >/dev/null 2>&1; then
    gate_ready=1
    break
  fi
  sleep 0.5
done
if [ -z "${gate_ready:-}" ]; then
  echo "gate did not become healthy; refusing to start the agent without it" >&2
  exit 1
fi

# --- Egress proxy ------------------------------------------------------------
# The agent's Landlock policy only allows TCP connections to 8080 (nginx),
# 8090 (gate) and this proxy, which opens HTTPS tunnels to allowlisted
# public hosts only (egress/proxy.py). It holds no secrets and gets a clean
# environment built with builtins, like the gate.
EGRESS_USER=omegaegress
EGRESS_PORT=3128
run_egress() {
  local name omega_dir="${OMEGA_DIR}"
  for name in $(compgen -e); do
    case "${name}" in
      # Non-secret proxy settings may come from OMEGA_* variables (src/config.py).
      LANG|OMEGA_egressAllowlist|OMEGA_egressExtraDomains|OMEGA_egressAllowPorts) ;;
      *) unset "${name}" 2>/dev/null || true ;;
    esac
  done
  export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  export HOME=/nonexistent LANG="${LANG:-C.UTF-8}" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
  export OMEGA_egressPort="${EGRESS_PORT}"
  cd "${omega_dir}"
  while :; do
    setpriv --reuid="${EGRESS_USER}" --regid="${EGRESS_USER}" --init-groups --no-new-privs \
      python3 -I "${omega_dir}/egress/proxy.py" "$@" \
      || echo "egress proxy exited with status $?, restarting" >&2
    sleep 1
  done
}
( run_egress "$@" ) &

for _ in $(seq 1 60); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${EGRESS_PORT}") 2>/dev/null; then
    egress_ready=1
    break
  fi
  sleep 0.5
done
if [ -z "${egress_ready:-}" ]; then
  echo "egress proxy did not start; refusing to start the agent without it" >&2
  exit 1
fi

# Optional knowledge-base import. A trusted one-time step run by the
# entrypoint (it calls the embedding provider directly), so it runs before
# the agent's firewall and proxy settings below apply to uid 65534.
if [[ "${IMPORT_KB_ON_START}" == "1" ]]; then
  su nobody -s /bin/sh -c "${OMEGA_DIR}/scripts/import_knowledge.sh"
fi

# --- Per-user firewall ---------------------------------------------------------
# Landlock limits the agent's TCP connections to ports; these rules limit the
# address: uid 65534 may reach 127.0.0.1 on the policy's ports only (plus
# egressExtraPorts anywhere). All other traffic, UDP/DNS included, is
# refused. Needs CAP_NET_ADMIN, which the launcher adds.
agent_extra_ports=""
allow_unrestricted_network=""
for arg in "$@"; do
  case "${arg}" in
    egressExtraPorts=*) agent_extra_ports="${arg#*=}" ;;
    allowUnrestrictedNetwork=True|allowUnrestrictedNetwork=true|allowUnrestrictedNetwork=1) allow_unrestricted_network=1 ;;
  esac
done
if [ -n "${allow_unrestricted_network}" ]; then
  echo "WARNING: allowUnrestrictedNetwork: no firewall for the agent" >&2
elif ! python3 -I "${OMEGA_DIR}/profile/firewall.py" --policy "${OMEGA_DIR}/profile/policy.yaml" \
       --uid 65534 --extra-ports "${agent_extra_ports}"; then
  echo "Could not install the agent's firewall (the container needs --cap-add NET_ADMIN)." \
       "Refusing to start; pass allowUnrestrictedNetwork=True to run without it." >&2
  exit 1
fi

# Every HTTP client the agent uses (openai, requests, urllib, ddgs, git,
# curl, pip) goes through the egress proxy, except the local services.
EGRESS_PROXY_URL="http://127.0.0.1:${EGRESS_PORT}"
export HTTP_PROXY="${EGRESS_PROXY_URL}" HTTPS_PROXY="${EGRESS_PROXY_URL}"
export http_proxy="${EGRESS_PROXY_URL}" https_proxy="${EGRESS_PROXY_URL}"
export DDGS_PROXY="${EGRESS_PROXY_URL}"
export NO_PROXY="127.0.0.1,localhost,::1" no_proxy="127.0.0.1,localhost,::1"


MEMORY_PORTABILITY_PYTHON='import os
import sys
from config import init_config
from memory_export import create_memory_store
from memory_portability import MemoryTransfer

init_config(sys.argv[1:])
transfer = MemoryTransfer(
    transfer_dir="/memory-transfer",
    store=create_memory_store(),
)
operation = os.environ["MEMORY_PORTABILITY_OPERATION"]
if operation == "recover":
    transfer.recover()
elif operation == "import":
    transfer.import_archive(
        os.environ["MEMORY_IMPORT_FILE"],
        mode=os.environ.get("MEMORY_IMPORT_MODE", "overwrite"),
        include_history=os.environ.get("MEMORY_IMPORT_NO_HISTORY") != "1",
        include_vectors=os.environ.get("MEMORY_IMPORT_NO_VECTOR") != "1",
    )
else:
    raise ValueError(f"Unsupported memory portability operation: {operation!r}")'
export MEMORY_PORTABILITY_PYTHON
export PYTHONPATH="${OMEGA_DIR}:${OMEGA_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"

export MEMORY_PORTABILITY_OPERATION=recover
"${agent_su[@]}" -s /bin/sh -c 'exec python3 -c "$MEMORY_PORTABILITY_PYTHON" "$@"' sh "$@" \
  || { echo "Memory import recovery failed. Aborting startup." >&2; exit 1; }

if [[ -n "${MEMORY_IMPORT_FILE:-}" ]]; then
  echo "memory_portability: importing ${MEMORY_IMPORT_FILE}"
  export MEMORY_PORTABILITY_OPERATION=import
  "${agent_su[@]}" -s /bin/sh -c 'exec python3 -c "$MEMORY_PORTABILITY_PYTHON" "$@"' sh "$@" \
    || { echo "Memory import failed. Aborting startup." >&2; exit 1; }
  echo "memory_portability: import complete"
fi
unset MEMORY_PORTABILITY_OPERATION MEMORY_PORTABILITY_PYTHON PYTHONPATH

# Scrub environment: only allowlisted vars survive.
SAFE_VARS="HOME USER PATH HOSTNAME TERM LANG LC_ALL \
  PYTHONDONTWRITEBYTECODE PYTHONUNBUFFERED \
  HF_HOME SENTENCE_TRANSFORMERS_HOME HF_HUB_OFFLINE TRANSFORMERS_OFFLINE \
  CHROMA_DB_PATH EMBEDDING_PROVIDER OMEGA_DIR MEMORY_DIR TEST_SERVER_IP \
  HTTP_PROXY HTTPS_PROXY http_proxy https_proxy DDGS_PROXY NO_PROXY no_proxy"

env_args=""
for var in $SAFE_VARS; do
  eval val=\${$var:-}
  if [ -n "$val" ]; then
    env_args="$env_args $var=$val"
  fi
done

exec env -i $env_args "${agent_su[@]}" -s /bin/sh -c "sh run.sh run.metta GATEWAY_URL=\"http://localhost:8080\" GATE_URL=\"http://127.0.0.1:${GATE_PORT}\" securityPolicyPath=${OMEGA_DIR}/profile/policy.yaml $*"
