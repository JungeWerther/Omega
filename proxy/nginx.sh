#!/bin/sh
set -eu

# The channel routes live under /gate/${OMEGA_GATE_KEY}/. Without a long key
# that prefix would be guessable (or empty), handing the bot credentials to
# anything that can reach nginx, so refuse to start.
key_length=$(printf '%s' "${OMEGA_GATE_KEY:-}" | wc -c)
if [ "${key_length}" -lt 32 ]; then
    echo "nginx.sh: OMEGA_GATE_KEY must be at least 32 characters" >&2
    exit 1
fi
case "${OMEGA_GATE_KEY}" in
    *[!0-9a-f]*)
        echo "nginx.sh: OMEGA_GATE_KEY must be lowercase hex" >&2
        exit 1
        ;;
esac

NGINX_TEMPLATE=${NGINX_TEMPLATE:-/opt/nginx/nginx.conf.template}
NGINX_CONFIG=${NGINX_CONFIG:-/opt/nginx/nginx.conf}
SUBST_VARS=$(grep -o '\${[A-Z_0-9]*}' "${NGINX_TEMPLATE}" | sort -u | tr '\n' ' ')
touch "${NGINX_CONFIG}"
chmod 0600 "${NGINX_CONFIG}"
envsubst "$SUBST_VARS" \
    < "${NGINX_TEMPLATE}" \
    > "${NGINX_CONFIG}"

nginx -c "${NGINX_CONFIG}"
