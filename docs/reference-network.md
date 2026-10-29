# Reference — Network egress

The agent runs an LLM that can execute shell commands, so a prompt injection
could try to send memory, history or files to an attacker's server. In the
Docker image the agent can only open TCP connections to three local
services:

| Port | Service | Reaches |
|---|---|---|
| 8080 | nginx credential proxy | the configured LLM / embedding provider (keys injected by nginx) |
| 8090 | gate | the chat channel, after sender authentication ([channel auth](reference-channel-auth.md)) |
| 3128 | egress proxy (`egress/proxy.py`) | HTTPS to allowlisted public hosts |

Two mechanisms enforce this, both driven by `network_policy.connect_tcp` in
`profile/policy.yaml`:

- **Per-user firewall** (`profile/firewall.py`, installed by the entrypoint
  as root, needs `--cap-add NET_ADMIN`, which the launcher adds). Packets
  from the agent's uid may only go to `127.0.0.1` on those ports. Other TCP
  connections are rejected as administratively prohibited, and all other
  traffic is dropped, including UDP and DNS (even to Docker's resolver). The
  agent never resolves names; the egress proxy does.
- **Landlock network rules** (Linux 6.7+) restrict the agent's TCP connects
  to the same ports and deny binding. Landlock checks ports only, not
  addresses, which is why the firewall is the primary boundary. On older
  kernels this layer is skipped.

At startup the agent checks the property itself before it does anything
else:

- A loopback port outside the list must be unreachable.
- Its own non-loopback address on an *allowed* port must be refused as
  prohibited (`EHOSTUNREACH`), not answered by the kernel (`ECONNREFUSED`).
  This is the case an attacker's server on port 8080 would hit.
- UDP to a non-loopback address must be refused.

If any check fails, the agent exits (status 78).

## Egress proxy

The agent's environment sets `HTTPS_PROXY`, `HTTP_PROXY`, `DDGS_PROXY` (and
`NO_PROXY=127.0.0.1,localhost,::1`), so web search, `git`, `curl`, `pip` and
Python HTTP clients go through the proxy. It opens an HTTPS (`CONNECT`)
tunnel only when:

- the host is a valid DNS name (no NUL or other control characters a
  resolver might cut the name at),
- the host is on the allowlist: `example.com` matches exactly that host,
  `*.example.com` matches its subdomains,
- the port is allowed (443 by default),
- the host is a name, not an IP address, and
- every address it resolves to is public. Loopback, private, link-local
  (including `169.254.169.254` cloud metadata), carrier-grade NAT, multicast
  and reserved ranges are refused. The tunnel goes to an address checked
  there, so DNS rebinding cannot redirect it.

The proxy runs as its own user (`omegaegress`), holds no credentials and
logs every allowed and refused host.

The default allowlist contains the exact hosts the `websearch` skill
queries: duckduckgo.com, html.duckduckgo.com, www.bing.com,
search.brave.com, www.google.com, www.mojeek.com, www.startpage.com,
yandex.com, search.yahoo.com, news.search.yahoo.com. An attacker cannot read
a search engine's query log, so these are not an exfiltration channel.
Parent domains are deliberately not allowed: `google.com` would include
`docs.google.com` (public forms anyone can post to), and Wikipedia accepts
anonymous edits.

## Configuration

| Launcher option | Setting | Effect |
|---|---|---|
| `--egress-allow github.com,*.githubusercontent.com` | `egressExtraDomains` | Add hosts to the allowlist (repeatable; `*.` for subdomains). |
| — | `egressAllowlist` | Replace the default allowlist entirely. |
| — | `egressAllowPorts` | Ports the proxy tunnels to (default `443`). |
| — | `egressExtraPorts` | Extra local TCP ports the agent may connect to. The launcher adds `9765` for `-p Test` (the autotests' mock LLM). |
| `--allow-unrestricted-network` | `allowUnrestrictedNetwork` | Skip the firewall and the Landlock network rules, e.g. where the container cannot get `NET_ADMIN`. The agent can then connect anywhere directly. |

Allowing a code host such as `github.com` lets a prompt-injected agent push
data to a repository the attacker controls, if the attacker supplies a
token. Add such domains only when the agent needs them.

Proxy settings can also be given as `OMEGA_egressAllowlist`,
`OMEGA_egressExtraDomains` and `OMEGA_egressAllowPorts` environment
variables.

## Remaining gaps

- Traffic to the LLM provider through nginx is not filtered: the agent can
  put anything into its prompts. The provider is trusted.
- Without Docker (`profile/policy-native.yaml`) there are no network rules.
