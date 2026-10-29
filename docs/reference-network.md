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

This is enforced by Landlock network rules in `profile/policy.yaml`
(`network_policy.connect_tcp`), which need Landlock ABI 4 (Linux 6.7 or
newer). At startup the agent connects to a port outside the list and refuses
to run unless Landlock denies it. Binding TCP ports is denied too.

## Egress proxy

The agent's environment sets `HTTPS_PROXY`, `HTTP_PROXY`, `DDGS_PROXY` (and
`NO_PROXY=127.0.0.1,localhost,::1`), so web search, `git`, `curl`, `pip` and
Python HTTP clients go through the proxy. It opens an HTTPS (`CONNECT`)
tunnel only when:

- the host is on the allowlist (the domain or any subdomain),
- the port is allowed (443 by default),
- the host is a name, not an IP address, and
- every address it resolves to is public. Loopback, private, link-local
  (including `169.254.169.254` cloud metadata), carrier-grade NAT, multicast
  and reserved ranges are refused. The tunnel goes to an address checked
  there, so DNS rebinding cannot redirect it.

The proxy runs as its own user (`omegaegress`), holds no credentials and
logs every allowed and refused host.

The default allowlist contains the search engines the `websearch` skill
uses: duckduckgo.com, bing.com, search.brave.com, google.com, mojeek.com,
startpage.com, yandex.com, search.yahoo.com, wikipedia.org. An attacker
cannot read a search engine's query log, so these are not an exfiltration
channel.

## Configuration

| Launcher option | Setting | Effect |
|---|---|---|
| `--egress-allow github.com,pypi.org` | `egressExtraDomains` | Add domains to the allowlist (repeatable). |
| — | `egressAllowlist` | Replace the default allowlist entirely. |
| — | `egressAllowPorts` | Ports the proxy tunnels to (default `443`). |
| — | `egressExtraPorts` | Extra local TCP ports the agent may connect to. The launcher adds `9765` for `-p Test` (the autotests' mock LLM). |
| `--allow-unrestricted-network` | `allowUnrestrictedNetwork` | Drop the Landlock network rules, e.g. on kernels older than 6.7. The agent can then connect anywhere directly. |

Allowing a code host such as `github.com` lets a prompt-injected agent push
data to a repository the attacker controls, if the attacker supplies a
token. Add such domains only when the agent needs them.

## Remaining gaps

- **UDP** is not covered by Landlock network rules, so DNS queries can still
  carry small amounts of data to an attacker's name server. Closing this
  needs a network-level firewall around the container. For example, run it on
  a Docker network whose only route out is through a filtering proxy.
- Traffic to the LLM provider through nginx is not filtered: the agent can
  put anything into its prompts. The provider is trusted.
- Without Docker (`profile/policy-native.yaml`) there are no network rules.
