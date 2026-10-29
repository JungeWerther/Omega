# Reference — Channel authentication and the gate

The agent runs an LLM that can execute shell commands. Anything the agent
process can write, a successful prompt injection can rewrite. Channel
authentication therefore does not live in the agent process.

## Processes in the Docker image

| Process | User | Holds | Listens on |
|---|---|---|---|
| nginx credential proxy | `www-data` | provider API keys, bot tokens, the gate key | `127.0.0.1:8080` |
| gate (`gate/main.py`) | `omegagate` | `OMEGA_AUTH_SECRET`, `OMEGA_WS_TOKEN`, owner and group records | `127.0.0.1:8090` |
| agent (`run.metta`) | `nobody` | nothing secret | — |

The gate runs the selected channel plugin (IRC, Telegram, Slack, Mattermost or
WebSocket), decides for every inbound message whether the sender is the owner
or an authorized group, and keeps the records in `/var/lib/omega-gate`
(the `omega-gate` Docker volume, mode `0700`, owned by `omegagate`).

The agent reaches the channel only through four gate endpoints:

| Endpoint | Purpose |
|---|---|
| `GET /v1/health` | readiness |
| `GET /v1/receive` | next message that already passed authentication |
| `POST /v1/send` | send a reply; the channel plugin's own target checks still apply |
| `GET /v1/principal` | which principal may run `/memory-export` |

There is no endpoint to bind an owner or authorize a group. Those only happen
when the owner sends `auth <secret>`, `/bind` or `/unbind` through the chat
itself.

nginx serves the bot-token routes (`/telegram/`, `/slack/`, `/mattermost/`, …)
only under `/gate/<key>/`, where `<key>` is 48 random hex characters generated
at container start and given to nginx and the gate only. The agent can still
use the LLM provider routes, but it cannot read the chat or post as the bot
directly.

## Owner secret

* The launcher generates a random secret (`secrets.token_urlsafe(18)`) and
  prints it. `-s <secret>` overrides it; secrets shorter than 16 characters
  produce a warning.
* The first sender who presents the secret becomes the owner. The record is
  permanent: later senders cannot take over with the same secret.
* Wrong guesses are rate limited: 5 per sender and 20 in total per 15
  minutes. During a lockout even the correct secret is refused.

## Group tiers (Telegram)

When the owner sends `/bind` in a group, every member can talk to the bot
there. What they may make it *do* depends on the tier:

| Bind command | Tier | Members' messages |
|---|---|---|
| `/bind` | `chat` (default) | Reach the agent labelled as untrusted input, like a web page. They taint the turn, so shell, file writes and other actions they lead to wait for the owner's `/approve`. Members cannot approve. |
| `/bind tools` | `tools` | Act with the owner's authority. |

Only the owner can change a group's tier, by sending `/bind` or
`/bind tools` again. The owner's own messages are always trusted. Groups
bound before tiers existed are `chat`. The tier travels with each message
from the channel plugin through the gate (`/v1/receive` returns
`trusted`), never as message text a member could forge. The agent-side
client treats a missing flag as untrusted.

## Failing closed

| Situation | Before | Now |
|---|---|---|
| No `OMEGA_AUTH_SECRET` | everyone allowed | nobody can authenticate; set `allowUnauthenticated=True` to accept everyone |
| Gate unreachable from the agent | n/a | no messages, no export principal |
| Error while checking a secret | — | treated as a wrong secret |
| Auth record path is a symlink | followed | write refused |

## Upgrading

Older versions kept the records in `memory/.channel/`, which the agent can
write. On the first start with an empty `omega-gate` volume the entrypoint
copies them once into the gate volume and logs a warning. If the agent may have
been exposed to untrusted content before the upgrade, inspect
`authenticated-group.json` for groups you did not bind.

The old copies stay in `memory/.channel/` and are ignored.

## Running without Docker

Without the entrypoint there is no separate user, so the gate's isolation does
not apply: channel plugins run in the agent process and records go to
`authStateDir` (default `memory/.channel`). Authentication still fails closed
and is still rate limited, but a compromised agent can edit the records.

## IRC specifics

IRC identities are weaker than Telegram or Slack user IDs, so the IRC adapter
adds its own rules (see [channels](reference-channels.md#channelsircpy)):
TLS with certificate verification, `auth` accepted only as a private message,
and the owner bound to a services account (`account-tag`) instead of a
nickname. Records written under the old `IRC` identifier (bare nicknames) are
not trusted; the owner authenticates once again after upgrading.
