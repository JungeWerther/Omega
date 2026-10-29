# Reference — Configuration

Every tunable in Omega is declared as `(= (name) (empty))` and later bound by a `configure` call inside an `init*` function. The `configure` helper in `src/config.metta` is:

```metta
(= (configure $name $default)
   (let $value (configGetByKey $name $default)
        (add-atom &self (= ($name) $value))))
```

This resolves the value through the Python configuration layer, using command-line overrides, environment variables, YAML configuration, and the caller's default in that order.

## Loop (`src/loop.metta`, `initLoop`)

| Parameter | Default | Meaning |
|---|---|---|
| `maxNewInputLoops` | 50 | How many turns the agent keeps running after a new human message before idling. |
| `maxWakeLoops` | 1 | Extra turns granted on each scheduled wake-up. |
| `sleepInterval` | 1 (seconds) | Delay between loop iterations. |
| `LLM` | `gpt-5.4` | Model identifier passed to the provider. |
| `provider` | `Anthropic` | LLM provider — `Anthropic`, `OpenAI`, `ASICloud`, or `ASIOne`. |
| `maxOutputToken` | 6000 | Output cap passed to the provider. |
| `reasoningMode` | `medium` | Reasoning-effort hint passed to the provider. |
| `wakeupInterval` | 600 (seconds) | How long idle before the next scheduled wake-up. |

## Memory (`src/memory.metta`, `initMemory`)

| Parameter | Default | Meaning |
|---|---|---|
| `maxFeedback` | 50000 (chars) | Ceiling on a single tool call result text fed back into the prompt. |
| `maxRecallItems` | 20 | Items returned by `query`. |
| `maxEpisodeRecallLines` | 20 | Lines returned by `episodes`. |
| `maxHistory` | 30000 (chars) | Tail of `memory/history.metta` included in the prompt. |
| `memoryDirectory` | `./repos/Omega/memory` | Directory containing persistent memory files such as `history.metta`. |
| `chromaDbPath` | `./chroma_db` | ChromaDB persistence directory used for memory backup and restore. |
| `embeddingprovider` | `Local` | `Local` (Python-side model), or the id of a provider that serves an OpenAI-compatible `/embeddings` endpoint — `OpenAI` and `ASICloud` are known to. The gateway supplies that provider's key. |
| `embeddingModel` | empty | Model asked of a non-`Local` `embeddingprovider`. Empty means the provider default: `text-embedding-3-large` for `OpenAI`, `WhereIsAI/UAE-Large-V1` for `ASICloud`. |
| `embeddingBatchSize` | `32` | Positive integer: maximum texts per cloud embedding request during runtime knowledge loading. Lower it for providers with smaller request limits. The default keeps valid OpenAI inputs below the 300,000-token request limit (32 × 8192 = 262,144 tokens). Larger values must fit the provider's input-count and total-token limits. This does not split or truncate individual texts that exceed the model's context limit. |

### Startup knowledge indexing

`knowledgeIndexingBackground` defaults to `false`, keeping synchronous startup.
Set it to `true` to index `knowledge-priors/*.md` in a background thread while
plugins and channels start. Completed files become available to `query`
progressively in the runtime memory collection. Background errors are logged.

Local model loading still happens before indexing and can delay cold startup.

## Channels (`src/channels.metta`, `initChannels`)

| Parameter | Default | Meaning |
|---|---|---|
| `commchannel` | `irc` | Active channel — `irc`, `telegram`, `slack`, `mattermost`, or `websocket`. |
| `IRC_channel` | *(empty)* | Optional channel to also join. Empty means private messages with the owner only. Everyone in a channel can read the agent's replies there. |
| `IRC_server` | `irc.libera.chat` | IRC server hostname. |
| `IRC_port` | 6697 | IRC port (6697 TLS, 6667 plain). |
| `IRC_tls` | `true` | Connect with TLS and verify the server certificate. |
| `IRC_allowPlaintext` | `false` | Must be `true` to run with `IRC_tls: false`. The secret and every message then travel in clear text. |
| `IRC_requireAccount` | `true` | Bind the owner to a services account via IRCv3 `account-tag`. Set `false` on networks without it (QuakeNet) to bind to `ident@host` instead. |
| `IRC_privateReplyTTL` | 600 | Seconds after the owner's last message that private replies may still go to that nickname on servers without MONITOR. With MONITOR, replies are held as soon as the owner's nick goes offline. Held replies are sent when the owner speaks again. |
| `IRC_user` | `omega` | IRC nickname. The launcher picks `omega` plus six random hex digits. If the nick is taken, digits are appended and logged. |
| `TG_CHAT_ID` | *(empty)* | Legacy single-chat bootstrap/fallback, primarily for authentication-disabled deployments. With authentication enabled, the authenticated owner's DM becomes the proactive-message default. |
| `TG_ALLOWED_CHAT_IDS` | *(empty)* | Optional comma-separated initial allowed-chat set. The authenticated owner can add groups with `/bind` and remove them with `/unbind`; those changes are persisted in `authStateDir/authenticated-group.json` (the gate volume in Docker), not written back to YAML. |
| `TG_POLL_TIMEOUT` | 20 | Telegram long-poll timeout in seconds. |
| `SL_CHANNEL_ID` | *(empty — auto-bind supported)* | Optional Slack channel ID where Omega reads/writes messages. Leave empty to auto-bind on first valid inbound auth/message. |
| `SL_POLL_INTERVAL` | 60 | Slack poll interval in seconds (minimum effective value is 60). |
| `MM_URL` | `https://chat.singularitynet.io` | Mattermost base URL. |
| `MM_CHANNEL_ID` | `8fjrmabjx7gupy7e5kjznpt5qh` | Target channel ID. |
| `WS_URL` | *(empty — set at runtime)* | WebSocket endpoint URL (`ws://` or `wss://`). Required when `commchannel=websocket`. |
| `WS_TOKEN` | *(empty — optional)* | Bearer token sent as `Authorization: Bearer <token>`. Leave empty for an unauthenticated endpoint. In Docker pass it as the `OMEGA_WS_TOKEN` environment variable, not as an argument, so it stays out of the process list. |
| `authStateDir` | `memory/.channel` | Directory holding the channel owner and group records. The Docker entrypoint sets it to `/var/lib/omega-gate`, which only the gate user can write. |
| `securityPolicyPath` | `profile/policy-native.yaml` (the Docker launcher passes `profile/policy.yaml`) | Landlock filesystem policy for the agent. The native policy uses paths relative to the PeTTa checkout and includes the running Python environment. The agent exits (status 78) if the policy is missing, Landlock is unavailable or older than ABI 3 (Linux 6.2, needed to restrict truncation), or a self-test after applying it shows an access outside the policy still works, in-process or from a child process. |
| `egressExtraDomains` / `egressAllowlist` | search engines | Domains the agent may reach over HTTPS through the egress proxy (launcher: `--egress-allow`). See [network egress](reference-network.md). |
| `allowUnrestrictedNetwork` | `False` | Skip the agent's per-user firewall and Landlock network rules (launcher: `--allow-unrestricted-network`), e.g. where the container cannot get `NET_ADMIN`. |
| `allowUnsandboxed` | `False` | Set to `True` (launcher: `--allow-unsandboxed`) to keep running when the sandbox cannot be applied, for example on a host without Landlock. The agent can then read and write every file its user can. |
| `allowUnauthenticated` | `False` | Without `OMEGA_AUTH_SECRET`, nobody can authenticate. Set to `True` to accept messages from anyone instead. |

| Environment variable | Meaning |
|---|---|
| `TG_BOT_TOKEN` | Telegram bot token (from BotFather). |
| `OMEGA_AUTH_SECRET` | Owner secret. The first sender of `auth <secret>` becomes the owner; wrong guesses are rate limited. Without it nobody can authenticate unless `allowUnauthenticated=True`. See [channel authentication](reference-channel-auth.md). |
| `MM_BOT_TOKEN` | Bot auth token. |
| `SL_BOT_TOKEN` | Slack bot token (`xoxb-...`). |

## Command-line overrides

Any `configure`d parameter can be overridden at startup:

```bash
metta run.metta provider=Anthropic LLM=claude-opus-4-6 commchannel=mattermost
```

Configuration values are resolved in this order: command-line `key=value`,
`OMEGA_<KEY>` environment variable, `config/config.yaml`, then the caller's
default. `TG_BOT_TOKEN` and `OMEGA_AUTH_SECRET` are read directly from the
environment and must be placed before the `metta`/`petta` command.

For numeric settings, unambiguous integer and floating-point command-line values
are parsed as numbers: `maxFeedback=25000` and `sleepInterval=0.5` can be used in
arithmetic. The caller's default determines the setting's type; when no default is
provided, the YAML value is used. String settings and settings without a known
type keep their CLI text unchanged, including `IRC_channel=123`,
`IRC_channel=001`, and `OPENROUTER_SESSION_ID=123`.
A bare argument remains a boolean flag, but a numeric setting requires
`key=<number>`. For example,
`maxFeedback` without a value raises an error naming the parameter when resolved.

Telegram example:

```bash
TG_BOT_TOKEN=... OMEGA_AUTH_SECRET=... \
  metta run.metta commchannel=telegram
```

Slack example:

```bash
SL_BOT_TOKEN=xoxb-... metta run.metta commchannel=slack SL_CHANNEL_ID=C0123456789
```

WebSocket example:

```bash
metta run.metta commchannel=websocket WS_URL=wss://chat.example.com/agent WS_TOKEN=...
```

The `argk` helper parses `key=value` pairs from `argv`.
