# Reference — Prompt-injection containment

Everything a tool returns from outside the owner's control can contain
instructions written by an attacker: a web page, a downloaded file, command
output, a memory recalled from an earlier conversation, another agent's
reply. Omega cannot reliably tell an injected instruction from data, so
`src/guard.py` limits what such text can make the agent do.

## Labelling

Tool results go back to the LLM wrapped like this:

```
<untrusted_data source="websearch">
...page text...
</untrusted_data>
```

The skill rules in the system prompt say that such content is data and
that instructions found inside it must not be followed. Text that tries
to close or fake the wrapper is neutralised. Results Omega generates itself
are not wrapped: `send`, `pin`, `nop`, `version`, `get-io-policy`, the
file-write and delete verifications, `remember`, and loop errors.

## Taint and owner approval

Reading any other result *taints* the turn. While tainted, only these
skills run directly:

| Runs while tainted | Why |
|---|---|
| `send`, `pin`, `nop`, `version`, `get-io-policy` | talk to the owner or keep notes |
| `websearch`, `read-file`, `query`, `episodes` | only read (search hosts cannot be read back by an attacker) |

Everything else, including `shell`, `write-file`, `write-file-b64`,
`append-file`, `delete-file`, `remember`, `metta` and every plugin skill,
is **held**. Instead of running it, Omega:

1. tells the LLM `HELD_FOR_OWNER_APPROVAL id=<id>: ...`, and
2. sends the owner `Approval needed [<id>]: ... the agent wants to run:
   (shell "...")` through the chat channel.

The owner answers `/approve <id>` (the exact call may run once) or
`/deny <id>`. The agent then gets `[OWNER APPROVED <id>] ...` or
`[OWNER DENIED <id>] ...` as its next message. Repeating a held call does
not ask again. Requests expire after an hour, and at most 20 are kept.

A new message from the owner ends the taint. `/approve` and `/deny` replies
do not: approving one action does not wave through the next one the
injected text asks for.

Approvals come only through the chat channel, which only the authenticated
owner (and groups the owner bound) can use; see
[channel authentication](reference-channel-auth.md). Tool output never
reaches that path.

## The `metta` skill is opt-in

`metta` evaluates arbitrary MeTTa, which reaches Python through `py-call`
and can rewrite the agent's own skills, prompt extensions and listeners.
It is registered only with `enableMettaSkill=True` (config file or
command line), and even then it is held while the turn is tainted.

## The tool-call parser

The loop evaluates the s-expression built from the LLM's tool calls. Calls
to unknown tools used to be written with the model-supplied name as a bare
symbol, so a crafted name containing parentheses could add calls of its
own. Invalid names are now written as escaped strings, and a response
whose call ids contain parentheses, quotes, `;`, backslashes or whitespace
is rejected.

## Limits

- The guard cannot stop the agent from *saying* something an injection
  wants it to say via `send`; the owner reads those messages.
- Text the LLM copies into its own commands (for example a `pin`) stays in
  the conversation history and can influence later turns. Held actions
  still need approval while the turn is tainted, but once the owner sends
  a new message, the history is not re-scanned.
- Filesystem and network limits ([sandbox](reference-skills-io.md),
  [network](reference-network.md)) apply whether or not an action was
  approved.
