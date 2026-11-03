# Providers — contract (Phase 1)

Status: Phase 1 contract, 2026-10-11.

## 1. What changes

Today a provider is a `[[providers]]` entry in `config.toml` with kinds `openai-compat`, `fake`, `acp`,
a `[brain]` preset for local Ollama, and keys looked up as `AUX_KEY_<ID>`. Phase 1 moves providers to
their own file, adds the `anthropic` and `ollama` kinds, a capability table, fallbacks, and a
per-agent and per-skill brain choice. There is **no OpenAI provider**.

## 2. `~/.auxesis/providers.toml`

```toml
[[provider]]
id       = "deepseek"                       # [a-z0-9-]{1,32}, unique
kind     = "openai"                         # openai | anthropic | ollama | acp | fake
base_url = "https://api.deepseek.com/v1"    # https, or http on loopback only
key      = "env:AUX_KEY_DEEPSEEK"           # env:<NAME> only; resolved from ~/.auxesis/.env then the process env
models   = ["deepseek-chat"]                # optional allowlist; empty = what the catalog lists for this provider
disable_thinking = true                     # openai kind only (existing DeepSeek toggle)

[[provider]]
id = "anthropic"
kind = "anthropic"
base_url = "https://api.anthropic.com"
key = "env:AUX_KEY_ANTHROPIC"

[[provider]]
id = "ollama-cloud"
kind = "openai"                             # §5 decides; `ollama` kind is for a local daemon
base_url = "https://ollama.com/v1"
key = "env:AUX_KEY_OLLAMA_CLOUD"

[[provider]]
id = "opencode"
kind = "acp"
agent = "opencode"                          # names an [acp.agents.*] entry; no key, the CLI holds its login

[brain]
default  = "deepseek/deepseek-chat"         # <provider>/<model>
fallback = ["anthropic/claude-haiku-5-5"]   # tried in order, only on §6 errors
```

Rules: unknown keys are a load error. A `key` that is not `env:` is a load error (no pasted secrets in
TOML). A `[[providers]]` table in `config.toml` is migrated once into `providers.toml` (keys stay
where they are; `key_user = "x"` becomes `key = "env:AUX_KEY_X"`), the old table is commented out with
a dated note, and the migration is logged.

Key resolution: `key = "env:NAME"` reads the process environment, then `~/.auxesis/.env` (0600). That
is the only resolver for new entries. A migrated legacy entry also keeps its old `key_user` lookup
(today's `crates/aux-providers/src/key.rs` order) until the owner runs `aux provider key <id>`, which
writes the value to `.env`; the migration itself never reads or copies a Keychain item, and no test
touches the Keychain (see `CONTRIBUTING.md`). `[brain] preset = "ollama"` keeps working: it expands to a
`kind = "ollama"` provider at `http://127.0.0.1:11434`.

## 3. Brain selection

`brain` is `<provider>/<model>` or a bare provider id (its first model). Resolution order, first hit
wins: skill front matter `brain:` → agent `agent.md` `brain:` → `[brain] default`. Skill `brain:` may
also be a hint (`cheap`, `strong`, `none`) mapped in `[brain.hints]`; an unmapped hint falls through.
`none` means the skill runs without a model (`collect-receipts`). The resolved brain is written on every
`skill.run` and `turn` Ledger row as `brain`.

## 4. Capabilities and the catalog

`catalog/models.toml` is generated **offline** by `scripts/import-models.py` from a saved models.dev
JSON file checked in next to it (`catalog/models.dev.json`, with its fetch date). The app never
fetches models.dev or any registry at runtime. One row per model:

```toml
[[model]]
provider = "anthropic"   id = "claude-opus-5-5"   tools = true   structured_output = true
context = 1000000        output = 128000          input_usd_mtok = 4.0   output_usd_mtok = 20.0
```

Phase 1 seeds at least: `anthropic/claude-opus-5-5`, `anthropic/claude-sonnet-5-5`,
`anthropic/claude-haiku-5-5`, `deepseek/deepseek-chat`, and the Ollama Cloud models the owner uses.
A model missing from the catalog is `tools = false` until the owner adds it.

**Gating.** A skill with any tool needs `tools = true`. Otherwise the skill refuses to start with the
label `chat only` and the reason ("<model> cannot use tools; pick another brain for this skill"), and
the brain picker shows `chat only` next to the model. `structured_output` is informational in Phase 1.

## 5. Kinds

| Kind | Wire | Notes |
|---|---|---|
| `openai` | `POST {base}/chat/completions` | Today's `openai_compat.rs`, renamed kind. DeepSeek, Ollama Cloud, LM Studio. |
| `anthropic` | `POST {base}/v1/messages`, headers `x-api-key`, `anthropic-version: 2023-06-01`, `content-type: application/json` | New adapter (§5.1). |
| `ollama` | `POST {base}/v1/chat/completions` (local daemon, no key) | Today's `[brain]` preset path; loopback only unless `allow_remote_base_url`. |
| `acp` | ACP over stdio (`aux-acp`) | Turn-level backend. Unfrozen for OpenCode. Read-only skills only in Phase 1 (§7). |
| `fake` | in process | Tests. |

**Ollama Cloud.** The implementation tests both `openai` kind against `https://ollama.com/v1` and the
`ollama` kind against `https://ollama.com` on one tool-call fixture with a real key in a manual run,
and keeps the one whose tool calls round-trip. Default: `openai`.

### 5.1 The `anthropic` adapter

- Request: `model`, `max_tokens` (16000 non-streaming, 64000 streaming), `system` (string), `messages`
  (user / assistant, assistant tool calls as `tool_use` blocks, results as `tool_result` blocks in one
  user message), `tools` (`name`, `description`, `input_schema`, `strict: true` when the runtime marks
  the tool strict). No `temperature`, no `top_p`, no `budget_tokens`, no assistant prefill.
- **Forced tools.** `claude-opus-5-5` and `claude-sonnet-5-5` reject `tool_choice` `any`/`tool`
  (400). The adapter never sends a forced `tool_choice`: when the runtime forces `skill__<name>`, it
  sends `tool_choice: {"type":"auto"}`, `strict: true` on that tool, offers only that tool, and adds
  one system line: "Call the tool skill__<name> exactly once. Do not answer in text." A text answer
  is the existing "model did not fill the skill" refusal.
- Effort: `output_config: {"effort": "<low|medium|high>"}` from the provider entry
  (`effort = "medium"` default). Thinking is left to the model's default (adaptive); thinking blocks
  in a response are dropped from what the runtime keeps and never sent back.
- Response: `content[]` of `text` and `tool_use` (`id`, `name`, `input`); `stop_reason` in
  `end_turn | tool_use | max_tokens | refusal | pause_turn | stop_sequence`. `refusal` is a typed
  error (`ProviderError::Refused { category }`), not a fallback trigger. `max_tokens` with a partial
  tool call is an error, never executed.
- Streaming (SSE): `message_start`, `content_block_start`, `content_block_delta` (`text_delta`,
  `input_json_delta`), `content_block_stop`, `message_delta` (carries `stop_reason`, `usage`),
  `message_stop`, `ping`, `error`. Tool input is assembled from `input_json_delta` and parsed once at
  `content_block_stop`; a parse failure is an error.
- Usage: `usage.input_tokens`, `usage.output_tokens` feed the budget meter.
- The key travels only in `x-api-key`. Never in a URL, never in a body, never in a log.

## 6. Fallbacks

A fallback hop happens only on transport and 5xx errors: connect/TLS/timeout errors
before any response byte, HTTP 500, 502, 503, 504, 529. Never on 408 or 429 (the turn fails with a
"rate limited, try again" message), never on 400/401/403/404, never on `refusal`, never after a tool call was
received, never inside a skill's send phase. One hop per entry of `[brain] fallback`, in order, then
the turn fails. Every hop writes a Ledger row `provider.fallback {from, to, reason}`; the turn's
`brain` field records the provider that answered. In Private mode the fallback provider receives the
same `SafeText` (the gate runs once per turn, not per provider).

## 7. ACP brain (OpenCode)

`kind = "acp"` providers run through `aux-acp`. Today `acp` is a frozen, off-by-default feature of
`auxd` (`crates/auxd/Cargo.toml` default is `["l1-fetch"]`); Phase 1 adds `acp` to the default features and
to the CI frozen-features line. In Phase 1 an ACP brain reports `tools = false` in the catalog,
because Auxesis cannot gate its tool calls per call: it runs plain chat and skills with no tools;
any skill that declares a tool refuses it with the `chat only` label. This is how Phase 1 treats
OpenCode (refused by `send-invite`, by design). In Private, these paths are Covered: the prompt, host
file reads and terminal output reach the agent through the session gate (tokenised), values the agent
names by token are rehydrated on the Mac just before a local run, and the owner sees the answer
rehydrated. The ACP agent's own tools stay sandboxed by the existing `aux-acp` supervisor.

## 8. Surfaces

CLI: `aux provider list | add <kind> | test <id> | remove <id>`, `aux brain show` (resolution for an
agent and each skill). `test` makes one minimal call (no tools) and prints latency and the model.
The Settings → Providers screen is planned for a later phase.

## 9. Done when

1. The hero test passes on `fake`, and on `deepseek`, `anthropic` and `ollama-cloud` in the owner
   nightly (keys present); a leg without a key is `skipped`, not passed (`docs/phase1.md` §6).
2. In Open mode, OpenCode answers plain chat through `kind = "acp"`, and `send-invite` refuses it
   with `chat only`.
3. A brain without tools is refused by a skill with the `chat only` label.
4. Canary: a fake upstream records every request; no request body or URL on any provider contains a
   key value (`AUX_KEY_*`) or a real party value from the fixture contacts in Private mode.
5. A 503 from the first provider produces one `provider.fallback` row and an answer from the second;
   a 400 or a 429 produces no fallback.
6. `config.toml` with a legacy `[[providers]]` table migrates once, and a second start does nothing.
