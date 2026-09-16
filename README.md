# secret-guard

Claude Code plugin: secrets in tool results are replaced by placeholders before the model
sees them, the real value is put back when the placeholder appears in a later tool call, the
mapping lives per session and expires.

```
$ cat monitoring.env                   # what the model sees:
MONITOR_URL=https://monitor.example.com/api
MONITOR_TOKEN=[SECRET_20260916195748_b9e4]

$ curl -H 'Authorization: Bearer [SECRET_20260916195748_b9e4]' …   # what actually runs:
curl -H 'Authorization: Bearer 7f3a…real…' …
```

What is protected: every tool result (Bash, Read, Grep, MCP, subagent output…), the
transcript on disk, and what is sent to the API. Verified with an egress-logging proxy — see
"Known holes" for the one path that still leaks.

## Install

The plugin is a directory; Python 3.9+ and nothing else.

```bash
# permanently, from inside Claude Code:
/plugin marketplace add paidem/secret-guard
/plugin install secret-guard@paidem

# or try it in one session without installing:
git clone https://github.com/paidem/secret-guard ~/secret-guard
claude --plugin-dir ~/secret-guard
```

Then create the word list:

```bash
mkdir -p ~/.claude/secret-guard
cp <plugin-dir>/config/denylist.example.txt ~/.claude/secret-guard/denylist.txt
$EDITOR ~/.claude/secret-guard/denylist.txt        # one prohibited word / known value per line
```

Do **not** combine with another hook that rewrites tool output (output compressors, other
redactors): parallel PostToolUse hooks all see the original output and the last one to finish
wins.

## How it works

| event | action |
|---|---|
| `PostToolUse` (all tools) | every string in `tool_response` is scanned; hits become `[SECRET_<yyyymmddHHMMSS>_<hex>]`; the whole response is returned as `updatedToolOutput`. The same value always gets the same placeholder within a session. |
| `PreToolUse` (all tools) | placeholders in `tool_input` are replaced by the real value from **this session's** vault (`updatedInput`). Unknown placeholders stay literal and you get a notice. `WebFetch`/`WebSearch` calls carrying a placeholder are denied. |
| `UserPromptSubmit` | a prompt that itself contains a secret is blocked (Claude Code cannot rewrite a prompt). Put the value in a file and refer to the path. `prompt_policy: off` disables. |
| `PostToolUseFailure` | output of a failing Bash command **cannot** be rewritten; the hook warns you when it contained a secret. |
| `PreCompact` | warns (or refuses, see below) and tells the summarizer to keep placeholders verbatim. |
| `SessionStart` | tells the model how placeholders work; sweeps expired vaults. |
| `SessionEnd` | deletes the vault on `/clear` and logout; otherwise it survives for `--resume`. |

Detection = built-in patterns (`config/patterns.json`: AWS, GitHub, GitLab, Slack, Stripe,
Google, Anthropic/OpenAI, npm/PyPI/HF, Azure, JWT, PEM blocks, `Bearer`/`Basic`, URL
credentials, `--password` flags, generic `password/token/secret/api_key = value`) plus your
denylist. No entropy heuristics: on infra output they fire on every hash and UUID, and a false
positive removes information from the model. Documentation examples (`AKIAIOSFODNN7EXAMPLE`,
`changeme`, `xxxxxxxx`) are allowlisted.

## Files

```
~/.claude/secret-guard/                 (override: SECRET_GUARD_HOME)
  config.json        overrides, see below
  denylist.txt       literal | ci:literal | re:regex   — one per line
  allowlist.txt      same syntax; never redact these
  patterns.json      extra detectors, same schema as config/patterns.json
  vault/<session>.json   0600; placeholder -> value, kind, uses, first seen
  secret-guard.log   events only, never values
<project>/.claude/secret-guard/{denylist,allowlist}.txt   merged in when present
```

`config.json` defaults:

```json
{
  "ttl_hours": 24,                       "delete_on": ["clear", "logout"],
  "reinject_deny_tools": ["WebFetch", "WebSearch"],
  "prompt_policy": "block",              "compact_policy": "warn",
  "on_error": "withhold",                "max_scan_bytes": 8388608,
  "builtin_patterns": true,              "disabled_patterns": [],
  "log": true
}
```

## CLI

```bash
SG=<plugin-dir>/bin/secret-guard.py   # installed plugins live under ~/.claude/plugins/
$SG list                    # vaults: session, entries, age
$SG list 76c3e539           # placeholders in one session (kinds, uses; never values)
$SG show '[SECRET_20260916195748_b9e4]'     # the real value, for you
$SG scan some-output.txt    # dry run: what would be redacted
$SG purge                   # expired vaults; --all for everything; <session> for one
$SG selftest
```

## Known holes

1. **Post-compaction file restore.** After every context compaction Claude Code re-attaches
   up to 5 recently read or written files (≤5000 tokens each) straight from disk as synthetic
   Read results. That path bypasses hooks. Measured: a `.env` read with `cat` and a file the
   model wrote with a re-injected token both came back raw after compaction and were sent
   to the API. Mitigations, in order of strength:
   - `permissions.deny` rules for known secret files, e.g.
     `"Read(**/.env)", "Read(**/.env.*)", "Read(**/credentials*)", "Read(**/*.pem)"`.
     The restore runs the Read permission check and skips denied files; `cat` still works
     and is redacted.
   - `compact_policy: block` refuses compaction while the session vault is non-empty. Measured:
     nothing leaked, but when the context was genuinely full the turn failed with
     "Prompt is too long" and the session was over. Use it only for short sessions where a
     leak would be worse than a lost session. Default `warn` records which files held secrets
     (`secret-guard.log`, `pre-compact` line) and instructs the summarizer to keep
     placeholders verbatim.
   - Files larger than ~20 KB are only restored as a path reference, never as content.
2. **Failing Bash commands.** Non-zero exit goes through `PostToolUseFailure`, which cannot
   be rewritten. `cmd || true` style wrappers avoid it; a transparent wrapper is a follow-up.
3. **`@file` mentions** inline the file outside the hook pipeline. Use Read or `cat`.
4. **Local transcript.** The hook's own stdout is recorded in the transcript as a
   `hook_success` attachment, so a re-injected value does sit in
   `~/.claude/projects/…/<session>.jsonl` (mode 0600). It is not part of the messages sent
   to the API (verified).
5. **Text matching.** Secrets split across lines, base64-encoded, or produced by a model that
   is trying to evade will get through. This is a seat belt; keep credentials least-privilege.

## Verified platform behaviour (Claude Code 2.1.273)

- `updatedToolOutput` must have the **same shape** as `tool_response` (object for Bash/Read,
  list of content blocks for MCP). A plain string is rejected.
- `updatedInput` is executed; the assistant's `tool_use` block in the transcript keeps the
  placeholder.
- `session_id` is stable across `--resume`; `--fork-session` and `/clear` start a new one.
  Subagent tool calls carry the parent `session_id`.
- PreCompact: plain-text stdout becomes summarizer instructions; exit 2 blocks.

## Acceptance runs (headless `claude -p` behind an egress-logging proxy)

| run | setup | result |
|---|---|---|
| A | cat a `.env` with a fake GitLab token + denylisted word; Write the placeholder to a file; echo it | model saw placeholders only; written file holds the real token; **0 of 7** API requests contained the token or the word |
| B | new session echoes A's placeholder | echoed literally, not resolved; 0 leaks |
| C | same as A with autocompact forced, `compact_policy: warn` | PreCompact fired 3×, summarizer instruction delivered; post-compact file restore sent the raw token in 5 of 8 requests (hole 1) |
| D | same with `compact_policy: block` | 0 leaks; turn failed "Prompt is too long" |

## Development

```bash
python3 -m unittest discover -s tests -v
bin/secret-guard.py selftest
```

## License

MIT.
