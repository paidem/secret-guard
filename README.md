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

The guard replaces detected secrets in successful tool results before they reach the
model. It reduces exposure; it does not guarantee that transcripts, diagnostic logs,
telemetry, or every API request are secret-free. See "Known holes" for paths that bypass
redaction and the version-specific acceptance results below.

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
denylist and values already discovered in the current session. Overlapping detections
redact their complete union. Object keys are scanned too; changes that would corrupt a
tool's schema cause withholding instead. Documentation examples (`AKIAIOSFODNN7EXAMPLE`,
`changeme`, `xxxxxxxx`) are allowlisted.

Optional entropy detection finds opaque strings inside larger blocks of text even when
they have no recognised vendor prefix or `password=` label. Enable it in `config.json`:

```json
{"entropy_detection": true}
```

The detector measures Shannon entropy **per candidate string**, rather than averaging the
whole paragraph (which can hide a short secret among ordinary text). Defaults: at least
24 characters and 4.2 bits per character, with at least two of lowercase, uppercase, and
digits present. UUIDs, existing placeholders, and pure hexadecimal strings are excluded;
the normal allowlist also applies. Set `entropy_include_hex: true` to inspect hexadecimal
strings at `entropy_hex_threshold` (default 3.3), accepting false positives on hashes.

Entropy cannot distinguish a random credential from a random public identifier or a base64
asset, and low-entropy passwords can still be missed. It is off by default. Preview with
`scan --entropy <file>` before enabling it across sessions. Findings use the same reversible
vault mapping and prompt blocking as other detectors. The approach is also used by
[Gitleaks](https://github.com/gitleaks/gitleaks) and
[detect-secrets](https://github.com/Yelp/detect-secrets/blob/master/detect_secrets/plugins/high_entropy_strings.py).

## Files

```
~/.claude/secret-guard/                 (override: SECRET_GUARD_HOME)
  config.json        overrides, see below
  denylist.txt       literal | ci:literal | re:regex   — one per line
  allowlist.txt      same syntax; never redact these
  patterns.json      extra detectors, same schema as config/patterns.json
  vault/<session>.json   0600; placeholder -> value, kind, uses, first seen
  vault/<session>.json.lock   stable empty lock files, retained after cleanup
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
  "scan_timeout_seconds": 2,
  "entropy_detection": false,           "entropy_min_length": 24,
  "entropy_threshold": 4.2,             "entropy_include_hex": false,
  "entropy_hex_threshold": 3.3,
  "builtin_patterns": true,              "disabled_patterns": [],
  "log": true
}
```

Malformed configuration, detector rules, and vaults produce inspection failures rather
than silently disabling rules. Inspection failures block prompts and tool execution;
`compact_policy: block` also refuses compaction on errors. Post-tool failures follow
`on_error`. Scanning uses an internal deadline (configurable up to 3 seconds), leaving time
to report failure before Claude Code's hook timeout. Requires a POSIX system with `fcntl`
and `SIGALRM` (Linux/macOS).

Oversized or unscannable Bash, text Read, and MCP results receive safe replacement output.
For unsupported response schemas, the guard stops the turn instead of emitting an invalid
replacement that Claude Code would ignore. Stopping does not erase the original result:
do not resume that conversation with sensitive output still present. Narrow the operation
or add a supported response adapter. Ordinary prompt/tool activity refreshes vault expiry;
cleanup holds the same lock as writers. Purge removes vault JSON, retaining empty lock files.

## CLI

```bash
SG=<plugin-dir>/bin/secret-guard.py   # installed plugins live under ~/.claude/plugins/
$SG list                    # vaults: session, entries, age
$SG list 76c3e539           # placeholders in one session (kinds, uses; never values)
$SG show '[SECRET_20260916195748_b9e4]'     # the real value, for you
$SG scan some-output.txt    # dry run: what would be redacted
$SG scan --entropy some-output.txt  # preview entropy findings without changing config
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
     leak would be worse than a lost session. Default `warn` reports known secret-bearing
     paths on stderr, logs their count, and instructs the summarizer to keep
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
