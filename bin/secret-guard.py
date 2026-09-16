#!/usr/bin/env python3
"""
secret-guard — reversible secret redaction for Claude Code, as a hook.

PostToolUse   : every string inside tool_response is scanned; secrets and denylisted words
                become [SECRET_<yyyymmddHHMMSS>_<hex>] placeholders (updatedToolOutput).
PreToolUse    : placeholders inside tool_input are substituted with the real value from
                THIS session's vault (updatedInput). Other sessions' placeholders stay literal.
UserPromptSubmit: a prompt that itself contains a secret is blocked (rewriting is not
                possible), unless prompt_policy = off.
SessionStart  : explains the mechanism to the model, sweeps expired vaults.
SessionEnd    : deletes the vault on /clear or logout, sweeps expired vaults.

State: ~/.claude/secret-guard/ (override with SECRET_GUARD_HOME)
  config.json, denylist.txt, allowlist.txt, patterns.json (extra rules),
  vault/<session_id>.json (0600), secret-guard.log (events only, never values).

CLI:  secret-guard.py hook | list [session] | show <placeholder> [--session id]
      | scan <file|-> | purge [--all | session] | selftest

Python 3.9+, standard library only. See docs/superpowers/specs/ for the design.
"""

import datetime as _dt
import fcntl
import hashlib
import json
import os
import re
import signal
import sys
import tempfile
import time
from contextlib import contextmanager

VERSION = "0.1.0"

PLACEHOLDER_RE = re.compile(r"\[SECRET_(\d{14})_([0-9a-f]{4,})\]")

PLUGIN_ROOT = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))


def guard_home():
    return os.environ.get("SECRET_GUARD_HOME") or os.path.join(
        os.path.expanduser("~"), ".claude", "secret-guard")


DEFAULTS = {
    "ttl_hours": 24,
    "delete_on": ["clear", "logout"],
    "reinject_deny_tools": ["WebFetch", "WebSearch"],
    "prompt_policy": "block",          # block | off
    "compact_policy": "warn",          # warn | block | off   (see README: post-compact file restore)
    "on_error": "withhold",            # withhold | passthrough
    "max_scan_bytes": 8 * 1024 * 1024,
    "scan_timeout_seconds": 2,
    "builtin_patterns": True,
    "disabled_patterns": [],
    "log": True,
}

SESSION_CONTEXT = (
    "secret-guard is active in this session. A local hook scans every tool result and "
    "replaces secret values (tokens, passwords, private keys, and a user-maintained word "
    "list) with placeholders of the form [SECRET_<timestamp>_<hex>]. To use such a value "
    "in a Bash command, a file written with Write/Edit, or an MCP call, write the "
    "placeholder verbatim; the hook substitutes the real value at execution time, in this "
    "session only. Do not try to reconstruct, guess, decode or work around a placeholder, "
    "and do not ask the user to paste the real value. Placeholders from other sessions "
    "cannot be resolved here."
)


# ----------------------------------------------------------------------------- config

def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except Exception as e:  # malformed config must not disable the guard silently
        sys.stderr.write("secret-guard: cannot parse %s: %s\n" % (path, e))
        return default


def load_config():
    cfg = dict(DEFAULTS)
    user = load_json(os.path.join(guard_home(), "config.json"), {})
    if isinstance(user, dict):
        cfg.update(user)
    return cfg


def read_list_file(path):
    """denylist/allowlist syntax -> list of (kind_suffix, compiled_regex)."""
    out = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return out
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if line.startswith("re:"):
                out.append(("regex", re.compile(line[3:])))
            elif line.startswith("ci:"):
                out.append(("literal", re.compile(re.escape(line[3:]), re.IGNORECASE)))
            else:
                out.append(("literal", re.compile(re.escape(line))))
        except re.error as e:
            sys.stderr.write("secret-guard: %s:%d bad regex: %s\n" % (path, n, e))
    return out


def list_files(name, cwd):
    """User-level file, plus project-level one when a cwd is known."""
    paths = [os.path.join(guard_home(), name)]
    if cwd:
        paths.append(os.path.join(cwd, ".claude", "secret-guard", name))
    return paths


# ---------------------------------------------------------------------------- detection

FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}

VALUE_NOISE = re.compile(
    r"^(?:null|none|nil|true|false|undefined|required|optional|string|bearer|basic|token|secret|password)$",
    re.IGNORECASE)


def value_is_noise(v):
    """Values the generic rules must not treat as secrets."""
    if not v:
        return True
    if PLACEHOLDER_RE.fullmatch(v) or re.fullmatch(
            r"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*|"
            r"<[A-Za-z_][A-Za-z0-9_-]*>|\{\{[^{}]+\}\}", v):
        return True
    if VALUE_NOISE.match(v):
        return True
    if len(set(v)) <= 2:              # xxxxxxxx, ********, 00000000
        return True
    return False


class Detector(object):
    def __init__(self, pid, kind, regex, group=0, generic=False):
        self.id = pid
        self.kind = kind
        self.regex = regex
        self.group = group
        self.generic = generic

    def find(self, text):
        for m in self.regex.finditer(text):
            try:
                groups = self.group if isinstance(self.group, list) else [self.group]
                start, end = next((m.span(g) for g in groups if m.start(g) >= 0), (-1, -1))
            except (IndexError, re.error):
                start, end = m.span(0)
            if start < 0 or end <= start:
                continue
            if self.generic and value_is_noise(text[start:end]):
                continue
            yield start, end


def build_detectors(cfg, cwd=None):
    dets = []
    disabled = set(cfg.get("disabled_patterns") or [])

    def add_pattern_file(path):
        data = load_json(path, {})
        for p in (data.get("patterns") or []):
            if p.get("id") in disabled:
                continue
            flags = 0
            for ch in (p.get("flags") or ""):
                flags |= FLAGS.get(ch, 0)
            try:
                rx = re.compile(p["regex"], flags)
            except (re.error, KeyError) as e:
                sys.stderr.write("secret-guard: bad pattern %s: %s\n" % (p.get("id"), e))
                continue
            dets.append(Detector(p.get("id", "?"), p.get("kind", "secret"), rx,
                                 p.get("group", 0), bool(p.get("generic"))))

    if cfg.get("builtin_patterns", True):
        add_pattern_file(os.path.join(PLUGIN_ROOT, "config", "patterns.json"))
    add_pattern_file(os.path.join(guard_home(), "patterns.json"))

    for path in list_files("denylist.txt", cwd):
        for n, (kind, rx) in enumerate(read_list_file(path), 1):
            dets.append(Detector("denylist:%s:%d" % (os.path.basename(os.path.dirname(path)), n),
                                 "denylist", rx))
    return dets


def build_allowlist(cwd=None):
    rxs = [rx for _, rx in read_list_file(os.path.join(PLUGIN_ROOT, "config", "allowlist.txt"))]
    for path in list_files("allowlist.txt", cwd):
        rxs.extend(rx for _, rx in read_list_file(path))
    return rxs


def allowed(value, allowlist):
    for rx in allowlist:
        if rx.fullmatch(value):
            return True
    return False


def find_secrets(text, detectors, allowlist, known_values=()):
    """-> list of (start, end, kind, detector_id), non-overlapping, ascending."""
    hits = []
    for value in known_values:
        if not value or allowed(value, allowlist):
            continue
        start = text.find(value)
        while start >= 0:
            hits.append((start, start + len(value), "known-secret", "vault"))
            start = text.find(value, start + 1)
    for d in detectors:
        for start, end in d.find(text):
            val = text[start:end]
            if PLACEHOLDER_RE.fullmatch(val) or allowed(val, allowlist):
                continue
            hits.append((start, end, d.kind, d.id))
    hits.sort(key=lambda h: (h[0], -h[1]))
    out = []
    for h in hits:
        if out and h[0] < out[-1][1]:
            previous = out[-1]
            out[-1] = (previous[0], max(previous[1], h[1]), previous[2], previous[3])
        else:
            out.append(h)
    return out


# -------------------------------------------------------------------------------- vault

def now_iso():
    return _dt.datetime.now().replace(microsecond=0).isoformat()


class Vault(object):
    """Per-session placeholder <-> value store. One JSON file, 0600, flock'd."""

    def __init__(self, session_id):
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", session_id or ""):
            raise ValueError("bad session id")
        self.session_id = session_id
        self.dir = os.path.join(guard_home(), "vault")
        self.path = os.path.join(self.dir, session_id + ".json")
        self.data = None
        self._lock = None

    def __enter__(self):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self._lock = os.fdopen(os.open(self.path + ".lock", os.O_WRONLY | os.O_CREAT, 0o600), "a")
        fcntl.flock(self._lock, fcntl.LOCK_EX)
        self.data = load_json(self.path, None) or {
            "session_id": self.session_id, "created": now_iso(),
            "updated": now_iso(), "entries": {}}
        self._dirty = False
        return self

    def __exit__(self, *exc):
        try:
            if self._dirty and exc[0] is None:
                self._write()
        finally:
            fcntl.flock(self._lock, fcntl.LOCK_UN)
            self._lock.close()

    def _write(self):
        self.data["updated"] = now_iso()
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=1, sort_keys=True)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def exists(self):
        return os.path.exists(self.path)

    def touch(self):
        self._dirty = True

    def placeholder_for(self, value, kind, tool):
        entries = self.data["entries"]
        for ph, e in entries.items():
            if e["value"] == value:
                e["uses"] = e.get("uses", 0)
                self._dirty = True
                return ph
        digest = hashlib.sha256((self.session_id + "\0" + value).encode("utf-8")).hexdigest()
        stamp = _dt.datetime.now().strftime("%Y%m%d%H%M%S")
        n = 4
        while True:
            ph = "[SECRET_%s_%s]" % (stamp, digest[:n])
            if ph not in entries:
                break
            n += 2
        entries[ph] = {"value": value, "kind": kind, "first_tool": tool,
                       "first_seen": now_iso(), "uses": 0}
        self._dirty = True
        return ph

    def resolve(self, placeholder):
        e = self.data["entries"].get(placeholder)
        if e is None:
            return None
        e["uses"] = e.get("uses", 0) + 1
        self._dirty = True
        return e["value"]

    def note_file(self, path):
        """Remember a file whose on-disk content holds a secret (for the PreCompact warning)."""
        if not path:
            return
        files = self.data.setdefault("files", [])
        if path not in files:
            files.append(path)
            self._dirty = True

    def delete(self):
        for p in (self.path, self.path + ".lock"):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass


def sweep_vaults(ttl_hours):
    """Delete vault files not touched for ttl_hours. Returns number removed."""
    d = os.path.join(guard_home(), "vault")
    if not os.path.isdir(d):
        return 0
    cutoff = time.time() - float(ttl_hours) * 3600
    removed = 0
    for name in os.listdir(d):
        p = os.path.join(d, name)
        if not name.endswith(".json") or name.startswith(".tmp-"):
            continue
        try:
            if os.stat(p).st_mtime < cutoff:
                os.unlink(p)
                try:
                    os.unlink(p + ".lock")
                except FileNotFoundError:
                    pass
                removed += 1
        except FileNotFoundError:
            pass
    return removed


# ---------------------------------------------------------------------------- redaction

def redact_text(text, vault, detectors, allowlist, tool):
    hits = find_secrets(text, detectors, allowlist,
                        [e["value"] for e in vault.data["entries"].values()])
    if not hits:
        return text, []
    kinds = []
    parts = []
    pos = 0
    for start, end, kind, _pid in hits:
        parts.append(text[pos:start])
        parts.append(vault.placeholder_for(text[start:end], kind, tool))
        kinds.append(kind)
        pos = end
    parts.append(text[pos:])
    return "".join(parts), kinds


def deep_map(obj, fn):
    """Apply fn to every string in a JSON structure. -> (new_obj, changed)."""
    if isinstance(obj, str):
        new = fn(obj)
        return new, new != obj
    if isinstance(obj, list):
        changed = False
        out = []
        for item in obj:
            n, c = deep_map(item, fn)
            out.append(n)
            changed = changed or c
        return out, changed
    if isinstance(obj, dict):
        changed = False
        out = {}
        for k, v in obj.items():
            n, c = deep_map(v, fn)
            out[k] = n
            changed = changed or c
        return out, changed
    return obj, False


READER_CMD_RE = re.compile(r"(?:^|[|;&]\s*|\(\s*)(?:sudo\s+)?(?:cat|head|tail|less|more|bat|tac)\b([^|;&<>]*)")


def files_touched(tool, tool_input, cwd):
    """Paths whose on-disk content the model just saw or wrote. Claude Code tracks the same
    ones (Read/Write/Edit, and cat/head/tail in Bash) for its post-compaction file restore."""
    if tool in ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit"):
        p = tool_input.get("file_path") or tool_input.get("notebook_path")
        return [p] if p else []
    if tool != "Bash":
        return []
    out = []
    for m in READER_CMD_RE.finditer(tool_input.get("command") or ""):
        for tok in m.group(1).split():
            if tok.startswith("-") or tok.startswith("$"):
                continue
            tok = tok.strip("'\"")
            p = tok if os.path.isabs(tok) else os.path.join(cwd or os.getcwd(), tok)
            p = os.path.normpath(os.path.expanduser(p))
            if os.path.isfile(p) and p not in out:
                out.append(p)
    return out


def withhold(obj, reason, tool):
    """Build a replacement only for output schemas we know how to preserve."""
    msg = "[secret-guard: tool output withheld — %s]" % reason
    if tool.startswith("mcp__"):
        return [{"type": "text", "text": msg}]
    if tool == "Bash" and isinstance(obj, dict) and isinstance(obj.get("stdout"), str):
        new, _ = deep_map(obj, lambda s: msg if s else s)
        return new
    if tool == "Read" and isinstance(obj, dict) and obj.get("type") == "text" \
            and isinstance(obj.get("file"), dict):
        new, _ = deep_map(obj, lambda s: msg if s else s)
        new["type"] = "text"
        return new
    return None


def withheld_response(inp, reason):
    replacement = withhold(inp.get("tool_response"), reason, inp.get("tool_name", ""))
    if replacement is None:
        # An invalid replacement is ignored by Claude Code. Stop this turn instead.
        return {"continue": False, "stopReason": "secret-guard: " + reason +
                "; cannot safely replace this tool's output. Do not resume with this result."}
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                    "updatedToolOutput": replacement}}


# ------------------------------------------------------------------------------ logging

def log_event(cfg, session_id, event, **fields):
    if not cfg.get("log", True):
        return
    try:
        os.makedirs(guard_home(), mode=0o700, exist_ok=True)
        line = "%s %s %s" % (now_iso(), (session_id or "-")[:8], event)
        for k, v in fields.items():
            line += " %s=%s" % (k, json.dumps(v) if not isinstance(v, str) else v)
        with open(os.path.join(guard_home(), "secret-guard.log"), "a", encoding="utf-8") as f:
            f.write(line + "\n")
        os.chmod(os.path.join(guard_home(), "secret-guard.log"), 0o600)
    except Exception:
        pass


# ------------------------------------------------------------------------- hook handlers

class ScanTimeout(Exception):
    pass


@contextmanager
def scan_deadline(seconds):
    """Interrupt even a single pathological stdlib regex before the host timeout."""
    seconds = float(seconds)
    if not 0 < seconds <= 3:
        raise ValueError("scan_timeout_seconds must be greater than 0 and at most 3")
    def expired(signum, frame):
        raise ScanTimeout("scan deadline exceeded")
    previous = signal.signal(signal.SIGALRM, expired)
    timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        signal.setitimer(signal.ITIMER_REAL, *timer)

def emit(obj):
    sys.stdout.write(json.dumps(obj))
    sys.stdout.write("\n")
    sys.stdout.flush()


def on_post_tool_use(inp, cfg):
    sid = inp.get("session_id")
    tool = inp.get("tool_name", "?")
    resp = inp.get("tool_response")
    if resp is None:
        return {}
    size = len(json.dumps(resp))
    if size > int(cfg["max_scan_bytes"]):
        log_event(cfg, sid, "withheld", tool=tool, reason="too-large", bytes=size)
        return withheld_response(inp, "%d bytes exceeds max_scan_bytes; narrow the command" % size)
    detectors = build_detectors(cfg, inp.get("cwd"))
    allowlist = build_allowlist(inp.get("cwd"))
    kinds_all = []
    with Vault(sid) as vault:
        # Discover values across the entire response before replacing any field: a
        # bare value may precede the labelled field which identifies it as a secret.
        def discover(s):
            for start, end, kind, _ in find_secrets(s, detectors, allowlist):
                vault.placeholder_for(s[start:end], kind, tool)
            return s
        deep_map(resp, discover)
        def fn(s):
            new, kinds = redact_text(s, vault, detectors, allowlist, tool)
            kinds_all.extend(kinds)
            return new
        new_resp, changed = deep_map(resp, fn)
        if changed:
            for path in files_touched(tool, inp.get("tool_input") or {}, inp.get("cwd")):
                vault.note_file(path)
    if not changed:
        return {}
    summary = {}
    for k in kinds_all:
        summary[k] = summary.get(k, 0) + 1
    desc = ", ".join("%s x%d" % (k, n) if n > 1 else k for k, n in sorted(summary.items()))
    log_event(cfg, sid, "redacted", tool=tool, count=len(kinds_all), kinds=sorted(summary))
    return {"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "updatedToolOutput": new_resp,
        "additionalContext": "secret-guard: %d value(s) in this result replaced by [SECRET_…] placeholders (%s)."
                             % (len(kinds_all), desc)}}


def on_pre_tool_use(inp, cfg):
    sid = inp.get("session_id")
    tool = inp.get("tool_name", "?")
    ti = inp.get("tool_input")
    if ti is None or not PLACEHOLDER_RE.search(json.dumps(ti)):
        return {}
    unknown = set()
    resolved = 0
    with Vault(sid) as vault:
        def fn(s):
            def sub(m):
                nonlocal resolved
                v = vault.resolve(m.group(0))
                if v is None:
                    unknown.add(m.group(0))
                    return m.group(0)
                resolved += 1
                return v
            return PLACEHOLDER_RE.sub(sub, s)
        new_ti, changed = deep_map(ti, fn)
    out = {}
    if unknown:
        note = ("secret-guard: placeholder(s) not known to this session, left as literal text: "
                + ", ".join(sorted(unknown)))
        out["systemMessage"] = note
        out["hookSpecificOutput"] = {"hookEventName": "PreToolUse", "additionalContext": note}
        log_event(cfg, sid, "unknown-placeholder", tool=tool, count=len(unknown))
    if resolved and tool in (cfg.get("reinject_deny_tools") or []):
        log_event(cfg, sid, "reinject-denied", tool=tool, count=resolved)
        out["hookSpecificOutput"] = {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "secret-guard: refusing to pass a secret value to %s. "
                                        "Use a local tool (Bash/curl) if this is really needed." % tool}
        return out
    if changed:
        log_event(cfg, sid, "reinjected", tool=tool, count=resolved)
        out.setdefault("hookSpecificOutput", {"hookEventName": "PreToolUse"})["updatedInput"] = new_ti
        if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            with Vault(sid) as vault:
                vault.note_file(ti.get("file_path") or ti.get("notebook_path"))
    return out


COMPACT_INSTRUCTIONS = (
    "Secret values in this conversation appear as [SECRET_<timestamp>_<hex>] placeholders "
    "managed by a local hook. Keep every placeholder verbatim in the summary wherever the "
    "value matters; never expand, shorten or paraphrase them."
)


def on_pre_compact(inp, cfg):
    """Post-compaction, Claude Code re-attaches up to 5 recently read files straight from disk,
    bypassing PostToolUse. We cannot filter that; we can warn, or refuse the compaction."""
    policy = cfg.get("compact_policy", "warn")
    if policy == "off":
        return None
    sid = inp.get("session_id")
    try:
        with Vault(sid) as v:
            entries = len(v.data.get("entries", {}))
            files = list(v.data.get("files", []))
    except ValueError:
        return None
    if not entries:
        return None
    log_event(cfg, sid, "pre-compact", trigger=inp.get("trigger"), policy=policy,
              entries=entries, files=len(files))
    if policy == "block":
        sys.stderr.write(
            "secret-guard: compaction refused (compact_policy=block): this session holds %d secret(s) "
            "and Claude Code would re-attach recently read files raw after compacting. "
            "Files that held secrets: %s. Finish and /clear, or set compact_policy to warn.\n"
            % (entries, ", ".join(files) or "(none via Read/Write)"))
        return 2
    sys.stderr.write(
        "secret-guard: compaction will re-attach up to 5 recently read files RAW (Claude Code "
        "limitation). Secret-bearing files this session: %s\n" % (", ".join(files) or "(none via Read/Write)"))
    sys.stdout.write(COMPACT_INSTRUCTIONS + "\n")
    return None


def on_post_tool_use_failure(inp, cfg):
    """The error text cannot be rewritten (platform limit); warn the user when it leaked."""
    sid = inp.get("session_id")
    err = inp.get("error")
    if not isinstance(err, str) or not err:
        return {}
    detectors = build_detectors(cfg, inp.get("cwd"))
    with Vault(sid) as vault:
        hits = find_secrets(err, detectors, build_allowlist(inp.get("cwd")),
                            [e["value"] for e in vault.data["entries"].values()])
    if not hits:
        return {}
    kinds = sorted(set(h[2] for h in hits))
    log_event(cfg, sid, "leak-on-failure", tool=inp.get("tool_name"), count=len(hits), kinds=kinds)
    return {"systemMessage": "secret-guard WARNING: the failed %s call returned %d secret-like value(s) (%s) "
                             "in its error text, which Claude Code does not let a hook rewrite. "
                             "The model has seen them; rotate if they were real."
                             % (inp.get("tool_name"), len(hits), ", ".join(kinds))}


def on_user_prompt_submit(inp, cfg):
    if cfg.get("prompt_policy", "block") == "off":
        return {}
    prompt = inp.get("prompt") or ""
    detectors = build_detectors(cfg, inp.get("cwd"))
    with Vault(inp.get("session_id")) as vault:
        hits = find_secrets(prompt, detectors, build_allowlist(inp.get("cwd")),
                            [e["value"] for e in vault.data["entries"].values()])
    if not hits:
        return {}
    kinds = sorted(set(h[2] for h in hits))
    log_event(cfg, inp.get("session_id"), "prompt-blocked", count=len(hits), kinds=kinds)
    return {"decision": "block",
            "reason": "secret-guard: the prompt contains %d secret-like value(s) (%s). Claude Code cannot "
                      "redact a prompt, so it was not sent. Put the value in a file and refer to the path "
                      "(the file's contents will be redacted when read), or set prompt_policy to off in "
                      "%s/config.json." % (len(hits), ", ".join(kinds), guard_home())}


def on_session_start(inp, cfg):
    sid = inp.get("session_id")
    removed = sweep_vaults(cfg["ttl_hours"])
    ctx = SESSION_CONTEXT
    try:
        with Vault(sid) as v:
            n = len(v.data["entries"])
        if n and inp.get("source") == "resume":
            ctx += " %d placeholder(s) from this session's earlier turns are still resolvable." % n
    except Exception:
        pass
    log_event(cfg, sid, "session-start", source=inp.get("source"), swept=removed)
    return {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": ctx}}


def on_session_end(inp, cfg):
    sid = inp.get("session_id")
    reason = inp.get("reason")
    deleted = False
    if reason in (cfg.get("delete_on") or []):
        try:
            Vault(sid).delete()
            deleted = True
        except ValueError:
            pass
    removed = sweep_vaults(cfg["ttl_hours"])
    log_event(cfg, sid, "session-end", reason=reason, deleted=deleted, swept=removed)
    return {}


HANDLERS = {
    "PreToolUse": on_pre_tool_use,
    "PostToolUse": on_post_tool_use,
    "PostToolUseFailure": on_post_tool_use_failure,
    "UserPromptSubmit": on_user_prompt_submit,
    "SessionStart": on_session_start,
    "SessionEnd": on_session_end,
    "PreCompact": on_pre_compact,     # plain-text stdout = summarizer instructions; returns 2 to block
}


def run_hook():
    raw = sys.stdin.read()
    try:
        inp = json.loads(raw)
    except Exception:
        emit({})
        return 0
    cfg = load_config()
    ev = inp.get("hook_event_name")
    handler = HANDLERS.get(ev)
    if handler is None:
        emit({})
        return 0
    try:
        with scan_deadline(cfg["scan_timeout_seconds"]):
            result = handler(inp, cfg)
        if ev == "PreCompact":
            return result or 0
        emit(result)
    except Exception as e:
        log_event(cfg, inp.get("session_id"), "error", hook=ev, error=repr(e))
        sys.stderr.write("secret-guard: %s handler failed: %r\n" % (ev, e))
        if ev == "PreCompact":
            return 2 if isinstance(e, ScanTimeout) else 0
        if isinstance(e, ScanTimeout) and ev == "UserPromptSubmit":
            emit({"decision": "block", "reason": "secret-guard: inspection timed out"})
            return 0
        if isinstance(e, ScanTimeout) and ev == "PreToolUse":
            emit({"hookSpecificOutput": {"hookEventName": ev, "permissionDecision": "deny",
                                         "permissionDecisionReason": "secret-guard: inspection timed out"}})
            return 0
        if ev == "PostToolUse" and cfg.get("on_error", "withhold") == "withhold" \
                and inp.get("tool_response") is not None:
            emit(withheld_response(inp, "redaction failed"))
        else:
            emit({})
    return 0


# ---------------------------------------------------------------------------------- CLI

def cli_list(args):
    d = os.path.join(guard_home(), "vault")
    if not os.path.isdir(d):
        print("no vaults")
        return 0
    names = sorted(n for n in os.listdir(d) if n.endswith(".json") and not n.startswith(".tmp-"))
    want = args[0] if args else None
    for n in names:
        sid = n[:-5]
        if want and not sid.startswith(want):
            continue
        data = load_json(os.path.join(d, n), {})
        age_h = (time.time() - os.stat(os.path.join(d, n)).st_mtime) / 3600
        print("%s  entries=%d  last-used=%.1fh ago  created=%s" % (
            sid, len(data.get("entries", {})), age_h, data.get("created")))
        if want:
            for ph, e in sorted(data.get("entries", {}).items()):
                print("   %s  %-18s uses=%-3d first=%s via %s" % (
                    ph, e.get("kind"), e.get("uses", 0), e.get("first_seen"), e.get("first_tool")))
    return 0


def cli_show(args):
    if not args:
        print("usage: show <placeholder> [--session <id-prefix>]")
        return 2
    ph = args[0]
    sid_prefix = args[2] if len(args) > 2 and args[1] == "--session" else None
    d = os.path.join(guard_home(), "vault")
    for n in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if not n.endswith(".json") or (sid_prefix and not n.startswith(sid_prefix)):
            continue
        e = load_json(os.path.join(d, n), {}).get("entries", {}).get(ph)
        if e:
            print(e["value"])
            return 0
    print("not found", file=sys.stderr)
    return 1


def cli_scan(args):
    cfg = load_config()
    src = args[0] if args else "-"
    text = sys.stdin.read() if src == "-" else open(src, "r", encoding="utf-8", errors="replace").read()
    hits = find_secrets(text, build_detectors(cfg, os.getcwd()), build_allowlist(os.getcwd()))
    for start, end, kind, pid in hits:
        line = text.count("\n", 0, start) + 1
        v = text[start:end]
        shown = v[:3] + "…" + v[-2:] if len(v) > 8 else "…"
        print("line %d  %-18s %-24s %s (%d chars)" % (line, kind, pid, shown, len(v)))
    print("%d hit(s)" % len(hits), file=sys.stderr)
    return 0


def cli_purge(args):
    d = os.path.join(guard_home(), "vault")
    if not os.path.isdir(d):
        return 0
    if args and args[0] == "--all":
        n = 0
        for name in os.listdir(d):
            os.unlink(os.path.join(d, name))
            n += 1
        print("removed %d file(s)" % n)
        return 0
    if args:
        for name in os.listdir(d):
            if name.startswith(args[0]):
                os.unlink(os.path.join(d, name))
                print("removed", name)
        return 0
    print("removed %d expired vault(s)" % sweep_vaults(load_config()["ttl_hours"]))
    return 0


def cli_selftest():
    cfg = load_config()
    dets = build_detectors(cfg, None)
    allow = build_allowlist(None)
    samples = [
        ("glpat-abcdefghijklmnopqrst", True),
        ("AKIAIOSFODNN7EXAMPLE", False),
        ("password=hunter2hunter2", True),
        ("password=${DB_PASSWORD}", False),
        ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop", True),
        ("ssh -p 2222 root@host", False),
    ]
    ok = True
    for text, expect in samples:
        got = bool(find_secrets(text, dets, allow))
        ok = ok and (got == expect)
        print("%s  %-60s expected=%s got=%s" % ("ok " if got == expect else "FAIL", text[:60], expect, got))
    print("%d detector(s) loaded, home=%s" % (len(dets), guard_home()))
    return 0 if ok else 1


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "hook"
    args = argv[2:]
    if cmd == "hook":
        return run_hook()
    if cmd == "list":
        return cli_list(args)
    if cmd == "show":
        return cli_show(args)
    if cmd == "scan":
        return cli_scan(args)
    if cmd == "purge":
        return cli_purge(args)
    if cmd == "selftest":
        return cli_selftest()
    if cmd in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    print("unknown command: %s" % cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
