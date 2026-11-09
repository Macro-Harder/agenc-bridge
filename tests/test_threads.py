#!/usr/bin/env python3
"""Tests for bridge threads: one thread per project, each a
recognisable agent with its own rules and history, all served by
the one assistant.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_threads -v

Isolated keys, registry, and bus; nothing here touches the live
bus, registry, or keys.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import bridge

ROOT = Path(__file__).parent.parent

def _read_payload(path, registry):
    """Read a bus envelope file and return its decrypted payload
    envelope (v3 decrypts as its recipient; v2 passes through)."""
    raw = json.loads(Path(path).read_text())
    return bridge.decrypt_envelope(raw, raw.get("to", ""), registry)

PASSPHRASE = "test-passphrase-123"


def run_bridge(*argv, env):
    return subprocess.run(
        [sys.executable, str(ROOT / "bridge.py"), *argv],
        env=env, capture_output=True, text=True)


class ThreadTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="thread-test-"))
        cls.registry_path = cls.tmp / "trusted-keys.json"
        cls.keys_dir = cls.tmp / "keys"
        cls.env = dict(os.environ)
        cls.env.update({
            "AGENC_BRIDGE_KEYS_DIR": str(cls.keys_dir),
            "AGENC_BRIDGE_REGISTRY": str(cls.registry_path),
            "AGENC_BRIDGE_PASSPHRASE": PASSPHRASE,
        })
        for node in ("alice", "bob", "carol"):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "keygen", "--node", node],
                           env=cls.env, capture_output=True, check=True)
        for node, role in (("alice", "owner"), ("bob", "worker"),
                           ("carol", "asker")):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "trust", "--node", node,
                            "--pubkey", str(cls.keys_dir / f"{node}.pub"),
                            "--role", role],
                           env=cls.env, capture_output=True, check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        os.environ["AGENC_BRIDGE_KEYS_DIR"] = str(self.keys_dir)
        os.environ["AGENC_BRIDGE_REGISTRY"] = str(self.registry_path)
        os.environ["AGENC_BRIDGE_PASSPHRASE"] = PASSPHRASE
        self.bus = self.tmp / f"bus-{uuid.uuid4().hex[:8]}"
        self.dirs = bridge.bus_dirs(self.bus)
        self.registry = json.loads(self.registry_path.read_text())

    def _signed(self, env, node):
        path = self.tmp / f"tmp-{env['id']}.json"
        bridge.write_envelope(path, env, node)
        signed = json.loads(path.read_text())
        path.unlink()
        return signed

    def _ask(self, thread, prompt, rules=None, sender="carol"):
        argv = ["ask", "--bus", str(self.bus), "--to", "alice",
                "--sender", sender, "--prompt", prompt]
        if thread:
            argv += ["--thread", thread]
        if rules:
            argv += ["--rules", rules]
        return run_bridge(*argv, env=self.env)

    def test_ask_creates_thread_with_rules(self):
        out = self._ask("website", "What is 6 times 7?",
                        rules="Answer in one word.")
        self.assertEqual(out.returncode, 0, out.stderr)
        pid = out.stdout.strip()
        self.assertTrue(pid.startswith("prompt-"))
        self.assertIn("thread website", out.stderr)
        record = json.loads(
            (self.dirs["threads"] / "website" / "thread.json").read_text())
        self.assertEqual(record["rules"], "Answer in one word.")
        self.assertEqual(record["created_by"], "carol")
        self.assertIn("Answer in one word.",
                      (self.dirs["threads"] / "website"
                       / "rules.md").read_text())
        env = _read_payload(
            self.dirs["prompts"] / "alice" / f"{pid}.json", self.registry)
        self.assertEqual(env["thread"], "website")

    def test_thread_shows_history_and_rules(self):
        out1 = self._ask("website", "What is 6 times 7?",
                         rules="Answer in one word.")
        pid1 = out1.stdout.strip()
        self._ask("website", "And 7 times 8?")
        out = run_bridge("reply", "--bus", str(self.bus), "--id", pid1,
                         "--from-node", "alice", "--text", "42",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        answer = _read_payload(
            self.dirs["answers"] / f"{pid1}.json", self.registry)
        self.assertEqual(answer["thread"], "website")
        out = run_bridge("thread", "--bus", str(self.bus), "--id",
                         "website", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("Answer in one word.", out.stdout)
        self.assertIn("What is 6 times 7?", out.stdout)
        self.assertIn("And 7 times 8?", out.stdout)
        self.assertIn("42", out.stdout)

    def test_threads_do_not_mix(self):
        self._ask("website", "Website question?",
                  rules="Website rules.")
        self._ask("budget", "Budget question?", rules="Budget rules.")
        out = run_bridge("thread", "--bus", str(self.bus), "--id",
                         "website", env=self.env)
        self.assertIn("Website question?", out.stdout)
        self.assertIn("Website rules.", out.stdout)
        self.assertNotIn("Budget question?", out.stdout)
        self.assertNotIn("Budget rules.", out.stdout)
        out = run_bridge("thread", "--bus", str(self.bus), "--id",
                         "budget", env=self.env)
        self.assertIn("Budget question?", out.stdout)
        self.assertNotIn("Website question?", out.stdout)

    def test_ask_without_thread_starts_new_one(self):
        out = self._ask(None, "A one-off question?")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertRegex(out.stderr, r"thread thread-[0-9a-f]{8}")
        name = out.stderr.strip().split()[-1]
        self.assertTrue(
            (self.dirs["threads"] / name / "thread.json").exists())

    def test_history_page_is_the_wiki_index(self):
        # The index lives in the wiki: ask writes the question,
        # reply writes the answer, both verbatim and in order.
        out1 = self._ask("website", "What is 6 times 7?",
                         rules="Answer in one word.")
        pid1 = out1.stdout.strip()
        history = (self.dirs["threads"] / "website" / "history.md")
        self.assertIn("What is 6 times 7?", history.read_text())
        out = run_bridge("reply", "--bus", str(self.bus), "--id", pid1,
                         "--from-node", "alice", "--text", "42",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        text = history.read_text()
        self.assertIn("What is 6 times 7?", text)
        self.assertIn("\n42\n", text)
        # The question comes before its answer (the "42" inside a
        # prompt id or timestamp does not count — match the answer
        # on its own line).
        self.assertLess(text.index("What is 6 times 7?"),
                        text.index("\n42\n"))

    def test_note_records_fact(self):
        self._ask("website", "What is 6 times 7?",
                  rules="Answer in one word.")
        out = run_bridge("note", "--bus", str(self.bus),
                         "--thread", "website",
                         "--text", "Deadline is Friday.",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("Deadline is Friday.",
                      (self.dirs["threads"] / "website"
                       / "facts.md").read_text())
        out = run_bridge("thread", "--bus", str(self.bus), "--id",
                         "website", env=self.env)
        self.assertIn("Deadline is Friday.", out.stdout)

    def test_old_json_record_migrates(self):
        # Threads used to be bus/threads/<name>.json; now they are
        # a directory. The old record migrates on first use, with
        # its history rebuilt once from the bus.
        legacy = {"thread": "legacy", "created_at": "2026-11-07T00:00:00Z",
                  "created_by": "carol", "rules": "Legacy rules.",
                  "updated_at": "2026-11-07T00:00:00Z"}
        (self.dirs["threads"] / "legacy.json").write_text(
            json.dumps(legacy))
        env = {"v": 2, "id": "prompt-legacy1", "from": "carol",
               "to": "alice", "kind": "prompt", "thread": "legacy",
               "created_at": "2026-11-07T00:00:00Z",
               "prompt": {"text": "Old question?", "context": ""}}
        signed = self._signed(env, "carol")
        dest = self.dirs["read"] / "alice"
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "prompt-legacy1.json").write_text(
            json.dumps(signed, indent=2))
        out = run_bridge("thread", "--bus", str(self.bus), "--id",
                         "legacy", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("Legacy rules.", out.stdout)
        self.assertIn("Old question?", out.stdout)
        self.assertFalse((self.dirs["threads"] / "legacy.json").exists())
        self.assertTrue(
            (self.dirs["threads"] / "legacy" / "thread.json").exists())
        self.assertIn("Old question?",
                      (self.dirs["threads"] / "legacy"
                       / "history.md").read_text())

    def test_bad_thread_name_rejected(self):
        out = self._ask("../evil", "Nope?")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("bad thread name", out.stderr)


if __name__ == "__main__":
    unittest.main()
