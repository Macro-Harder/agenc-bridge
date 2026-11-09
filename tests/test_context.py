#!/usr/bin/env python3
"""Tests for `bridge.py context`: only the context that matters
for a question — the thread's rules, its distilled facts, the
recent turns, and older turns whose words match the question.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_context -v

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
PASSPHRASE = "test-passphrase-123"


def run_bridge(*argv, env):
    return subprocess.run(
        [sys.executable, str(ROOT / "bridge.py"), *argv],
        env=env, capture_output=True, text=True)


class ContextTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="context-test-"))
        cls.registry_path = cls.tmp / "trusted-keys.json"
        cls.keys_dir = cls.tmp / "keys"
        cls.env = dict(os.environ)
        cls.env.update({
            "AGENC_BRIDGE_KEYS_DIR": str(cls.keys_dir),
            "AGENC_BRIDGE_REGISTRY": str(cls.registry_path),
            "AGENC_BRIDGE_PASSPHRASE": PASSPHRASE,
        })
        for node in ("alice", "carol"):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "keygen", "--node", node],
                           env=cls.env, capture_output=True, check=True)
        for node, role in (("alice", "owner"), ("carol", "asker")):
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
        # Four turns in one thread, plus a fact.
        self._turn("What is the project deadline?", "Friday.",
                   rules="Answer in one sentence.")
        self._turn("What colour should the homepage be?", "Blue.")
        self._turn("What is 6 times 7?", "42.")
        self._turn("What is the capital of France?", "Paris.")
        run_bridge("note", "--bus", str(self.bus), "--thread", "website",
                   "--text", "Deadline is Friday.", env=self.env)

    def _turn(self, question, answer, rules=None):
        argv = ["ask", "--bus", str(self.bus), "--to", "alice",
                "--sender", "carol", "--thread", "website",
                "--prompt", question]
        if rules:
            argv += ["--rules", rules]
        out = run_bridge(*argv, env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        pid = out.stdout.strip()
        out = run_bridge("reply", "--bus", str(self.bus), "--id", pid,
                         "--from-node", "alice", "--text", answer,
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        return pid

    def _context(self, *extra):
        return run_bridge("context", "--bus", str(self.bus),
                          "--thread", "website", *extra, env=self.env)

    def test_context_returns_rules_facts_and_recent(self):
        out = self._context()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("Answer in one sentence.", out.stdout)
        self.assertIn("Deadline is Friday.", out.stdout)
        # Default recent is 3 of 4 turns: the oldest (deadline)
        # is out, the rest are in.
        self.assertNotIn("What is the project deadline?", out.stdout)
        self.assertIn("What colour should the homepage be?", out.stdout)
        self.assertIn("What is 6 times 7?", out.stdout)
        self.assertIn("Paris", out.stdout)
        self.assertNotIn("matching", out.stdout)

    def test_context_matches_older_turns_by_keyword(self):
        out = self._context("--query", "deadline", "--recent", "1")
        self.assertEqual(out.returncode, 0, out.stderr)
        # Recent is only the last turn (Paris); the deadline turn
        # is pulled back in as a match.
        self.assertIn("What is the project deadline?", out.stdout)
        self.assertIn("Friday.", out.stdout)
        self.assertIn("Paris", out.stdout)
        self.assertNotIn("What colour should the homepage be?",
                         out.stdout)
        self.assertNotIn("What is 6 times 7?", out.stdout)

    def test_context_recent_limit(self):
        out = self._context("--recent", "1")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("Paris", out.stdout)
        self.assertNotIn("What is 6 times 7?", out.stdout)
        self.assertNotIn("What colour should the homepage be?",
                         out.stdout)

    def test_context_unknown_thread(self):
        out = run_bridge("context", "--bus", str(self.bus),
                         "--thread", "nope", "--query", "x",
                         env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("no such thread", out.stderr)


if __name__ == "__main__":
    unittest.main()
