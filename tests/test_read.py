#!/usr/bin/env python3
"""Tests for read-on-read: everything that has been read moves to
bus/read/<reader>/ — results after `wait`, answers after
`fetch-answer`, messages after `inbox`, prompts after `reply`.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_read -v

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


class ReadTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="read-test-"))
        cls.registry_path = cls.tmp / "trusted-keys.json"
        cls.keys_dir = cls.tmp / "keys"
        cls.env = dict(os.environ)
        cls.env.update({
            "AGENC_BRIDGE_KEYS_DIR": str(cls.keys_dir),
            "AGENC_BRIDGE_REGISTRY": str(cls.registry_path),
            "AGENC_BRIDGE_PASSPHRASE": PASSPHRASE,
        })
        for node in ("alice", "bob"):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "keygen", "--node", node],
                           env=cls.env, capture_output=True, check=True)
        for node, role in (("alice", "owner"), ("bob", "worker")):
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

    def _result(self, frm="bob", to="alice"):
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        env = {"v": 2, "id": task_id, "from": frm, "to": to,
               "kind": "result", "created_at": "2026-11-07T00:00:00Z",
               "result": {"status": "ok", "returncode": 0, "stdout": "done",
                          "stderr": "", "started_at": "2026-11-07T00:00:00Z",
                          "finished_at": "2026-11-07T00:00:00Z",
                          "duration_s": 0.1}}
        return task_id, self._signed(env, frm)

    def test_wait_moves_result_to_read(self):
        task_id, signed = self._result()
        # A result is only believable against its task: the task
        # envelope (alice -> bob) must be in done/ for wait to
        # bind the result (bob -> alice) to it.
        task_env = {"v": 2, "id": task_id, "from": "alice", "to": "bob",
                    "kind": "task", "created_at": "2026-11-07T00:00:00Z",
                    "task": {"kind": "prompt", "prompt": "do it",
                             "cwd": ".", "model": "m", "timeout_s": 60,
                             "max_cost_usd": 0.0, "budget": None,
                             "max_calls": None}}
        (self.dirs["done"] / f"{task_id}.json").write_text(
            json.dumps(self._signed(task_env, "alice"), indent=2))
        (self.dirs["results"] / f"{task_id}.json").write_text(
            json.dumps(signed, indent=2))
        out = run_bridge("wait", "--bus", str(self.bus), "--id", task_id,
                         "--timeout-s", "10", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("done", out.stdout)
        self.assertFalse((self.dirs["results"] / f"{task_id}.json").exists())
        self.assertTrue(
            (self.dirs["read"] / "alice" / f"{task_id}.json").exists())

    def test_fetch_answer_moves_answer_to_read(self):
        prompt_id = f"prompt-{uuid.uuid4().hex[:12]}"
        # The prompt (bob -> alice) must be in read/alice/ for
        # fetch-answer to bind the answer (alice -> bob) to it.
        prompt_env = {"v": 2, "id": prompt_id, "from": "bob", "to": "alice",
                      "kind": "prompt", "thread": "",
                      "created_at": "2026-11-07T00:00:00Z",
                      "prompt": {"text": "What is 6 times 7?",
                                 "context": ""}}
        dest = self.dirs["read"] / "alice"
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{prompt_id}.json").write_text(
            json.dumps(self._signed(prompt_env, "bob"), indent=2))
        env = {"v": 2, "id": prompt_id, "from": "alice", "to": "bob",
               "kind": "answer", "created_at": "2026-11-07T00:00:00Z",
               "answer": {"text": "42", "in_reply_to": prompt_id}}
        signed = self._signed(env, "alice")
        (self.dirs["answers"] / f"{prompt_id}.json").write_text(
            json.dumps(signed, indent=2))
        out = run_bridge("fetch-answer", "--bus", str(self.bus),
                         "--id", prompt_id, "--timeout-s", "10",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("42", out.stdout)
        self.assertFalse((self.dirs["answers"] / f"{prompt_id}.json").exists())
        self.assertTrue(
            (self.dirs["read"] / "bob" / f"{prompt_id}.json").exists())

    def test_inbox_moves_messages_to_read(self):
        env = {"v": 2, "id": f"msg-{uuid.uuid4().hex[:12]}",
               "from": "bob", "to": "alice", "kind": "message",
               "created_at": "2026-11-07T00:00:00Z",
               "message": {"text": "hello", "needs_reply": False,
                           "in_reply_to": ""}}
        signed = self._signed(env, "bob")
        dest = self.dirs["messages"] / "alice"
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{signed['id']}.json").write_text(
            json.dumps(signed, indent=2))
        out = run_bridge("inbox", "--bus", str(self.bus), "--node", "alice",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("hello", out.stdout)
        self.assertFalse((dest / f"{signed['id']}.json").exists())
        self.assertTrue(
            (self.dirs["read"] / "alice" / f"{signed['id']}.json").exists())
        # A second look finds nothing — it has been read.
        out = run_bridge("inbox", "--bus", str(self.bus), "--node", "alice",
                         env=self.env)
        self.assertIn("(inbox empty)", out.stdout)

    def test_inbox_keep_leaves_messages(self):
        env = {"v": 2, "id": f"msg-{uuid.uuid4().hex[:12]}",
               "from": "bob", "to": "alice", "kind": "message",
               "created_at": "2026-11-07T00:00:00Z",
               "message": {"text": "keep me", "needs_reply": False,
                           "in_reply_to": ""}}
        signed = self._signed(env, "bob")
        dest = self.dirs["messages"] / "alice"
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{signed['id']}.json").write_text(
            json.dumps(signed, indent=2))
        out = run_bridge("inbox", "--bus", str(self.bus), "--node", "alice",
                         "--keep", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("keep me", out.stdout)
        self.assertTrue((dest / f"{signed['id']}.json").exists())
        self.assertFalse(
            (self.dirs["read"] / "alice" / f"{signed['id']}.json").exists())
    def test_prompt_and_answer_same_reader_both_kept(self):
        # A prompt and its answer share an id. When the asker and
        # the assistant are the same node, both land in the same
        # read/<node>/ folder — the second must not overwrite the
        # first (this bit the live bus: the answers clobbered the
        # questions in the threads demo).
        prompt_id = f"prompt-{uuid.uuid4().hex[:12]}"
        env = {"v": 2, "id": prompt_id, "from": "alice", "to": "alice",
               "kind": "prompt", "thread": "demo",
               "created_at": "2026-11-07T00:00:00Z",
               "prompt": {"text": "What is 6 times 7?", "context": ""}}
        signed = self._signed(env, "alice")
        dest = self.dirs["prompts"] / "alice"
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{prompt_id}.json").write_text(
            json.dumps(signed, indent=2))
        out = run_bridge("reply", "--bus", str(self.bus), "--id",
                         prompt_id, "--from-node", "alice",
                         "--text", "42", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        out = run_bridge("fetch-answer", "--bus", str(self.bus),
                         "--id", prompt_id, "--timeout-s", "10",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("42", out.stdout)
        prompt_path = self.dirs["read"] / "alice" / f"{prompt_id}.json"
        answer_path = (self.dirs["read"] / "alice"
                       / f"{prompt_id}.answer.json")
        self.assertTrue(prompt_path.exists(),
                        "the prompt was overwritten by its answer")
        self.assertTrue(answer_path.exists())
        self.assertIn("What is 6 times 7?",
                      _read_payload(prompt_path, self.registry)
                      ["prompt"]["text"])
        self.assertIn("42",
                      _read_payload(answer_path, self.registry)
                      ["answer"]["text"])


if __name__ == "__main__":
    unittest.main()
