#!/usr/bin/env python3
"""Rejection tests — when a verification pass fails *after* the
sender was authenticated, the sender gets a rejection back with
the reason, so wait() / fetch-answer() return promptly instead
of timing out. When the signature itself failed, the claimed
sender cannot be trusted, so nothing is sent back — dead/ and
the log only.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_rejection -v

Isolated keys, registry, and bus; nothing here touches the live
bus, registry, or keys. Per-node encryption keys live in the
tmp passphrases dir (derived from the isolated keys dir).
"""
import base64
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
import relay

ROOT = Path(__file__).parent.parent


def _read_payload(path, registry):
    """Read a bus envelope file and return its decrypted payload
    envelope: v3 files decrypt as their recipient (the keys are
    local in these tests), v2 files pass through."""
    raw = json.loads(Path(path).read_text())
    return bridge.decrypt_envelope(raw, raw.get("to", ""), registry)
PASSPHRASE = "test-passphrase-123"


def run_bridge(*argv, env, inp=None):
    return subprocess.run(
        [sys.executable, str(ROOT / "bridge.py"), *argv],
        env=env, input=inp, capture_output=True, text=True)


class RejectionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="rejection-test-"))
        cls.registry_path = cls.tmp / "trusted-keys.json"
        cls.keys_dir = cls.tmp / "keys"
        cls.env = dict(os.environ)
        cls.env.update({
            "AGENC_BRIDGE_KEYS_DIR": str(cls.keys_dir),
            "AGENC_BRIDGE_REGISTRY": str(cls.registry_path),
            "AGENC_BRIDGE_PASSPHRASE": PASSPHRASE,
        })
        for node in ("alice", "bob", "carol", "eve", "mallory", "relay"):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "keygen", "--node", node],
                           env=cls.env, capture_output=True, check=True)
        for node, role in (("alice", "owner"), ("bob", "worker"),
                           ("carol", "worker"), ("eve", "asker"),
                           ("mallory", "slave"), ("relay", "relay")):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "trust", "--node", node,
                            "--pubkey", str(cls.keys_dir / f"{node}.pub"),
                            "--role", role],
                           env=cls.env, capture_output=True, check=True)
        cls.registry = json.loads(cls.registry_path.read_text())
        cls.project_root = cls.tmp / "proj"
        cls.project_root.mkdir()
        cls.stub = cls.tmp / "stub-agent.sh"
        cls.stub.write_text("#!/bin/sh\necho stub-ok\n")
        cls.stub.chmod(0o755)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        os.environ["AGENC_BRIDGE_KEYS_DIR"] = str(self.keys_dir)
        os.environ["AGENC_BRIDGE_REGISTRY"] = str(self.registry_path)
        os.environ["AGENC_BRIDGE_PASSPHRASE"] = PASSPHRASE
        self.bus = self.tmp / f"bus-{uuid.uuid4().hex[:8]}"
        self.dirs = bridge.bus_dirs(self.bus)

    def _signed(self, env, node):
        path = self.tmp / f"tmp-{env['id']}.json"
        bridge.write_envelope(path, env, node)
        signed = json.loads(path.read_text())
        path.unlink()
        return signed

    def _task_env(self, task_id, frm="alice", to="bob"):
        return {"v": 2, "id": task_id, "from": frm, "to": to,
                "kind": "task", "created_at": "2026-11-07T00:00:00Z",
                "task": {"kind": "prompt", "prompt": "do it", "cwd": ".",
                         "model": "m", "timeout_s": 60,
                         "max_cost_usd": 0.0, "budget": None,
                         "max_calls": None}}

    def _prompt_env(self, prompt_id, frm="eve", to="alice"):
        return {"v": 2, "id": prompt_id, "from": frm, "to": to,
                "kind": "prompt", "thread": "",
                "created_at": "2026-11-07T00:00:00Z",
                "prompt": {"text": "What is 6 times 7?", "context": ""}}

    # Worker side: a task that fails a later check gets a rejected
    # result, and wait() returns promptly with the reason.

    def test_task_permission_rejection_via_poll(self):
        # Eve is an asker: she may not send tasks.
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        signed = self._signed(self._task_env(task_id, frm="eve"), "eve")
        (self.dirs["tasks"] / f"{task_id}.json").write_text(
            json.dumps(signed, indent=2))
        done = bridge.poll_once(self.bus, "bob", self.project_root,
                                self.registry, agent_cmd=[str(self.stub)])
        self.assertEqual(done, task_id)
        result = _read_payload(
            self.dirs["results"] / f"{task_id}.json", self.registry)
        self.assertEqual(result["result"]["status"], "rejected")
        self.assertIn("may not send task", result["result"]["stderr"])
        self.assertEqual(result["from"], "bob")
        self.assertTrue((self.dirs["dead"] / f"{task_id}.json").exists())
        out = run_bridge("wait", "--bus", str(self.bus), "--id", task_id,
                         "--timeout-s", "10", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("rejected", out.stdout)
        self.assertIn("may not send task", out.stderr)

    def test_replayed_task_gets_rejection(self):
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        bridge.mark_seen(self.bus, task_id)  # already claimed once
        signed = self._signed(self._task_env(task_id), "alice")
        (self.dirs["tasks"] / f"{task_id}.json").write_text(
            json.dumps(signed, indent=2))
        done = bridge.poll_once(self.bus, "bob", self.project_root,
                                self.registry, agent_cmd=[str(self.stub)])
        self.assertEqual(done, task_id)
        result = _read_payload(
            self.dirs["results"] / f"{task_id}.json", self.registry)
        self.assertEqual(result["result"]["status"], "rejected")
        self.assertIn("replayed", result["result"]["stderr"])
        out = run_bridge("wait", "--bus", str(self.bus), "--id", task_id,
                         "--timeout-s", "10", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("replayed", out.stderr)

    def test_malformed_task_still_rejected(self):
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        task = {"kind": "prompt", "prompt": {"text": "not a string"},
                "cwd": ".", "model": "m", "timeout_s": 60,
                "max_cost_usd": 0.0}
        env = {"v": 2, "id": task_id, "from": "alice", "to": "bob",
               "kind": "task", "created_at": bridge.utcnow(),
               "task": task}
        (self.dirs["tasks"] / f"{task_id}.json").write_text(
            json.dumps(self._signed(env, "alice"), indent=2))
        done = bridge.poll_once(self.bus, "bob", self.project_root,
                                self.registry, agent_cmd=[str(self.stub)])
        self.assertEqual(done, task_id)
        result = _read_payload(
            self.dirs["results"] / f"{task_id}.json", self.registry)
        self.assertEqual(result["result"]["status"], "rejected")
        self.assertIn("malformed task", result["result"]["stderr"])
        self.assertTrue((self.dirs["done"] / f"{task_id}.json").exists())

    def test_rejection_never_overwrites_genuine_result(self):
        # A replayed task must not clobber the real result that is
        # already waiting for the sender.
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        genuine = self._signed(
            {"v": 2, "id": task_id, "from": "bob", "to": "alice",
             "kind": "result", "created_at": "2026-11-07T00:00:00Z",
             "result": {"status": "ok", "returncode": 0,
                        "stdout": "GENUINE", "stderr": "",
                        "started_at": "2026-11-07T00:00:00Z",
                        "finished_at": "2026-11-07T00:00:00Z",
                        "duration_s": 0.1}}, "bob")
        (self.dirs["results"] / f"{task_id}.json").write_text(
            json.dumps(genuine, indent=2))
        bridge.mark_seen(self.bus, task_id)
        signed = self._signed(self._task_env(task_id), "alice")
        (self.dirs["tasks"] / f"{task_id}.json").write_text(
            json.dumps(signed, indent=2))
        bridge.poll_once(self.bus, "bob", self.project_root,
                         self.registry, agent_cmd=[str(self.stub)])
        kept = _read_payload(
            self.dirs["results"] / f"{task_id}.json", self.registry)
        self.assertEqual(kept["result"]["stdout"], "GENUINE")

    # No rejection when the sender cannot be trusted.

    def test_bad_signature_gets_no_rejection_poll(self):
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        signed = self._signed(self._task_env(task_id), "alice")
        # Tamper after signing: flip a byte in the ciphertext
        # (v3: the signature covers header + ciphertext, so this
        # is the tamper-after-signing equivalent of editing the
        # payload — the signature no longer verifies).
        ct = bytearray(base64.b64decode(signed["ciphertext"]))
        ct[0] ^= 1
        signed["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        (self.dirs["tasks"] / f"{task_id}.json").write_text(
            json.dumps(signed, indent=2))
        done = bridge.poll_once(self.bus, "bob", self.project_root,
                                self.registry, agent_cmd=[str(self.stub)])
        self.assertIsNone(done)
        self.assertFalse((self.dirs["results"] / f"{task_id}.json").exists(),
                         "a tampered task got a rejection reply")
        self.assertTrue((self.dirs["dead"] / f"{task_id}.json").exists())

    def test_bad_signature_gets_no_rejection_relay(self):
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        signed = self._signed(self._task_env(task_id), "alice")
        ct = bytearray(base64.b64decode(signed["ciphertext"]))
        ct[0] ^= 1
        signed["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        r = relay.Relay(self.bus, self.registry)
        r.handle_envelope(signed)
        self.assertFalse((self.dirs["results"] / f"{task_id}.json").exists(),
                         "a tampered envelope got a rejection reply")
        self.assertFalse((self.dirs["tasks"] / f"{task_id}.json").exists())

    # Relay side: the relay rejects on the worker's behalf, and
    # the reader accepts a relay rejection — but not a forged one.

    def test_relay_task_rejection_accepted_by_wait(self):
        # Eve (asker) sends a task through the relay: it may not.
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        signed = self._signed(self._task_env(task_id, frm="eve"), "eve")
        r = relay.Relay(self.bus, self.registry)
        r.handle_envelope(signed)
        result = _read_payload(
            self.dirs["results"] / f"{task_id}.json", self.registry)
        self.assertEqual(result["from"], "relay")
        self.assertEqual(result["result"]["status"], "rejected")
        self.assertIn("may not send task", result["result"]["stderr"])
        self.assertTrue((self.dirs["dead"] / f"{task_id}.json").exists())
        out = run_bridge("wait", "--bus", str(self.bus), "--id", task_id,
                         "--timeout-s", "10", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("may not send task", out.stderr)

    def test_relay_unknown_recipient_gets_rejection(self):
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        # No encryption key exists for ghost, so no v3 envelope
        # to it can be built. The case the relay must still
        # catch is a legacy (v2) envelope to an unknown node —
        # build it by hand (sign, don't encrypt) and open the
        # migration window for the relay call.
        env = self._task_env(task_id, to="ghost")
        env["signature"] = bridge.sign(env, "alice")
        os.environ["AGENC_BRIDGE_ALLOW_V2"] = "1"
        try:
            r = relay.Relay(self.bus, self.registry)
            r.handle_envelope(env)
        finally:
            del os.environ["AGENC_BRIDGE_ALLOW_V2"]
        result = _read_payload(
            self.dirs["results"] / f"{task_id}.json", self.registry)
        self.assertEqual(result["from"], "relay")
        self.assertIn("unknown recipient", result["result"]["stderr"])
        out = run_bridge("wait", "--bus", str(self.bus), "--id", task_id,
                         "--timeout-s", "10", env=self.env)
        self.assertNotEqual(out.returncode, 0)

    def test_forged_rejection_refused_by_wait(self):
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        (self.dirs["done"] / f"{task_id}.json").write_text(json.dumps(
            self._signed(self._task_env(task_id), "alice"), indent=2))
        # Carol (another worker) forges a rejected result for
        # bob's task — it must be refused, not shown.
        forged = self._signed(
            {"v": 2, "id": task_id, "from": "carol", "to": "alice",
             "kind": "result", "created_at": "2026-11-07T00:00:00Z",
             "result": {"status": "rejected", "returncode": None,
                        "stdout": "", "stderr": "FORGED-REJECTION",
                        "started_at": "2026-11-07T00:00:00Z",
                        "finished_at": "2026-11-07T00:00:00Z",
                        "duration_s": 0}}, "carol")
        (self.dirs["results"] / f"{task_id}.json").write_text(
            json.dumps(forged, indent=2))
        out = run_bridge("wait", "--bus", str(self.bus), "--id", task_id,
                         "--timeout-s", "10", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertNotIn("FORGED-REJECTION", out.stdout)
        # And a "relay" rejection signed with a non-relay key.
        forged2 = self._signed(
            {"v": 2, "id": task_id, "from": "relay", "to": "alice",
             "kind": "result", "created_at": "2026-11-07T00:00:00Z",
             "result": {"status": "rejected", "returncode": None,
                        "stdout": "", "stderr": "FORGED-RELAY",
                        "started_at": "2026-11-07T00:00:00Z",
                        "finished_at": "2026-11-07T00:00:00Z",
                        "duration_s": 0}}, "carol")
        (self.dirs["results"] / f"{task_id}.json").write_text(
            json.dumps(forged2, indent=2))
        out = run_bridge("wait", "--bus", str(self.bus), "--id", task_id,
                         "--timeout-s", "10", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertNotIn("FORGED-RELAY", out.stdout)

    # Prompts: a rejected prompt surfaces as an error, not an answer.

    def test_prompt_rejection_via_reply(self):
        # Mallory is a slave: she may not ask the assistant.
        # (Workers can ask since 2026-11-07 — a worker prompt is
        # data, not a command — so the no-permission case is now
        # the slave.)
        prompt_id = f"prompt-{uuid.uuid4().hex[:12]}"
        dest = self.dirs["prompts"] / "alice"
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{prompt_id}.json").write_text(json.dumps(
            self._signed(self._prompt_env(prompt_id, frm="mallory"),
                         "mallory"),
            indent=2))
        out = run_bridge("reply", "--bus", str(self.bus), "--id", prompt_id,
                         "--from-node", "alice", "--text", "42",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        answer = _read_payload(
            self.dirs["answers"] / f"{prompt_id}.json", self.registry)
        self.assertTrue(answer["answer"]["rejected"])
        self.assertIn("may not send prompt", answer["answer"]["reason"])
        self.assertTrue((self.dirs["dead"] / f"{prompt_id}.json").exists())
        out = run_bridge("fetch-answer", "--bus", str(self.bus),
                         "--id", prompt_id, "--timeout-s", "10",
                         env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("rejected", out.stderr)

    def test_relay_prompt_rejection_accepted_by_fetch_answer(self):
        # Mallory is a slave: she may not ask the assistant, so
        # the relay rejects her prompt and fetch-answer surfaces
        # the rejection instead of an answer.
        prompt_id = f"prompt-{uuid.uuid4().hex[:12]}"
        signed = self._signed(self._prompt_env(prompt_id, frm="mallory"),
                              "mallory")
        r = relay.Relay(self.bus, self.registry)
        r.handle_envelope(signed)
        answer = _read_payload(
            self.dirs["answers"] / f"{prompt_id}.json", self.registry)
        self.assertEqual(answer["from"], "relay")
        self.assertTrue(answer["answer"]["rejected"])
        out = run_bridge("fetch-answer", "--bus", str(self.bus),
                         "--id", prompt_id, "--timeout-s", "10",
                         env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("may not send prompt", out.stderr)

    # Messages: dead/ + log only, by design — no waiter, and a
    # return message would look like a new message.

    def test_message_rejection_is_dead_only(self):
        # Mallory is a slave: she may not send messages.
        msg_id = f"msg-{uuid.uuid4().hex[:12]}"
        signed = self._signed(
            {"v": 2, "id": msg_id, "from": "mallory", "to": "alice",
             "kind": "message", "created_at": "2026-11-07T00:00:00Z",
             "message": {"text": "hi", "needs_reply": False,
                         "in_reply_to": ""}}, "mallory")
        r = relay.Relay(self.bus, self.registry)
        r.handle_envelope(signed)
        self.assertTrue((self.dirs["dead"] / f"{msg_id}.json").exists())
        self.assertEqual(list(self.dirs["results"].glob("*.json")), [])
        self.assertEqual(list(self.dirs["answers"].glob("*.json")), [])
        self.assertEqual(
            list((self.dirs["messages"] / "alice").glob("*.json")), [])


if __name__ == "__main__":
    unittest.main()
