#!/usr/bin/env python3
"""Replay-claim tests — the replay guard in check_envelope was
check-then-mark: two concurrent consumers could both pass
check_envelope for the same envelope before either marked it
seen, so the same task/prompt/message could be acted on twice.

check_envelope now takes claim=True: the replay check and the
mark happen as ONE atomic step, gated by an O_EXCL claim file in
seen/ (the same idiom cmd_reply already used for its reply
claim). Exactly one concurrent caller passes; the rest get
"replayed envelope id". The default (claim=False) stays a pure
check for callers that list or retry — prompts listing and the
registry-update path, whose decrypt-failure retry depends on
the id NOT being claimed by a check that never consumed it.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_replay_claim -v

Isolated keys, registry, and bus; nothing touches the live bus.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import bridge

ROOT = Path(__file__).parent.parent
PASSPHRASE = "test-passphrase-123"


class ReplayClaimTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="replay-claim-test-"))
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
                           ("carol", "worker")):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "trust", "--node", node,
                            "--pubkey", str(cls.keys_dir / f"{node}.pub"),
                            "--role", role],
                           env=cls.env, capture_output=True, check=True)
        cls.registry = json.loads(cls.registry_path.read_text())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        os.environ["AGENC_BRIDGE_KEYS_DIR"] = str(self.keys_dir)
        os.environ["AGENC_BRIDGE_REGISTRY"] = str(self.registry_path)
        os.environ["AGENC_BRIDGE_PASSPHRASE"] = PASSPHRASE
        os.environ["AGENC_BRIDGE_ALLOW_V2"] = "1"
        self.bus = self.tmp / f"bus-{uuid.uuid4().hex[:8]}"
        bridge.bus_dirs(self.bus)

    def tearDown(self):
        os.environ.pop("AGENC_BRIDGE_ALLOW_V2", None)

    def _signed_task(self, to="bob"):
        env = {"v": 2, "id": f"task-{uuid.uuid4().hex[:12]}",
               "from": "alice", "to": to, "kind": "task",
               "created_at": "2026-11-07T00:00:00Z",
               "task": {"kind": "prompt", "prompt": "do it", "cwd": ".",
                        "model": "m", "timeout_s": 60,
                        "max_cost_usd": 0.0, "budget": None,
                        "max_calls": None}}
        path = self.tmp / f"tmp-{env['id']}.json"
        bridge.write_envelope(path, env, "alice")
        signed = json.loads(path.read_text())
        path.unlink()
        return signed

    def test_concurrent_claims_exactly_one_passes(self):
        signed = self._signed_task()
        n = 8
        barrier = threading.Barrier(n)
        results = []
        lock = threading.Lock()

        def worker():
            barrier.wait(timeout=10)
            res = bridge.check_envelope(signed, self.registry,
                                         "bob", self.bus, claim=True)
            with lock:
                results.append(res)

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        oks = [r for r in results if r[0]]
        replays = [r for r in results
                   if not r[0] and "replayed envelope id" in r[1]]
        self.assertEqual(len(results), n)
        self.assertEqual(len(oks), 1,
                         f"exactly one claim may pass, got {results}")
        self.assertEqual(len(replays), n - 1)

    def test_claim_is_recorded_as_seen(self):
        signed = self._signed_task()
        ok, _ = bridge.check_envelope(signed, self.registry,
                                      "bob", self.bus, claim=True)
        self.assertTrue(ok)
        # A later plain check and a later claim both see the replay.
        ok2, reason2 = bridge.check_envelope(signed, self.registry,
                                             "bob", self.bus)
        self.assertFalse(ok2)
        self.assertIn("replayed envelope id", reason2)
        ok3, _ = bridge.check_envelope(signed, self.registry,
                                       "bob", self.bus, claim=True)
        self.assertFalse(ok3)

    def test_default_check_stays_pure(self):
        signed = self._signed_task()
        # Listing-style callers check the same envelope repeatedly;
        # a pure check must not consume it.
        for _ in range(2):
            ok, _ = bridge.check_envelope(signed, self.registry,
                                          "bob", self.bus)
            self.assertTrue(ok)
        bridge.mark_seen(self.bus, signed["id"])
        ok, reason = bridge.check_envelope(signed, self.registry,
                                           "bob", self.bus)
        self.assertFalse(ok)
        self.assertIn("replayed envelope id", reason)

    def test_failed_check_does_not_claim(self):
        # Addressed to carol; checked as bob it fails on the
        # recipient check — that failure must not burn the id, so
        # carol's own claiming check still passes.
        signed = self._signed_task(to="carol")
        ok, reason = bridge.check_envelope(signed, self.registry,
                                           "bob", self.bus, claim=True)
        self.assertFalse(ok)
        self.assertIn("not addressed to", reason)
        ok2, _ = bridge.check_envelope(signed, self.registry,
                                       "carol", self.bus, claim=True)
        self.assertTrue(ok2)


if __name__ == "__main__":
    unittest.main()
