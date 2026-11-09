#!/usr/bin/env python3
"""Tests for caps through the keys and AgenC (bridge.py).

- Each node can have its own provider key (its own OpenRouter key,
  with its own credit limit set at OpenRouter). The bridge stores
  it encrypted with the bridge passphrase and hands it to the
  agent as OPENROUTER_API_KEY, so the provider — not the bridge —
  enforces the dollar cap.
- AgenC's own per-run bounds (token preset, call cap) travel in
  the task envelope and reach `agenc -p` as --budget /
  --task-max-calls. The bridge keeps no spend ledger of its own.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_caps -v

Isolated keys, registry, and bus; nothing here touches the live
bus, registry, or keys. The provider keys used here are dummy
values, never real credentials.
"""
import json
import os
import shutil
import stat
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
DUMMY_KEY = "sk-or-v1-test-provider-key-for-bob"


def run_bridge(*argv, env):
    return subprocess.run(
        [sys.executable, str(ROOT / "bridge.py"), *argv],
        env=env, capture_output=True, text=True)


class CapsTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="caps-test-"))
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
        # A stub `agenc` on PATH that logs its argv and the provider
        # key it was given, then answers OK. It proves what reached
        # the agent, without running a real model.
        cls.bin_dir = cls.tmp / "bin"
        cls.bin_dir.mkdir()
        cls.log = cls.tmp / "agent-calls.log"
        stub = cls.bin_dir / "agenc"
        stub.write_text(
            "#!/bin/sh\n"
            f"echo \"ARGV: $@\" >> {cls.log}\n"
            "echo \"OPENROUTER_API_KEY=$OPENROUTER_API_KEY\" "
            f">> {cls.log}\n"
            "echo OK\n")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        cls.orig_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{cls.bin_dir}:{cls.orig_path}"
        cls.project_root = cls.tmp / "proj"
        cls.project_root.mkdir()

    @classmethod
    def tearDownClass(cls):
        os.environ["PATH"] = cls.orig_path
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        os.environ["AGENC_BRIDGE_KEYS_DIR"] = str(self.keys_dir)
        os.environ["AGENC_BRIDGE_REGISTRY"] = str(self.registry_path)
        os.environ["AGENC_BRIDGE_PASSPHRASE"] = PASSPHRASE
        self.bus = self.tmp / f"bus-{uuid.uuid4().hex[:8]}"
        self.dirs = bridge.bus_dirs(self.bus)
        self.registry = json.loads(self.registry_path.read_text())
        if self.log.exists():
            self.log.unlink()

    def _store_key(self, node="bob", key=DUMMY_KEY):
        src = self.tmp / f"{node}-key.txt"
        src.write_text(key)
        out = run_bridge("provider-key", "--node", node,
                         "--from-file", str(src), env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out

    def test_provider_key_store_load_and_plaintext_deleted(self):
        self._store_key()
        src = self.tmp / "bob-key.txt"
        self.assertFalse(src.exists(), "plaintext key file must be deleted")
        enc = bridge.keys_dir() / "bob.provider.enc"
        self.assertTrue(enc.is_file())
        self.assertEqual(bridge.load_provider_key("bob"), DUMMY_KEY)
        out = run_bridge("registry", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("bob [worker]", out.stdout)
        self.assertIn("provider key: set", out.stdout)
        self.assertNotIn(DUMMY_KEY, out.stdout)

    def test_provider_key_remove(self):
        self._store_key()
        out = run_bridge("provider-key", "--node", "bob", "--remove",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertFalse((bridge.keys_dir() / "bob.provider.enc").exists())
        self.assertIsNone(bridge.load_provider_key("bob"))

    def test_run_agent_passes_budget_calls_and_key(self):
        result = bridge.run_agent(
            "Reply with exactly the word OK.", self.project_root, 60,
            budget="eco", max_calls=5, provider_key=DUMMY_KEY)
        self.assertEqual(result["status"], "ok")
        lines = self.log.read_text().splitlines()
        self.assertIn("ARGV: -p --no-tui --budget eco "
                      "--task-max-calls 5 "
                      "Reply with exactly the word OK.", lines)
        self.assertIn(f"OPENROUTER_API_KEY={DUMMY_KEY}", lines)

    def test_poll_passes_caps_and_key_to_agenc(self):
        self._store_key()
        out = run_bridge("send", "--bus", str(self.bus), "--to", "bob",
                         "--sender", "alice",
                         "--prompt", "Reply with exactly the word OK.",
                         "--budget", "eco", "--max-calls", "3",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        registry = bridge.load_registry(
            type("A", (), {"registry": str(self.registry_path)})())
        done = bridge.poll_once(self.bus, "bob", self.project_root,
                                registry)
        self.assertIsNotNone(done)
        lines = self.log.read_text().splitlines()
        self.assertTrue(any("--budget eco" in l for l in lines),
                        lines)
        self.assertTrue(any("--task-max-calls 3" in l for l in lines),
                        lines)
        self.assertIn(f"OPENROUTER_API_KEY={DUMMY_KEY}", lines)
        results = list((self.bus / "results").glob("*.json"))
        self.assertEqual(len(results), 1)
        env = _read_payload(results[0], self.registry)
        self.assertEqual(env["result"]["status"], "ok")

    def test_poll_fails_closed_when_key_unreadable(self):
        self._store_key()
        enc = bridge.keys_dir() / "bob.provider.enc"
        enc.write_bytes(b"garbage, not an encrypted key")
        out = run_bridge("send", "--bus", str(self.bus), "--to", "bob",
                         "--sender", "alice",
                         "--prompt", "Reply with exactly the word OK.",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        registry = bridge.load_registry(
            type("A", (), {"registry": str(self.registry_path)})())
        done = bridge.poll_once(self.bus, "bob", self.project_root,
                                registry)
        self.assertIsNotNone(done)
        # The agent never ran: no stub log at all.
        self.assertFalse(self.log.exists())
        results = list((self.bus / "results").glob("*.json"))
        self.assertEqual(len(results), 1)
        env = _read_payload(results[0], registry)
        self.assertEqual(env["result"]["status"], "rejected")
        self.assertIn("provider key unreadable",
                      env["result"]["stderr"])


if __name__ == "__main__":
    unittest.main()
