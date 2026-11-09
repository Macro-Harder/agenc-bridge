#!/usr/bin/env python3
"""Per-node encryption key tests — every node's private key at
rest (and its provider key) is encrypted with that node's own
encryption key, not one shared passphrase for all nodes.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_per_node_keys -v

Isolated keys, passphrases, registry, and bus; nothing here
touches the live config. The explicit override
AGENC_BRIDGE_PASSPHRASES_DIR is used here to prove it works;
the other suites rely on the default, which derives the
passphrases dir from the isolated keys dir.
"""
import base64
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
PASSPHRASE = "test-passphrase-123"


def run_bridge(*argv, env, inp=None):
    return subprocess.run(
        [sys.executable, str(ROOT / "bridge.py"), *argv],
        env=env, input=inp, capture_output=True, text=True)


class PerNodeKeyTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="pernode-test-"))
        cls.registry_path = cls.tmp / "trusted-keys.json"
        cls.keys_dir = cls.tmp / "keys"
        cls.passphrases_dir = cls.tmp / "passphrases"
        cls.env = dict(os.environ)
        cls.env.update({
            "AGENC_BRIDGE_KEYS_DIR": str(cls.keys_dir),
            "AGENC_BRIDGE_PASSPHRASES_DIR": str(cls.passphrases_dir),
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
        os.environ["AGENC_BRIDGE_PASSPHRASES_DIR"] = str(
            self.passphrases_dir)
        os.environ["AGENC_BRIDGE_REGISTRY"] = str(self.registry_path)
        os.environ["AGENC_BRIDGE_PASSPHRASE"] = PASSPHRASE
        for var in list(os.environ):
            if var.startswith("AGENC_BRIDGE_PASSPHRASE_"):
                del os.environ[var]

    def _legacy_node(self, name):
        """A node made the old way: its key encrypted with the
        shared passphrase, no per-node file. Returns the node name."""
        pem = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519"],
            capture_output=True, check=True).stdout
        pub = subprocess.run(
            ["openssl", "pkey", "-pubout"], input=pem,
            capture_output=True, check=True).stdout
        enc = bridge._openssl_enc(pem, PASSPHRASE)
        (self.keys_dir / f"{name}.pem.enc").write_bytes(enc)
        os.chmod(self.keys_dir / f"{name}.pem.enc", 0o600)
        (self.keys_dir / f"{name}.pub").write_text(pub.decode())
        return name

    def test_two_nodes_have_different_keys(self):
        a = (self.passphrases_dir / "alice").read_text().strip()
        b = (self.passphrases_dir / "bob").read_text().strip()
        self.assertTrue(a and b)
        self.assertNotEqual(a, b,
                            "two nodes share one encryption key")
        self.assertEqual(
            stat.S_IMODE((self.passphrases_dir / "alice").stat().st_mode),
            0o600)
        # Alice's key file does not decrypt with Bob's key.
        data = (self.keys_dir / "alice.pem.enc").read_bytes()
        with self.assertRaises(SystemExit):
            bridge._openssl_enc(data, b, decrypt=True)
        # ... but does with her own.
        pem = bridge._openssl_enc(data, a, decrypt=True)
        self.assertTrue(pem.startswith(b"-----BEGIN PRIVATE KEY-----"))

    def test_per_node_env_var_honoured(self):
        env = dict(self.env)
        env["AGENC_BRIDGE_PASSPHRASE_CAROL"] = "carol-env-key-xyz"
        out = run_bridge("keygen", "--node", "carol", env=env)
        self.assertEqual(out.returncode, 0, out.stderr)
        # Env-managed: no file is written for the key.
        self.assertFalse((self.passphrases_dir / "carol").exists())
        os.environ["AGENC_BRIDGE_PASSPHRASE_CAROL"] = "carol-env-key-xyz"
        try:
            pem = bridge.load_private_key_pem("carol")
            self.assertTrue(pem.startswith(b"-----BEGIN PRIVATE KEY-----"))
        finally:
            del os.environ["AGENC_BRIDGE_PASSPHRASE_CAROL"]
        # Without the env var, the shared passphrase cannot
        # decrypt a key that was encrypted with Carol's own key.
        with self.assertRaises(SystemExit):
            bridge.load_private_key_pem("carol")

    def test_shared_fallback_for_legacy_node(self):
        self._legacy_node("legacy1")
        self.assertEqual(bridge.encryption_key_status("legacy1"), "shared")
        pem = bridge.load_private_key_pem("legacy1")
        self.assertTrue(pem.startswith(b"-----BEGIN PRIVATE KEY-----"))
        self.assertFalse((self.passphrases_dir / "legacy1").exists())

    def test_rekey_migrates_legacy_node(self):
        self._legacy_node("mig1")
        # A provider key stored the old way (shared passphrase).
        out = run_bridge("provider-key", "--node", "mig1",
                         "--from-stdin", env=self.env,
                         inp="sk-test-provider-key-123")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(bridge.load_provider_key("mig1"),
                         "sk-test-provider-key-123")
        out = run_bridge("rekey", "--node", "mig1", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue((self.passphrases_dir / "mig1").exists())
        self.assertEqual(bridge.encryption_key_status("mig1"), "per-node")
        # The node still decrypts — private key and provider key.
        pem = bridge.load_private_key_pem("mig1")
        self.assertTrue(pem.startswith(b"-----BEGIN PRIVATE KEY-----"))
        self.assertEqual(bridge.load_provider_key("mig1"),
                         "sk-test-provider-key-123")
        # ... but the old shared passphrase no longer decrypts it.
        data = (self.keys_dir / "mig1.pem.enc").read_bytes()
        with self.assertRaises(SystemExit):
            bridge._openssl_enc(data, PASSPHRASE, decrypt=True)
        prov = (self.keys_dir / "mig1.provider.enc").read_bytes()
        with self.assertRaises(SystemExit):
            bridge._openssl_enc(prov, PASSPHRASE, decrypt=True)

    def test_rekey_fails_closed_on_wrong_current_key(self):
        # A node whose per-node file holds the wrong key: rekey
        # must refuse and change nothing on disk.
        self._legacy_node("bad1")
        (self.passphrases_dir / "bad1").write_text(
            base64.b64encode(b"0" * 32).decode())
        before = (self.keys_dir / "bad1.pem.enc").read_bytes()
        out = run_bridge("rekey", "--node", "bad1", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        after = (self.keys_dir / "bad1.pem.enc").read_bytes()
        self.assertEqual(before, after, "rekey overwrote an unreadable key")

    def test_rekey_refuses_env_managed_node(self):
        env = dict(self.env)
        env["AGENC_BRIDGE_PASSPHRASE_ENVNODE"] = "envnode-key-xyz"
        out = run_bridge("keygen", "--node", "envnode", env=env)
        self.assertEqual(out.returncode, 0, out.stderr)
        out = run_bridge("rekey", "--node", "envnode", env=env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("AGENC_BRIDGE_PASSPHRASE_ENVNODE", out.stderr)

    def test_keygen_reuses_existing_per_node_key(self):
        before = (self.passphrases_dir / "alice").read_text()
        out = run_bridge("keygen", "--node", "alice", env=self.env)
        self.assertNotEqual(out.returncode, 0)  # key already exists
        self.assertEqual((self.passphrases_dir / "alice").read_text(),
                         before)

    def test_registry_shows_encryption_status(self):
        self._legacy_node("legacy2")
        out = run_bridge("trust", "--node", "legacy2",
                         "--pubkey", str(self.keys_dir / "legacy2.pub"),
                         "--role", "worker", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        out = run_bridge("registry", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("encryption key: per-node", out.stdout)
        self.assertIn("encryption key: shared", out.stdout)


if __name__ == "__main__":
    unittest.main()
