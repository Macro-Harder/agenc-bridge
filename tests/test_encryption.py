#!/usr/bin/env python3
"""Per-pipe encryption (v3) tests — Phase 1 plus daily rotation
and the key-mismatch system.

An envelope's routing header stays plaintext and signed; its
payload is AEAD-encrypted for the intended recipient only
(X25519 ECDH per sender->recipient pipe, AES-256-GCM). A message
sent to the wrong pipe does not come out as gibberish —
decryption fails closed and nothing comes out at all. The relay
never decrypts. Encryption keys rotate daily (rotate-keys) with
a 48h grace window; after it, the old key is destroyed. When a
message cannot be decrypted, the failure is COMMUNICATED, not
silent: a mismatch rejection names the message id and its
created_at timestamp, both key ids, and how to recover
(resync + rerequest + resend). The MCP routing token is verified
in-process before anything is sent and never travels in an
envelope, so encryption must not break token flow — and the
mismatch system must never log or return a token value.

These tests use isolated keys, passphrases, registry, tokens
file, and bus; nothing here touches the live bus, registry, or
keys. Token values are never printed — a failing assertion must
not leak one.

Run with the system python:
    python3 -m unittest tests.test_encryption -v
"""
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
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


class _MCPClient:
    """One MCP server process over stdio, driven with JSON-RPC."""

    def __init__(self, env, bus, caller, default_token=None):
        self.env = env
        self.bus = bus
        args = [sys.executable, str(ROOT / "bridge-mcp.py"),
                "--node", caller, "--bus", str(bus)]
        if default_token:
            args += ["--token", default_token]
        self.proc = subprocess.Popen(
            args, env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, text=True, bufsize=1)
        self._next_id = 1
        self._send({"jsonrpc": "2.0", "id": self._next_id,
                    "method": "initialize", "params": {}})
        self._next_id += 1
        self._read()  # initialize result
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def _read(self):
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("MCP server closed the connection")
        return json.loads(line)

    def call(self, tool, arguments):
        rid = self._next_id
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                    "params": {"name": tool, "arguments": arguments}})
        return self._read()

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.stdout.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


class _Responder(threading.Thread):
    """Answers prompts for target nodes, as those nodes."""

    def __init__(self, env, bus, targets):
        super().__init__(daemon=True)
        self.env = env
        self.bus = bus
        self.targets = targets
        self.stop_event = threading.Event()
        self.answered = set()

    def run(self):
        while not self.stop_event.is_set():
            for target in self.targets:
                d = self.bus / "prompts" / target
                if not d.exists():
                    continue
                for path in sorted(d.glob("*.json")):
                    pid = path.stem
                    if pid in self.answered:
                        continue
                    self.answered.add(pid)
                    run_bridge("reply", "--bus", str(self.bus),
                               "--id", pid, "--from-node", target,
                               "--text", f"answer from {target}",
                               env=self.env)
            time.sleep(0.2)


class EncryptionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="enc-test-"))
        cls.registry_path = cls.tmp / "trusted-keys.json"
        cls.keys_dir = cls.tmp / "keys"
        cls.passphrases_dir = cls.tmp / "passphrases"
        cls.tokens_path = cls.tmp / "mcp-tokens.json"
        cls.env = dict(os.environ)
        cls.env.update({
            "AGENC_BRIDGE_KEYS_DIR": str(cls.keys_dir),
            "AGENC_BRIDGE_PASSPHRASES_DIR": str(cls.passphrases_dir),
            "AGENC_BRIDGE_REGISTRY": str(cls.registry_path),
            "AGENC_BRIDGE_MCP_TOKENS": str(cls.tokens_path),
            "AGENC_BRIDGE_PASSPHRASE": PASSPHRASE,
        })
        # alice: owner. bob: worker. carol: asker. t1: asker target.
        # relay: relay. Every node gets an encryption keypair at
        # keygen; trust publishes it (attestation verified).
        for node in ("alice", "bob", "carol", "t1", "relay"):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "keygen", "--node", node],
                           env=cls.env, capture_output=True, check=True)
        for node, role in (("alice", "owner"), ("bob", "worker"),
                           ("carol", "asker"), ("t1", "asker"),
                           ("relay", "relay")):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "trust", "--node", node,
                            "--pubkey", str(cls.keys_dir / f"{node}.pub"),
                            "--role", role],
                           env=cls.env, capture_output=True, check=True)
        cls.registry = json.loads(cls.registry_path.read_text())
        for node in ("alice", "bob", "carol", "t1", "relay"):
            assert cls.registry["nodes"][node].get("enc_public_key"), node
        # A project root for poll (must be a git repo with a commit).
        cls.project = cls.tmp / "proj"
        cls.project.mkdir()
        subprocess.run(["git", "init", "-q", str(cls.project)],
                       check=True)
        subprocess.run(["git", "-C", str(cls.project), "config",
                        "user.email", "t@t"], check=True)
        subprocess.run(["git", "-C", str(cls.project), "config",
                        "user.name", "t"], check=True)
        (cls.project / "x").write_text("")
        subprocess.run(["git", "-C", str(cls.project), "add", "x"],
                       check=True)
        subprocess.run(["git", "-C", str(cls.project),
                        "-c", "commit.gpgsign=false", "commit", "-qm",
                        "init"], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        for key in ("AGENC_BRIDGE_KEYS_DIR", "AGENC_BRIDGE_PASSPHRASES_DIR",
                    "AGENC_BRIDGE_REGISTRY", "AGENC_BRIDGE_MCP_TOKENS",
                    "AGENC_BRIDGE_PASSPHRASE"):
            os.environ[key] = self.env[key]
        os.environ.pop("AGENC_BRIDGE_ALLOW_V2", None)
        self.bus = self.tmp / f"bus-{uuid.uuid4().hex[:8]}"
        self.dirs = bridge.bus_dirs(self.bus)
        self.env["AGENC_BRIDGE_BUS"] = str(self.bus)
        os.environ["AGENC_BRIDGE_BUS"] = str(self.bus)
        self.registry = json.loads(self.registry_path.read_text())

    # --- helpers ---

    def _send_task(self, sender="alice", to="bob", prompt="hello"):
        out = run_bridge("send", "--bus", str(self.bus), "--to", to,
                         "--prompt", prompt, "--sender", sender,
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout.strip()

    def _poll_once(self, node="bob"):
        out = run_bridge("poll", "--bus", str(self.bus), "--node", node,
                         "--project-root", str(self.project),
                         "--agent-cmd", "echo", env=self.env)
        return out

    def _read_env(self, path):
        return json.loads(Path(path).read_text())

    def _registry(self):
        return json.loads(self.registry_path.read_text())

    def _expire_and_prune(self, node):
        """Push a node's retired keys past their grace window and
        prune them (the daily rotation's cleanup step). Returns
        the retired key ids that were destroyed."""
        reg = self._registry()
        entry = reg["nodes"][node]
        retired = [p["key_id"] for p in entry.get("enc_prev_keys", [])]
        for prev in entry.get("enc_prev_keys", []):
            prev["valid_until"] = "2020-01-01T00:00:00Z"
        self.registry_path.write_text(json.dumps(reg, indent=2))
        recs = bridge._read_enc_retired(node)
        for rec in recs:
            rec["valid_until"] = "2020-01-01T00:00:00Z"
        bridge._write_enc_retired(node, recs)
        out = run_bridge("rotate-keys", "--node", node, env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        return retired

    def _make_stale_mismatch(self):
        """Build a stale-key mismatch and return (task_id,
        created_at, used_key_id, stale_registry_path).
        bob rotates (K1 -> K2) and K1 is pruned; alice sends using
        a stale registry copy that still lists K1 as bob's key."""
        stale_path = self.tmp / f"stale-{uuid.uuid4().hex[:8]}.json"
        stale_path.write_text(self.registry_path.read_text())
        stale = json.loads(stale_path.read_text())
        used_key_id = stale["nodes"]["bob"]["enc_key_id"]
        out = run_bridge("rotate-keys", "--node", "bob", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self._expire_and_prune("bob")
        stale_env = dict(self.env)
        stale_env["AGENC_BRIDGE_REGISTRY"] = str(stale_path)
        out = run_bridge("send", "--bus", str(self.bus), "--to", "bob",
                         "--prompt", "stale pipe", "--sender", "alice",
                         env=stale_env)
        self.assertEqual(out.returncode, 0, out.stderr)
        task_id = out.stdout.strip()
        raw = self._read_env(self.dirs["tasks"] / f"{task_id}.json")
        self.assertEqual(raw["enc"]["to_key_id"], used_key_id)
        out = self._poll_once("bob")
        self.assertIn("key mismatch", out.stderr)
        return task_id, raw["created_at"], used_key_id, stale_path

    # --- v3 envelopes ---

    def test_v3_envelope_is_ciphertext_on_disk(self):
        task_id = self._send_task(prompt="top secret prompt")
        raw = self._read_env(self.dirs["tasks"] / f"{task_id}.json")
        self.assertEqual(raw["v"], 3)
        self.assertIn("ciphertext", raw)
        self.assertIn("enc", raw)
        self.assertEqual(raw["enc"]["alg"], "X25519+AES-256-GCM")
        self.assertNotIn("task", raw)
        self.assertNotIn("top secret prompt",
                         Path(self.dirs["tasks"] / f"{task_id}.json")
                         .read_text())
        plain = bridge.decrypt_envelope(raw, "bob", self.registry)
        self.assertEqual(plain["task"]["prompt"], "top secret prompt")
        self.assertEqual(plain["from"], "alice")
        self.assertEqual(plain["to"], "bob")

    def test_wrong_recipient_cannot_decrypt(self):
        task_id = self._send_task()
        raw = self._read_env(self.dirs["tasks"] / f"{task_id}.json")
        with self.assertRaises(bridge.DecryptError):
            bridge.decrypt_envelope(raw, "carol", self.registry)
        # The sender can re-read its own mail (for resend).
        plain = bridge.decrypt_envelope(raw, "alice", self.registry)
        self.assertEqual(plain["task"]["prompt"], "hello")

    def test_tampered_ciphertext_refused(self):
        task_id = self._send_task(prompt="untouchable")
        raw = self._read_env(self.dirs["tasks"] / f"{task_id}.json")
        # Tamper the ciphertext, then re-sign so the signature is
        # valid — the AEAD tag must still refuse it.
        bad = dict(raw)
        ct = bytearray(base64.b64decode(bad["ciphertext"]))
        ct[0] ^= 1
        bad["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        bad.pop("signature", None)
        bad["signature"] = bridge.sign(bad, "alice")
        (self.dirs["tasks"] / f"{task_id}.json").write_text(
            json.dumps(bad, indent=2))
        out = self._poll_once("bob")
        self.assertIn("key mismatch", out.stderr)
        result_path = self.dirs["results"] / f"{task_id}.json"
        self.assertTrue(result_path.exists(),
                        "a tampered task gets a rejection, not silence")
        result = bridge.decrypt_envelope(
            self._read_env(result_path), "alice", self._registry())
        self.assertEqual(result["result"]["status"], "rejected")
        self.assertIn("key mismatch", result["result"]["stderr"])
        self.assertIn(task_id, result["result"]["stderr"])

    def test_relay_cannot_read_content(self):
        task_id = self._send_task(prompt="relay must not read this")
        raw = self._read_env(self.dirs["tasks"] / f"{task_id}.json")
        # The relay's own checks pass (signature + version) without
        # decryption — that is all it needs to route.
        self.assertTrue(bridge.verify_basic(raw, self.registry)[0])
        # But the relay cannot decrypt: the envelope is not
        # addressed to it, and it holds no key for this pipe.
        with self.assertRaises(bridge.DecryptError):
            bridge.decrypt_envelope(raw, "relay", self.registry)
        self.assertNotIn("relay must not read this",
                         json.dumps(raw))

    # --- rotation ---

    def test_rotation_keeps_inflight_mail_readable(self):
        task1 = self._send_task(prompt="before rotation")
        old_key = self.registry["nodes"]["bob"]["enc_key_id"]
        out = run_bridge("rotate-keys", "--node", "bob", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f"{old_key} ->", out.stdout)
        reg = self._registry()
        self.assertNotEqual(reg["nodes"]["bob"]["enc_key_id"], old_key)
        self.assertTrue(any(
            p["key_id"] == old_key
            for p in reg["nodes"]["bob"].get("enc_prev_keys", [])),
            "old public key stays in the registry for the grace window")
        # In-flight mail (encrypted under the old key) still reads.
        out = self._poll_once("bob")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f"done {task1}: ok", out.stdout)
        # New mail encrypts under the new key and reads.
        task2 = self._send_task(prompt="after rotation")
        raw2 = self._read_env(self.dirs["tasks"] / f"{task2}.json")
        self.assertEqual(raw2["enc"]["to_key_id"],
                         reg["nodes"]["bob"]["enc_key_id"])
        out = self._poll_once("bob")
        self.assertIn(f"done {task2}: ok", out.stdout)

    def test_rotation_destroys_old_key_after_grace(self):
        task1 = self._send_task(prompt="doomed mail")
        old_key = self.registry["nodes"]["bob"]["enc_key_id"]
        out = run_bridge("rotate-keys", "--node", "bob", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        pruned = self._expire_and_prune("bob")
        self.assertIn(old_key, pruned)
        reg = self._registry()
        self.assertFalse(any(
            p["key_id"] == old_key
            for p in reg["nodes"]["bob"].get("enc_prev_keys", [])))
        self.assertFalse(
            (self.keys_dir / f"bob.x25519.{old_key}.enc").exists(),
            "old private key file is destroyed")
        raw = self._read_env(self.dirs["tasks"] / f"{task1}.json")
        with self.assertRaises(bridge.DecryptError) as ctx:
            bridge.decrypt_envelope(raw, "bob", reg)
        self.assertEqual(ctx.exception.used_to_key_id, old_key)

    def test_rotate_keys_dry_run_changes_nothing(self):
        before_reg = self.registry_path.read_bytes()
        before_keys = sorted(p.name for p in self.keys_dir.iterdir())
        out = run_bridge("rotate-keys", "--dry-run", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("would rotate", out.stdout)
        self.assertEqual(self.registry_path.read_bytes(), before_reg)
        self.assertEqual(sorted(p.name for p in self.keys_dir.iterdir()),
                         before_keys)

    def test_rekey_reencrypts_enc_keys(self):
        before = (self.keys_dir / "bob.x25519.enc").read_bytes()
        key_id_before = self.registry["nodes"]["bob"]["enc_key_id"]
        out = run_bridge("rekey", "--node", "bob", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        # Same keypair (same public key id), re-encrypted under the
        # new per-node passphrase.
        self.assertEqual(self._registry()["nodes"]["bob"]["enc_key_id"],
                         key_id_before)
        self.assertNotEqual((self.keys_dir / "bob.x25519.enc").read_bytes(),
                            before)
        task_id = self._send_task(prompt="after rekey")
        out = self._poll_once("bob")
        self.assertIn(f"done {task_id}: ok", out.stdout)

    # --- mismatch communication ---

    def test_stale_key_mismatch_rejection(self):
        task_id, created_at, used_key_id, _ = self._make_stale_mismatch()
        # The rejection is a result, not silence: wait() returns
        # promptly with the mismatch report.
        out = run_bridge("wait", "--bus", str(self.bus), "--id", task_id,
                         "--timeout-s", "30", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("key mismatch", out.stderr)
        self.assertIn(task_id, out.stderr)
        self.assertIn(created_at, out.stderr)
        self.assertIn(used_key_id, out.stderr)
        # The mismatch is logged with id + timestamp + keys.
        recs = bridge.read_mismatches(self.bus)
        self.assertEqual(len(recs), 1)
        rec = recs[0]
        self.assertEqual(rec["id"], task_id)
        self.assertEqual(rec["created_at"], created_at)
        self.assertEqual(rec["from"], "alice")
        self.assertEqual(rec["to"], "bob")
        self.assertEqual(rec["kind"], "task")
        self.assertEqual(rec["used_to_key_id"], used_key_id)
        # And visible in status.
        out = run_bridge("status", "--bus", str(self.bus), "--node",
                         "alice", "--tcp-port", "18999", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("key mismatches: 1", out.stdout)
        self.assertIn(task_id, out.stdout)
        # The original is in dead/ with the mismatch reason.
        out = run_bridge("dead", "--bus", str(self.bus), env=self.env)
        self.assertIn(task_id, out.stdout)
        self.assertIn("key mismatch", out.stdout)

    def test_rerequest_and_resend(self):
        task_id, created_at, _used, _stale = self._make_stale_mismatch()
        # The node that missed the message asks for a re-send.
        out = run_bridge("rerequest", "--bus", str(self.bus),
                         "--id", task_id, "--to", "alice",
                         "--sender", "bob", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        msg_id = out.stdout.strip()
        out = run_bridge("inbox", "--bus", str(self.bus), "--node",
                         "alice", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(task_id, out.stdout)
        self.assertIn(created_at, out.stdout)
        self.assertIn("resend", out.stdout)
        # The sender re-sends the original, re-encrypted under the
        # current key. (The original is decrypted from the
        # sender's copy, whose header carries the keys it used.)
        out = run_bridge("resend", "--bus", str(self.bus), "--id",
                         task_id, "--sender", "alice", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        new_id = out.stdout.strip()
        self.assertNotEqual(new_id, task_id)
        raw = self._read_env(self.dirs["tasks"] / f"{new_id}.json")
        self.assertEqual(raw["v"], 3)
        plain = bridge.decrypt_envelope(raw, "bob", self._registry())
        self.assertEqual(plain["task"]["prompt"], "stale pipe")
        self.assertEqual(plain["resend_of"], task_id)
        self.assertEqual(plain["resend_of_created_at"], created_at)
        # And the re-sent message arrives and runs.
        out = self._poll_once("bob")
        self.assertIn(f"done {new_id}: ok", out.stdout)
        out = run_bridge("wait", "--bus", str(self.bus), "--id", new_id,
                         "--timeout-s", "30", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_resend_refuses_other_senders(self):
        task_id = self._send_task(prompt="not yours")
        out = run_bridge("resend", "--bus", str(self.bus), "--id",
                         task_id, "--sender", "bob", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("only the original sender", out.stderr)

    def test_rerequest_needs_a_mismatch(self):
        out = run_bridge("rerequest", "--bus", str(self.bus),
                         "--id", "task-20261107-000000-deadbe",
                         "--to", "alice", "--sender", "bob", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("no mismatch recorded", out.stderr)

    # --- v2 migration ---

    def _make_legacy_node(self, name="dave"):
        """A node with a signing key only — no encryption keypair,
        like a node created before per-pipe encryption."""
        pem = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519"],
            capture_output=True, check=True).stdout
        pub = subprocess.run(
            ["openssl", "pkey", "-pubout"], input=pem,
            capture_output=True, check=True).stdout
        (self.keys_dir / f"{name}.pub").write_bytes(pub)
        (self.keys_dir / f"{name}.pem.enc").write_bytes(
            bridge._openssl_enc(pem, PASSPHRASE))
        os.chmod(self.keys_dir / f"{name}.pem.enc", 0o600)
        out = run_bridge("trust", "--node", name,
                         "--pubkey", str(self.keys_dir / f"{name}.pub"),
                         "--role", "worker", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIsNone(self._registry()["nodes"][name].get(
            "enc_public_key"))

    def test_v2_rejected_by_default(self):
        # A v2 envelope with a valid signature, to an encrypted node.
        env = {"v": 2, "id": f"task-{uuid.uuid4().hex[:12]}",
               "from": "alice", "to": "bob", "kind": "task",
               "created_at": "2026-11-07T00:00:00Z",
               "task": {"kind": "prompt", "prompt": "old world",
                        "cwd": ".", "model": "test", "timeout_s": 60,
                        "max_cost_usd": 0.0}}
        # Build the v2 file by hand: sign the v2 dict directly
        # (write_envelope would encrypt it, since bob holds a key).
        sig = bridge.sign(env, "alice")
        v2 = {"signature": sig}
        v2.update(env)
        (self.dirs["tasks"] / f"{env['id']}.json").write_text(
            json.dumps(v2, indent=2))
        ok, reason = bridge.verify_basic(v2, self.registry)
        self.assertFalse(ok)
        self.assertIn("unsupported envelope version: 2", reason)
        out = self._poll_once("bob")
        self.assertFalse((self.dirs["results"] / f"{env['id']}.json")
                         .exists(), "a v2 envelope gets no rejection")
        self.assertTrue((self.dirs["dead"] / f"{env['id']}.json").exists())

    def test_v2_migration_window(self):
        self._make_legacy_node("dave")
        env_v2 = dict(self.env)
        env_v2["AGENC_BRIDGE_ALLOW_V2"] = "1"
        # Legacy recipient (no encryption key): v2 is accepted.
        out = run_bridge("send", "--bus", str(self.bus), "--to", "dave",
                         "--prompt", "legacy mail", "--sender", "alice",
                         env=env_v2)
        self.assertEqual(out.returncode, 0, out.stderr)
        task_id = out.stdout.strip()
        raw = self._read_env(self.dirs["tasks"] / f"{task_id}.json")
        self.assertEqual(raw["v"], 2)
        self.assertIn("task", raw)
        out = run_bridge("poll", "--bus", str(self.bus), "--node", "dave",
                         "--project-root", str(self.project),
                         "--agent-cmd", "echo", env=env_v2)
        self.assertIn(f"done {task_id}: ok", out.stdout)
        # Encrypted recipient: v2 is still a downgrade, even in
        # the window.
        env = {"v": 2, "id": f"task-{uuid.uuid4().hex[:12]}",
               "from": "alice", "to": "bob", "kind": "task",
               "created_at": "2026-11-07T00:00:00Z",
               "task": {"kind": "prompt", "prompt": "downgrade me",
                        "cwd": ".", "model": "test", "timeout_s": 60,
                        "max_cost_usd": 0.0}}
        sig = bridge.sign(env, "alice")
        v2 = {"signature": sig}
        v2.update(env)
        # The in-process check reads the flag from os.environ
        # (the subprocess env above does not reach it).
        os.environ["AGENC_BRIDGE_ALLOW_V2"] = "1"
        try:
            ok, reason = bridge.verify_basic(v2, self.registry)
        finally:
            os.environ.pop("AGENC_BRIDGE_ALLOW_V2", None)
        self.assertFalse(ok)
        self.assertIn("downgrade", reason)

    def test_broadcast_refused_when_v2_rejected(self):
        out = run_bridge("send", "--bus", str(self.bus), "--to", "*",
                         "--prompt", "anyone", "--sender", "alice",
                         env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("cannot send to '*'", out.stderr)
        env_v2 = dict(self.env)
        env_v2["AGENC_BRIDGE_ALLOW_V2"] = "1"
        out = run_bridge("send", "--bus", str(self.bus), "--to", "*",
                         "--prompt", "anyone", "--sender", "alice",
                         env=env_v2)
        self.assertEqual(out.returncode, 0, out.stderr)
        task_id = out.stdout.strip()
        raw = self._read_env(self.dirs["tasks"] / f"{task_id}.json")
        self.assertEqual(raw["v"], 2)

    # --- keys, publish, resync ---

    def test_keys_command(self):
        out = run_bridge("keys", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        for node in ("alice", "bob", "carol"):
            self.assertIn(node, out.stdout)
            self.assertIn(self.registry["nodes"][node]["enc_key_id"],
                          out.stdout)
        self.assertIn("attestation ok", out.stdout)
        old_key = self.registry["nodes"]["bob"]["enc_key_id"]
        out = run_bridge("rotate-keys", "--node", "bob", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        out = run_bridge("keys", "--node", "bob", env=self.env)
        self.assertNotIn(old_key, out.stdout.split("retired")[0])
        self.assertIn(f"retired {old_key} until", out.stdout)

    def test_publish_enc_key(self):
        reg = self._registry()
        key_id = reg["nodes"]["bob"]["enc_key_id"]
        for f in ("enc_public_key", "enc_key_id", "enc_rotated_at",
                  "enc_attestation"):
            reg["nodes"]["bob"].pop(f, None)
        self.registry_path.write_text(json.dumps(reg, indent=2))
        out = run_bridge("publish-enc-key", "--node", "bob", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(key_id, out.stdout)
        self.assertEqual(self._registry()["nodes"]["bob"]["enc_key_id"],
                         key_id)

    def test_resync_refuses_tampered_registry(self):
        good = self.tmp / "good.json"
        good.write_text(self.registry_path.read_text())
        tampered = json.loads(good.read_text())
        # Substitute alice's encryption key: the attestation no
        # longer matches, so resync must refuse the whole copy.
        other = base64.b64encode(bytes(range(32))).decode()
        tampered["nodes"]["alice"]["enc_public_key"] = other
        bad_path = self.tmp / "bad.json"
        bad_path.write_text(json.dumps(tampered, indent=2))
        before = self.registry_path.read_bytes()
        out = run_bridge("resync", "--registry", str(bad_path),
                         env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("attestation", out.stderr)
        self.assertEqual(self.registry_path.read_bytes(), before)
        out = run_bridge("resync", "--registry", str(good),
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("resynced registry", out.stdout)

    # --- MCP token + encryption ---

    def test_token_routed_mcp_ask_through_encryption(self):
        out = run_bridge("mcp-token", "--from", "carol", "--to", "t1",
                         "--approve-by", "alice", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        token = out.stdout.strip()
        self.assertTrue(token.startswith("mcp-"))
        responder = _Responder(self.env, self.bus, ["t1"])
        responder.start()
        try:
            client = _MCPClient(self.env, self.bus, "carol",
                                default_token=token)
            try:
                res = client.call("ask_muse", {
                    "token": token, "to": "t1",
                    "prompt": "What is 6 times 7?"})
            finally:
                client.close()
        finally:
            responder.stop_event.set()
            responder.join(timeout=5)
        self.assertNotIn("error", res, res)
        text = res["result"]["content"][0]["text"]
        self.assertEqual(text, "answer from t1")
        # The prompt and answer on disk are v3 ciphertext: the
        # question text and the token appear nowhere in the bus.
        bus_text = ""
        for path in self.bus.rglob("*.json"):
            bus_text += path.read_text()
        self.assertIn('"v": 3', bus_text)
        self.assertNotIn("What is 6 times 7?", bus_text)
        self.assertNotIn(token, bus_text)

    def test_mismatch_never_logs_token(self):
        out = run_bridge("mcp-token", "--from", "carol", "--to", "t1",
                         "--approve-by", "alice", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        token = out.stdout.strip()
        task_id, _created, _used, _stale = self._make_stale_mismatch()
        out = run_bridge("wait", "--bus", str(self.bus), "--id", task_id,
                         "--timeout-s", "30", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertNotIn(token, out.stderr)
        self.assertNotIn(token, (self.bus / "mismatch.jsonl").read_text())
        out = run_bridge("status", "--bus", str(self.bus), "--node",
                         "alice", "--tcp-port", "18999", env=self.env)
        self.assertNotIn(token, out.stdout)
        for path in (self.bus / "dead").glob("*.json"):
            self.assertNotIn(token, path.read_text())


if __name__ == "__main__":
    unittest.main()
