#!/usr/bin/env python3
"""Red-team tests for the AgenC Bridge — attacks that must fail.

Each test is an attack (or a break-it attempt) against the bridge,
written so it PASSES only when the bridge holds. If one of these
fails, the attack worked and the bridge needs a fix.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_redteam -v

Isolated keys, registry, and bus; nothing here touches the live
bus, registry, or keys. The "attacker" is bob, a trusted worker
node — the point is that a trusted-but-malicious (or compromised)
node must not be able to escape its role, write outside the bus,
or exhaust the relay.
"""
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import bridge
import link
import relay

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


class RedTeamTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="redteam-test-"))
        cls.registry_path = cls.tmp / "trusted-keys.json"
        cls.keys_dir = cls.tmp / "keys"
        cls.env = dict(os.environ)
        cls.env.update({
            "AGENC_BRIDGE_KEYS_DIR": str(cls.keys_dir),
            "AGENC_BRIDGE_REGISTRY": str(cls.registry_path),
            "AGENC_BRIDGE_PASSPHRASE": PASSPHRASE,
        })
        for node in ("alice", "bob", "relay"):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "keygen", "--node", node],
                           env=cls.env, capture_output=True, check=True)
        for node, role in (("alice", "owner"), ("bob", "worker"),
                           ("relay", "relay")):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "trust", "--node", node,
                            "--pubkey", str(cls.keys_dir / f"{node}.pub"),
                            "--role", role],
                           env=cls.env, capture_output=True, check=True)
        cls.registry = json.loads(cls.registry_path.read_text())
        cls.bus = cls.tmp / "bus"
        cls.project_root = cls.tmp / "proj"
        cls.project_root.mkdir()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        os.environ["AGENC_BRIDGE_KEYS_DIR"] = str(self.keys_dir)
        os.environ["AGENC_BRIDGE_REGISTRY"] = str(self.registry_path)
        os.environ["AGENC_BRIDGE_PASSPHRASE"] = PASSPHRASE
        # A fresh bus per test, so one test's files can't leak into
        # another's assertions about what was (not) written.
        self.bus = self.tmp / f"bus-{uuid.uuid4().hex[:8]}"
        bridge.bus_dirs(self.bus)

    def _signed(self, **overrides):
        """A validly-signed envelope from bob (worker), with the
        given fields overridden — the attacker controls the content,
        not the key. Written through write_envelope, so it is a
        genuine v3 envelope (payload encrypted for alice); the tmp
        file name is fixed, never the envelope id, so a traversal
        id in an override cannot escape the tmp dir."""
        env = {
            "v": bridge.VERSION,
            "id": f"task-{uuid.uuid4().hex[:6]}",
            "from": "bob", "to": "alice", "kind": "task",
            "created_at": bridge.utcnow(),
            "task": {"kind": "prompt", "prompt": "hi", "cwd": ".",
                     "model": bridge.DEFAULT_MODEL, "timeout_s": 60,
                     "max_cost_usd": 0.0},
        }
        env.update(overrides)
        path = self.tmp / "tmp-signed.json"
        bridge.write_envelope(path, env, "bob")
        signed = json.loads(path.read_text())
        path.unlink()
        return signed

    def test_id_path_traversal_rejected(self):
        # bob signs a task whose id walks out of the bus. The relay
        # writes envelopes to <dir>/<id>.json — a "../" id must never
        # reach the filesystem.
        env = self._signed(id="../../evil")
        ok, reason = bridge.verify_basic(env, self.registry)
        self.assertFalse(ok, "envelope with a traversal id verified")
        r = relay.Relay(self.bus, self.registry)
        r.handle_envelope(env)
        self.assertFalse((self.tmp / "evil.json").exists())
        self.assertFalse((self.bus / "evil.json").exists())
        self.assertEqual(list(self.bus.rglob("evil*")), [])

    def test_to_path_traversal_rejected(self):
        # A prompt's destination dir is bus/prompts/<to>/ — a "../"
        # recipient must never reach the filesystem either. Build
        # the prompt envelope fully, THEN sign it, so the signature
        # is valid and only the traversal can fail it.
        env = {
            "v": bridge.VERSION,
            "id": "prompt-abc123",
            "from": "bob", "to": "../../evil", "kind": "prompt",
            "created_at": bridge.utcnow(),
            "prompt": "hi",
        }
        env["signature"] = bridge.sign(env, "bob")
        ok, reason = bridge.verify_basic(env, self.registry)
        self.assertFalse(ok, "envelope with a traversal recipient verified")
        r = relay.Relay(self.bus, self.registry)
        r.handle_envelope(env)
        self.assertFalse((self.bus / "evil").exists())
        self.assertEqual(list(self.bus.rglob("evil*")), [])

    def test_node_name_path_traversal_rejected(self):
        # A node name becomes a file name (keys/<node>.pem.enc,
        # keys/<node>.pub). A "../" name must be refused at keygen.
        out = run_bridge("keygen", "--node", "../evil", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertFalse((self.keys_dir.parent / "evil.pem.enc").exists())
        self.assertFalse((self.tmp / "evil.pem.enc").exists())

    def test_cwd_escape_rejected(self):
        # A task whose cwd escapes the project root must be rejected,
        # not run. The escaping cwd is set before signing (the
        # payload is encrypted, so it cannot be edited after).
        env = self._signed(task={"kind": "prompt", "prompt": "hi",
                                 "cwd": "../../etc",
                                 "model": bridge.DEFAULT_MODEL,
                                 "timeout_s": 60, "max_cost_usd": 0.0})
        bridge.bus_dirs(self.bus)
        # Claim it the way poll_once does, then run the worker path.
        path = self.bus / "tasks" / f"{env['id']}.json"
        bridge.write_envelope_file(path, env)
        done = bridge.poll_once(self.bus, "alice", self.project_root,
                                self.registry)
        self.assertIsNotNone(done)
        results = list((self.bus / "results").glob("*.json"))
        self.assertEqual(len(results), 1)
        result = _read_payload(results[0], self.registry)
        self.assertEqual(result["result"]["status"], "rejected")
        self.assertIn("escapes project root",
                      result["result"]["stderr"])

    def test_malformed_envelopes_rejected(self):
        good = self._signed()
        cases = {
            "no version": {**good, "v": 99},
            "no signature": {k: v for k, v in good.items()
                             if k != "signature"},
            "bad base64 signature": {**good, "signature": "!!!"},
            "unknown sender": {**good, "from": "mallory"},
        }
        for name, env in cases.items():
            with self.subTest(name=name):
                if name == "unknown sender":
                    env["signature"] = bridge.sign(env, "bob")
                ok, _ = bridge.verify_basic(env, self.registry)
                self.assertFalse(ok, f"{name} verified")

    def test_tcp_relay_survives_a_huge_line(self):
        # A node sends a 2MB line to the TCP relay. The relay must
        # drop it (and the connection) without crashing or buffering
        # it — and still serve the next client.
        port = 18770
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "relay.py"),
             "--host", "127.0.0.1", "--port", str(port),
             "--bus", str(self.bus),
             "--registry", str(self.registry_path)],
            env=self.env, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            # Wait for the listener.
            for _ in range(50):
                try:
                    s = socket.create_connection(("127.0.0.1", port),
                                                 timeout=1)
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                self.fail("relay did not start")
            # Signed hello, then a 2MB line, then close.
            hello = json.dumps({"type": "hello", "node": "bob",
                                "nonce": "n1"}, sort_keys=True,
                               separators=(",", ":"))
            s.sendall((link._sign_line("bob", hello) + "\n").encode())
            s.recv(4096)  # the welcome
            try:
                s.sendall(b"X" * (2 * 1024 * 1024) + b"\n")
            except (BrokenPipeError, ConnectionResetError):
                pass  # the relay closed the connection mid-send —
                # that is the drop working, not a failure
            time.sleep(0.5)
            s.close()
            # The relay must still be alive for the next client:
            # reconnect (a fresh nonce — hellos are single-use),
            # hello, send a valid task, see it in the bus.
            s2 = socket.create_connection(("127.0.0.1", port), timeout=5)
            hello2 = json.dumps({"type": "hello", "node": "bob",
                                 "nonce": "n2"}, sort_keys=True,
                                separators=(",", ":"))
            s2.sendall((link._sign_line("bob", hello2) + "\n").encode())
            s2.recv(4096)
            env = self._signed(id="task-huge-line-ok")
            line = json.dumps({"type": "envelope", "envelope": env},
                              sort_keys=True, separators=(",", ":"))
            s2.sendall((link._sign_line("bob", line) + "\n").encode())
            time.sleep(0.5)
            s2.close()
            self.assertTrue((self.bus / "tasks" /
                             "task-huge-line-ok.json").exists(),
                            "relay did not survive the huge line")
        finally:
            proc.terminate()
            proc.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
