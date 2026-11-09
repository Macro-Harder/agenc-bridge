#!/usr/bin/env python3
"""Tests for `bridge.py status` (the pulse) and `bridge.py dead`.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_status -v

The tests use an isolated keys dir, registry, and bus. Nothing
here touches the live bus, registry, or keys. The pulse test
starts a real relay.py (TCP) on a test port.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import bridge

ROOT = Path(__file__).parent.parent
BASE_PORT = 19765
PASSPHRASE = "test-passphrase-123"


def run_bridge(*argv, env):
    return subprocess.run(
        [sys.executable, str(ROOT / "bridge.py"), *argv],
        env=env, capture_output=True, text=True)


class StatusTests(unittest.TestCase):
    _counter = 0

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="status-test-"))
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
        # Oscar: in the registry but never approved.
        subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                        "keygen", "--node", "oscar"],
                       env=cls.env, capture_output=True, check=True)
        subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                        "trust", "--node", "oscar",
                        "--pubkey", str(cls.keys_dir / "oscar.pub"),
                        "--role", "worker"],
                       env=cls.env, capture_output=True, check=True)
        registry = json.loads(cls.registry_path.read_text())
        del registry["nodes"]["oscar"]["role_certificate"]
        cls.registry_path.write_text(json.dumps(registry, indent=2))

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        os.environ["AGENC_BRIDGE_KEYS_DIR"] = str(self.keys_dir)
        os.environ["AGENC_BRIDGE_REGISTRY"] = str(self.registry_path)
        os.environ["AGENC_BRIDGE_PASSPHRASE"] = PASSPHRASE
        StatusTests._counter += 1
        self.bus = self.tmp / f"bus-{StatusTests._counter}"
        self.dirs = bridge.bus_dirs(self.bus)

    def _signed(self, env, node):
        path = self.tmp / f"tmp-{env['id']}.json"
        bridge.write_envelope(path, env, node)
        signed = json.loads(path.read_text())
        path.unlink()
        return signed

    def _task(self, frm="alice", to="bob"):
        env = {"v": 2, "id": f"task-{uuid.uuid4().hex[:12]}",
               "from": frm, "to": to, "kind": "task",
               "created_at": "2026-11-07T00:00:00Z",
               "task": {"kind": "prompt", "prompt": "do the thing",
                        "cwd": ".", "model": "test", "timeout_s": 60,
                        "max_cost_usd": 0.0}}
        return self._signed(env, frm)

    def test_status_reports_down_and_counts(self):
        # One waiting task, one dead letter (tampered signature).
        task = self._task()
        (self.dirs["tasks"] / f"{task['id']}.json").write_text(
            json.dumps(task, indent=2))
        bad = self._task()
        # Tamper after signing: flip a byte in the ciphertext
        # (v3: the signature covers header + ciphertext).
        ct = bytearray(base64.b64decode(bad["ciphertext"]))
        ct[0] ^= 1
        bad["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        (self.dirs["dead"] / f"{bad['id']}.json").write_text(
            json.dumps(bad, indent=2))
        out = run_bridge("status", "--bus", str(self.bus),
                         "--node", "alice", "--tcp-port", "18999",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("tcp hello: DOWN", out.stdout)
        self.assertIn("no heartbeat", out.stdout)
        self.assertIn("tasks waiting: 1", out.stdout)
        self.assertIn("dead: 1", out.stdout)
        self.assertIn("alice [owner]", out.stdout)
        self.assertIn("approved by alice", out.stdout)
        self.assertIn("oscar [worker]", out.stdout)
        self.assertIn("UNAPPROVED", out.stdout)

    def test_dead_lists_reasons(self):
        # A tampered envelope (bad signature) and an uncertified
        # sender (unapproved role) — dead must name the reason.
        # The prompt text itself must NOT leak: both envelopes
        # are v3 ciphertext on disk, so `dead` shows the reason
        # but never the content.
        bad = self._task()
        ct = bytearray(base64.b64decode(bad["ciphertext"]))
        ct[0] ^= 1
        bad["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        (self.dirs["dead"] / f"{bad['id']}.json").write_text(
            json.dumps(bad, indent=2))
        env = {"v": 2, "id": f"task-{uuid.uuid4().hex[:12]}",
               "from": "oscar", "to": "bob", "kind": "task",
               "created_at": "2026-11-07T00:00:00Z",
               "task": {"kind": "prompt", "prompt": "let me in",
                        "cwd": ".", "model": "test", "timeout_s": 60,
                        "max_cost_usd": 0.0}}
        signed = self._signed(env, "oscar")
        (self.dirs["dead"] / f"{signed['id']}.json").write_text(
            json.dumps(signed, indent=2))
        out = run_bridge("dead", "--bus", str(self.bus), env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("bad signature", out.stdout)
        self.assertIn("unapproved role for oscar", out.stdout)
        self.assertNotIn("let me in", out.stdout)

    def test_status_pulse_alive(self):
        port = BASE_PORT + StatusTests._counter
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "relay.py"),
             "--host", "127.0.0.1", "--port", str(port),
             "--bus", str(self.bus),
             "--registry", str(self.registry_path)],
            env=self.env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.time() + 15
            while time.time() < deadline:
                line = proc.stdout.readline()
                if "listening" in line:
                    break
            else:
                raise RuntimeError("relay.py did not start")
            # Wait for the first heartbeat beat (watch loop: 2s max).
            hb = self.bus / ".heartbeat-tcp"
            deadline = time.time() + 10
            while not hb.exists() and time.time() < deadline:
                time.sleep(0.2)
            self.assertTrue(hb.exists(), "no heartbeat file from relay")
            out = run_bridge("status", "--bus", str(self.bus),
                             "--node", "alice", "--tcp-port", str(port),
                             env=self.env)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertIn("tcp hello: ALIVE", out.stdout)
            self.assertIn(f"tcp relay 127.0.0.1:{port}: heartbeat",
                          out.stdout)
            # The web relay is not running in this test, so its
            # heartbeat is correctly absent.
            self.assertIn("web relay not configured: no heartbeat",
                          out.stdout)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    unittest.main()
