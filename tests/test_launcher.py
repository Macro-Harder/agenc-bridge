#!/usr/bin/env python3
"""Launcher tests — the system that starts.

`bridge.py launch --node <caller> [--to <target>]` issues a fresh
MCP routing token and starts the MCP server in the foreground.
The token is kept completely separate from the encrypted
envelopes: it is verified in-process by bridge-mcp.py before
anything is sent, and it never travels in an envelope — so
encryption can never turn a valid token into a rejection, and
the token gate still rejects anyone who does not hold it.

The launcher hands the token to the server through its
environment only: never on a command line (it would leak in
`ps`), never printed, never logged. When the server stops, its
token is revoked by default — a fresh token is issued on the
next launch.

These tests use isolated keys, passphrases, registry, tokens
file, and bus; nothing here touches the live bus, registry, or
keys. Token values are never printed and never stored — a stub
server records only the SHA-256 of the token it received, and
absence from disk is checked by scanning for the token's shape
(`mcp-<id>-<secret>`), never by holding the value.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_launcher -v
"""
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import bridge

ROOT = Path(__file__).parent.parent
PASSPHRASE = "test-passphrase-123"

# The shape of a raw routing token: mcp-<12 hex>-<43 base64url>.
# Used to prove no raw token reached disk or output, without
# ever holding a token value in the test.
TOKEN_SHAPE = re.compile(r"mcp-[0-9a-f]{12}-[A-Za-z0-9_-]{40,}")


def run_bridge(*argv, env, inp=None):
    return subprocess.run(
        [sys.executable, str(ROOT / "bridge.py"), *argv],
        env=env, input=inp, capture_output=True, text=True)


STUB = '''#!/usr/bin/env python3
"""Test stand-in for bridge-mcp.py: records what it was started
with, without ever writing the token itself. Writes one JSON
line to $LAUNCH_STUB_OUT: its argv, the SHA-256 of the token it
received (or null), and whether AGENC_BRIDGE_NODE was set.
Sleeps $LAUNCH_STUB_SLEEP seconds first when set, so the test
can inspect the live process."""
import hashlib
import json
import os
import sys
import time

out = os.environ.get("LAUNCH_STUB_OUT", "")
rec = {"argv": sys.argv[1:],
       "node_env": os.environ.get("AGENC_BRIDGE_NODE"),
       "token_sha256": None,
       "pid": os.getpid()}
tok = os.environ.get("AGENC_BRIDGE_MCP_TOKEN", "")
if tok:
    rec["token_sha256"] = hashlib.sha256(tok.encode()).hexdigest()
if out:
    Path = __import__("pathlib").Path
    Path(out).write_text(json.dumps(rec))
time.sleep(float(os.environ.get("LAUNCH_STUB_SLEEP", "0")))
'''


class _MCPDriver:
    """Drive a JSON-RPC MCP server over stdio (the launcher's
    child, reached through the launcher's own stdio)."""

    def __init__(self, proc):
        self.proc = proc
        self._next_id = 1
        self._send({"jsonrpc": "2.0", "id": self._next_id,
                    "method": "initialize", "params": {}})
        self._next_id += 1
        self._read()  # initialize result
        self._send({"jsonrpc": "2.0",
                    "method": "notifications/initialized"})

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


class LauncherTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="launcher-test-"))
        cls.registry_path = cls.tmp / "trusted-keys.json"
        cls.keys_dir = cls.tmp / "keys"
        cls.passphrases_dir = cls.tmp / "passphrases"
        cls.tokens_path = cls.tmp / "mcp-tokens.json"
        cls.stub_path = cls.tmp / "stub-server.py"
        cls.stub_path.write_text(STUB)
        cls.env = dict(os.environ)
        cls.env.update({
            "AGENC_BRIDGE_KEYS_DIR": str(cls.keys_dir),
            "AGENC_BRIDGE_PASSPHRASES_DIR": str(cls.passphrases_dir),
            "AGENC_BRIDGE_REGISTRY": str(cls.registry_path),
            "AGENC_BRIDGE_MCP_TOKENS": str(cls.tokens_path),
            "AGENC_BRIDGE_PASSPHRASE": PASSPHRASE,
        })
        # alice: owner (sole master, the approver). carol: asker.
        # bob: worker. t1: asker target. relay: relay.
        for node in ("alice", "bob", "carol", "t1", "relay"):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "keygen", "--node", node],
                           env=cls.env, capture_output=True, check=True)
        for node, role in ((("alice", "owner"), ("bob", "worker"),
                            ("carol", "asker"), ("t1", "asker"),
                            ("relay", "relay"))):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "trust", "--node", node,
                            "--pubkey", str(cls.keys_dir / f"{node}.pub"),
                            "--role", role],
                           env=cls.env, capture_output=True, check=True)
        cls.registry = json.loads(cls.registry_path.read_text())
        for node in ("alice", "bob", "carol", "t1", "relay"):
            assert cls.registry["nodes"][node].get("enc_public_key"), node

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
        self.stub_out = self.tmp / f"stub-{uuid.uuid4().hex[:8]}.json"
        # A clean tokens file per test: issued tokens must not
        # leak across tests (each test asserts on its own token).
        self.tokens_path.write_text(json.dumps({"tokens": []}))

    def _tokens(self):
        return json.loads(self.tokens_path.read_text()).get("tokens", [])

    def _launch_stub(self, node="carol", to="t1", days=30, extra=(),
                     stub_env=None):
        """Run the launcher against the stub server; return
        (proc, record) — the record is what the stub saw."""
        env = dict(self.env)
        if stub_env:
            env.update(stub_env)
        env["LAUNCH_STUB_OUT"] = str(self.stub_out)
        argv = [sys.executable, str(ROOT / "bridge.py"), "launch",
                "--node", node, "--to", to, "--expiry-days", str(days),
                "--server", str(self.stub_path), "--bus", str(self.bus),
                *extra]
        proc = subprocess.run(argv, env=env, capture_output=True,
                              text=True, timeout=60)
        # A refused launch never starts the stub: no record.
        rec = (json.loads(self.stub_out.read_text())
               if self.stub_out.exists() else None)
        return proc, rec

    def _scan_for_token_shape(self, *texts):
        """No raw token shape anywhere in the given texts (or in
        any file under the bus). The test never holds a token
        value; the shape is enough to catch a leak."""
        for text in texts:
            self.assertIsNone(TOKEN_SHAPE.search(text),
                              "raw token shape leaked in output")
        for path in self.bus.rglob("*"):
            if path.is_file():
                self.assertIsNone(
                    TOKEN_SHAPE.search(path.read_text(errors="replace")),
                    f"raw token shape leaked in bus file {path}")

    # --- issuance + handoff ---

    def test_launch_issues_token_and_hands_it_over_by_env(self):
        proc, rec = self._launch_stub()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # The stub got exactly the issued token (by hash), as the
        # right node, with nothing token-like in its argv.
        tokens = self._tokens()
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0]["from"], "carol")
        self.assertEqual(tokens[0]["to"], "t1")
        self.assertEqual(rec["token_sha256"], tokens[0]["sha256"])
        self.assertEqual(rec["node_env"], "carol")
        self.assertEqual(rec["argv"], ["--node", "carol",
                                       "--bus", str(self.bus)])
        # The launcher reported only the token id, never the token.
        self.assertIn(tokens[0]["token_id"], proc.stderr)
        self._scan_for_token_shape(proc.stdout, proc.stderr)

    def test_launch_token_absent_from_ps_args(self):
        """While the server is alive, its process list entry must
        carry no token — the token travels by environment only."""
        env = dict(self.env)
        env["LAUNCH_STUB_OUT"] = str(self.stub_out)
        env["LAUNCH_STUB_SLEEP"] = "10"
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "bridge.py"), "launch",
             "--node", "carol", "--to", "t1",
             "--server", str(self.stub_path), "--bus", str(self.bus)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)
        try:
            for _ in range(50):
                if self.stub_out.exists():
                    break
                time.sleep(0.1)
            rec = json.loads(self.stub_out.read_text())
            cmdline = Path(f"/proc/{rec['pid']}/cmdline").read_bytes()
            self.assertNotIn(b"mcp-", cmdline)
            self.assertNotIn(b"AGENC_BRIDGE_MCP_TOKEN", cmdline)
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def test_launch_expiry_days_honored(self):
        proc, rec = self._launch_stub(days=7)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        exp = datetime.strptime(self._tokens()[0]["exp"],
                                "%Y-%m-%dT%H:%M:%SZ").replace(
                                    tzinfo=timezone.utc)
        want = datetime.now(timezone.utc) + timedelta(days=7)
        self.assertLess(abs((exp - want).total_seconds()), 300)

    def test_launch_revokes_token_when_server_stops(self):
        proc, rec = self._launch_stub()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        token_id = self._tokens()[0]["token_id"]
        self.assertTrue(self._tokens()[0]["revoked"])
        self.assertIn(f"routing token {token_id} revoked", proc.stderr)

    def test_launch_no_revoke_leaves_token_live(self):
        proc, rec = self._launch_stub(extra=("--no-revoke",))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(self._tokens()[0]["revoked"])
        self.assertIn("left live (--no-revoke)", proc.stderr)

    # --- pre-flight failures: nothing issued, nothing started ---

    def test_launch_uncertified_node_refused(self):
        # Tamper with carol's role without re-certifying, then put
        # the registry back — the tamper must not leak into the
        # other tests (they need carol certified).
        original = self.registry_path.read_bytes()
        try:
            reg = json.loads(original)
            reg["nodes"]["carol"]["role"] = "worker"  # no re-certification
            self.registry_path.write_text(json.dumps(reg, indent=2))
            proc, rec = self._launch_stub()
        finally:
            self.registry_path.write_bytes(original)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not certified", proc.stderr)
        self.assertIsNone(rec)
        self.assertEqual(self._tokens(), [])

    def test_launch_unknown_node_refused(self):
        proc = run_bridge("launch", "--node", "nobody", "--to", "t1",
                          "--server", str(self.stub_path),
                          "--bus", str(self.bus), env=self.env)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not in the registry", proc.stderr)
        self.assertEqual(self._tokens(), [])

    def test_launch_no_master_key_refused(self):
        keys2 = self.tmp / "keys-no-master"
        shutil.copytree(self.keys_dir, keys2)
        (keys2 / "alice.pem.enc").unlink()
        env = dict(self.env)
        env["AGENC_BRIDGE_KEYS_DIR"] = str(keys2)
        proc = run_bridge("launch", "--node", "carol", "--to", "t1",
                          "--server", str(self.stub_path),
                          "--bus", str(self.bus), env=env)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("no master key", proc.stderr)
        self.assertEqual(self._tokens(), [])

    # --- end to end through the real server + encryption ---

    def test_launched_server_serves_message_muse_encrypted(self):
        """The launched server talks through the encrypted path:
        a message it sends lands as a v3 envelope on disk — no
        plaintext, no token shape anywhere in the bus."""
        env = dict(self.env)
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "bridge.py"), "launch",
             "--node", "carol", "--to", "t1", "--bus", str(self.bus)],
            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            driver = _MCPDriver(proc)
            res = driver.call("message_muse", {
                "text": "hello from the launched server", "to": "t1"})
            self.assertFalse(res.get("result", {}).get("isError"),
                             res)
            files = list((self.dirs["messages"] / "t1").glob("*.json"))
            self.assertEqual(len(files), 1)
            raw = json.loads(files[0].read_text())
            self.assertEqual(raw.get("v"), 3)
            self.assertNotIn("hello from the launched server",
                             files[0].read_text())
            plain = bridge.decrypt_envelope(raw, "t1", self.registry)
            self.assertEqual(plain["message"]["text"],
                             "hello from the launched server")
            self._scan_for_token_shape(files[0].read_text())
        finally:
            proc.terminate()
            _, err = proc.communicate(timeout=10)
            self._scan_for_token_shape(err)
            self.assertTrue(self._tokens()[0]["revoked"])

    def test_launched_server_token_routed_ask_through_encryption(self):
        """Token + encryption together, through the launched
        server: the ask is answered by the target node, and the
        prompt/answer on disk are v3 ciphertext, not plaintext."""
        env = dict(self.env)
        responder = _Responder(env, self.bus, ["t1"])
        responder.start()
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "bridge.py"), "launch",
             "--node", "carol", "--to", "t1", "--bus", str(self.bus)],
            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            driver = _MCPDriver(proc)
            res = driver.call("ask_muse", {
                "prompt": "What is 6 times 7?", "to": "t1",
                "timeout_s": 30})
            content = res.get("result", {}).get("content", [])
            self.assertFalse(res.get("result", {}).get("isError"), res)
            self.assertEqual(content[0]["text"], "answer from t1")
            # The answered prompt moves to read/<node>/, and the
            # answer moves to read/<asker>/ once fetch-answer
            # shows it — read-on-read on both sides.
            prompts = list((self.dirs["prompts"] / "t1").glob("*.json"))
            prompts += list((self.dirs["read"] / "t1").glob("*.json"))
            answers = list(self.dirs["answers"].glob("*.json"))
            answers += list((self.dirs["read"] / "carol").glob("*.json"))
            self.assertEqual(len(prompts), 1)
            self.assertEqual(len(answers), 1)
            for path in prompts + answers:
                raw = json.loads(path.read_text())
                self.assertEqual(raw.get("v"), 3)
                self.assertNotIn("6 times 7", path.read_text())
                self._scan_for_token_shape(path.read_text())
        finally:
            responder.stop_event.set()
            proc.terminate()
            _, err = proc.communicate(timeout=10)
            self._scan_for_token_shape(err)
            self.assertTrue(self._tokens()[0]["revoked"])


if __name__ == "__main__":
    unittest.main()
