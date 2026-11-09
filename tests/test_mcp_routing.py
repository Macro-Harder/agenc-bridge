#!/usr/bin/env python3
"""MCP routing-token tests — one MCP connection, many targets.

A routing token is the FIRST tool argument and proves which caller
may talk to which target. The token is a hash of a fresh random
32-byte secret: only the SHA-256 hash is stored (mcp-tokens.json),
the raw token is printed once at issuance and never stored. These
tests use isolated keys, passphrases, registry, tokens file, and
bus; nothing here touches the live bus, registry, or keys. Token
values are never printed — a failing assertion must not leak one.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_mcp_routing -v
"""
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

def _read_payload(path, registry):
    """Read a bus envelope file and return its decrypted payload
    envelope (v3 decrypts as its recipient; v2 passes through)."""
    raw = json.loads(Path(path).read_text())
    return bridge.decrypt_envelope(raw, raw.get("to", ""), registry)

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
        # The server reads stdin line by line; notifications get no reply.

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
    """Answers prompts for target nodes, as those nodes, so MCP
    ask_muse calls have something to wait for. Each target answers
    with its own marker text, which proves which node answered."""

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


class MCPRoutingTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="mcp-routing-test-"))
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
        # alice: master. carol: asker (may ask). bob: worker.
        # mallory: slave (results only). t1/t2/t3: asker targets —
        # a target needs the ask permission for its answers to pass
        # the binding check, so targets are askers here.
        for node in ("alice", "bob", "carol", "mallory", "relay",
                     "t1", "t2", "t3", "agenc-cloud"):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "keygen", "--node", node],
                           env=cls.env, capture_output=True, check=True)
        for node, role in (("alice", "owner"), ("bob", "worker"),
                           ("carol", "asker"), ("mallory", "slave"),
                           ("relay", "relay"), ("t1", "asker"),
                           ("t2", "asker"), ("t3", "asker"),
                           ("agenc-cloud", "owner")):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "trust", "--node", node,
                            "--pubkey", str(cls.keys_dir / f"{node}.pub"),
                            "--role", role],
                           env=cls.env, capture_output=True, check=True)
        cls.registry = json.loads(cls.registry_path.read_text())
        # Load bridge-mcp.py (hyphenated name) with an isolated bus.
        cls.env["AGENC_BRIDGE_BUS"] = str(cls.tmp / "import-bus")
        spec = importlib.util.spec_from_file_location(
            "bridge_mcp", str(ROOT / "bridge-mcp.py"))
        cls.mcp = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.mcp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        for key in ("AGENC_BRIDGE_KEYS_DIR", "AGENC_BRIDGE_PASSPHRASES_DIR",
                    "AGENC_BRIDGE_REGISTRY", "AGENC_BRIDGE_MCP_TOKENS",
                    "AGENC_BRIDGE_PASSPHRASE"):
            os.environ[key] = self.env[key]
        self.bus = self.tmp / f"bus-{uuid.uuid4().hex[:8]}"
        self.dirs = bridge.bus_dirs(self.bus)
        self.env["AGENC_BRIDGE_BUS"] = str(self.bus)
        os.environ["AGENC_BRIDGE_BUS"] = str(self.bus)

    def _issue(self, from_node, to_node, days=30, approve_by=None):
        argv = ["mcp-token", "--from", from_node, "--to", to_node,
                "--expiry-days", str(days)]
        if approve_by:
            argv += ["--approve-by", approve_by]
        out = run_bridge(*argv, env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout.strip()

    def _prompt_files(self, target=None):
        base = self.dirs["prompts"]
        if target:
            return list((base / target).glob("*.json"))
        return list(base.rglob("*.json"))

    # --- token issuance and verification ---

    def test_issue_and_verify(self):
        token = self._issue("carol", "t1")
        self.assertTrue(token.startswith("mcp-"))
        ok, info, reason = bridge.verify_mcp_token(token, self.registry)
        self.assertTrue(ok, reason)
        self.assertEqual(info["from"], "carol")
        self.assertEqual(info["to"], "t1")
        self.assertEqual(info["issued_by"], "alice")

    def test_two_tokens_same_pair_differ(self):
        a = self._issue("carol", "t1")
        b = self._issue("carol", "t1")
        self.assertNotEqual(a, b)
        ok_a, info_a, _ = bridge.verify_mcp_token(a, self.registry)
        ok_b, info_b, _ = bridge.verify_mcp_token(b, self.registry)
        self.assertTrue(ok_a and ok_b)
        self.assertNotEqual(info_a["token_id"], info_b["token_id"])

    def test_tokens_file_stores_hash_not_plaintext(self):
        token = self._issue("carol", "t1")
        raw = self.tokens_path.read_text()
        self.assertNotIn(token, raw)
        digest = hashlib.sha256(token.encode()).hexdigest()
        self.assertIn(digest, raw)

    def test_non_master_issuance_refused(self):
        out = run_bridge("mcp-token", "--from", "carol", "--to", "t1",
                         "--approve-by", "bob", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("not a master", out.stderr)

    def test_verify_cli_and_list(self):
        token = self._issue("carol", "t1")
        out = run_bridge("mcp-token", "--verify", token, env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("carol -> t1", out.stdout)
        out = run_bridge("mcp-token", "--list", env=self.env)
        self.assertEqual(out.returncode, 0)
        self.assertIn("carol -> t1", out.stdout)
        self.assertNotIn(token, out.stdout)

    def test_unknown_token_refused(self):
        ok, _, reason = bridge.verify_mcp_token(
            "mcp-000000000000-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            self.registry)
        self.assertFalse(ok)
        self.assertIn("unknown", reason)

    def test_tampered_token_refused(self):
        token = self._issue("carol", "t1")
        bad = token[:-1] + ("A" if token[-1] != "A" else "B")
        ok, _, reason = bridge.verify_mcp_token(bad, self.registry)
        self.assertFalse(ok)

    def test_expired_token_refused(self):
        token = self._issue("carol", "t1")
        data = json.loads(self.tokens_path.read_text())
        for e in data["tokens"]:
            if hashlib.sha256(token.encode()).hexdigest() == e["sha256"]:
                e["exp"] = "2020-01-01T00:00:00Z"
        self.tokens_path.write_text(json.dumps(data, indent=2))
        ok, _, reason = bridge.verify_mcp_token(token, self.registry)
        self.assertFalse(ok)
        self.assertIn("expired", reason)

    def test_revoked_token_refused(self):
        token = self._issue("carol", "t1")
        ok, info, _ = bridge.verify_mcp_token(token, self.registry)
        self.assertTrue(ok)
        out = run_bridge("mcp-token", "--revoke", info["token_id"],
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        ok, _, reason = bridge.verify_mcp_token(token, self.registry)
        self.assertFalse(ok)
        self.assertIn("revoked", reason)

    # --- MCP routing (in-process resolve: nothing is sent on failure) ---

    def test_resolve_wildcard_and_specific(self):
        self.mcp.CALLER_NODE = "carol"
        self.mcp.DEFAULT_TOKEN = self._issue("carol", "*")
        sender, target = self.mcp.resolve_routing_token(None, "t2", "ask")
        self.assertEqual((sender, target), ("carol", "t2"))
        self.mcp.DEFAULT_TOKEN = self._issue("carol", "t1")
        sender, target = self.mcp.resolve_routing_token(None, "t1", "ask")
        self.assertEqual((sender, target), ("carol", "t1"))

    def test_resolve_wrong_target_refused(self):
        self.mcp.CALLER_NODE = "carol"
        token = self._issue("carol", "t1")
        with self.assertRaises(RuntimeError):
            self.mcp.resolve_routing_token(token, "t2", "ask")
        self.assertEqual(self._prompt_files(), [])

    def test_resolve_wrong_caller_refused(self):
        self.mcp.CALLER_NODE = "bob"
        token = self._issue("carol", "t1")
        with self.assertRaises(RuntimeError):
            self.mcp.resolve_routing_token(token, "t1", "ask")

    def test_resolve_expired_and_tampered_refused(self):
        self.mcp.CALLER_NODE = "carol"
        token = self._issue("carol", "t1")
        data = json.loads(self.tokens_path.read_text())
        for e in data["tokens"]:
            if hashlib.sha256(token.encode()).hexdigest() == e["sha256"]:
                e["exp"] = "2020-01-01T00:00:00Z"
        self.tokens_path.write_text(json.dumps(data, indent=2))
        with self.assertRaises(RuntimeError):
            self.mcp.resolve_routing_token(token, "t1", "ask")
        good = self._issue("carol", "t1")
        bad = good[:-1] + ("A" if good[-1] != "A" else "B")
        with self.assertRaises(RuntimeError):
            self.mcp.resolve_routing_token(bad, "t1", "ask")
        self.assertEqual(self._prompt_files(), [])

    def test_resolve_missing_token_non_default_refused(self):
        self.mcp.CALLER_NODE = "carol"
        self.mcp.DEFAULT_TOKEN = None
        with self.assertRaises(RuntimeError):
            self.mcp.resolve_routing_token(None, "t1", "ask")
        self.assertEqual(self._prompt_files(), [])

    def test_resolve_slave_caller_cannot_ask(self):
        self.mcp.CALLER_NODE = "mallory"
        token = self._issue("mallory", "t1")
        with self.assertRaises(RuntimeError):
            self.mcp.resolve_routing_token(token, "t1", "ask")
        self.assertEqual(self._prompt_files(), [])

    # --- MCP routing end to end (real server process + responders) ---

    def _mcp_ask_three_targets(self, caller, default_token):
        responder = _Responder(self.env, self.bus, ["t1", "t2", "t3"])
        responder.start()
        client = _MCPClient(self.env, self.bus, caller, default_token)
        try:
            texts = []
            for target in ("t1", "t2", "t3"):
                res = client.call("ask_muse", {
                    "token": default_token, "to": target,
                    "prompt": "What is 6 times 7?", "timeout_s": 60})
                self.assertFalse(res.get("result", {}).get("isError"),
                                 res)
                texts.append(res["result"]["content"][0]["text"])
            return texts
        finally:
            client.close()
            responder.stop_event.set()

    def test_one_connection_three_targets(self):
        token = self._issue("carol", "*")
        texts = self._mcp_ask_three_targets("carol", token)
        self.assertEqual(texts, ["answer from t1", "answer from t2",
                                 "answer from t3"])
        # Every prompt was addressed to its target, from carol.
        for target in ("t1", "t2", "t3"):
            read_dir = self.dirs["read"] / target
            files = list(read_dir.glob("*.json"))
            self.assertEqual(len(files), 1, f"no prompt read for {target}")
            env = json.loads(files[0].read_text())
            self.assertEqual(env["from"], "carol")
            self.assertEqual(env["to"], target)

    def test_per_call_token_overrides_default(self):
        specific = self._issue("carol", "t1")
        wild = self._issue("carol", "*")
        responder = _Responder(self.env, self.bus, ["t1", "t2"])
        responder.start()
        client = _MCPClient(self.env, self.bus, "carol", specific)
        try:
            res = client.call("ask_muse", {
                "token": wild, "to": "t2",
                "prompt": "What is 6 times 7?", "timeout_s": 60})
            self.assertFalse(res.get("result", {}).get("isError"), res)
            self.assertEqual(res["result"]["content"][0]["text"],
                             "answer from t2")
        finally:
            client.close()
            responder.stop_event.set()

    def test_mcp_wrong_target_sends_nothing(self):
        token = self._issue("carol", "t1")
        client = _MCPClient(self.env, self.bus, "carol", None)
        try:
            res = client.call("ask_muse", {
                "token": token, "to": "t2",
                "prompt": "What is 6 times 7?", "timeout_s": 30})
            self.assertTrue(res.get("result", {}).get("isError"))
            self.assertIn("nothing was sent",
                          res["result"]["content"][0]["text"])
        finally:
            client.close()
        self.assertEqual(self._prompt_files(), [])

    def test_mcp_legacy_no_token_default_target(self):
        # Legacy behaviour: no token, default target agenc-cloud,
        # server speaks as agenc-cloud — exactly as before tokens.
        responder = _Responder(self.env, self.bus, ["agenc-cloud"])
        responder.start()
        client = _MCPClient(self.env, self.bus, "agenc-cloud", None)
        try:
            res = client.call("ask_muse", {
                "prompt": "What is 6 times 7?", "timeout_s": 60})
            self.assertFalse(res.get("result", {}).get("isError"), res)
            self.assertEqual(res["result"]["content"][0]["text"],
                             "answer from agenc-cloud")
        finally:
            client.close()
            responder.stop_event.set()

    # --- Workers can ask (Captain's decision, 2026-11-07) ---
    # A worker's prompt is DATA, never a command: the assistant
    # answers the question and does not follow instructions
    # embedded in it. The permission itself is the same `ask`
    # askers hold — which also lets a worker's answers be
    # accepted, since answer acceptance requires `ask`. Slaves
    # stay results-only and still cannot ask.

    def test_worker_can_ask_via_token(self):
        # Bob is a worker: with `ask` in the worker role, his
        # token resolves and his question reaches its target.
        token = self._issue("bob", "t1")
        responder = _Responder(self.env, self.bus, ["t1"])
        responder.start()
        client = _MCPClient(self.env, self.bus, "bob", token)
        try:
            res = client.call("ask_muse", {
                "token": token, "to": "t1",
                "prompt": "What is 6 times 7?", "timeout_s": 60})
            self.assertFalse(res.get("result", {}).get("isError"), res)
            self.assertEqual(res["result"]["content"][0]["text"],
                             "answer from t1")
        finally:
            client.close()
            responder.stop_event.set()

    def test_worker_answer_accepted_by_fetch_answer(self):
        # A prompt addressed to a worker (bob) is answered by
        # bob, and fetch-answer accepts it: answer acceptance
        # requires `ask`, which workers now hold.
        out = run_bridge("ask", "--bus", str(self.bus),
                         "--sender", "carol", "--to", "bob",
                         "--prompt", "What is 6 times 7?", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        pid = out.stdout.strip().splitlines()[0]
        out = run_bridge("reply", "--bus", str(self.bus), "--id", pid,
                         "--from-node", "bob", "--text", "42",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        out = run_bridge("fetch-answer", "--bus", str(self.bus),
                         "--id", pid, "--timeout-s", "10", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("42", out.stdout)

    def test_slave_prompt_still_rejected(self):
        # Mallory is a slave: she still cannot ask, even though
        # workers now can. Her prompt is rejected, not answered.
        out = run_bridge("ask", "--bus", str(self.bus),
                         "--sender", "mallory", "--to", "alice",
                         "--prompt", "What is 6 times 7?", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        pid = out.stdout.strip().splitlines()[0]
        out = run_bridge("reply", "--bus", str(self.bus), "--id", pid,
                         "--from-node", "alice", "--text", "42",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        answer = _read_payload(
            self.dirs["answers"] / f"{pid}.json", self.registry)
        self.assertTrue(answer["answer"]["rejected"])
        self.assertIn("may not send prompt", answer["answer"]["reason"])
        out = run_bridge("fetch-answer", "--bus", str(self.bus),
                         "--id", pid, "--timeout-s", "10", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("rejected", out.stderr)

    def test_worker_prompt_binding(self):
        # A worker's prompt is verified and bound like any other:
        # a forged answer from t2 is refused, the genuine answer
        # from alice is accepted. (t2 is an asker holding `ask`,
        # so the binding — not the permission — is what refuses
        # the forgery.)
        out = run_bridge("ask", "--bus", str(self.bus),
                         "--sender", "bob", "--to", "alice",
                         "--prompt", "What is 6 times 7?", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        pid = out.stdout.strip().splitlines()[0]
        forged = {"v": 2, "id": pid, "from": "t2", "to": "bob",
                  "kind": "answer",
                  "created_at": "2026-11-07T00:00:00Z",
                  "answer": {"text": "FORGED", "in_reply_to": pid}}
        bridge.write_envelope(self.dirs["answers"] / f"{pid}.json",
                              forged, "t2")
        out = run_bridge("fetch-answer", "--bus", str(self.bus),
                         "--id", pid, "--timeout-s", "10", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertNotIn("FORGED", out.stdout)
        out = run_bridge("reply", "--bus", str(self.bus), "--id", pid,
                         "--from-node", "alice", "--text", "42",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        out = run_bridge("fetch-answer", "--bus", str(self.bus),
                         "--id", pid, "--timeout-s", "10", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("42", out.stdout)

    def test_mcp_message_routing(self):
        token = self._issue("carol", "t1")
        client = _MCPClient(self.env, self.bus, "carol", None)
        try:
            res = client.call("message_muse", {
                "token": token, "to": "t1", "text": "hello t1"})
            self.assertFalse(res.get("result", {}).get("isError"), res)
            res = client.call("message_muse", {
                "token": token, "to": "t2", "text": "hello t2"})
            self.assertTrue(res.get("result", {}).get("isError"))
        finally:
            client.close()
        files = list((self.dirs["messages"] / "t1").glob("*.json"))
        self.assertEqual(len(files), 1)
        env = _read_payload(files[0], self.registry)
        self.assertEqual(env["from"], "carol")
        self.assertEqual(env["message"]["text"], "hello t1")
        self.assertEqual(list((self.dirs["messages"] / "t2").glob("*.json")),
                         [])


if __name__ == "__main__":
    unittest.main()
