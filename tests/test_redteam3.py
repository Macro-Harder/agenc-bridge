#!/usr/bin/env python3
"""Red-team tests, round 3 — regression tests for the findings in
the insider-access review (1 HIGH, 3 MEDIUM, 6 LOW), each fixed
and each covered here so it cannot silently come back.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_redteam3 -v

Isolated keys, registry, bus, root pin, and tokens file; nothing
here touches the live bus, registry, keys, or root pin. The
attacker is a trusted node — bob (worker) — because the point is
that a trusted-but-malicious (or compromised) node must not be
able to promote itself, forge another agent's memory, flip a
completed task's outcome, or flood the relay by reconnecting.
"""
import importlib
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

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


class RedTeam3Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="redteam3-test-"))
        cls.registry_path = cls.tmp / "trusted-keys.json"
        cls.keys_dir = cls.tmp / "keys"
        cls.passphrases_dir = cls.tmp / "passphrases"
        cls.tokens_path = cls.tmp / "mcp-tokens.json"
        # Build the env from scratch for bridge variables: other
        # test modules leave AGENC_BRIDGE_* set in os.environ
        # (e.g. AGENC_BRIDGE_PASSPHRASES_DIR from test_mcp_routing),
        # and inheriting one silently redirects this file's keys.
        cls.env = {k: v for k, v in os.environ.items()
                   if not k.startswith("AGENC_BRIDGE_")}
        cls.env.update({
            "AGENC_BRIDGE_KEYS_DIR": str(cls.keys_dir),
            "AGENC_BRIDGE_PASSPHRASES_DIR": str(cls.passphrases_dir),
            "AGENC_BRIDGE_REGISTRY": str(cls.registry_path),
            "AGENC_BRIDGE_PASSPHRASE": PASSPHRASE,
            "AGENC_BRIDGE_MCP_TOKENS": str(cls.tokens_path),
        })
        for node in ("alice", "bob", "carol", "eve", "mallory", "relay"):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "keygen", "--node", node],
                           env=cls.env, capture_output=True, check=True)
        for node, role in (("alice", "owner"), ("bob", "worker"),
                           ("carol", "asker"), ("eve", "asker"),
                           ("mallory", "slave"), ("relay", "relay")):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "trust", "--node", node,
                            "--pubkey", str(cls.keys_dir / f"{node}.pub"),
                            "--role", role],
                           env=cls.env, capture_output=True, check=True)
        cls.registry = json.loads(cls.registry_path.read_text())
        cls.pristine_registry = json.loads(json.dumps(cls.registry))
        # Load bridge-mcp.py (hyphenated name) the same way
        # test_mcp_routing.py does.
        spec = importlib.util.spec_from_file_location(
            "bridge_mcp", str(ROOT / "bridge-mcp.py"))
        cls.mcp = importlib.util.module_from_spec(spec)
        # Registered in sys.modules so importlib.reload works on it
        # (test_l4 reloads it under a patched environment).
        sys.modules["bridge_mcp"] = cls.mcp
        spec.loader.exec_module(cls.mcp)
        cls.project_root = cls.tmp / "proj"
        cls.project_root.mkdir()
        stub = cls.tmp / "stub-agent.sh"
        stub.write_text("#!/bin/sh\necho stub-ok\n")
        stub.chmod(0o755)
        cls.stub = stub

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        # Same isolation in-process: clear every AGENC_BRIDGE_*
        # var another module may have left, then set exactly the
        # ones this file owns.
        for key in list(os.environ):
            if key.startswith("AGENC_BRIDGE_"):
                del os.environ[key]
        os.environ["AGENC_BRIDGE_KEYS_DIR"] = str(self.keys_dir)
        os.environ["AGENC_BRIDGE_PASSPHRASES_DIR"] = str(
            self.passphrases_dir)
        os.environ["AGENC_BRIDGE_REGISTRY"] = str(self.registry_path)
        os.environ["AGENC_BRIDGE_PASSPHRASE"] = PASSPHRASE
        os.environ["AGENC_BRIDGE_MCP_TOKENS"] = str(self.tokens_path)
        self.bus = self.tmp / f"bus-{uuid.uuid4().hex[:8]}"
        self.dirs = bridge.bus_dirs(self.bus)
        # Restore the pristine registry, root pin, and tokens
        # file: several tests tamper them, and no test may leak
        # that into the next.
        self.registry_path.write_text(
            json.dumps(json.loads(json.dumps(self.pristine_registry)),
                       indent=2))
        self.registry = json.loads(json.dumps(self.pristine_registry))
        pin_path = bridge.root_pin_path()
        pin_path.parent.mkdir(parents=True, exist_ok=True)
        pin_path.write_text(json.dumps({
            "node": "alice",
            "fingerprint": self.pristine_registry["nodes"]["alice"][
                "fingerprint"]}, indent=2))
        os.chmod(pin_path, 0o600)
        self.tokens_path.write_text(json.dumps({"tokens": []}))

    def _write_registry(self, registry):
        self.registry_path.write_text(json.dumps(registry, indent=2))
        self.registry = registry

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

    def _result_env(self, task_id, frm="bob", to="alice", stdout="done"):
        return {"v": 2, "id": task_id, "from": frm, "to": to,
                "kind": "result", "created_at": "2026-11-07T00:00:00Z",
                "result": {"status": "ok", "returncode": 0,
                           "stdout": stdout, "stderr": "",
                           "started_at": "2026-11-07T00:00:00Z",
                           "finished_at": "2026-11-07T00:00:00Z",
                           "duration_s": 0.1}}

    def _prompt_env(self, prompt_id, frm="carol", to="alice"):
        return {"v": 2, "id": prompt_id, "from": frm, "to": to,
                "kind": "prompt", "thread": "",
                "created_at": "2026-11-07T00:00:00Z",
                "prompt": {"text": "What is 6 times 7?", "context": ""}}

    def _answer_env(self, prompt_id, frm="alice", to="carol", text="42"):
        return {"v": 2, "id": prompt_id, "from": frm, "to": to,
                "kind": "answer", "created_at": "2026-11-07T00:00:00Z",
                "answer": {"text": text, "in_reply_to": prompt_id}}

    def _start_relay(self, port):
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "relay.py"),
             "--host", "127.0.0.1", "--port", str(port),
             "--bus", str(self.bus),
             "--registry", str(self.registry_path)],
            env=self.env, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=1)
                s.close()
                return proc
            except OSError:
                time.sleep(0.1)
        proc.terminate()
        self.fail("relay did not start")

    def _tamper_bob_to_master(self):
        """The round-3 H1 PoC: edit bob's registry entry to master
        and self-sign a certificate claiming approved_by bob."""
        reg = json.loads(self.registry_path.read_text())
        bob = reg["nodes"]["bob"]
        bob["role"] = "master"
        bob["permissions"] = bridge.ROLES["master"]
        bob["role_certificate"] = bridge.sign_role_certificate(
            "bob", "master", bridge.ROLES["master"],
            bob["fingerprint"], "bob")
        self._write_registry(reg)
        return reg

    # H1: role certificates chain to a pinned root — a worker
    # cannot promote itself by editing the registry file.

    def test_h1_self_signed_non_root_cert_rejected(self):
        self.assertTrue(bridge.verify_role_certificate(
            "alice", self.registry["nodes"]["alice"], self.registry))
        self.assertTrue(bridge.verify_role_certificate(
            "bob", self.registry["nodes"]["bob"], self.registry))
        self.assertEqual(
            bridge.cert_chain("bob", self.registry["nodes"]["bob"],
                              self.registry),
            ["bob", "alice"])
        reg = self._tamper_bob_to_master()
        self.assertFalse(bridge.verify_role_certificate(
            "bob", reg["nodes"]["bob"], reg),
            "bob's self-signed master certificate must not verify")
        self.assertIsNone(bridge.cert_chain(
            "bob", reg["nodes"]["bob"], reg))
        # The tamper does not poison the other nodes: the pinned
        # root still anchors their chains.
        self.assertTrue(bridge.verify_role_certificate(
            "alice", reg["nodes"]["alice"], reg))
        self.assertTrue(bridge.verify_role_certificate(
            "carol", reg["nodes"]["carol"], reg))
        # And a prompt from bob-as-master is refused outright.
        env = self._signed(self._prompt_env("prompt-h1", frm="bob",
                                            to="alice"), "bob")
        ok, reason = bridge.verify(env, reg)
        self.assertFalse(ok)
        self.assertIn("unapproved role", reason)

    def test_h1_promote_self_approval_refused(self):
        self._tamper_bob_to_master()
        out = run_bridge("promote", "--node", "bob", "--role", "master",
                         "--approve-by", "bob", env=self.env)
        self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)
        out = run_bridge("approve", "--node", "bob",
                         "--approve-by", "bob", env=self.env)
        self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_h1_legit_chain_and_second_master(self):
        out = run_bridge("promote", "--node", "bob", "--role", "master",
                         "--approve-by", "alice", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        reg = json.loads(self.registry_path.read_text())
        self.assertEqual(bridge.cert_chain("bob", reg["nodes"]["bob"], reg),
                         ["bob", "alice"])
        # A master approved by the root can approve others: the
        # chain grows by one link, still rooted at alice.
        out = run_bridge("promote", "--node", "carol", "--role", "worker",
                         "--approve-by", "bob", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        reg = json.loads(self.registry_path.read_text())
        self.assertEqual(
            bridge.cert_chain("carol", reg["nodes"]["carol"], reg),
            ["carol", "bob", "alice"])
        self.assertTrue(bridge.verify_role_certificate(
            "carol", reg["nodes"]["carol"], reg))

    def test_h1_cycle_rejected(self):
        # A approves B and B approves A: a cycle that never
        # reaches the root must not verify for either node.
        for node in ("bob", "carol"):
            out = run_bridge("promote", "--node", node, "--role", "master",
                             "--approve-by", "alice", env=self.env)
            self.assertEqual(out.returncode, 0, out.stderr)
        reg = json.loads(self.registry_path.read_text())
        for node, approver in (("bob", "carol"), ("carol", "bob")):
            entry = reg["nodes"][node]
            entry["role_certificate"] = bridge.sign_role_certificate(
                node, "master", bridge.ROLES["master"],
                entry["fingerprint"], approver)
        self._write_registry(reg)
        self.assertFalse(bridge.verify_role_certificate(
            "bob", reg["nodes"]["bob"], reg))
        self.assertFalse(bridge.verify_role_certificate(
            "carol", reg["nodes"]["carol"], reg))

    def test_h1_derived_root_fails_closed_on_tamper(self):
        # Without a pin file, the root is derived from the
        # registry: exactly one self-signed master. An intact
        # registry derives alice; a tampered one (two self-signed
        # masters) has no root at all, so every certificate fails
        # closed rather than trusting the forgery.
        pin_path = bridge.root_pin_path()
        pin_path.unlink(missing_ok=True)
        self.assertTrue(bridge.verify_role_certificate(
            "alice", self.registry["nodes"]["alice"],
            self.registry))
        self.assertTrue(bridge.verify_role_certificate(
            "bob", self.registry["nodes"]["bob"], self.registry))
        reg = self._tamper_bob_to_master()
        self.assertIsNone(bridge.load_root_pin(reg))
        self.assertFalse(bridge.verify_role_certificate(
            "bob", reg["nodes"]["bob"], reg))
        self.assertFalse(bridge.verify_role_certificate(
            "alice", reg["nodes"]["alice"], reg))

    def test_h1_pin_root_command(self):
        out = run_bridge("pin-root", "--node", "alice", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        pin = json.loads(bridge.root_pin_path().read_text())
        self.assertEqual(pin["node"], "alice")
        self.assertEqual(pin["fingerprint"],
                         self.registry["nodes"]["alice"]["fingerprint"])
        # Pinning a non-root refuses.
        out = run_bridge("pin-root", "--node", "bob", env=self.env)
        self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)
        # And pinning refuses when the registry is tampered.
        self._tamper_bob_to_master()
        bridge.root_pin_path().unlink(missing_ok=True)
        out = run_bridge("pin-root", env=self.env)
        self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)

    # M1: thread wikis are signed — a forged fact or turn is
    # flagged, not served as memory.

    def _make_thread(self, name="demo"):
        out = run_bridge("ask", "--bus", str(self.bus), "--sender", "carol",
                         "--to", "alice", "--prompt", "What is 6 times 7?",
                         "--thread", name, env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        prompt_id = out.stdout.strip().splitlines()[0]
        out = run_bridge("reply", "--bus", str(self.bus), "--id", prompt_id,
                         "--text", "42", "--from-node", "alice",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        out = run_bridge("note", "--bus", str(self.bus), "--thread", name,
                         "--text", "The answer is 42.", "--sender", "alice",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        return prompt_id

    def test_m1_legit_wiki_verifies(self):
        self._make_thread()
        out = run_bridge("thread", "--bus", str(self.bus), "--id", "demo",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("facts.md verified", out.stdout)
        self.assertIn("rules.md verified", out.stdout)
        self.assertNotIn("TAMPERED", out.stdout)
        self.assertNotIn("UNVERIFIED", out.stdout)

    def test_m1_archived_turns_still_verify(self):
        # A turn whose envelopes were swept into bus-archive-*/
        # read/ is still genuine: the history check scans the
        # archive too, instead of flagging real turns
        # UNVERIFIED (a false positive that would teach the
        # operator to ignore the flag).
        prompt_id = self._make_thread()
        # reply moves the prompt to read/<to>/; the answer stays
        # in answers/ until fetch-answer reads it.
        prompt_file = self.dirs["read"] / "alice" / f"{prompt_id}.json"
        answer_file = self.dirs["answers"] / f"{prompt_id}.json"
        self.assertTrue(prompt_file.exists())
        self.assertTrue(answer_file.exists())
        arch_read = self.bus.parent / "bus-archive-20261107" / "read" / "alice"
        arch_ans = self.bus.parent / "bus-archive-20261107" / "answers"
        arch_read.mkdir(parents=True)
        arch_ans.mkdir(parents=True)
        shutil.move(str(prompt_file), str(arch_read / prompt_file.name))
        shutil.move(str(answer_file), str(arch_ans / answer_file.name))
        out = run_bridge("thread", "--bus", str(self.bus), "--id", "demo",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertNotIn("UNVERIFIED", out.stdout)
        self.assertIn("facts.md verified", out.stdout)

    def test_m1_forged_facts_flagged_tampered(self):
        self._make_thread()
        facts = self.dirs["threads"] / "demo" / "facts.md"
        with facts.open("a") as f:
            f.write("\n- FORGED: the password is hunter2\n")
        out = run_bridge("thread", "--bus", str(self.bus), "--id", "demo",
                         env=self.env)
        self.assertIn("TAMPERED", out.stdout)
        self.assertIn("facts.md TAMPERED", out.stdout)
        out = run_bridge("context", "--bus", str(self.bus),
                         "--thread", "demo", "--query", "password",
                         env=self.env)
        self.assertIn("TAMPERED", out.stdout)

    def test_m1_forged_history_section_flagged_only_that_section(self):
        prompt_id = self._make_thread()
        history = self.dirs["threads"] / "demo" / "history.md"
        text = history.read_text().replace("\n42\n", "\n43\n")
        history.write_text(text)
        out = run_bridge("thread", "--bus", str(self.bus), "--id", "demo",
                         env=self.env)
        # The forged answer flags; the genuine question still
        # verifies (they share an id — verification is per
        # section, not per id).
        lines = out.stdout.splitlines()
        q = [l for l in lines if l.startswith("## Q " + prompt_id)][0]
        a = [l for l in lines if l.startswith("## A " + prompt_id)][0]
        self.assertNotIn("UNVERIFIED", q)
        self.assertIn("UNVERIFIED", a)

    def test_m1_sign_thread_repairs(self):
        self._make_thread()
        facts = self.dirs["threads"] / "demo" / "facts.md"
        with facts.open("a") as f:
            f.write("\n- FORGED: the password is hunter2\n")
        out = run_bridge("thread", "--bus", str(self.bus), "--id", "demo",
                         env=self.env)
        self.assertIn("TAMPERED", out.stdout)
        out = run_bridge("sign-thread", "--bus", str(self.bus),
                         "--thread", "demo", "--sender", "alice",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        out = run_bridge("thread", "--bus", str(self.bus), "--id", "demo",
                         env=self.env)
        self.assertNotIn("TAMPERED", out.stdout)
        self.assertIn("facts.md verified", out.stdout)

    def test_m1_unauthorized_signer_refused(self):
        self._make_thread()
        out = run_bridge("sign-thread", "--bus", str(self.bus),
                         "--thread", "demo", "--sender", "bob",
                         env=self.env)
        self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)
        # A manifest entry "signed" by bob (worker) for the facts
        # does not verify either.
        manifest_path = self.dirs["threads"] / "demo" / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        facts = self.dirs["threads"] / "demo" / "facts.md"
        digest = bridge.hashlib.sha256(facts.read_bytes()).hexdigest()
        payload = bridge._wiki_manifest_payload(
            "demo", "facts.md", digest, bridge.utcnow())
        sig = bridge._sign_bytes(payload.encode(), "bob")
        manifest["files"]["facts.md"] = {
            "sha256": digest, "signed_by": "bob",
            "signature": bridge.base64.b64encode(sig).decode(),
            "updated_at": bridge.utcnow()}
        manifest_path.write_text(json.dumps(manifest, indent=2))
        status = bridge._verify_wiki_manifest(self.dirs, "demo",
                                              self.registry)
        self.assertEqual(status["facts.md"][0], "tampered")

    def test_m1_note_by_worker_not_signed(self):
        # A worker noting a fact changes facts.md without a valid
        # signature for the change (bob may not sign this wiki),
        # so the file no longer matches its manifest: tampered,
        # not verified — never silently trusted.
        self._make_thread()
        out = run_bridge("note", "--bus", str(self.bus), "--thread", "demo",
                         "--text", "A worker wrote this.", "--sender", "bob",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        out = run_bridge("thread", "--bus", str(self.bus), "--id", "demo",
                         env=self.env)
        self.assertIn("facts.md TAMPERED", out.stdout)
        self.assertNotIn("facts.md verified", out.stdout)

    # M2: replaying a completed task must not flip its outcome
    # to "rejected".

    def test_m2_replay_completed_task_no_second_rejection(self):
        task_id = f"task-m2-{uuid.uuid4().hex[:6]}"
        signed = self._signed(self._task_env(task_id), "alice")
        (self.dirs["tasks"] / f"{task_id}.json").write_text(
            json.dumps(signed, indent=2))
        done = bridge.poll_once(self.bus, "bob", self.project_root,
                                self.registry, agent_cmd=[str(self.stub)])
        self.assertEqual(done, task_id)
        result_path = self.dirs["results"] / f"{task_id}.json"
        self.assertTrue(result_path.exists())
        self.assertEqual(
            _read_payload(result_path, self.registry)["result"]["status"],
            "ok")
        # wait() shows the genuine result and moves it to read/.
        out = run_bridge("wait", "--bus", str(self.bus), "--id", task_id,
                         "--timeout-s", "10", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertFalse(result_path.exists())
        self.assertTrue((self.dirs["read"] / "alice" /
                         f"{task_id}.json").exists())
        # Replay the completed task: the worker must not write a
        # fresh rejection for it.
        shutil.copyfile(self.dirs["done"] / f"{task_id}.json",
                        self.dirs["tasks"] / f"{task_id}.json")
        # The replay is skipped, not processed: poll_once returns
        # None (no task done), and — the point of M2 — writes no
        # rejection.
        done = bridge.poll_once(self.bus, "bob", self.project_root,
                                self.registry, agent_cmd=[str(self.stub)])
        self.assertIsNone(done)
        self.assertFalse(result_path.exists(),
                         "replay wrote a second (rejected) result")
        self.assertTrue((self.dirs["read"] / "alice" /
                         f"{task_id}.json").exists(),
                        "genuine result must survive the replay")

    def test_m2_relay_reject_skips_delivered(self):
        task_id = f"task-m2r-{uuid.uuid4().hex[:6]}"
        task = self._signed(self._task_env(task_id), "alice")
        (self.dirs["done"] / f"{task_id}.json").write_text(
            json.dumps(task, indent=2))
        genuine = self._signed(self._result_env(task_id), "bob")
        (self.dirs["read"] / "alice").mkdir(parents=True, exist_ok=True)
        (self.dirs["read"] / "alice" / f"{task_id}.json").write_text(
            json.dumps(genuine, indent=2))
        r = relay.Relay(self.bus, self.registry)
        self.assertFalse(r._reject(task, "replayed envelope id"),
                         "relay must not reject an already-delivered task")
        self.assertFalse((self.dirs["results"] /
                          f"{task_id}.json").exists())

    # M3: the rate limit is per node, the socket cap counts
    # sockets, and a superseded connection is closed.

    def test_m3_limiter_shared_across_connections(self):
        r = relay.Relay(self.bus, self.registry)
        r.limiters["bob"] = relay.RateLimiter(limit=3, window=60)
        first = r.limiter_for("bob")
        self.assertIs(first, r.limiter_for("bob"),
                      "one node, one limiter — not one per connection")
        self.assertTrue(first.allow())
        self.assertTrue(first.allow())
        self.assertTrue(first.allow())
        self.assertFalse(first.allow())
        # A "new connection" gets the same exhausted limiter.
        self.assertFalse(r.limiter_for("bob").allow())

    def test_m3_socket_cap_counts_sockets(self):
        r = relay.Relay(self.bus, self.registry)
        old_max = relay.MAX_CONNECTIONS
        relay.MAX_CONNECTIONS = 2
        try:
            socks = [socket.socketpair()[0] for _ in range(4)]
            conns = [relay.SocketConn(s) for s in socks]
            ok, old = r.register_connection("bob", conns[0])
            self.assertTrue(ok)
            self.assertIsNone(old)
            ok, old = r.register_connection("carol", conns[1])
            self.assertTrue(ok)
            # Two sockets live: the cap is reached. A third node
            # is refused — and one node holding many sockets
            # would occupy many slots, not one.
            ok, old = r.register_connection("eve", conns[2])
            self.assertFalse(ok)
            self.assertIsNone(old)
            # But bob reconnecting supersedes his own socket
            # 1-for-1 (net count unchanged), so it is allowed
            # even at the cap — and returns the old connection
            # for the caller to close.
            ok, old = r.register_connection("bob", conns[3])
            self.assertTrue(ok)
            self.assertIs(old, conns[0])
            self.assertEqual(len(r.live_sockets), 2)
            self.assertNotIn(conns[0], r.live_sockets)
            r.unregister_connection("bob", conns[3])
            r.unregister_connection("carol", conns[1])
        finally:
            relay.MAX_CONNECTIONS = old_max
            for s in socks:
                s.close()

    def test_m3_superseded_connection_closed_live(self):
        port = 18790
        proc = self._start_relay(port)
        try:
            def hello_sock(nonce):
                hello = json.dumps({"type": "hello", "node": "bob",
                                    "nonce": nonce}, sort_keys=True,
                                   separators=(",", ":"))
                s = socket.create_connection(("127.0.0.1", port), timeout=5)
                s.sendall((link._sign_line("bob", hello) + "\n").encode())
                self.assertIn(b"welcome", s.recv(4096))
                return s
            s1 = hello_sock("m3-nonce-1")
            s1.settimeout(3)
            s2 = hello_sock("m3-nonce-2")
            # The first connection is closed at once by the relay.
            try:
                data = s1.recv(4096)
            except socket.timeout:
                data = b"data"
            self.assertEqual(data, b"",
                             "superseded connection must be closed")
            # And an envelope sent on it is never processed.
            task_id = f"task-m3-{uuid.uuid4().hex[:6]}"
            env = self._signed(self._task_env(task_id), "alice")
            line = link._sign_line(
                "alice", json.dumps({"type": "envelope", "envelope": env},
                                    sort_keys=True,
                                    separators=(",", ":"))) + "\n"
            try:
                s1.sendall(line.encode())
            except OSError:
                pass  # already closed — also fine
            time.sleep(0.5)
            self.assertFalse((self.dirs["tasks"] /
                              f"{task_id}.json").exists())
            s2.close()
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    # L2: rekey is atomic — backups exist, and a failed swap
    # restores the previous files.

    def test_l2_rekey_keeps_backups_and_node_works(self):
        out = run_bridge("rekey", "--node", "carol", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        key_bak = self.passphrases_dir / "carol.bak"
        enc_bak = self.keys_dir / "carol.pem.bak"
        self.assertTrue(key_bak.exists(), "old key file backup missing")
        self.assertTrue(enc_bak.exists(), "old ciphertext backup missing")
        # The old backup still decrypts with the old key: the
        # node is recoverable from the .bak files alone.
        old_key = key_bak.read_text().strip()
        pem = bridge._openssl_enc(enc_bak.read_bytes(), old_key,
                                  decrypt=True)
        self.assertIn(b"PRIVATE KEY", pem)
        # And the node still signs with its new key.
        env = self._signed(self._prompt_env("prompt-l2"), "carol")
        self.assertTrue(bridge.verify(env, self.registry)[0])

    def test_l2_restore_helper(self):
        target = self.tmp / "restore-me.txt"
        target.write_text("original")
        created = self.tmp / "restore-created.txt"
        backups = bridge._backup_key_files([target, created])
        target.write_text("changed")
        created.write_text("new file")
        bridge._restore_key_files(backups)
        self.assertEqual(target.read_text(), "original")
        self.assertFalse(created.exists(),
                         "a file the swap created must be removed")
        # with_suffix replaces the suffix: restore-me.txt -> restore-me.bak
        self.assertTrue((self.tmp / "restore-me.bak").exists())

    # L1: is_relay_rejection verifies the signature itself.

    def test_l1_relay_rejection_checks_signature(self):
        rej = {"v": 2, "id": "task-l1", "from": "relay", "to": "alice",
               "kind": "result", "created_at": "2026-11-07T00:00:00Z",
               "result": {"status": "rejected", "returncode": None,
                          "stdout": "", "stderr": "nope",
                          "started_at": "2026-11-07T00:00:00Z",
                          "finished_at": "2026-11-07T00:00:00Z",
                          "duration_s": 0}}
        # Bob forging a relay rejection: signed by bob, claiming
        # from=relay — must not count as one.
        forged = self._signed(dict(rej), "bob")
        self.assertFalse(bridge.is_relay_rejection(forged, self.registry))
        # The real relay signing it does count.
        genuine = self._signed(dict(rej), "relay")
        self.assertTrue(bridge.is_relay_rejection(genuine, self.registry))

    # L3: shared-passphrase fallback — warning plus a supported
    # way to retire it.

    def _make_legacy_node(self, name="dave"):
        """A node whose key is encrypted with the shared
        passphrase only (pre-migration), like a node created
        before per-node keys."""
        pem = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519"],
            capture_output=True, check=True).stdout
        pub = subprocess.run(
            ["openssl", "pkey", "-pubout"], input=pem,
            capture_output=True, check=True).stdout
        der = subprocess.run(
            ["openssl", "pkey", "-pubout", "-outform", "DER"], input=pem,
            capture_output=True, check=True).stdout
        (self.keys_dir / f"{name}.pub").write_bytes(pub)
        (self.keys_dir / f"{name}.pem.enc").write_bytes(
            bridge._openssl_enc(pem, PASSPHRASE))
        os.chmod(self.keys_dir / f"{name}.pem.enc", 0o600)
        out = run_bridge("trust", "--node", name,
                         "--pubkey", str(self.keys_dir / f"{name}.pub"),
                         "--role", "worker", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(bridge.encryption_key_status(name), "shared")

    def test_l3_retire_refuses_then_succeeds(self):
        shared_file = bridge.shared_passphrase_path()
        shared_file.write_text(PASSPHRASE)
        self._make_legacy_node()
        out = run_bridge("retire-shared-passphrase", env=self.env)
        self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("dave", out.stderr)
        out = run_bridge("rekey", "--node", "dave", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(bridge.encryption_key_status("dave"), "per-node")
        out = run_bridge("retire-shared-passphrase", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertFalse(shared_file.exists())
        self.assertTrue(
            Path(str(shared_file) + ".retired").exists(),
            "retired file is kept as a backup, not deleted")

    def test_l3_registry_warns_shared_nodes(self):
        self._make_legacy_node()
        out = run_bridge("registry", env=self.env)
        self.assertIn("dave", out.stdout)
        self.assertIn("shared (legacy", out.stdout)
        self.assertIn("WARNING", out.stderr)

    # L4: the MCP server can be pointed at another relay.

    def test_l4_mcp_relay_host_port_override(self):
        # A fresh load under the patched env (bridge-mcp.py reads
        # the relay host/port at import time; reload cannot find
        # the hyphenated file through the normal finders, so load
        # it from the path again instead).
        env = dict(os.environ)
        env["AGENC_BRIDGE_RELAY_HOST"] = "127.0.0.2"
        env["AGENC_BRIDGE_RELAY_PORT"] = "18791"
        with mock.patch.dict(os.environ, env):
            spec = importlib.util.spec_from_file_location(
                "bridge_mcp_override", str(ROOT / "bridge-mcp.py"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            self.assertEqual(mod.RELAY_HOST, "127.0.0.2")
            self.assertEqual(mod.RELAY_PORT, 18791)
            seen = {}

            class FakeLink:
                def __init__(self, node, host=None, port=None):
                    seen.update(node=node, host=host, port=port)

                def close(self):
                    pass

            with mock.patch("link.Link", FakeLink):
                mod.make_link("alice")
            self.assertEqual(seen, {"node": "alice", "host": "127.0.0.2",
                                    "port": 18791})

    # L5: MCP per-caller identity — already fixed by the token
    # build; verify the token build covers it (two callers, two
    # tokens, two different senders — not both "agenc-cloud").

    def test_l5_tokens_give_per_caller_identity(self):
        registry = json.loads(self.registry_path.read_text())
        carol_token, _ = bridge.issue_mcp_token(
            registry, "carol", "alice", 30, "alice")
        eve_token, _ = bridge.issue_mcp_token(
            registry, "eve", "alice", 30, "alice")
        old_caller, old_default = (self.mcp.CALLER_NODE,
                                   self.mcp.DEFAULT_TOKEN)
        try:
            self.mcp.CALLER_NODE = "carol"
            self.mcp.DEFAULT_TOKEN = carol_token
            sender, target = self.mcp.resolve_routing_token(
                None, "alice", "ask")
            self.assertEqual((sender, target), ("carol", "alice"))
            self.mcp.CALLER_NODE = "eve"
            self.mcp.DEFAULT_TOKEN = eve_token
            sender, target = self.mcp.resolve_routing_token(
                None, "alice", "ask")
            self.assertEqual((sender, target), ("eve", "alice"))
            # Carol's token does not let eve speak as carol.
            self.mcp.DEFAULT_TOKEN = carol_token
            with self.assertRaises(RuntimeError):
                self.mcp.resolve_routing_token(None, "alice", "ask")
        finally:
            self.mcp.CALLER_NODE, self.mcp.DEFAULT_TOKEN = (
                old_caller, old_default)

    # H1 follow-up: token issuance requires a certified
    # approver — `_resolve_token_approver` used to let any
    # cert-less entry claiming master/owner issue tokens (the
    # old cert-None allowance). It now enforces the same bar
    # as `_resolve_approver`: a certificate present must chain
    # to the root; a certificate absent is allowed only for the
    # sole master (first certification of a legacy root).

    def _make_certless_master(self):
        """A registry entry that claims master but holds no role
        certificate: keygen + trust first (so the key file,
        fingerprint, and public key are real), then strip the
        certificate alice just signed for it. The name is unique
        per call — the L3 tests already create a node called
        "dave", and keygen refuses an existing node."""
        name = f"tok-{uuid.uuid4().hex[:6]}"
        out = run_bridge("keygen", "--node", name, env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        out = run_bridge("trust", "--node", name,
                         "--pubkey", str(self.keys_dir / f"{name}.pub"),
                         "--role", "master", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        reg = json.loads(self.registry_path.read_text())
        reg["nodes"][name]["role_certificate"] = None
        self._write_registry(reg)
        return name

    def test_token_certless_non_sole_master_refused(self):
        dave = self._make_certless_master()
        reg = json.loads(self.registry_path.read_text())
        # Direct check: the resolver refuses dave outright.
        with self.assertRaises(SystemExit):
            bridge._resolve_token_approver(reg, dave)
        # And the CLI refuses to issue, printing no token.
        out = run_bridge("mcp-token", "--from", "carol", "--to", "eve",
                         "--expiry-days", "1", "--approve-by", dave,
                         env=self.env)
        self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("no certified role", out.stderr)
        self.assertNotIn("mcp-", out.stdout)
        # No token was recorded for dave either.
        data = json.loads(self.tokens_path.read_text())
        self.assertEqual(
            [e for e in data["tokens"]
             if e.get("issued_by") == dave], [])

    def test_token_certified_master_can_issue_and_verify(self):
        # A token issued by a certified master verifies — the
        # pre-tightening issuance path is unchanged for issuers
        # that were already valid, so tokens minted before this
        # change keep working.
        out = run_bridge("mcp-token", "--from", "carol", "--to", "eve",
                         "--expiry-days", "1", "--approve-by", "alice",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        token = out.stdout.strip()
        self.assertTrue(token.startswith("mcp-"), token[:12])
        reg = json.loads(self.registry_path.read_text())
        ok, info, reason = bridge.verify_mcp_token(token, reg)
        self.assertTrue(ok, reason)
        self.assertEqual(info["issued_by"], "alice")
        out = run_bridge("mcp-token", "--verify", token, env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("carol -> eve", out.stdout)

    def test_token_certless_sole_master_allowed_then_self_heals(self):
        # Strip alice's certificate: she is the only master in
        # this registry, so the legacy sole-master allowance
        # lets her issue. (Any other cert-less master is refused
        # — see test_token_certless_non_sole_master_refused.)
        reg = json.loads(self.registry_path.read_text())
        reg["nodes"]["alice"]["role_certificate"] = None
        self._write_registry(reg)
        out = run_bridge("mcp-token", "--from", "carol", "--to", "eve",
                         "--expiry-days", "1", "--approve-by", "alice",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        token = out.stdout.strip()
        self.assertTrue(token.startswith("mcp-"), token[:12])
        # The token cannot verify yet: verification requires a
        # valid certificate for the issuer, and alice has none.
        # This is the one corner where issuance and verification
        # diverge — and it self-heals the moment alice
        # certifies herself, which the allowance exists to let
        # her do.
        reg = json.loads(self.registry_path.read_text())
        ok, _, reason = bridge.verify_mcp_token(token, reg)
        self.assertFalse(ok)
        self.assertIn("no longer a master", reason)
        out = run_bridge("trust", "--node", "alice",
                         "--pubkey", str(self.keys_dir / "alice.pub"),
                         "--role", "owner", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        reg = json.loads(self.registry_path.read_text())
        self.assertTrue(bridge.verify_role_certificate(
            "alice", reg["nodes"]["alice"], reg))
        ok, info, reason = bridge.verify_mcp_token(token, reg)
        self.assertTrue(ok, reason)
        self.assertEqual(info["issued_by"], "alice")

    def test_token_issued_by_certless_master_fails_verify(self):
        # Issuance and verification must agree: a token whose
        # issuer holds no certificate dies at verification, even
        # if it was minted directly (bypassing the CLI resolver).
        dave = self._make_certless_master()
        reg = json.loads(self.registry_path.read_text())
        token, _ = bridge.issue_mcp_token(reg, "carol", "eve", 30,
                                          dave)
        ok, _, reason = bridge.verify_mcp_token(token, reg)
        self.assertFalse(ok)
        self.assertIn("no longer a master", reason)

    def test_token_auto_resolution_skips_certless_masters(self):
        # With no certified master left (alice stripped, dave
        # cert-less), auto resolution finds nobody — it must not
        # fall back to a cert-less entry just because a key is
        # on this machine.
        self._make_certless_master()
        reg = json.loads(self.registry_path.read_text())
        reg["nodes"]["alice"]["role_certificate"] = None
        self._write_registry(reg)
        out = run_bridge("mcp-token", "--from", "carol", "--to", "eve",
                         "--expiry-days", "1", env=self.env)
        self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("no master key on this machine", out.stderr)
        self.assertNotIn("mcp-", out.stdout)

    # L6: refused forgeries are swept to dead/ instead of
    # lingering in results/ or answers/.

    def test_l6_wait_sweeps_refused_result_to_dead(self):
        task_id = f"task-l6-{uuid.uuid4().hex[:6]}"
        task = self._signed(self._task_env(task_id, to="eve"), "alice")
        (self.dirs["done"] / f"{task_id}.json").write_text(
            json.dumps(task, indent=2))
        forged = self._signed(
            self._result_env(task_id, frm="carol"), "carol")
        path = self.dirs["results"] / f"{task_id}.json"
        path.write_text(json.dumps(forged, indent=2))
        out = run_bridge("wait", "--bus", str(self.bus), "--id", task_id,
                         "--timeout-s", "10", env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertFalse(path.exists(),
                         "refused result must not linger in results/")
        self.assertTrue((self.dirs["dead"] / f"{task_id}.json").exists(),
                        "refused result must be swept to dead/")

    def test_l6_fetch_answer_sweeps_refused_answer_to_dead(self):
        prompt_id = f"prompt-l6-{uuid.uuid4().hex[:6]}"
        prompt = self._signed(self._prompt_env(prompt_id), "carol")
        (self.dirs["prompts"] / "alice").mkdir(parents=True, exist_ok=True)
        (self.dirs["prompts"] / "alice" / f"{prompt_id}.json").write_text(
            json.dumps(prompt, indent=2))
        forged = self._signed(
            self._answer_env(prompt_id, frm="eve"), "eve")
        path = self.dirs["answers"] / f"{prompt_id}.json"
        path.write_text(json.dumps(forged, indent=2))
        out = run_bridge("fetch-answer", "--bus", str(self.bus),
                         "--id", prompt_id, "--timeout-s", "10",
                         env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertFalse(path.exists(),
                         "refused answer must not linger in answers/")
        self.assertTrue((self.dirs["dead"] / f"{prompt_id}.json").exists(),
                        "refused answer must be swept to dead/")


if __name__ == "__main__":
    unittest.main()
