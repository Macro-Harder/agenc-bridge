#!/usr/bin/env python3
"""Tests for relay-web.py — the AgenC Bridge web relay.

Run with the venv python (needs the `websockets` library):
    .venv/bin/python -m unittest tests.test_relay_web -v

The tests spin up a real relay-web.py on localhost with an isolated
bus, registry, keys, and passphrase, then drive it with WebSocket
clients. Nothing here touches the live bus, registry, or keys.

Covered: signed hello + delivery, forged/unsigned messages,
tampered envelopes, unknown nodes, role permissions (an asker may
not send tasks; a slave may only return results), role
certificates (an uncertified node is ignored; a role changed
without a master's signature is ignored; only a master can
promote a slave), role surfacing in inbox output, replay
rejection, offline catch-up, prompt/answer, and the WebLink
client.
"""
import asyncio
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import bridge
from link import WebLink, _sign_line, _verify_relay_line, _canonical

ROOT = Path(__file__).parent.parent

def _decrypted(envelope, node, registry):
    """A pushed envelope is v3 on the wire; decrypt it as the
    receiving node before asserting on its payload."""
    return bridge.decrypt_envelope(envelope, node, registry)

BASE_PORT = 18766
PASSPHRASE = "test-passphrase-123"


def signed_envelope(env, node, tmpdir):
    """Sign an envelope with bridge's own scheme, without touching
    the bus. Returns the signed dict (signature first)."""
    path = Path(tmpdir) / f"tmp-{env['id']}.json"
    bridge.write_envelope(path, env, node)
    signed = json.loads(path.read_text())
    path.unlink()
    return signed


class TestClient:
    """A raw WebSocket client for the web relay: signed hello, then
    send/receive signed wire lines. Received envelopes land in
    self.received (an asyncio.Queue)."""

    def __init__(self, node, url):
        self.node = node
        self.url = url
        self.received = asyncio.Queue()
        self.ws = None
        self._task = None

    async def connect(self):
        import websockets
        self.ws = await websockets.connect(self.url, max_size=10 * 1024 * 1024)
        hello = {"type": "hello", "node": self.node,
                 "nonce": uuid.uuid4().hex}
        await self.ws.send(_sign_line(self.node, _canonical(hello)))
        reply = await self.ws.recv()
        msg = json.loads(_verify_relay_line(str(reply), self.registry))
        assert msg.get("type") == "welcome", f"no welcome: {msg}"
        self._task = asyncio.create_task(self._listen())

    @property
    def registry(self):
        return bridge.load_registry()

    async def _listen(self):
        try:
            async for raw in self.ws:
                try:
                    msg = json.loads(_verify_relay_line(str(raw), self.registry))
                except Exception:
                    continue
                if msg.get("type") == "envelope":
                    await self.received.put(msg["envelope"])
        except Exception:
            pass

    async def send_envelope(self, envelope):
        line = _sign_line(self.node, _canonical(
            {"type": "envelope", "envelope": envelope}))
        await self.ws.send(line)

    async def send_raw_line(self, line):
        await self.ws.send(line)

    async def close(self):
        if self._task:
            self._task.cancel()
        if self.ws:
            await self.ws.close()


def drain(queue):
    """Collect everything already queued, without waiting."""
    out = []
    while True:
        try:
            out.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            return out


class WebRelayTests(unittest.IsolatedAsyncioTestCase):
    # Keys + registry are shared; each test gets a FRESH bus and a
    # fresh relay subprocess on its own port. That matters: the
    # relay's reconnect catch-up re-pushes everything addressed to a
    # node, so a shared bus would leak earlier tests' envelopes into
    # later ones.
    _counter = 0

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="webrelay-test-"))
        cls.registry_path = cls.tmp / "trusted-keys.json"
        cls.keys_dir = cls.tmp / "keys"
        cls.env = dict(os.environ)
        cls.env.update({
            "AGENC_BRIDGE_KEYS_DIR": str(cls.keys_dir),
            "AGENC_BRIDGE_REGISTRY": str(cls.registry_path),
            "AGENC_BRIDGE_PASSPHRASE": PASSPHRASE,
        })
        # Test nodes: alice (owner/master), bob (worker), carol (asker),
        # slave (slave: results only), dave (slave, for promotion tests),
        # oscar (worker, but NEVER approved — his input must be ignored),
        # relay.
        for node in ("alice", "bob", "carol", "slave", "dave", "oscar", "relay"):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "keygen", "--node", node],
                           env=cls.env, capture_output=True, check=True)
        for node, role in (("alice", "owner"), ("bob", "worker"),
                           ("carol", "asker"), ("slave", "slave"),
                           ("dave", "slave"), ("oscar", "worker"),
                           ("relay", "relay")):
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "trust", "--node", node,
                            "--pubkey", str(cls.keys_dir / f"{node}.pub"),
                            "--role", role],
                           env=cls.env, capture_output=True, check=True)
        # Strip oscar's certificate: he is in the registry, but no
        # master ever approved his role.
        registry = json.loads(cls.registry_path.read_text())
        del registry["nodes"]["oscar"]["role_certificate"]
        cls.registry_path.write_text(json.dumps(registry, indent=2))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _start_relay(self):
        self.proc = subprocess.Popen(
            [str(ROOT / ".venv" / "bin" / "python"), str(ROOT / "relay-web.py"),
             "--host", "127.0.0.1", "--port", str(self.port),
             "--bus", str(self.bus), "--registry", str(self.registry_path)],
            env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        deadline = time.time() + 15
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if "listening" in line:
                return
        else:
            raise RuntimeError("relay-web did not start: "
                               + (self.proc.stdout.read() or ""))

    def _stop_relay(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        try:
            self.proc.stdout.close()
        except Exception:
            pass

    def restart_relay(self):
        """Restart the relay on the same bus/port/registry, so it
        picks up registry changes (a promotion, a tamper)."""
        self._stop_relay()
        self._start_relay()

    def setUp(self):
        # The test process signs with the test keys.
        os.environ["AGENC_BRIDGE_KEYS_DIR"] = str(self.keys_dir)
        os.environ["AGENC_BRIDGE_REGISTRY"] = str(self.registry_path)
        os.environ["AGENC_BRIDGE_PASSPHRASE"] = PASSPHRASE
        self.registry = json.loads(self.registry_path.read_text())
        WebRelayTests._counter += 1
        self.port = BASE_PORT + WebRelayTests._counter
        self.url = f"ws://127.0.0.1:{self.port}"
        self.bus = self.tmp / f"bus-{WebRelayTests._counter}"
        self._start_relay()

    def tearDown(self):
        self._stop_relay()

    def task_envelope(self, frm, to, prompt="do the thing"):
        env = {"v": 2, "id": f"task-{uuid.uuid4().hex[:12]}",
               "from": frm, "to": to, "kind": "task",
               "created_at": "2026-11-07T00:00:00Z",
               "task": {"kind": "prompt", "prompt": prompt, "cwd": ".",
                        "model": "test", "timeout_s": 60, "max_cost_usd": 0.0}}
        return signed_envelope(env, frm, self.tmp)

    def prompt_envelope(self, frm, to, text):
        env = {"v": 2, "id": f"prompt-{uuid.uuid4().hex[:12]}",
               "from": frm, "to": to, "kind": "prompt",
               "created_at": "2026-11-07T00:00:00Z",
               "prompt": {"text": text, "context": ""}}
        return signed_envelope(env, frm, self.tmp)

    def answer_envelope(self, frm, to, prompt_id, text):
        # The answer reuses the prompt's id (that's how bridge.py reply
        # works, and how wait_for finds it).
        env = {"v": 2, "id": prompt_id,
               "from": frm, "to": to, "kind": "answer",
               "created_at": "2026-11-07T00:00:00Z",
               "answer": {"text": text, "in_reply_to": prompt_id}}
        return signed_envelope(env, frm, self.tmp)

    def result_envelope(self, frm, to, task_id):
        env = {"v": 2, "id": task_id,
               "from": frm, "to": to, "kind": "result",
               "created_at": "2026-11-07T00:00:00Z",
               "result": {"status": "ok", "returncode": 0, "stdout": "done",
                          "stderr": "", "started_at": "2026-11-07T00:00:00Z",
                          "finished_at": "2026-11-07T00:00:00Z",
                          "duration_s": 0.1}}
        return signed_envelope(env, frm, self.tmp)

    def message_envelope(self, frm, to, text):
        env = {"v": 2, "id": f"msg-{uuid.uuid4().hex[:12]}",
               "from": frm, "to": to, "kind": "message",
               "created_at": "2026-11-07T00:00:00Z",
               "message": {"text": text, "needs_reply": False,
                           "in_reply_to": ""}}
        return signed_envelope(env, frm, self.tmp)

    async def test_hello_and_task_delivery(self):
        alice = TestClient("alice", self.url)
        bob = TestClient("bob", self.url)
        await alice.connect()
        await bob.connect()
        env = self.task_envelope("alice", "bob")
        await alice.send_envelope(env)
        got = await asyncio.wait_for(bob.received.get(), timeout=10)
        self.assertEqual(got["id"], env["id"])
        self.assertEqual(_decrypted(got, "bob", self.registry)
                         ["task"]["prompt"], "do the thing")
        # The relay also wrote it to the bus (durable record).
        self.assertTrue((self.bus / "tasks" / f"{env['id']}.json").exists())
        await alice.close()
        await bob.close()

    async def test_forged_message_rejected(self):
        import websockets
        alice = TestClient("alice", self.url)
        await alice.connect()
        env = self.task_envelope("alice", "bob")
        # Same envelope, but the wire signature is garbage.
        bad_line = base64.b64encode(b"\x00" * 64).decode() + " " + _canonical(
            {"type": "envelope", "envelope": env})
        await alice.send_raw_line(bad_line)
        with self.assertRaises(websockets.exceptions.ConnectionClosed):
            await asyncio.wait_for(alice.ws.recv(), timeout=5)
        self.assertFalse((self.bus / "tasks" / f"{env['id']}.json").exists())
        await alice.close()

    async def test_tampered_envelope_rejected(self):
        alice = TestClient("alice", self.url)
        bob = TestClient("bob", self.url)
        await alice.connect()
        await bob.connect()
        env = self.task_envelope("alice", "bob")
        # Tamper after signing: flip a byte in the ciphertext —
        # the signature covers header + ciphertext, so this
        # breaks the signature the same way editing the payload
        # did for v2.
        ct = bytearray(base64.b64decode(env["ciphertext"]))
        ct[0] ^= 1
        env["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        await alice.send_envelope(env)
        await asyncio.sleep(1)
        self.assertEqual(drain(bob.received), [])
        self.assertFalse((self.bus / "tasks" / f"{env['id']}.json").exists())
        await alice.close()
        await bob.close()

    async def test_unknown_node_rejected(self):
        import websockets
        # mallory has a key but was never trusted.
        subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                        "keygen", "--node", "mallory"],
                       env=self.env, capture_output=True, check=True)
        mallory = TestClient("mallory", self.url)
        with self.assertRaises(Exception):
            await asyncio.wait_for(mallory.connect(), timeout=5)
        await mallory.close()

    async def test_asker_cannot_send_task_but_can_ask(self):
        carol = TestClient("carol", self.url)
        alice = TestClient("alice", self.url)
        await carol.connect()
        await alice.connect()
        task = self.task_envelope("carol", "alice")
        await carol.send_envelope(task)
        await asyncio.sleep(1)
        self.assertEqual(drain(alice.received), [])
        self.assertFalse((self.bus / "tasks" / f"{task['id']}.json").exists())
        # ...but asking is allowed.
        prompt = self.prompt_envelope("carol", "alice", "what is 2+2?")
        await carol.send_envelope(prompt)
        got = await asyncio.wait_for(alice.received.get(), timeout=10)
        self.assertEqual(got["id"], prompt["id"])
        await carol.close()
        await alice.close()

    async def test_replay_rejected(self):
        alice = TestClient("alice", self.url)
        bob = TestClient("bob", self.url)
        await alice.connect()
        await bob.connect()
        env = self.task_envelope("alice", "bob")
        await alice.send_envelope(env)
        await asyncio.wait_for(bob.received.get(), timeout=10)
        await alice.send_envelope(env)  # same id again
        await asyncio.sleep(1)
        self.assertEqual(drain(bob.received), [])
        await alice.close()
        await bob.close()

    async def test_offline_catchup(self):
        alice = TestClient("alice", self.url)
        await alice.connect()
        env = self.task_envelope("alice", "bob")  # bob is offline
        await alice.send_envelope(env)
        await asyncio.sleep(1)
        self.assertTrue((self.bus / "tasks" / f"{env['id']}.json").exists())
        bob = TestClient("bob", self.url)
        await bob.connect()
        got = await asyncio.wait_for(bob.received.get(), timeout=10)
        self.assertEqual(got["id"], env["id"])
        await alice.close()
        await bob.close()

    async def test_slave_can_only_return_results(self):
        # A slave may return results, but may not task, ask, or
        # message anyone — it can never prompt the master (or anyone
        # else) into an action.
        slave = TestClient("slave", self.url)
        alice = TestClient("alice", self.url)
        await slave.connect()
        await alice.connect()
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        result = self.result_envelope("slave", "alice", task_id)
        await slave.send_envelope(result)
        got = await asyncio.wait_for(alice.received.get(), timeout=10)
        self.assertEqual(got["id"], task_id)
        self.assertEqual(got["kind"], "result")
        self.assertTrue((self.bus / "results" / f"{task_id}.json").exists())
        for kind, sub, helper in (
                ("task", "tasks", lambda: self.task_envelope("slave", "alice")),
                ("prompt", "prompts/alice",
                 lambda: self.prompt_envelope("slave", "alice", "do this?")),
                ("message", "messages/alice",
                 lambda: self.message_envelope("slave", "alice", "hey"))):
            env = helper()
            await slave.send_envelope(env)
            await asyncio.sleep(1)
            self.assertEqual(drain(alice.received), [], f"slave sent a {kind}")
            self.assertFalse((self.bus / sub / f"{env['id']}.json").exists(),
                             f"slave's {kind} reached the bus")
        await slave.close()
        await alice.close()

    async def test_worker_can_still_return_results(self):
        # The result/task permission split must not break workers:
        # a worker returns results (permission "result") and may
        # also send tasks (permission "task").
        bob = TestClient("bob", self.url)
        alice = TestClient("alice", self.url)
        await bob.connect()
        await alice.connect()
        task_id = f"task-{uuid.uuid4().hex[:12]}"
        result = self.result_envelope("bob", "alice", task_id)
        await bob.send_envelope(result)
        got = await asyncio.wait_for(alice.received.get(), timeout=10)
        self.assertEqual(got["kind"], "result")
        await bob.close()
        await alice.close()

    async def test_uncertified_node_ignored(self):
        # Oscar is in the registry, correctly signed, but no master
        # ever approved his role. His envelopes must be ignored.
        oscar = TestClient("oscar", self.url)
        alice = TestClient("alice", self.url)
        await oscar.connect()
        await alice.connect()
        env = self.task_envelope("oscar", "alice")
        await oscar.send_envelope(env)
        await asyncio.sleep(1)
        self.assertEqual(drain(alice.received), [])
        self.assertFalse((self.bus / "tasks" / f"{env['id']}.json").exists())
        await oscar.close()
        await alice.close()

    async def test_role_change_without_authority_ignored(self):
        # Dave is a certified slave: he cannot send tasks.
        dave = TestClient("dave", self.url)
        alice = TestClient("alice", self.url)
        await dave.connect()
        await alice.connect()
        env = self.task_envelope("dave", "alice")
        await dave.send_envelope(env)
        await asyncio.sleep(1)
        self.assertEqual(drain(alice.received), [])
        # Now change dave's role in the registry file to master,
        # WITHOUT a master's signature (the way an attacker would).
        registry = json.loads(self.registry_path.read_text())
        registry["nodes"]["dave"]["role"] = "master"
        registry["nodes"]["dave"]["permissions"] = [
            "task", "result", "ask", "message"]
        self.registry_path.write_text(json.dumps(registry, indent=2))
        self.restart_relay()
        await dave.close()
        await alice.close()
        dave = TestClient("dave", self.url)
        alice = TestClient("alice", self.url)
        await dave.connect()
        await alice.connect()
        env = self.task_envelope("dave", "alice")
        await dave.send_envelope(env)
        await asyncio.sleep(1)
        self.assertEqual(drain(alice.received), [],
                         "a role changed without authority must be ignored")
        self.assertFalse((self.bus / "tasks" / f"{env['id']}.json").exists())
        # A real promotion — approved by master alice — unlocks it.
        try:
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "promote", "--node", "dave", "--role", "master"],
                           env=self.env, capture_output=True, check=True)
            self.restart_relay()
            await dave.close()
            await alice.close()
            dave = TestClient("dave", self.url)
            alice = TestClient("alice", self.url)
            await dave.connect()
            await alice.connect()
            env = self.task_envelope("dave", "alice")
            await dave.send_envelope(env)
            got = await asyncio.wait_for(alice.received.get(), timeout=10)
            self.assertEqual(got["id"], env["id"])
        finally:
            # Put dave back to slave so the shared registry is clean
            # for the other tests (no restart needed — each test
            # starts a fresh relay).
            subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                            "trust", "--node", "dave",
                            "--pubkey", str(self.keys_dir / "dave.pub"),
                            "--role", "slave"],
                           env=self.env, capture_output=True, check=True)
        await dave.close()
        await alice.close()

    async def test_role_surfaced_in_inbox(self):
        # When a master reads a message, it sees the sender's role
        # — it knows it is talking to a worker, not a master.
        bob = TestClient("bob", self.url)
        alice = TestClient("alice", self.url)
        await bob.connect()
        await alice.connect()
        env = self.message_envelope("bob", "alice", "status: all good")
        await bob.send_envelope(env)
        deadline = time.time() + 10
        path = self.bus / "messages" / "alice" / f"{env['id']}.json"
        while not path.exists() and time.time() < deadline:
            await asyncio.sleep(0.2)
        self.assertTrue(path.exists(), "relay did not deliver the message")
        out = subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                              "inbox", "--bus", str(self.bus),
                              "--node", "alice"],
                             env=self.env, capture_output=True, text=True)
        self.assertIn("from bob (worker)", out.stdout)
        self.assertIn("status: all good", out.stdout)
        await bob.close()
        await alice.close()

    async def test_prompt_answer_over_web(self):
        carol = TestClient("carol", self.url)
        alice = TestClient("alice", self.url)
        await carol.connect()
        await alice.connect()
        prompt = self.prompt_envelope("carol", "alice", "what is 6 times 7?")
        await carol.send_envelope(prompt)
        got = await asyncio.wait_for(alice.received.get(), timeout=10)
        self.assertEqual(got["id"], prompt["id"])
        answer = self.answer_envelope("alice", "carol", prompt["id"], "42")
        await alice.send_envelope(answer)
        back = await asyncio.wait_for(carol.received.get(), timeout=10)
        self.assertEqual(_decrypted(back, "carol", self.registry)
                         ["answer"]["text"], "42")
        await carol.close()
        await alice.close()

    def test_weblink_client_ask_answer(self):
        # WebLink (the class bridge-mcp.py uses) end to end.
        async def run():
            alice = TestClient("alice", self.url)
            await alice.connect()
            link = WebLink("carol", self.url)
            try:
                prompt = self.prompt_envelope("carol", "alice", "what is 3+4?")
                link.send_envelope(prompt)
                got = await asyncio.wait_for(alice.received.get(), timeout=10)
                self.assertEqual(got["id"], prompt["id"])
                answer = self.answer_envelope("alice", "carol", prompt["id"], "7")
                await alice.send_envelope(answer)
                back = link.wait_for(prompt["id"], timeout_s=10, kind="answer")
                self.assertIsNotNone(back)
                self.assertEqual(_decrypted(back, "carol", self.registry)
                                 ["answer"]["text"], "7")
            finally:
                link.close()
                await alice.close()
        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
