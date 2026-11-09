"""Client for the AgenC Bridge relay: authenticate once with your own
Ed25519 key, keep the connection open, receive envelopes as they are
pushed. Every line starts with its signature, and the relay's pushes
are verified against the relay key in the registry.

Usage:
    from link import Link
    link = Link("agenc-cloud")          # connects + authenticates
    link.send_envelope(envelope_dict)   # verified + routed by the relay
    answer = link.wait_for(prompt_id, timeout_s=180)  # pushed, no polling
    link.close()
"""
import base64
import json
import socket
import sys
import threading
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import bridge


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _sign_line(node, line):
    """Sign a wire line with a node's private key. The signature is
    the FIRST part of every message."""
    sig = bridge._sign_bytes(line.encode(), node)
    return base64.b64encode(sig).decode() + " " + line


def _verify_relay_line(line, registry):
    """Verify a relay push: first part must be the relay's valid
    signature. Returns the JSON part, or raises."""
    sig_b64, _, rest = line.partition(" ")
    entry = registry.get("nodes", {}).get("relay")
    if not entry:
        raise ConnectionError("relay key not in registry")
    try:
        sig = base64.b64decode(sig_b64)
    except Exception:
        raise ConnectionError("message rejected: bad signature")
    if not sig_b64 or not bridge._verify_bytes(
            rest.encode(), sig, entry["public_key"]):
        raise ConnectionError("message rejected: bad relay signature")
    return rest


class Link:
    def __init__(self, node, registry=None, host="127.0.0.1", port=8765):
        self.node = node
        self.registry = registry or bridge.load_registry()
        self.sock = socket.create_connection((host, port), timeout=10)
        self.buf = b""
        self.waiters = {}   # envelope id -> [event, envelope]
        self.inbox = {}     # envelopes that arrived before wait_for
        self.lock = threading.Lock()
        nonce = uuid.uuid4().hex
        hello = {"type": "hello", "node": node, "nonce": nonce}
        self._send_raw(hello)
        reply = self._read_line()
        welcome = json.loads(reply)
        if welcome.get("type") != "welcome":
            raise ConnectionError("relay refused authentication")
        if welcome.get("nonce") != nonce:
            # The welcome must echo this connection's nonce. A
            # welcome for another nonce is not an answer to this
            # hello — refuse it rather than trusting the relay.
            raise ConnectionError(
                "relay welcome nonce does not match the hello")
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()

    def _sign_line(self, line):
        return _sign_line(self.node, line)

    def _send_raw(self, obj):
        # The signature is the FIRST part of every message.
        self.sock.sendall((self._sign_line(_canonical(obj)) + "\n").encode())

    def _verify_line(self, line):
        return _verify_relay_line(line, self.registry)

    def _read_line(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("relay closed the connection")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return self._verify_line(line.decode())

    def _listen(self):
        try:
            while True:
                msg = json.loads(self._read_line())
                if msg.get("type") == "envelope":
                    env = msg["envelope"]
                    with self.lock:
                        waiter = self.waiters.get(env.get("id"))
                        if waiter is not None and (
                                waiter[2] is None
                                or waiter[2] == env.get("kind")):
                            waiter[1] = env
                            waiter[0].set()
                        else:
                            # Arrived before wait_for, or a different kind
                            # than the waiter wants (a prompt and its answer
                            # share an id) — keep it, wait_for picks it up.
                            self.inbox[(env.get("id"), env.get("kind"))] = env
        except (ConnectionError, OSError, json.JSONDecodeError):
            pass

    def send_envelope(self, envelope):
        self._send_raw({"type": "envelope", "envelope": envelope})

    def wait_for(self, env_id, timeout_s=180, kind=None):
        """Wait for the envelope with this id. kind narrows it: a
        prompt and its answer share an id, so ask_muse waits for
        kind="answer" and the early prompt can't satisfy it."""
        import threading as _t
        event = _t.Event()
        with self.lock:
            if kind is not None:
                hit = self.inbox.pop((env_id, kind), None)
                if hit is not None:
                    return hit
            else:
                for key in list(self.inbox):
                    if key[0] == env_id:
                        return self.inbox.pop(key)
            self.waiters[env_id] = [event, None, kind]
        try:
            if event.wait(timeout_s):
                with self.lock:
                    return self.waiters[env_id][1]
            return None
        finally:
            with self.lock:
                self.waiters.pop(env_id, None)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class WebLink:
    """Same interface as Link, but over a WebSocket to relay-web.py —
    the relay that works over the internet. Needs the `websockets`
    library (see requirements.txt). The asyncio loop runs in a
    background thread; the caller stays synchronous.

    Usage:
        link = WebLink("agenc-cloud", "wss://relay.example.com:8766")
        link.send_envelope(envelope_dict)
        answer = link.wait_for(prompt_id, timeout_s=180)
        link.close()
    """

    def __init__(self, node, url, registry=None):
        self.node = node
        self.url = url
        self.registry = registry or bridge.load_registry()
        self.waiters = {}   # envelope id -> [event, envelope]
        self.inbox = {}     # envelopes that arrived before wait_for
        self.lock = threading.Lock()
        self._ready = threading.Event()
        self._error = None
        self._loop = None
        self._ws = None
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=15):
            raise ConnectionError("web relay did not answer in time")
        if self._error is not None:
            raise self._error

    def _run_loop(self):
        import asyncio
        import websockets
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._run(websockets))
        except Exception as e:  # noqa: BLE001 - surfaced in __init__/send
            if not self._ready.is_set():
                self._error = e
                self._ready.set()
        finally:
            try:
                self._loop.close()
            except Exception:
                pass

    async def _run(self, websockets):
        nonce = uuid.uuid4().hex
        hello = {"type": "hello", "node": self.node, "nonce": nonce}
        async with websockets.connect(self.url, max_size=10 * 1024 * 1024) as ws:
            self._ws = ws
            await ws.send(_sign_line(self.node, _canonical(hello)))
            reply = await ws.recv()
            welcome = json.loads(_verify_relay_line(str(reply), self.registry))
            if welcome.get("type") != "welcome":
                raise ConnectionError("web relay refused authentication")
            if welcome.get("nonce") != nonce:
                raise ConnectionError(
                    "web relay welcome nonce does not match the hello")
            self._ready.set()
            try:
                async for raw in ws:
                    try:
                        msg = json.loads(_verify_relay_line(str(raw), self.registry))
                    except Exception:
                        continue
                    if msg.get("type") == "envelope":
                        env = msg["envelope"]
                        with self.lock:
                            waiter = self.waiters.get(env.get("id"))
                            if waiter is not None and (
                                    waiter[2] is None
                                    or waiter[2] == env.get("kind")):
                                waiter[1] = env
                                waiter[0].set()
                            else:
                                # Arrived before wait_for, or a different
                                # kind than the waiter wants — keep it.
                                self.inbox[(env.get("id"), env.get("kind"))] = env
            except Exception:
                pass
            finally:
                self._ws = None

    def send_envelope(self, envelope):
        import asyncio
        if self._loop is None or self._ws is None:
            raise ConnectionError("web relay not connected")
        line = _sign_line(self.node, _canonical(
            {"type": "envelope", "envelope": envelope}))
        fut = asyncio.run_coroutine_threadsafe(self._ws.send(line), self._loop)
        fut.result(timeout=10)

    def wait_for(self, env_id, timeout_s=180, kind=None):
        """Wait for the envelope with this id. kind narrows it: a
        prompt and its answer share an id, so ask_muse waits for
        kind="answer" and the early prompt can't satisfy it."""
        import threading as _t
        event = _t.Event()
        with self.lock:
            if kind is not None:
                hit = self.inbox.pop((env_id, kind), None)
                if hit is not None:
                    return hit
            else:
                for key in list(self.inbox):
                    if key[0] == env_id:
                        return self.inbox.pop(key)
            self.waiters[env_id] = [event, None, kind]
        try:
            if event.wait(timeout_s):
                with self.lock:
                    return self.waiters[env_id][1]
            return None
        finally:
            with self.lock:
                self.waiters.pop(env_id, None)

    def close(self):
        if self._loop is not None and self._ws is not None:
            import asyncio
            try:
                fut = asyncio.run_coroutine_threadsafe(self._ws.close(), self._loop)
                fut.result(timeout=5)
            except Exception:
                pass
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception:
                pass
