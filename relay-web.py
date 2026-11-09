#!/usr/bin/env python3
"""AgenC Bridge — web relay: the same authenticated relay, over the web.

The TCP relay (relay.py) only listens on localhost. This is the same
relay over WebSocket, so nodes on different machines can send each
other signed envelopes over the internet. Same rules, same
handshake — only the transport changes:

- A node connects (ws:// or wss://) and authenticates once with a
  signed hello: the first part of the message is its Ed25519
  signature over the hello, verified against its public key in the
  trusted-keys registry. Unknown node, bad signature, or a message
  without a valid signature first: dropped, connection closed.
- Every message after the hello starts with its signature, too:
  `<base64-signature> <json>` — the same wire line as the TCP
  relay, so the protocol is identical on both transports.
- The relay signs its own pushes with the relay key, so clients
  can verify the relay back.
- Envelopes are verified on receipt (signature, known sender, the
  sender's role allows that kind, the recipient is a known node,
  and — for tasks, prompts, and messages — the id was never seen
  before; results and answers share their task/prompt id, so their
  replay protection is the reader binding them to the node the
  task/prompt was addressed to, in bridge.py wait / fetch-answer)
  and written to the bus, which stays the durable record. The relay
  is the fast path: connected nodes get pushes within 0.5s via the
  bus watcher; offline nodes pick envelopes up from the bus when
  they reconnect.

Run (needs the websockets library — see requirements.txt):
  .venv/bin/python relay-web.py [--host 127.0.0.1] [--port 8766]
      [--bus PATH] [--registry PATH] [--cert CERT] [--key KEY]

--host defaults to 127.0.0.1 (safe). To expose it to the internet,
pass --host 0.0.0.0 and put TLS in front of it: either --cert/--key
here for wss:// directly, or a reverse proxy (Caddy/nginx) that
terminates TLS and forwards plain ws:// to this port. The relay
itself never sees a password or a secret — authentication is the
node's Ed25519 key, checked against the registry on every message.

Clients connect with link.py's WebLink (same interface as Link).
The MCP server (bridge-mcp.py) uses it when AGENC_BRIDGE_WEB_RELAY
is set, e.g. AGENC_BRIDGE_WEB_RELAY=wss://relay.example.com:8766.
"""
import argparse
import asyncio
import json
import ssl
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import bridge
from relay import Relay, _check_line, check_relay_key

HOST = "127.0.0.1"
PORT = 8766


class WSConn:
    """A relay connection over a WebSocket. Same send_line interface
    as relay.SocketConn, so Relay.push works unchanged. The bus
    watcher runs in a thread, so sends are scheduled onto the
    asyncio loop thread-safely."""

    def __init__(self, ws, loop):
        self.ws = ws
        self.loop = loop

    def send_line(self, line):
        fut = asyncio.run_coroutine_threadsafe(self.ws.send(line), self.loop)
        fut.add_done_callback(self._sent)

    @staticmethod
    def _sent(fut):
        try:
            fut.result()
        except Exception:
            pass  # peer gone — the handler's finally cleans up

    def close(self):
        """Close the WebSocket (fire-and-forget: the caller is on
        the loop thread, so it must not wait on the close). The
        handler's `async for` then ends and its finally cleans
        up — a superseded connection stops serving instead of
        lingering for sends."""
        try:
            asyncio.run_coroutine_threadsafe(self.ws.close(), self.loop)
        except Exception:
            pass


async def handle(ws, relay, loop):
    node = None
    conn = None
    try:
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=10)
        except (asyncio.TimeoutError, Exception):
            return
        sender, hello = _check_line(str(raw).strip(), relay.registry)
        if hello is None or hello.get("type") != "hello":
            return  # no valid signature first — reject immediately
        node = sender
        # A hello is single-use (see relay.py): a replayed hello
        # would displace the real connection and receive its
        # pushes. Check before registering, under the lock.
        # Registration also enforces the socket cap (counted in
        # live sockets, not node names) and returns any superseded
        # connection for this node, which is closed at once.
        conn = WSConn(ws, loop)
        with relay.lock:
            if not relay.check_hello_nonce(node, hello.get("nonce", "")):
                print(f"web relay: {node} hello nonce reused — dropping",
                      flush=True)
                return
            ok, old = relay._register_locked(node, conn)
            if not ok:
                print("web relay: connection cap reached — dropping",
                      flush=True)
                return
        if old is not None:
            old.close()
        welcome = {"type": "welcome", "nonce": hello.get("nonce", "")}
        welcome_line = json.dumps(welcome, sort_keys=True,
                                  separators=(",", ":"))
        try:
            await ws.send(relay._sign_line(welcome_line))
        except (Exception, SystemExit) as e:
            print(f"web relay: cannot sign welcome for {node}: {e}",
                  flush=True)
            return
        print(f"web relay: {node} connected", flush=True)
        # Catch-up: push live mail already waiting for this node.
        relay.catch_up(node)
        # The rate limit is per node, shared across this node's
        # connections — reconnecting does not reset it.
        limiter = relay.limiter_for(node)
        async for raw in ws:
            line = str(raw).strip()
            if not limiter.allow():
                print(f"web relay: {node} exceeded the line rate — "
                      f"dropping", flush=True)
                return
            sender, msg = _check_line(line, relay.registry)
            if msg is None:
                print(f"web relay: {node} sent a message without a valid "
                      f"signature — dropping", flush=True)
                return
            if msg.get("type") == "envelope":
                relay.handle_envelope(msg["envelope"])
    finally:
        if node and conn is not None:
            relay.unregister_connection(node, conn)
            print(f"web relay: {node} disconnected", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--bus", default=str(Path.home() / "workspace" / "agenc-bridge" / "bus"))
    ap.add_argument("--registry", default=None)
    ap.add_argument("--cert", default=None, help="TLS cert for wss://")
    ap.add_argument("--key", default=None, help="TLS key for wss://")
    args = ap.parse_args()
    check_relay_key()
    registry = bridge.load_registry(args)
    relay = Relay(args.bus, registry, name="web")
    threading.Thread(target=relay.watch_bus, daemon=True).start()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def serve():
        import websockets
        ssl_ctx = None
        if args.cert and args.key:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(args.cert, args.key)
        scheme = "wss" if ssl_ctx else "ws"
        async with websockets.serve(
                lambda ws: handle(ws, relay, loop),
                args.host, args.port, ssl=ssl_ctx):
            print(f"web relay listening on {scheme}://{args.host}:{args.port} "
                  f"(bus {args.bus})", flush=True)
            await asyncio.Future()  # run forever

    loop.run_until_complete(serve())


if __name__ == "__main__":
    main()
