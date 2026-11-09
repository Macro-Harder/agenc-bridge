#!/usr/bin/env python3
"""Hands-free registry distribution tests.

Rotation already ran hands-free on one machine; the human step
was copying the updated registry (new encryption public keys +
attestations) to every other machine. Distribution now closes
that loop: rotate-keys distributes the updated registry as a
signed registry-update envelope (v3, encrypted per-pipe, like
any other envelope), and each node applies it hands-free — in
its poll cycle, in the hook, or via `registry-pull` — after
validating it exactly like resync (root pin, certificate chains,
enc attestations) and checking the sequence is newer than the
one it already holds. Public keys and attestations only — a
registry update never carries a private key.

A node that was offline at rotation time picks the update up
when it reconnects: the envelope stays in
bus/registry-updates/<node>/ until applied, the relay pushes it
live and catches it up on reconnect, and the 48h grace window
means a pre-rotation message still decrypts after the update
lands. A tampered, unsigned, or worker-sent update is refused
and filed in dead/; a decrypt failure leaves the envelope
pending (never silently dropped).

These tests use isolated keys, passphrases, registry, tokens
file, and bus; nothing here touches the live bus, registry, or
keys.

Run with the system python:
    python3 -m unittest tests.test_distribution -v
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import bridge
import relay

ROOT = Path(__file__).parent.parent
PASSPHRASE = "test-passphrase-123"


def run_bridge(*argv, env, inp=None):
    return subprocess.run(
        [sys.executable, str(ROOT / "bridge.py"), *argv],
        env=env, input=inp, capture_output=True, text=True)


class DistributionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="dist-test-"))
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
        # alice: owner (the distributor — a certified master with
        # its key here). bob: worker. carol: asker. t1: asker.
        # relay: relay (holds its registry in memory, never
        # decrypts — it gets no update).
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

    def _registry(self):
        return json.loads(self.registry_path.read_text())

    def _seq(self):
        return bridge._registry_seq(self._registry())

    def _rotate_bob(self):
        """Rotate bob's keys (distributes automatically) and
        return (seq_before, seq_after)."""
        before = self._seq()
        out = run_bridge("rotate-keys", "--node", "bob",
                         "--bus", str(self.bus), env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        return before, self._seq()

    def _pending(self, node):
        d = self.dirs["registry-updates"] / node
        return sorted(d.glob("*.json")) if d.exists() else []

    def _craft_update(self, sender, to, registry_payload, env=None):
        """Write a registry-update envelope signed by `sender`
        (v3, encrypted to `to`) and return its path. The caller
        supplies the registry dict the payload carries — a
        tampered or stale one, to test refusal and skipping."""
        env = env or self.env
        reg = dict(registry_payload)
        env_dict = {
            "id": f"regupd-{uuid.uuid4().hex[:12]}",
            "from": sender, "to": to, "kind": "registry-update",
            "created_at": bridge.utcnow(),
            "registry_update": {
                "registry": reg,
                "seq": bridge._registry_seq(reg),
            },
        }
        path = self.tmp / f"craft-{uuid.uuid4().hex[:8]}.json"
        bridge.write_envelope(path, env_dict, sender, self._registry())
        return path

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
        out = run_bridge("rotate-keys", "--node", node,
                         "--bus", str(self.bus), env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        return retired

    # --- rotate distributes ---

    def test_rotate_distributes_registry(self):
        before, after = self._rotate_bob()
        self.assertEqual(after, before + 1)
        # Every node except the distributor (alice) and the relay
        # gets one update envelope; the relay never decrypts, so
        # it gets none.
        for node in ("bob", "carol", "t1"):
            self.assertEqual(len(self._pending(node)), 1, node)
        self.assertEqual(self._pending("alice"), [])
        self.assertEqual(self._pending("relay"), [])
        # The envelope is v3, signed, and carries the new
        # registry — public keys and attestations only.
        env = json.loads(self._pending("bob")[0].read_text())
        self.assertEqual(env["kind"], "registry-update")
        self.assertEqual(env["from"], "alice")
        self.assertEqual(env["to"], "bob")
        self.assertEqual(env["v"], 3)
        plain = bridge.decrypt_envelope(env, "bob", self._registry())
        carried = plain["registry_update"]["registry"]
        self.assertEqual(carried, self._registry())
        # The sequence rides in the registry itself.
        self.assertEqual(bridge._registry_seq(carried), after)
        dump = json.dumps(carried)
        self.assertNotIn("PRIVATE KEY", dump)
        for node_entry in carried["nodes"].values():
            self.assertFalse(
                any("private" in k.lower()
                    for k in node_entry), node_entry)

    def test_distribute_registry_to_one_node(self):
        before, after = self._rotate_bob()
        # Rotate already distributed to all three; a targeted
        # re-distribution reaches only carol.
        out = run_bridge("distribute-registry", "--to", "carol",
                         "--bus", str(self.bus), env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f"distributed registry seq {after + 1}",
                      out.stdout)
        self.assertEqual(len(self._pending("carol")), 2)
        self.assertEqual(len(self._pending("bob")), 1)
        self.assertEqual(len(self._pending("t1")), 1)

    def test_rotate_no_distribute_opt_out(self):
        out = run_bridge("rotate-keys", "--node", "bob",
                         "--bus", str(self.bus), "--no-distribute",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("distribution skipped (--no-distribute)",
                      out.stdout)
        for node in ("bob", "carol", "t1"):
            self.assertEqual(self._pending(node), [])

    # --- pull applies ---

    def test_registry_pull_applies_update(self):
        # A stale copy of the registry — the other machine's view
        # before the rotation.
        stale_path = self.tmp / f"stale-{uuid.uuid4().hex[:8]}.json"
        stale_path.write_text(self.registry_path.read_text())
        stale_before = json.loads(stale_path.read_text())
        before, after = self._rotate_bob()
        out = run_bridge("--registry", str(stale_path), "registry-pull",
                         "--node", "bob", "--bus", str(self.bus),
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f"bob: applied registry seq {after}", out.stdout)
        stale = json.loads(stale_path.read_text())
        self.assertEqual(bridge._registry_seq(stale), after)
        self.assertEqual(
            stale["nodes"]["bob"]["enc_key_id"],
            self._registry()["nodes"]["bob"]["enc_key_id"])
        self.assertNotEqual(
            stale["nodes"]["bob"]["enc_key_id"],
            stale_before["nodes"]["bob"]["enc_key_id"])
        # Applied: the envelope moved to read/bob/, and the
        # applied-seq sidecar records it.
        self.assertEqual(self._pending("bob"), [])
        self.assertEqual(
            len(list((self.dirs["read"] / "bob").glob("*.json"))), 1)
        applied = json.loads(
            (self.dirs["registry-updates"] / ".applied-bob.json")
            .read_text())
        self.assertEqual(applied.get("seq"), after)

    def test_poll_applies_pending_update(self):
        stale_path = self.tmp / f"stale-{uuid.uuid4().hex[:8]}.json"
        stale_path.write_text(self.registry_path.read_text())
        before, after = self._rotate_bob()
        stale_env = dict(self.env)
        stale_env["AGENC_BRIDGE_REGISTRY"] = str(stale_path)
        # The poll runs with the stale registry: its first cycle
        # must apply the pending update before running tasks.
        # (poll returns when no task is waiting — there is no
        # --once flag; a single cycle is all this needs.)
        out = run_bridge("poll", "--bus", str(self.bus), "--node", "bob",
                         "--project-root", str(self.project),
                         "--agent-cmd", "echo", env=stale_env)
        self.assertEqual(out.returncode, 0, out.stderr)
        stale = json.loads(stale_path.read_text())
        self.assertEqual(bridge._registry_seq(stale), after)
        self.assertEqual(
            stale["nodes"]["bob"]["enc_key_id"],
            self._registry()["nodes"]["bob"]["enc_key_id"])
        self.assertEqual(self._pending("bob"), [])

    # --- refusal ---

    def test_tampered_update_refused(self):
        stale_path = self.tmp / f"stale-{uuid.uuid4().hex[:8]}.json"
        stale_path.write_text(self.registry_path.read_text())
        stale_seq = bridge._registry_seq(json.loads(
            stale_path.read_text()))
        # --no-distribute, so the only pending envelope is the
        # crafted one below — a legit distribution would be
        # applied first and change the stale registry.
        out = run_bridge("rotate-keys", "--node", "bob",
                         "--bus", str(self.bus), "--no-distribute",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        # A registry-update whose payload has alice's encryption
        # key swapped: the attestation no longer matches, so the
        # whole update must be refused — and the stale registry
        # left untouched. The payload seq is bumped past the
        # stale one so the update reaches validation instead of
        # being skipped as not-newer.
        tampered = self._registry()
        tampered["nodes"]["alice"]["enc_public_key"] = \
            base64.b64encode(bytes(range(32))).decode()
        tampered["registry_seq"] = stale_seq + 1
        crafted = self._craft_update("alice", "bob", tampered)
        dest = self.dirs["registry-updates"] / "bob" / crafted.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(crafted, dest)
        before_bytes = stale_path.read_bytes()
        out = run_bridge("--registry", str(stale_path), "registry-pull",
                         "--node", "bob", "--bus", str(self.bus),
                         env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("attestation", out.stderr)
        self.assertEqual(stale_path.read_bytes(), before_bytes)
        self.assertEqual(
            len(list(self.dirs["dead"].glob("*.json"))), 1)

    def test_worker_sent_update_refused(self):
        stale_path = self.tmp / f"stale-{uuid.uuid4().hex[:8]}.json"
        stale_path.write_text(self.registry_path.read_text())
        stale_seq = bridge._registry_seq(json.loads(
            stale_path.read_text()))
        # --no-distribute, so the only pending envelope is the
        # crafted one below.
        out = run_bridge("rotate-keys", "--node", "bob",
                         "--bus", str(self.bus), "--no-distribute",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        # bob is a worker: even a payload that would validate
        # must be refused when it comes from him — only a
        # certified master distributes. The payload seq is
        # bumped past the stale one so the update reaches the
        # sender check instead of being skipped as not-newer.
        payload = self._registry()
        payload["registry_seq"] = stale_seq + 1
        crafted = self._craft_update("bob", "bob", payload)
        dest = self.dirs["registry-updates"] / "bob" / crafted.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(crafted, dest)
        before_bytes = stale_path.read_bytes()
        out = run_bridge("--registry", str(stale_path), "registry-pull",
                         "--node", "bob", "--bus", str(self.bus),
                         env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("not a certified master", out.stderr)
        self.assertEqual(stale_path.read_bytes(), before_bytes)
        self.assertEqual(
            len(list(self.dirs["dead"].glob("*.json"))), 1)

    def test_resync_refuses_rollback(self):
        old_path = self.tmp / f"old-{uuid.uuid4().hex[:8]}.json"
        old_path.write_text(self.registry_path.read_text())
        before, after = self._rotate_bob()
        self.assertEqual(after, before + 1)
        before_bytes = self.registry_path.read_bytes()
        out = run_bridge("resync", "--registry", str(old_path),
                         env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("rollback", out.stderr)
        self.assertEqual(self.registry_path.read_bytes(), before_bytes)

    # --- offline catch-up and grace window ---

    def test_offline_catchup_two_seqs_then_older_skipped(self):
        stale_path = self.tmp / f"stale-{uuid.uuid4().hex[:8]}.json"
        stale_path.write_text(self.registry_path.read_text())
        _, seq1 = self._rotate_bob()
        # A second rotation while bob is "offline": both updates
        # wait in his queue.
        out = run_bridge("rotate-keys", "--node", "carol",
                         "--bus", str(self.bus), env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        seq2 = self._seq()
        self.assertEqual(seq2, seq1 + 1)
        self.assertEqual(len(self._pending("bob")), 2)
        out = run_bridge("--registry", str(stale_path), "registry-pull",
                         "--node", "bob", "--bus", str(self.bus),
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        # Both envelopes are handled (pending empties, both land
        # in read/bob/) and the registry ends at the newest seq.
        # Which one applied first is filename order (random ids),
        # so the older may be applied or skipped as not-newer —
        # either way the newest registry wins.
        self.assertIn(str(seq2), out.stdout)
        stale = json.loads(stale_path.read_text())
        self.assertEqual(bridge._registry_seq(stale), seq2)
        self.assertEqual(self._pending("bob"), [])
        self.assertEqual(
            len(list((self.dirs["read"] / "bob").glob("*.json"))), 2)
        # An older update arriving late (fresh id, old registry)
        # is skipped, not an error — the newest registry wins.
        old_reg = None
        for path in (self.dirs["read"] / "bob").glob("*.json"):
            env = json.loads(path.read_text())
            plain = bridge.decrypt_envelope(env, "bob", self._registry())
            if bridge._registry_seq(
                    plain["registry_update"]["registry"]) == seq1:
                old_reg = plain["registry_update"]["registry"]
        self.assertIsNotNone(old_reg)
        crafted = self._craft_update("alice", "bob", old_reg)
        dest = self.dirs["registry-updates"] / "bob" / crafted.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(crafted, dest)
        out = run_bridge("--registry", str(stale_path), "registry-pull",
                         "--node", "bob", "--bus", str(self.bus),
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        # Skipped, not an error — either skip path ("already
        # applied" via the sidecar, or "not newer" via the local
        # registry) is the same outcome.
        self.assertTrue("not newer" in out.stderr
                        or "already applied" in out.stderr, out.stderr)
        stale = json.loads(stale_path.read_text())
        self.assertEqual(bridge._registry_seq(stale), seq2)
        # A superseded update is skipped, not refused: nothing
        # lands in dead/ for it (a refusal there would be noise
        # for ordinary operation — the live hook hit exactly
        # this case when a newer distribution landed first).
        self.assertEqual(list(self.dirs["dead"].glob("*.json")), [])

    def test_grace_window_message_still_decrypts_after_update(self):
        stale_path = self.tmp / f"stale-{uuid.uuid4().hex[:8]}.json"
        stale_path.write_text(self.registry_path.read_text())
        # A task sent to bob under his old key, before rotation.
        out = run_bridge("send", "--bus", str(self.bus), "--to", "bob",
                         "--prompt", "grace window", "--sender", "alice",
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        task_id = out.stdout.strip()
        before, after = self._rotate_bob()
        out = run_bridge("--registry", str(stale_path), "registry-pull",
                         "--node", "bob", "--bus", str(self.bus),
                         env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        # After adopting the update, the pre-rotation task still
        # decrypts: the old key is in enc_prev_keys and its
        # private key is still on disk for the 48h grace window.
        updated = json.loads(stale_path.read_text())
        env = json.loads((self.dirs["tasks"] / f"{task_id}.json")
                         .read_text())
        plain = bridge.decrypt_envelope(env, "bob", updated)
        self.assertEqual(plain["task"]["prompt"], "grace window")

    def test_old_key_destroyed_after_grace(self):
        stale_path = self.tmp / f"stale-{uuid.uuid4().hex[:8]}.json"
        stale_path.write_text(self.registry_path.read_text())
        old_key_id = json.loads(
            stale_path.read_text())["nodes"]["bob"]["enc_key_id"]
        before, after = self._rotate_bob()
        retired = self._expire_and_prune("bob")
        self.assertIn(old_key_id, retired)
        current = self._registry()
        self.assertNotIn(
            old_key_id,
            [p["key_id"] for p in
             current["nodes"]["bob"].get("enc_prev_keys", [])])
        self.assertNotIn(
            old_key_id, bridge.enc_private_key_ids("bob"))
        # A message sent under the destroyed key can no longer
        # be decrypted — the failure is closed, not silent.
        stale_env = dict(self.env)
        stale_env["AGENC_BRIDGE_REGISTRY"] = str(stale_path)
        out = run_bridge("send", "--bus", str(self.bus), "--to", "bob",
                         "--prompt", "too late", "--sender", "alice",
                         env=stale_env)
        self.assertEqual(out.returncode, 0, out.stderr)
        task_id = out.stdout.strip()
        env = json.loads((self.dirs["tasks"] / f"{task_id}.json")
                         .read_text())
        with self.assertRaises(bridge.DecryptError):
            bridge.decrypt_envelope(env, "bob", self._registry())

    # --- relay ---

    def test_default_bus_honors_env(self):
        # Regression: rotate-keys/distribute-registry/
        # registry-pull defaulted --bus to the live path and
        # ignored AGENC_BRIDGE_BUS, so test-suite rotations
        # distributed test registries into the live bus. The
        # default must be the env value when set, the live bus
        # otherwise.
        old = os.environ.get("AGENC_BRIDGE_BUS")
        try:
            os.environ["AGENC_BRIDGE_BUS"] = str(self.bus)
            self.assertEqual(bridge.default_bus(), str(self.bus))
            del os.environ["AGENC_BRIDGE_BUS"]
            self.assertEqual(
                bridge.default_bus(),
                str(Path.home() / "workspace" / "agenc-bridge" / "bus"))
        finally:
            if old is None:
                os.environ.pop("AGENC_BRIDGE_BUS", None)
            else:
                os.environ["AGENC_BRIDGE_BUS"] = old

    def test_relay_forwards_registry_update_and_refuses_worker(self):
        r = relay.Relay(self.bus, self.registry)
        # From alice (owner): routed to bob's update queue.
        env = {
            "id": f"regupd-{uuid.uuid4().hex[:12]}",
            "from": "alice", "to": "bob", "kind": "registry-update",
            "created_at": bridge.utcnow(),
            "registry_update": {
                "registry": self._registry(), "seq": self._seq(),
            },
        }
        path = self.tmp / f"relay-{uuid.uuid4().hex[:8]}.json"
        bridge.write_envelope(path, env, "alice", self._registry())
        signed = json.loads(path.read_text())
        r.handle_envelope(signed)
        self.assertTrue(
            (self.dirs["registry-updates"] / "bob" / f"{env['id']}.json")
            .exists())
        # From bob (worker): dropped, filed in dead/ — a worker
        # never distributes a registry.
        env2 = dict(env)
        env2["id"] = f"regupd-{uuid.uuid4().hex[:12]}"
        env2["from"] = "bob"
        env2["to"] = "carol"
        path2 = self.tmp / f"relay-{uuid.uuid4().hex[:8]}.json"
        bridge.write_envelope(path2, env2, "bob", self._registry())
        signed2 = json.loads(path2.read_text())
        r.handle_envelope(signed2)
        self.assertFalse(
            (self.dirs["registry-updates"] / "carol"
             / f"{env2['id']}.json").exists())
        self.assertEqual(
            len(list(self.dirs["dead"].glob(f"{env2['id']}.json"))), 1)


if __name__ == "__main__":
    unittest.main()
