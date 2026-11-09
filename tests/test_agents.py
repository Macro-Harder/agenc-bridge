#!/usr/bin/env python3
"""Tests for `bridge.py agent` — per-agent nodes.

A thread gives an agent identity, rules, and history, but no
permissions of its own. An agent node is a thread PLUS a node:
its own Ed25519 keypair, its own role in the registry (so it can
have different permissions from the other agents), its own thread
wiki (named after the node), and a place in the served-nodes
list, so the assistant's hook answers prompts addressed to it.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_agents -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import bridge

ROOT = Path(__file__).parent.parent
PASSPHRASE = "test-passphrase-123"


def run_bridge(*argv, env):
    return subprocess.run(
        [sys.executable, str(ROOT / "bridge.py"), *argv],
        env=env, capture_output=True, text=True)


class AgentTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="agent-test-"))
        cls.registry_path = cls.tmp / "trusted-keys.json"
        cls.keys_dir = cls.tmp / "keys"
        cls.served_file = cls.tmp / "served-nodes"
        cls.env = dict(os.environ)
        cls.env.update({
            "AGENC_BRIDGE_KEYS_DIR": str(cls.keys_dir),
            "AGENC_BRIDGE_REGISTRY": str(cls.registry_path),
            "AGENC_BRIDGE_PASSPHRASE": PASSPHRASE,
            "AGENC_BRIDGE_SERVED_NODES": str(cls.served_file),
        })
        # alice is the master on this machine (approves roles).
        subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                        "keygen", "--node", "alice"],
                       env=cls.env, capture_output=True, check=True)
        subprocess.run([sys.executable, str(ROOT / "bridge.py"),
                        "trust", "--node", "alice",
                        "--pubkey", str(cls.keys_dir / "alice.pub"),
                        "--role", "owner"],
                       env=cls.env, capture_output=True, check=True)
        cls.bus = cls.tmp / "bus"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        os.environ["AGENC_BRIDGE_KEYS_DIR"] = str(self.keys_dir)
        os.environ["AGENC_BRIDGE_REGISTRY"] = str(self.registry_path)
        os.environ["AGENC_BRIDGE_PASSPHRASE"] = PASSPHRASE
        os.environ["AGENC_BRIDGE_SERVED_NODES"] = str(self.served_file)
        if self.served_file.exists():
            self.served_file.unlink()

    def test_served_nodes_defaults_to_agenc_cloud(self):
        self.assertEqual(bridge.served_nodes(), ["agenc-cloud"])

    def test_agent_provisions_node_role_thread_and_served(self):
        out = run_bridge("agent", "--name", "demo-agent",
                         "--role", "worker",
                         "--rules", "Answer in one word only.",
                         "--bus", str(self.bus), env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("agent demo-agent ready", out.stdout)
        # Its own keypair.
        self.assertTrue((self.keys_dir / "demo-agent.pem.enc").exists())
        self.assertTrue((self.keys_dir / "demo-agent.pub").exists())
        # Its own role, certified by the master.
        registry = json.loads(self.registry_path.read_text())
        entry = registry["nodes"]["demo-agent"]
        self.assertEqual(entry["role"], "worker")
        self.assertEqual(entry["permissions"],
                         ["task", "result", "ask", "message"])
        self.assertEqual(entry["role_certificate"]["approved_by"], "alice")
        # Its own thread wiki, named after the node, with the rules.
        tdir = self.bus / "threads" / "demo-agent"
        self.assertTrue((tdir / "thread.json").exists())
        self.assertIn("Answer in one word only.",
                      (tdir / "rules.md").read_text())
        # Served by the assistant, alongside agenc-cloud.
        self.assertEqual(bridge.served_nodes(),
                         ["agenc-cloud", "demo-agent"])

    def test_agent_refuses_existing_node(self):
        run_bridge("agent", "--name", "demo-agent", "--role", "worker",
                   "--bus", str(self.bus), env=self.env)
        out = run_bridge("agent", "--name", "demo-agent",
                         "--role", "asker", "--bus", str(self.bus),
                         env=self.env)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("already a node", out.stderr)

    def test_agent_remove_revokes_and_unserves_but_keeps_wiki(self):
        run_bridge("agent", "--name", "demo-agent", "--role", "worker",
                   "--rules", "Answer in one word only.",
                   "--bus", str(self.bus), env=self.env)
        out = run_bridge("agent", "--name", "demo-agent", "--remove",
                         "--bus", str(self.bus), env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        registry = json.loads(self.registry_path.read_text())
        self.assertNotIn("demo-agent", registry["nodes"])
        self.assertEqual(bridge.served_nodes(), ["agenc-cloud"])
        # The thread wiki is kept as history.
        self.assertTrue((self.bus / "threads" / "demo-agent" /
                         "rules.md").exists())

    def test_prompt_to_agent_node_is_listed_for_it(self):
        run_bridge("agent", "--name", "demo-agent", "--role", "worker",
                   "--rules", "Answer in one word only.",
                   "--bus", str(self.bus), env=self.env)
        out = run_bridge("ask", "--bus", str(self.bus),
                         "--to", "demo-agent", "--sender", "alice",
                         "--prompt", "What is 6 times 7?",
                         "--thread", "demo-agent", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        out = run_bridge("prompts", "--bus", str(self.bus),
                         "--node", "demo-agent", env=self.env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("[thread demo-agent]", out.stdout)
        self.assertIn("What is 6 times 7?", out.stdout)


if __name__ == "__main__":
    unittest.main()
