#!/usr/bin/env python3
"""Tests for bridge.run_agent's subprocess contract.

A worker agent must never inherit the poller's stdin: some agent
CLIs (opencode run) read a non-TTY stdin until EOF before they
start, so an inherited open pipe hangs the task until it times
out. run_agent therefore runs every agent with stdin from
/dev/null.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_run_agent -v
"""
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))
import bridge


class RunAgentStdinTests(unittest.TestCase):

    def test_agent_runs_with_stdin_devnull(self):
        completed = subprocess.CompletedProcess(
            ["echo"], 0, stdout="ok", stderr="")
        with mock.patch.object(bridge.subprocess, "run",
                               return_value=completed) as run:
            result = bridge.run_agent("hello", Path("."), 30,
                                      agent_cmd=["echo"])
        self.assertEqual(result["status"], "ok")
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
