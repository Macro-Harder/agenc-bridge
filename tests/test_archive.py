#!/usr/bin/env python3
"""Tests for `bridge.py archive` — sweep finished bus items into
a dated archive, so the bus doesn't grow forever.

Only finished dirs move (done/read/dead); live state (tasks,
prompts, answers, messages) never moves, and claimed/ only moves
with --include-claimed. The replay guard (seen/) is never touched.

Run with the system python (stdlib only):
    python3 -m unittest tests.test_archive -v
"""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import bridge

ROOT = Path(__file__).parent.parent
DAY = 24 * 3600


def run_bridge(*argv):
    return subprocess.run(
        [sys.executable, str(ROOT / "bridge.py"), *argv],
        capture_output=True, text=True)


class ArchiveTests(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="archive-test-"))
        self.bus = self.tmp / "bus"
        self.dirs = bridge.bus_dirs(self.bus)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _file(self, subdir, name, age_days):
        p = self.dirs[subdir] / name
        p.write_text("{}")
        old = time.time() - age_days * DAY
        os.utime(p, (old, old))
        return p

    def _archive_root(self):
        import datetime
        return self.tmp / ("bus-archive-" +
                           datetime.datetime.now(
                               datetime.timezone.utc).strftime("%Y%m%d"))

    def test_archives_old_finished_items_only(self):
        self._file("done", "old-task.json", 10)
        self._file("done", "new-task.json", 1)
        self._file("read", "old-result.json", 10)
        self._file("dead", "old-dead.json", 10)
        self._file("tasks", "waiting.json", 10)
        self._file("claimed", "in-flight.json", 10)
        self._file("prompts", "unanswered.json", 10)
        self._file("messages", "unread.json", 10)
        out = run_bridge("archive", "--bus", str(self.bus),
                         "--older-than", "7")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("archived 3 items", out.stdout)
        root = self._archive_root()
        self.assertTrue((root / "done" / "old-task.json").exists())
        self.assertTrue((root / "read" / "old-result.json").exists())
        self.assertTrue((root / "dead" / "old-dead.json").exists())
        # Recent and live items stay put.
        self.assertTrue((self.dirs["done"] / "new-task.json").exists())
        self.assertTrue((self.dirs["tasks"] / "waiting.json").exists())
        self.assertTrue((self.dirs["claimed"] / "in-flight.json").exists())
        self.assertTrue((self.dirs["prompts"] / "unanswered.json").exists())
        self.assertTrue((self.dirs["messages"] / "unread.json").exists())
        # And the originals are gone from the bus.
        self.assertFalse((self.dirs["done"] / "old-task.json").exists())

    def test_dry_run_moves_nothing(self):
        self._file("done", "old-task.json", 10)
        out = run_bridge("archive", "--bus", str(self.bus),
                         "--older-than", "7", "--dry-run")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("would archive 1 items", out.stdout)
        self.assertTrue((self.dirs["done"] / "old-task.json").exists())
        self.assertFalse(self._archive_root().exists())

    def test_include_claimed_moves_old_claims(self):
        self._file("claimed", "stale-claim.json", 10)
        self._file("claimed", "fresh-claim.json", 1)
        out = run_bridge("archive", "--bus", str(self.bus),
                         "--older-than", "7", "--include-claimed")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("archived 1 items", out.stdout)
        self.assertTrue((self._archive_root() / "claimed" /
                         "stale-claim.json").exists())
        self.assertTrue((self.dirs["claimed"] /
                         "fresh-claim.json").exists())

    def test_nothing_old_reports_nothing(self):
        self._file("done", "new-task.json", 1)
        out = run_bridge("archive", "--bus", str(self.bus),
                         "--older-than", "7")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("nothing older than 7 days", out.stdout)
        self.assertFalse(self._archive_root().exists())

    def test_read_items_live_one_per_reader(self):
        # read/ holds read/<reader>/<id>.json, not flat files.
        reader_dir = self.dirs["read"] / "agenc-cloud"
        reader_dir.mkdir(exist_ok=True)
        p = reader_dir / "old-result.json"
        p.write_text("{}")
        old = time.time() - 10 * DAY
        os.utime(p, (old, old))
        out = run_bridge("archive", "--bus", str(self.bus),
                         "--older-than", "7")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("archived 1 items", out.stdout)
        self.assertTrue((self._archive_root() / "read" /
                         "agenc-cloud" / "old-result.json").exists())
        self.assertFalse(p.exists())


if __name__ == "__main__":
    unittest.main()
