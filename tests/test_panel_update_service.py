"""Test Suite for Panel Update Service & Checker."""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from services.update_checker import (
    _read_update_source,
    check_panel_update,
    _version_tuple,
)
from services.panel_update import (
    _read_update_status,
    _write_update_status,
    _update_is_busy,
    _queue_safe_update,
)


class TestPanelUpdateService(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.instance_dir = self.root / "instance"
        self.instance_dir.mkdir(parents=True, exist_ok=True)
        self.status_file = self.instance_dir / "update_status.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_version_tuple(self):
        self.assertEqual(_version_tuple("1.2.3"), (1, 2, 3))
        self.assertEqual(_version_tuple("v1.2.3"), (1, 2, 3))
        self.assertEqual(_version_tuple("2.0"), (2, 0, 0))
        self.assertEqual(_version_tuple("invalid"), (0, 0, 0))

    def test_update_is_busy(self):
        self.assertTrue(_update_is_busy({"status": "queued"}))
        self.assertTrue(_update_is_busy({"status": "downloading"}))
        self.assertTrue(_update_is_busy({"status": "restart"}))
        self.assertFalse(_update_is_busy({"status": "completed"}))
        self.assertFalse(_update_is_busy({"status": "failed"}))
        self.assertFalse(_update_is_busy({"status": "idle"}))

    def test_read_update_source_prefers_fresher_marker_over_old_git(self):
        marker_file = self.instance_dir / "update_source_panel.json"
        marker_payload = {
            "source": "main",
            "revision": "495b60e4af1616ce98007000b671f29dd92f0ab5",
            "revision_short": "495b60e4",
        }
        marker_file.write_text(json.dumps(marker_payload), encoding="utf-8")

        # Fake git repo with older HEAD
        git_dir = self.root / ".git"
        git_dir.mkdir(parents=True, exist_ok=True)
        head_file = git_dir / "HEAD"
        head_file.write_text("f33dd6b3573318f18c6b35ce6e92c5a5e072dad2", encoding="utf-8")

        # Set git HEAD mtime to older than marker
        now = time.time()
        os.utime(head_file, (now - 100, now - 100))
        os.utime(marker_file, (now, now))

        with mock.patch("services.update_checker.INSTANCE_DIR", str(self.instance_dir)):
            with mock.patch("services.update_checker.BASE_DIR", str(self.root)):
                with mock.patch("services.update_checker._local_git_revision", return_value="f33dd6b3573318f18c6b35ce6e92c5a5e072dad2"):
                    res = _read_update_source("panel")
                    self.assertEqual(res.get("revision"), "495b60e4af1616ce98007000b671f29dd92f0ab5")
                    self.assertEqual(res.get("revision_short"), "495b60e4")

    def test_read_update_source_prefers_git_if_newer_than_marker(self):
        marker_file = self.instance_dir / "update_source_panel.json"
        marker_payload = {
            "source": "main",
            "revision": "oldcommit11111111111111111111111111111111",
            "revision_short": "oldcommi",
        }
        marker_file.write_text(json.dumps(marker_payload), encoding="utf-8")

        git_dir = self.root / ".git"
        git_dir.mkdir(parents=True, exist_ok=True)
        head_file = git_dir / "HEAD"
        head_file.write_text("newcommit22222222222222222222222222222222", encoding="utf-8")

        # Set git HEAD mtime to newer than marker
        now = time.time()
        os.utime(marker_file, (now - 100, now - 100))
        os.utime(head_file, (now, now))

        with mock.patch("services.update_checker.INSTANCE_DIR", str(self.instance_dir)):
            with mock.patch("services.update_checker.BASE_DIR", str(self.root)):
                with mock.patch("services.update_checker._local_git_revision", return_value="newcommit22222222222222222222222222222222"):
                    res = _read_update_source("panel")
                    self.assertEqual(res.get("revision"), "newcommit22222222222222222222222222222222")

    def test_check_panel_update_not_available_when_same_revision(self):
        remote_info = {
            "version": "1.1.0",
            "target": "main",
            "revision": "495b60e4af1616ce98007000b671f29dd92f0ab5",
            "revision_short": "495b60e4",
        }
        installed_info = {
            "source": "main",
            "target": "main",
            "revision": "495b60e4af1616ce98007000b671f29dd92f0ab5",
            "revision_short": "495b60e4",
        }

        with mock.patch("services.update_checker._github_latest_panel_version", return_value=remote_info):
            with mock.patch("services.update_checker._read_update_source", return_value=installed_info):
                with mock.patch("services.update_checker.PANEL_VERSION", "1.1.0"):
                    res = check_panel_update(fresh=True)
                    self.assertFalse(res["update_available"])
                    self.assertFalse(res["revision_update_available"])
                    self.assertFalse(res["version_update_available"])

    def test_check_panel_update_available_when_different_revision(self):
        remote_info = {
            "version": "1.1.0",
            "target": "main",
            "revision": "495b60e4af1616ce98007000b671f29dd92f0ab5",
            "revision_short": "495b60e4",
        }
        installed_info = {
            "source": "main",
            "target": "main",
            "revision": "f33dd6b3573318f18c6b35ce6e92c5a5e072dad2",
            "revision_short": "f33dd6b3",
        }

        with mock.patch("services.update_checker._github_latest_panel_version", return_value=remote_info):
            with mock.patch("services.update_checker._read_update_source", return_value=installed_info):
                with mock.patch("services.update_checker.PANEL_VERSION", "1.1.0"):
                    res = check_panel_update(fresh=True)
                    self.assertTrue(res["update_available"])
                    self.assertTrue(res["revision_update_available"])

    def test_queue_safe_update_resets_status_immediately(self):
        # Prepare helper script dummy
        scripts_dir = self.root / "scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        helper_file = scripts_dir / "panel_update.py"
        helper_file.write_text("#!/usr/bin/env python3\npass\n", encoding="utf-8")

        # Previous status was completed
        old_status = {
            "status": "completed",
            "stage": "completed",
            "percent": 100,
            "message": "Old update finished.",
        }
        _write_update_status(self.status_file, old_status)

        with mock.patch("services.panel_update._launch_update", return_value={"launcher": "mock"}):
            res = _queue_safe_update(
                root=self.root,
                status_file=self.status_file,
                scope="panel",
                target="main",
            )
            # The status file on disk should now be queued, NOT completed!
            status_on_disk = _read_update_status(self.status_file)
            self.assertEqual(status_on_disk["status"], "queued")
            self.assertEqual(status_on_disk["percent"], 2)
            self.assertEqual(res["status"]["status"], "queued")


if __name__ == "__main__":
    unittest.main()
