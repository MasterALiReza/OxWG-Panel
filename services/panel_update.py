"""
OxWg Panel - Panel Update Service
=================================
Safe update queueing, status management, and subprocess execution for panel updates.
"""
import os
import sys
import json
import time
import shutil
import subprocess
from pathlib import Path
from typing import Any

from core.paths import BASE_DIR, INSTANCE_DIR, UPDATE_STATUS_FILE, UPDATE_LOCK_FILE
from services.update_checker import PANEL_REPO


def _status_file_path(status_file: Path | str | None = None) -> Path:
    if status_file is None:
        return Path(UPDATE_STATUS_FILE)
    return Path(status_file)


def _read_update_status(status_file: Path | str | None = None) -> dict[str, Any]:
    """Read update status JSON file or return idle state."""
    target = _status_file_path(status_file)
    try:
        if target.is_file():
            data = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {
        "status": "idle",
        "stage": "idle",
        "percent": 0,
        "message": "No update is running.",
        "log": [],
    }


def _write_update_status(status_file: Path | str | None, payload: dict[str, Any]) -> None:
    """Safely write update status to JSON file via atomic rename."""
    target = _status_file_path(status_file)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temp, target)


def _update_is_busy(status: dict[str, Any] | None) -> bool:
    """Return True if the status dictionary represents an active/running update."""
    return str((status or {}).get("status") or "").lower() in {
        "queued",
        "running",
        "backup",
        "downloading",
        "download",
        "extract",
        "install",
        "installing",
        "dependencies",
        "validate",
        "validating",
        "restart",
        "restarting",
        "rollback",
        "rolling_back",
        "rollback_restart",
    }


def _update_lock_active(root: Path | str = BASE_DIR) -> bool:
    """Check if the update.lock file exists and belongs to an active process."""
    lock_path = Path(root) / "instance" / "update.lock"
    if not lock_path.exists():
        return False

    try:
        pid_text = lock_path.read_text(encoding="utf-8").strip()
        pid = int(pid_text)
        if pid <= 1:
            raise ValueError("Invalid updater PID.")
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        try:
            lock_path.unlink(missing_ok=True)
        except Exception:
            pass
        return False
    except PermissionError:
        return True
    except Exception:
        try:
            lock_age = time.time() - lock_path.stat().st_mtime
        except Exception:
            lock_age = 999999
        if lock_age > 300:
            try:
                lock_path.unlink(missing_ok=True)
            except Exception:
                pass
            return False
        return True


def _norm_update_status(
    root: Path | str = BASE_DIR,
    status_file: Path | str | None = None,
) -> dict[str, Any]:
    """Retrieve current update status, automatically recovering stale lock states."""
    status = _read_update_status(status_file)
    if _update_is_busy(status) and not _update_lock_active(root):
        recovered = {
            "status": "idle",
            "stage": "idle",
            "percent": 0,
            "message": "Previous interrupted update state was cleared.",
            "previous_status": status.get("status"),
            "previous_message": status.get("message"),
            "recovered": True,
            "log": list(status.get("log") or [])[-20:],
        }
        try:
            _write_update_status(status_file, recovered)
        except Exception:
            pass
        return recovered
    return status


def _launch_update(
    *,
    cmd: list[str],
    root: Path | str,
    scope: str,
    log_path: Path | str,
) -> dict[str, Any]:
    """Launch panel updater via systemd-run if available, or subprocess.Popen."""
    systemd_run = shutil.which("systemd-run")
    if systemd_run:
        unit_name = f"wg-panel-update-{scope}-{int(time.time())}-{os.getpid()}"
        launch_command = [
            systemd_run,
            "--unit",
            unit_name,
            "--collect",
            "--quiet",
            "--property=Type=exec",
            "--property=KillMode=process",
            "--property=TimeoutStopSec=10min",
            f"--working-directory={root}",
            "--",
            *cmd,
        ]
        result = subprocess.run(
            launch_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "Could not create the independent updater service: "
                + (result.stdout.strip() or f"systemd-run exited with code {result.returncode}")
            )
        return {
            "launcher": "systemd-run",
            "unit": f"{unit_name}.service",
        }

    log_file = Path(log_path)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    stream = open(log_file, "ab", buffering=0)
    process = subprocess.Popen(
        cmd,
        cwd=str(root),
        stdin=subprocess.DEVNULL,
        stdout=stream,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
    )
    return {
        "launcher": "subprocess",
        "pid": process.pid,
    }


def _queue_safe_update(
    *,
    root: Path | str = BASE_DIR,
    service: str = "auto",
    status_file: Path | str | None = None,
    scope: str = "panel",
    target: str = "main",
) -> dict[str, Any]:
    """Validate prerequisites and queue update execution."""
    root_path = Path(root).resolve()
    target_status = _status_file_path(status_file)
    helper = root_path / "scripts" / "panel_update.py"
    if not helper.is_file():
        raise RuntimeError(f"Update helper is missing: {helper}")

    current = _norm_update_status(root_path, target_status)
    if _update_is_busy(current) or _update_lock_active(root_path):
        raise RuntimeError("An update is already running for this target.")

    cmd = [
        sys.executable,
        str(helper),
        "--root",
        str(root_path),
        "--repo",
        PANEL_REPO,
        "--service",
        service,
        "--status",
        str(target_status),
        "--scope",
        scope,
        "--target",
        str(target or "main"),
    ]

    log_path = root_path / "instance" / "update_runner.log"
    return _launch_update(cmd=cmd, root=root_path, scope=scope, log_path=log_path)
