"""
OxWg Panel - Backup Scheduler and State Service
===============================================
Automated backup scheduler loop, backup preferences persistence, and retention management.
"""
import os
import time
import threading
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from core.paths import (
    BACKUP_PREFS_FILE,
    BACKUP_SCHEDULE_FILE,
    BACKUP_AUTO_DIR,
    _BACKUP_SCHEDULER_STATE_FILE,
    _BACKUP_SCHEDULER_LOCK_FILE,
)
from core.file_utils import _json_load, _json_save
from services.panel_settings import _panel_timezone_name

logger = logging.getLogger(__name__)

_BACKUP_SCHEDULER_STARTED = False
_BACKUP_THREAD_LOCK = threading.Lock()


def _backup_prefs_default() -> dict[str, Any]:
    """Default backup preferences."""
    return {"include_wg": True, "send_to_telegram": False}


def _load_backup_settings() -> dict[str, Any]:
    """Load backup preferences from disk."""
    return _json_load(BACKUP_PREFS_FILE, _backup_prefs_default())


def _save_backup_settings(p: dict[str, Any]) -> dict[str, Any]:
    """Update and persist backup preferences."""
    cur = _load_backup_settings()
    cur.update({
        "include_wg": bool(p.get("include_wg", cur.get("include_wg", True))),
        "send_to_telegram": bool(p.get("send_to_telegram", cur.get("send_to_telegram", False))),
    })
    _json_save(BACKUP_PREFS_FILE, cur)
    return cur


def _load_backup_schedule() -> dict[str, Any]:
    """Load backup schedule settings from disk."""
    d = _json_load(BACKUP_SCHEDULE_FILE, {})
    return {
        "enabled": bool(d.get("enabled", False)),
        "freq": d.get("freq", "daily"),
        "time": d.get("time", "03:00"),
        "timezone": _panel_timezone_name(),
        "dow": list(map(str, d.get("dow", []))),
        "dom": int(d.get("dom", 1)),
        "cron": d.get("cron", ""),
        "keep": int(d.get("keep", 7)),
        "include_wg": bool(d.get("include_wg", True)),
        "send_to_telegram": bool(d.get("send_to_telegram", False)),
    }


def _save_backup_schedule(s: dict[str, Any]) -> None:
    """Save backup schedule settings to disk."""
    _json_save(BACKUP_SCHEDULE_FILE, s)


_APP_REF: Any = None


def set_app(app: Any) -> None:
    """Register the Flask application instance for background threads."""
    global _APP_REF
    _APP_REF = app


def _get_app_context():
    """Retrieve active or configured Flask application context."""
    global _APP_REF
    if _APP_REF is not None:
        return _APP_REF.app_context()
    try:
        from flask import current_app
        if current_app:
            return current_app.app_context()
    except Exception:
        pass
    from contextlib import nullcontext
    return nullcontext()


def _cron_field_match(val: int, expr: str, min_v: int, max_v: int) -> bool:
    """Evaluate a single 5-field cron component."""
    expr = (expr or '').strip()
    if expr in ('*', '?'):
        return True
    if '/' in expr:
        base, step = expr.split('/', 1)
        step_i = int(step)
        start = min_v if base in ('*', '') else int(base)
        return (val >= start) and ((val - start) % step_i == 0) and (val <= max_v)
    if ',' in expr:
        return any(_cron_field_match(val, sub, min_v, max_v) for sub in expr.split(','))
    if '-' in expr:
        lo, hi = [int(x) for x in expr.split('-', 1)]
        return lo <= val <= hi
    try:
        return val == int(expr)
    except ValueError:
        return False


def _backup_due_slot(schedule: dict[str, Any], now_utc: datetime | None = None) -> str | None:
    """
    Check if a scheduled backup is due in the current minute window.
    Evaluates in the configured schedule timezone.
    Returns slot identifier string if due, else None.
    """
    if not schedule.get("enabled"):
        return None

    now_utc = now_utc or datetime.now(timezone.utc)

    tz_name = (schedule.get("timezone") or _panel_timezone_name() or "UTC").strip()
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(tz_name)
    except Exception:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo("UTC")

    local_time = now_utc.astimezone(tz)
    freq = (schedule.get("freq") or "daily").lower()

    if freq == "custom":
        fields = (schedule.get("cron") or "").split()
        if len(fields) != 5:
            return None
        minute, hour, day, month, weekday = fields
        cron_weekday = (local_time.weekday() + 1) % 7
        matched = all((
            _cron_field_match(local_time.minute, minute, 0, 59),
            _cron_field_match(local_time.hour, hour, 0, 23),
            _cron_field_match(local_time.day, day, 1, 31),
            _cron_field_match(local_time.month, month, 1, 12),
            (
                _cron_field_match(cron_weekday, weekday, 0, 7)
                or (cron_weekday == 0 and _cron_field_match(7, weekday, 0, 7))
            ),
        ))
        if not matched:
            return None
        return f"custom:{local_time:%Y-%m-%dT%H:%M}"

    slot_time = schedule.get("time", "03:00")
    try:
        shour, sminute = [int(x) for x in slot_time.split(":", 1)]
    except Exception:
        shour, sminute = 3, 0

    if local_time.hour != shour or local_time.minute != sminute:
        return None

    if freq == "daily":
        return local_time.strftime("%Y-%m-%d")
    if freq == "weekly":
        dow_list = [int(x) for x in schedule.get("dow", []) if str(x).isdigit()]
        if not dow_list or local_time.weekday() in dow_list:
            return local_time.strftime("%Y-%W")
    if freq == "monthly":
        target_dom = int(schedule.get("dom", 1))
        if local_time.day == target_dom:
            return local_time.strftime("%Y-%m")

    return None


def _save_autobackup(data_bytes: bytes, keep: int | None = None) -> dict[str, Any]:
    """Save automated backup ZIP data and prune older backups."""
    root = Path(BACKUP_AUTO_DIR)
    root.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    name = f"auto_full_{ts}.zip"
    path = root / name

    with open(path, "wb") as f:
        f.write(data_bytes)

    st = path.stat()
    if keep is None:
        try:
            sched = _load_backup_schedule()
            keep = int(sched.get("keep", 7))
        except Exception:
            keep = 7

    keep_count = max(1, int(keep or 1))
    files = sorted(root.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    for p in files[keep_count:]:
        try:
            p.unlink()
        except OSError:
            pass

    return {"name": name, "size": st.st_size, "ts": int(st.st_mtime)}


def _backup_scheduler_loop(app: Any = None) -> None:
    """
    Background worker loop for scheduled automated backups.
    Acquires file lock to ensure single execution across worker processes.
    """
    if app is not None:
        set_app(app)
    lock_handle = None
    try:
        import fcntl
        lock_handle = open(_BACKUP_SCHEDULER_LOCK_FILE, "a+", encoding="utf-8")
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (ImportError, OSError):
        # On Windows or if lock already held by another worker
        pass
    except Exception:
        if lock_handle:
            try:
                lock_handle.close()
            except Exception:
                pass
        return

    while True:
        try:
            with _get_app_context():
                schedule = _load_backup_schedule()
                slot = _backup_due_slot(schedule)
                state = _json_load(_BACKUP_SCHEDULER_STATE_FILE, {})
                if not isinstance(state, dict):
                    state = {}

                if slot and state.get("last_slot") != slot:
                    # Slot is due; update state
                    state["last_slot"] = slot
                    state["last_run_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    _json_save(_BACKUP_SCHEDULER_STATE_FILE, state)
                    logger.info("Triggered scheduled backup for slot %s", slot)
        except Exception as exc:
            logger.warning("Backup scheduler tick failed: %s", exc)

        time.sleep(30)


def _start_backup_scheduler(app: Any = None) -> None:
    """Start background backup scheduler thread once per process."""
    global _BACKUP_SCHEDULER_STARTED
    if app is not None:
        set_app(app)
    with _BACKUP_THREAD_LOCK:
        if _BACKUP_SCHEDULER_STARTED:
            return
        _BACKUP_SCHEDULER_STARTED = True

        thread = threading.Thread(
            target=_backup_scheduler_loop,
            args=(app,),
            name="backup-scheduler",
            daemon=True,
        )
        thread.start()
