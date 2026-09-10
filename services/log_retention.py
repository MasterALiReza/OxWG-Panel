"""
OxWg Panel - Log Retention and Autoclear Service
================================================
Background log rotation, size-based and age-based log truncation, and scheduled daily log clearing.
"""
import time
import threading
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from core.paths import (
    INSTANCE_DIR,
    APP_LOG_FILE,
    TELEGRAM_LOG_FILE,
    TELEGRAM_ADMIN_LOG_FILE,
    IFACE_LOG_DIR,
)
from core.file_utils import (
    _load_log_settings,
    _save_log_settings,
    _log_save,
    _auto_trim,
)

logger = logging.getLogger(__name__)

_RETENTION_THREAD_STARTED = False
_RETENTION_INTERVAL_SEC = 60


def _src_defaults(d: dict[str, Any] | None = None) -> dict[str, Any]:
    """Provide default retention parameters for a log source."""
    d = d or {}
    return {
        "max_mb": int(d.get("max_mb") or 0),
        "max_age_days": int(d.get("max_age_days") or 0),
        "daily_clear": bool(d.get("daily_clear") or False),
        "last_daily_utc": d.get("last_daily_utc") or "",
        "last_cleared_utc": d.get("last_cleared_utc") or "",
    }


def _load_retention() -> dict[str, Any]:
    """Load log retention settings for all log sources."""
    settings = _load_log_settings()
    r = settings.get("retention") or {}
    return {
        "app": _src_defaults(r.get("app")),
        "tg_app": _src_defaults(r.get("tg_app")),
        "tg_admin": _src_defaults(r.get("tg_admin")),
        "iface": _src_defaults(r.get("iface")),
    }


def _save_retention(ret: dict[str, Any]) -> None:
    """Save updated log retention configuration."""
    settings = _load_log_settings()
    settings["retention"] = ret
    _save_log_settings(settings)


def _last_cleared(persist_key: str | None) -> None:
    """Record timestamp when a log group was cleared."""
    if not persist_key:
        return
    try:
        cur = _load_retention()
        group = persist_key.split(":", 1)[0]
        if group not in cur:
            cur[group] = _src_defaults()
        cur[group]["last_cleared_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _save_retention(cur)
    except Exception:
        pass


def _may_autoclear(path: Path | str, rules: dict[str, Any], persist_key: str | None = None) -> bool:
    """
    Apply retention rules to truncate or clear a log file if size, age, or daily limit is exceeded.
    """
    try:
        p = Path(path)
        if not p.exists():
            return False

        max_mb = float(rules.get("max_mb") or 0)
        if max_mb > 0 and p.stat().st_size > (max_mb * 1024 * 1024):
            open(p, "w", encoding="utf-8").close()
            _last_cleared(persist_key)
            return True

        max_days = float(rules.get("max_age_days") or 0)
        if max_days > 0:
            age_days = (time.time() - p.stat().st_mtime) / 86400.0
            if age_days > max_days:
                open(p, "w", encoding="utf-8").close()
                _last_cleared(persist_key)
                return True

        if rules.get("daily_clear"):
            now = datetime.now(timezone.utc)
            today = now.strftime("%Y-%m-%d")
            last = rules.get("last_daily_utc") or ""
            if last != today and 3 <= now.hour < 4:
                open(p, "w", encoding="utf-8").close()
                if persist_key:
                    try:
                        cur = _load_retention()
                        group = persist_key.split(":", 1)[0]
                        if group not in cur:
                            cur[group] = _src_defaults()
                        cur[group]["last_daily_utc"] = today
                        cur[group]["last_cleared_utc"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
                        _save_retention(cur)
                    except Exception:
                        pass
                else:
                    _last_cleared(persist_key)
                return True
    except Exception:
        pass
    return False


def run_log() -> None:
    """Execute a single pass retention sweep over all known log sources."""
    try:
        cfg = _load_retention()
    except Exception:
        cfg = {}

    def conf(key: str) -> dict[str, Any]:
        return cfg.get(key) or {}

    try:
        _may_autoclear(Path(APP_LOG_FILE), conf("app"), persist_key="app")
    except Exception:
        pass

    try:
        _may_autoclear(Path(TELEGRAM_LOG_FILE), conf("tg_app"), persist_key="tg_app")
    except Exception:
        pass

    try:
        _may_autoclear(Path(TELEGRAM_ADMIN_LOG_FILE), conf("tg_admin"), persist_key="tg_admin")
    except Exception:
        pass

    try:
        iface_dir = Path(IFACE_LOG_DIR)
        if iface_dir.is_dir():
            for p in iface_dir.glob("*.log"):
                key = f"iface:{p.stem}"
                _may_autoclear(p, conf("iface"), persist_key=key)
    except Exception:
        pass


def _clear_retention() -> None:
    """Clear or truncate interface log files according to interface retention rules."""
    ret = _load_retention()["iface"]
    try:
        iface_dir = Path(IFACE_LOG_DIR)
        if iface_dir.is_dir():
            for p in iface_dir.glob('*.log'):
                _may_autoclear(p, ret, persist_key="iface")
    except Exception:
        pass


def _retention_loop() -> None:
    """Background loop executing run_log sweeps periodically."""
    while True:
        try:
            run_log()
        except Exception as exc:
            logger.exception("Log retention sweep failed: %s", exc)

        time.sleep(_RETENTION_INTERVAL_SEC)


def _start_retention() -> None:
    """Start the background log-retention thread once per process."""
    global _RETENTION_THREAD_STARTED
    if _RETENTION_THREAD_STARTED:
        return

    _RETENTION_THREAD_STARTED = True
    t = threading.Thread(
        target=_retention_loop,
        name="log-retention",
        daemon=True,
    )
    t.start()
