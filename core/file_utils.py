"""
OxWg Panel - File and JSON Utilities
====================================
Safe file operations, atomic JSON persistence, and log rotation/trimming.
"""
import os
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from core.paths import LOGS_SETTINGS_FILE

logger = logging.getLogger(__name__)


def _load_log_settings() -> dict:
    """Load the logging settings from the instance directory."""
    try:
        with open(LOGS_SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_log_settings(data: dict):
    """Save the logging settings to the instance directory."""
    p = Path(LOGS_SETTINGS_FILE)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _will_persist() -> bool:
    """Check whether logging persistence is globally allowed."""
    s = _load_log_settings() or {}
    return bool(s.get('enabled', True) and s.get('persist', True) and not s.get('mute_save', False))


def _log_save(source: str) -> bool:
    """Check whether logging persistence is allowed for a specific source."""
    s = _load_log_settings() or {}
    if not s.get('enabled', True):
        return False
    if s.get('mute_save', False):
        return False
    if not s.get('persist', True):
        return False
    return bool((s.get('sources') or {}).get(source, True))


def _auto_trim(path: str | Path):
    """Trim a log file to the configured maximum line count."""
    try:
        s = _load_log_settings() or {}
        n = int(s.get('keep_last_lines') or 0)
        p = Path(path)
        if n > 0 and p.exists():
            with p.open('r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            if len(lines) > n:
                with p.open('w', encoding='utf-8') as f:
                    f.writelines(lines[-n:])
    except Exception:
        pass


def _extend_file(path: str | Path, text: str, source: str = 'app'):
    """Append text to a file if logging is enabled for the source, then trim."""
    if not _log_save(source):
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not text.endswith('\n'):
        text += '\n'
    try:
        with p.open('a', encoding='utf-8') as f:
            f.write(text)
    except Exception:
        pass
    _auto_trim(p)


def _write_json(path: str | Path, obj: dict):
    """Write an object to a JSON file ensuring parent directories exist."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2)


def _read_json(path: str | Path) -> dict:
    """Read a JSON file, returning an empty dict if not found or corrupted."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _json_load(path: str | Path, default=None):
    """Load JSON from path, returning default on failure."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


def _json_save(path: str | Path, data):
    """Atomically save data to JSON with restrictive file permissions."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = str(p) + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, str(p))
    try:
        os.chmod(str(p), 0o600)
    except Exception:
        pass


def _now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 representation ending with Z."""
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _read_tail(path: str | Path, max_bytes: int = 50000) -> str:
    """Read the trailing bytes of a file safely."""
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes), os.SEEK_SET)
            return f.read().decode('utf-8', errors='replace')
    except Exception:
        return ""

