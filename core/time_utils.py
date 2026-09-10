"""
OxWg Panel - Time Utilities
===========================
Time, timestamp, and ISO-8601 formatting utilities in canonical UTC.
"""
import re
import time
import logging
from datetime import datetime, timezone


def now_ts() -> int:
    """Return the current epoch timestamp in seconds."""
    return int(time.time())


def to_ts(value):
    """Convert an int/float, ISO string, or datetime to UTC epoch seconds."""
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return int(value)

    if isinstance(value, str):
        parsed = _tg_parse_datetime(value)
        if parsed is None:
            return None
        return int(parsed.timestamp())

    if not isinstance(value, datetime):
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)

    return int(value.timestamp())


def from_ts(ts):
    """Convert UTC epoch seconds into a naive UTC datetime object."""
    if ts is None:
        return None

    return (
        datetime
        .fromtimestamp(int(ts), tz=timezone.utc)
        .replace(tzinfo=None)
    )


def add_days_ts(base_ts, days_float):
    """Add fractional days to a base timestamp in seconds."""
    if base_ts is None or days_float in (None, ''):
        return None

    try:
        duration_seconds = int(round(float(days_float) * 86400.0))
    except (TypeError, ValueError, OverflowError):
        return None

    if duration_seconds <= 0:
        return None

    return int(base_ts) + duration_seconds


def _tg_parse_datetime(value):
    """Parse string, timestamp, or datetime into a timezone-aware UTC datetime."""
    if value in (None, "", "—"):
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(
                float(value),
                tz=timezone.utc,
            )
        except Exception:
            return None

    raw = str(value).strip()
    if not raw:
        return None

    try:
        if re.fullmatch(r"\d+(?:\.\d+)?", raw):
            return datetime.fromtimestamp(
                float(raw),
                tz=timezone.utc,
            )
        normalized = raw
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def isoz(value):
    """Format any instant representation as a canonical UTC ISO-8601 string (e.g. 2026-09-10T01:30:00Z)."""
    if value is None:
        return None

    ts = to_ts(value)
    if ts is None:
        return None

    return (
        datetime
        .fromtimestamp(ts, tz=timezone.utc)
        .isoformat(timespec='seconds')
        .replace('+00:00', 'Z')
    )


def _panel_filename_stamp(value=None, tz=None):
    """Produce a filename-safe timestamp in the panel timezone (YYYYMMDD_HHMMSS)."""
    parsed = _tg_parse_datetime(
        value if value is not None else datetime.now(timezone.utc)
    )
    if parsed is None:
        parsed = datetime.now(timezone.utc)

    if tz is None:
        try:
            from services.panel_settings import _panel_timezone
            tz = _panel_timezone()
        except Exception:
            try:
                from zoneinfo import ZoneInfo
                tz = ZoneInfo("UTC")
            except Exception:
                tz = timezone.utc

    return parsed.astimezone(tz).strftime('%Y%m%d_%H%M%S')


def _utc_timestamp_iso(value):
    """Return a canonical UTC API instant string without altering stored data."""
    parsed = _tg_parse_datetime(value)
    if parsed is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat(
        timespec='seconds'
    ).replace('+00:00', 'Z')


def _utc_log_formatter(pattern: str) -> logging.Formatter:
    """Create an unambiguous UTC formatter for log handlers."""
    formatter = logging.Formatter(
        pattern,
        datefmt='%Y-%m-%dT%H:%M:%SZ',
    )
    formatter.converter = time.gmtime
    return formatter
