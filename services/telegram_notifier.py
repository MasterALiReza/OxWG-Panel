"""
OxWg Panel - Telegram Notifier Service
======================================
Thread-safe event notifications, alert deduplication, backup zip delivery,
security notifications, and datetime/duration formatting for Telegram.
"""
import re
import time
import html
import threading
import logging
from datetime import datetime, timezone
from typing import Any
import requests

from core.paths import TELEGRAM_SETTINGS_FILE, TELEGRAM_ADMINS_FILE
from core.file_utils import _json_load, _json_save
from services.panel_settings import _panel_timezone

logger = logging.getLogger(__name__)

_TG_EVENT_LOCK = threading.Lock()
_TG_EVENT_LAST: dict[tuple[str, str], float] = {}

_TG_DEFAULTS = {
    'app_down': True,
    'app_up': True,
    'node_down': True,
    'node_up': True,
    'iface_down': True,
    'iface_up': True,
    'peer_expired': True,
    'peer_limit': True,
    'login_success': True,
    'login_fail': True,
    'suspicious_4xx': True,
    'security_block': True,
    'security_release': True,
    'security_auto_release': False,
    'traffic_policy_change': False,
    'traffic_apply_success': False,
    'traffic_apply_failed': True,
    'backup_success': False,
    'backup_failed': True,
    'update_success': True,
    'update_failed': True,
}


def _tg_event_escape(value: Any) -> str:
    """HTML-escape text for safe Telegram parse_mode='HTML' transmission."""
    return html.escape(str(value or ''), quote=True)


def _load_tg_settings() -> dict[str, Any]:
    """Load Telegram bot and notification settings from disk."""
    s = _json_load(TELEGRAM_SETTINGS_FILE, {})
    notify = s.get('notify') or {}
    return {
        'enabled': bool(s.get('enabled', False)),
        'notify': {
            key: bool(notify.get(key, default))
            for key, default in _TG_DEFAULTS.items()
        },
        'bot_token': (s.get('bot_token') or '').strip(),
    }


def _save_tg_settings(partial: dict[str, Any]) -> None:
    """Update and persist Telegram settings."""
    cur = _load_tg_settings()
    if 'bot_token' in partial and partial['bot_token'] is None:
        partial.pop('bot_token')
    cur.update({k: v for k, v in partial.items() if k != 'notify'})
    if 'notify' in partial and isinstance(partial['notify'], dict):
        cur['notify'].update(partial['notify'])
    _json_save(TELEGRAM_SETTINGS_FILE, cur)


def _load_tg_admins() -> list[dict[str, Any]]:
    """Load list of registered Telegram admin accounts."""
    a = _json_load(TELEGRAM_ADMINS_FILE, [])
    if not isinstance(a, list):
        return []
    return [admin for admin in a if isinstance(admin, dict)]


def _save_tg_admins(admins: list[dict[str, Any]]) -> None:
    """Save registered Telegram admin accounts."""
    _json_save(TELEGRAM_ADMINS_FILE, admins)


def _tg_event_enabled(event_key: str) -> bool:
    """Check if notifications are enabled for the specified event key."""
    settings = _load_tg_settings()
    if not settings.get('enabled'):
        return False
    notify = settings.get('notify') or {}
    return bool(notify.get(event_key, _TG_DEFAULTS.get(event_key, False)))


def _tg_event_key(event_key: str, dedupe_key: str = "", title: str = "") -> tuple[str, str]:
    """Build standardized tuple key for event deduplication."""
    return (str(event_key or "").strip(), str(dedupe_key or title or event_key or "").strip())


def _tg_human_bytes(value: Any) -> str:
    """Convert numeric byte count to human-readable string (e.g. 1.25 GiB)."""
    try:
        val = max(0.0, float(value or 0))
    except Exception:
        return '0 B'

    units = ('B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB')
    for unit in units:
        if val < 1024.0 or unit == units[-1]:
            if unit == 'B':
                return f"{int(val)} B"
            if val >= 10:
                return f"{val:.1f} {unit}"
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return f"{value} B"


def _tg_human_duration(value: Any) -> str:
    """Convert seconds into a concise human-readable duration."""
    try:
        seconds = max(0, int(float(value or 0)))
    except Exception:
        return ''

    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)

    parts = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if secs and not days and not hours:
        parts.append(f"{secs} second{'s' if secs != 1 else ''}")

    if not parts:
        return "0 seconds"
    return " ".join(parts[:3])


def _tg_parse_datetime(value: Any) -> datetime | None:
    """Parse various datetime representations into UTC-aware datetime."""
    if value in (None, "", "—"):
        return None

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        try:
            parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None
    else:
        raw = str(value).strip()
        if not raw:
            return None
        try:
            if re.fullmatch(r"\d+(?:\.\d+)?", raw):
                parsed = datetime.fromtimestamp(float(raw), tz=timezone.utc)
            else:
                normalized = raw
                if normalized.endswith("Z"):
                    normalized = normalized[:-1] + "+00:00"
                parsed = datetime.fromisoformat(normalized)
        except Exception:
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _tg_human_delta(seconds: float) -> str:
    """Format time difference as relative human string (e.g., '5 minutes ago', 'in 2 hours')."""
    future = seconds < 0
    sec = abs(int(seconds))

    if sec < 10:
        return "in a moment" if future else "just now"
    if sec < 60:
        text = f"{sec} second{'s' if sec != 1 else ''}"
    elif sec < 3600:
        val = max(1, sec // 60)
        text = f"{val} minute{'s' if val != 1 else ''}"
    elif sec < 86400:
        val = max(1, sec // 3600)
        text = f"{val} hour{'s' if val != 1 else ''}"
    elif sec < 604800:
        val = max(1, sec // 86400)
        text = f"{val} day{'s' if val != 1 else ''}"
    elif sec < 2592000:
        val = max(1, sec // 604800)
        text = f"{val} week{'s' if val != 1 else ''}"
    elif sec < 31536000:
        val = max(1, sec // 2592000)
        text = f"{val} month{'s' if val != 1 else ''}"
    else:
        val = max(1, sec // 31536000)
        text = f"{val} year{'s' if val != 1 else ''}"

    return f"in {text}" if future else f"{text} ago"


def _tg_human_datetime(
    value: Any,
    *,
    relative: bool = False,
    seconds: bool = False,
    fallback: str = "—",
) -> str:
    """Format datetime into panel timezone with optional relative delta."""
    parsed = _tg_parse_datetime(value)
    if parsed is None:
        return fallback if value in (None, "", "—") else str(value)

    local_tz = _panel_timezone()
    local_dt = parsed.astimezone(local_tz)
    now = datetime.now(timezone.utc).astimezone(local_tz)

    fmt = "%d %b %Y · %H:%M:%S" if seconds else "%d %b %Y · %H:%M"
    absolute = local_dt.strftime(fmt)

    if not relative:
        return absolute

    delta = (now - local_dt).total_seconds()
    human = _tg_human_delta(delta)
    return f"{absolute} ({human})"


def _tg_now_text() -> str:
    """Return current timestamp formatted for Telegram notifications."""
    return _tg_human_datetime(
        datetime.now(timezone.utc),
        relative=False,
        seconds=True,
    )


def _tg_chatid() -> str | None:
    """Return ID of the first unmuted Telegram administrator, or None."""
    admins = _load_tg_admins() or []
    for a in admins:
        if not a.get('muted') and str(a.get('id') or '').strip():
            return str(a['id'])
    return None


def _send_telegram_event(
    event_key: str,
    title: str,
    *,
    status: str = '',
    details: list[tuple[str, object]] | None = None,
    dedupe_key: str = '',
    dedupe_seconds: int = 60,
) -> bool:
    """
    Dispatch an HTML-escaped notification to all unmuted Telegram admins.
    Includes thread-safe deduplication.
    """
    event_key = str(event_key or '').strip()
    if not event_key or not _tg_event_enabled(event_key):
        return False

    settings = _load_tg_settings()
    bot_token = str(settings.get('bot_token') or '').strip()

    recipients = [
        str(admin.get('id') or '').strip()
        for admin in _load_tg_admins()
        if str(admin.get('id') or '').strip() and not admin.get('muted')
    ]

    if not bot_token or not recipients:
        return False

    event_identity = _tg_event_key(event_key, dedupe_key=dedupe_key, title=title)
    monotonic_now = time.monotonic()

    with _TG_EVENT_LOCK:
        previous_time = float(_TG_EVENT_LAST.get(event_identity) or 0)
        if dedupe_seconds > 0 and previous_time and (monotonic_now - previous_time < dedupe_seconds):
            return False

        _TG_EVENT_LAST[event_identity] = monotonic_now
        if len(_TG_EVENT_LAST) > 1000:
            expiry_time = monotonic_now - 86400
            for old_key, old_time in list(_TG_EVENT_LAST.items()):
                if float(old_time or 0) < expiry_time:
                    _TG_EVENT_LAST.pop(old_key, None)

    # Compose message text with strict HTML escaping
    icon_map = {
        'app_down': '⊘',
        'app_up': '●',
        'node_down': '○',
        'node_up': '●',
        'iface_down': '○',
        'iface_up': '●',
        'peer_expired': '✕',
        'peer_limit': '⚠',
        'security_block': '⛔',
        'security_release': '✓',
    }
    icon = icon_map.get(event_key, 'ℹ')
    header = f"{icon} <b>{_tg_event_escape(title)}</b>"
    if status:
        header += f" [{_tg_event_escape(status)}]"

    lines = [header]
    if details:
        for k, v in details:
            lines.append(f"• <b>{_tg_event_escape(k)}:</b> {_tg_event_escape(v)}")

    msg_text = "\n".join(lines)

    sent_any = False
    for chat_id in recipients:
        try:
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            resp = requests.post(
                url,
                json={
                    'chat_id': chat_id,
                    'text': msg_text,
                    'parse_mode': 'HTML',
                    'disable_web_page_preview': True,
                },
                timeout=5,
            )
            if resp.status_code == 200:
                sent_any = True
        except Exception as exc:
            logger.warning("Telegram notification failed for chat %s: %s", chat_id, exc)

    return sent_any


def _send_zip_telegram(
    data_bytes: bytes,
    filename: str,
    chat_id: str | None = None,
    caption: str | None = None,
) -> tuple[bool, str]:
    """Upload and deliver backup zip document directly to Telegram administrator."""
    settings = _load_tg_settings()
    if not settings.get("enabled"):
        return False, "Telegram disabled."

    token = (settings.get("bot_token") or "").strip()
    if not token:
        return False, "Telegram token missing."

    selected_chat_id = str(chat_id or _tg_chatid() or "").strip()
    if not selected_chat_id:
        return False, "No active Telegram administrator selected."

    active_admin_ids = {
        str(admin.get("id") or "").strip()
        for admin in (_load_tg_admins() or [])
        if not admin.get("muted") and str(admin.get("id") or "").strip()
    }
    if selected_chat_id not in active_admin_ids:
        return False, "Selected Telegram recipient is not an active panel administrator."

    size_bytes = len(data_bytes or b"")
    if not caption:
        try:
            size_text = _tg_human_bytes(size_bytes)
        except Exception:
            size_text = f"{size_bytes} bytes"
        created_at = _tg_now_text()
        caption = "\n".join([
            "<b>WG Panel backup</b>",
            "",
            "<b>Status</b> · Completed",
            f"<b>File</b> · <code>{_tg_event_escape(filename)}</code>",
            f"<b>Size</b> · {_tg_event_escape(size_text)}",
            f"<b>Created</b> · {_tg_event_escape(created_at)}",
        ])

    if len(caption) > 1000:
        caption = caption[:997] + "..."

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendDocument",
            data={
                "chat_id": selected_chat_id,
                "disable_notification": "true",
                "caption": caption,
                "parse_mode": "HTML",
            },
            files={
                "document": (
                    filename,
                    data_bytes,
                    "application/zip",
                )
            },
            timeout=60,
        )
        try:
            payload = response.json() or {}
        except Exception:
            payload = {}

        if response.ok and payload.get("ok"):
            return True, "Backup document sent to Telegram."

        description = str(payload.get("description") or response.text or "")[:300]
        return False, f"Telegram error {response.status_code}: {description}"
    except Exception as exc:
        return False, f"Telegram exception: {exc}"


def _security_notify_enabled(event_type: str) -> bool:
    """Check if security event notifications are enabled."""
    settings = _load_tg_settings()
    if not settings.get('enabled'):
        return False

    notify = settings.get('notify') or {}
    if event_type == 'login_success':
        return bool(notify.get('login_success', True))
    if event_type in {'login_failed', 'twofa_failed'}:
        return bool(notify.get('login_fail', True))

    return False


def _send_security_notification(
    event_type: str,
    username: str = '',
    reason: str = '',
) -> None:
    """Send panel login / 2FA security notifications to Telegram admins."""
    if not _security_notify_enabled(event_type):
        return

    from services.http_security import _request_client_ip, _request_device_summary
    from services.panel_settings import _is_https

    try:
        from flask import request
        panel_host = (getattr(request, 'host', None) or 'unknown').strip()[:255]
    except Exception:
        panel_host = 'unknown'

    client_ip, proxy_chain = _request_client_ip()
    device_summary, raw_user_agent = _request_device_summary()

    username = (username or 'unknown').strip()[:120]
    reason = (reason or '').strip()[:300]
    client_ip = (client_ip or 'unknown').strip()[:128]
    proxy_chain = (proxy_chain or '').strip()[:400]
    device_summary = (device_summary or 'Unknown device').strip()[:200]
    raw_user_agent = (raw_user_agent or '').strip()[:500]
    scheme = 'HTTPS' if _is_https() else 'HTTP'

    if event_type == 'login_success':
        event_key = 'login_success'
        title = 'Panel login accepted'
        status = 'Authenticated'
        dedupe_seconds = 0
    elif event_type == 'twofa_failed':
        event_key = 'login_fail'
        title = 'Two-factor verification rejected'
        status = 'Access denied'
        dedupe_seconds = 10
    elif event_type == 'login_failed':
        event_key = 'login_fail'
        title = 'Panel login rejected'
        status = 'Access denied'
        dedupe_seconds = 10
    else:
        logger.debug('Unknown security notification event: %s', event_type)
        return

    details = [
        ('Account', username),
        ('Client IP', client_ip),
        ('Device', device_summary),
        ('Panel address', f'{panel_host} · {scheme}'),
    ]
    if reason:
        details.append(('Reason', reason))
    if proxy_chain and proxy_chain != client_ip:
        details.append(('Proxy chain', proxy_chain))
    if raw_user_agent:
        details.append(('User agent', raw_user_agent))

    _send_telegram_event(
        event_key,
        title,
        status=status,
        details=details,
        dedupe_key=f'{event_type}:{client_ip}:{username}:{reason}',
        dedupe_seconds=dedupe_seconds,
    )
