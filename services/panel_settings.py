"""
OxWg Panel - Panel Settings and Runtime Configuration
=====================================================
Management of web panel network settings, TLS certificates, ports, runtime parameters, and timezone.
"""
import os
import re
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from core.paths import PANEL_SETTINGS_FILE, RUNTIME_FILE, BACKUP_SCHEDULE_FILE
from core.file_utils import _json_load, _json_save
from core.ip_utils import _public_ipv4
from services.peer_profiles import _panel_default_dns


def _valid_timezone_name(value: Any) -> str | None:
    """Validate timezone name using Python's ZoneInfo database."""
    name = str(value or "").strip()
    if not name:
        return None
    try:
        ZoneInfo(name)
        return name
    except Exception:
        return None


def _detect_system_timezone_name() -> str:
    """Detect system or scheduled timezone from environment, files, or system locale."""
    try:
        if BACKUP_SCHEDULE_FILE and os.path.isfile(BACKUP_SCHEDULE_FILE):
            data = _json_load(BACKUP_SCHEDULE_FILE, {})
            candidate = _valid_timezone_name(data.get("timezone"))
            if candidate:
                return candidate
    except Exception:
        pass

    try:
        if os.path.isfile("/etc/timezone"):
            with open("/etc/timezone", "r", encoding="utf-8") as f:
                candidate = _valid_timezone_name(f.read().strip())
                if candidate:
                    return candidate
    except Exception:
        pass

    try:
        if os.path.islink("/etc/localtime") or os.path.exists("/etc/localtime"):
            target = os.path.realpath("/etc/localtime")
            marker = "/zoneinfo/"
            if marker in target:
                candidate = _valid_timezone_name(target.split(marker, 1)[1])
                if candidate:
                    return candidate
    except Exception:
        pass

    try:
        tzinfo = datetime.now().astimezone().tzinfo
        candidate = _valid_timezone_name(getattr(tzinfo, "key", ""))
        if candidate:
            return candidate
    except Exception:
        pass

    return "UTC"


def _load_panel_settings() -> dict[str, Any]:
    """Load panel settings from disk, applying normalization and defaults."""
    Path(PANEL_SETTINGS_FILE).parent.mkdir(parents=True, exist_ok=True)
    j = _json_load(PANEL_SETTINGS_FILE, {})
    if not isinstance(j, dict):
        j = {}

    def _port(v, default=None):
        if v in (None, ""):
            return default
        try:
            p = int(v)
            return p if 1 <= p <= 65535 else default
        except Exception:
            return default

    timezone_name = _valid_timezone_name(j.get("timezone"))
    if not timezone_name:
        timezone_name = _detect_system_timezone_name()

    return {
        "tls_enabled": bool(j.get("tls_enabled", False)),
        "domain": (j.get("domain") or "").strip(),
        "force_https_redirect": bool(j.get("force_https_redirect", False)),
        "hsts": bool(j.get("hsts", False)),
        "http_port": _port(j.get("http_port"), None),
        "https_port": _port(j.get("https_port"), 443),
        "tls_cert_path": (j.get("tls_cert_path") or "").strip(),
        "tls_key_path": (j.get("tls_key_path") or "").strip(),
        "timezone": timezone_name,
    }


def _save_panel_settings(j: dict[str, Any]) -> None:
    """Save panel settings to disk atomically."""
    Path(PANEL_SETTINGS_FILE).parent.mkdir(parents=True, exist_ok=True)
    _json_save(PANEL_SETTINGS_FILE, j)


def _load_runtime() -> dict[str, Any]:
    """Load Gunicorn/WSGI runtime parameters from runtime.json."""
    s = _json_load(RUNTIME_FILE, {})
    if not isinstance(s, dict):
        s = {}

    def _i(x):
        try:
            return int(x)
        except Exception:
            return None

    return {
        'bind': (s.get('bind') or '').strip(),
        'port': _i(s.get('port')),
        'workers': _i(s.get('workers')),
        'threads': _i(s.get('threads')),
        'timeout': _i(s.get('timeout')),
        'graceful_timeout': _i(s.get('graceful_timeout')),
        'loglevel': (s.get('loglevel') or os.getenv('LOGLEVEL') or 'info').lower(),
    }


def _save_runtime(payload: dict[str, Any]) -> None:
    """Update and persist runtime parameters."""
    cur = _load_runtime()
    cur.update({k: v for k, v in payload.items() if v is not None})
    _json_save(RUNTIME_FILE, cur)


def _panel_timezone_name() -> str:
    """Return configured panel timezone name or detected system timezone."""
    try:
        settings = _load_panel_settings() or {}
        candidate = _valid_timezone_name(settings.get("timezone"))
        if candidate:
            return candidate
    except Exception:
        pass
    return _detect_system_timezone_name()


def _panel_timezone() -> ZoneInfo:
    """Return active ZoneInfo object for the panel."""
    try:
        return ZoneInfo(_panel_timezone_name())
    except Exception:
        return ZoneInfo("UTC")


def _panel_local_datetime(value: Any) -> datetime | None:
    """Convert value into a panel-timezone aware datetime."""
    from services.telegram_notifier import _tg_parse_datetime
    parsed = _tg_parse_datetime(value)
    if parsed is None:
        return None
    return parsed.astimezone(_panel_timezone())


def _panel_display_datetime(value: Any, *, seconds: bool = False) -> str | None:
    """Format one UTC instant in the saved panel timezone on the server."""
    local_value = _panel_local_datetime(value)
    if local_value is None:
        return None
    return local_value.strftime(
        '%Y-%m-%d %H:%M:%S' if seconds else '%Y-%m-%d %H:%M'
    )


def _panel_filename_stamp(value: Any = None) -> str:
    """Human timestamp in the panel timezone suitable for filenames."""
    from services.telegram_notifier import _tg_parse_datetime
    parsed = _tg_parse_datetime(
        value if value is not None else datetime.now(timezone.utc)
    )
    if parsed is None:
        parsed = datetime.now(timezone.utc)
    return parsed.astimezone(_panel_timezone()).strftime('%Y%m%d_%H%M%S')


def _utc_timestamp_iso(value: Any) -> str | None:
    """Return a canonical UTC API instant without changing stored data."""
    from services.telegram_notifier import _tg_parse_datetime
    parsed = _tg_parse_datetime(value)
    if parsed is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat(
        timespec='seconds'
    ).replace('+00:00', 'Z')


def _panel_filter_datetime_utc_naive(value: Any) -> datetime | None:
    """Convert an API filter value to a naive UTC datetime for comparison."""
    if value in (None, ''):
        return None

    try:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, (int, float)):
            parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
        else:
            raw = str(value).strip()
            if not raw:
                return None
            if re.fullmatch(r'\d+(?:\.\d+)?', raw):
                parsed = datetime.fromtimestamp(float(raw), tz=timezone.utc)
            else:
                if raw.endswith('Z'):
                    raw = raw[:-1] + '+00:00'
                parsed = datetime.fromisoformat(raw)
    except Exception:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_panel_timezone())

    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def _is_https(req=None) -> bool:
    """
    Return True if the current request is effectively HTTPS.

    Inspects request.is_secure, and standard reverse proxy headers:
    Forwarded, X-Forwarded-Proto, X-Forwarded-Ssl, X-Url-Scheme, CF-Visitor.
    """
    if req is None:
        try:
            from flask import request
            req = request
        except Exception:
            return False

    try:
        if getattr(req, "is_secure", False):
            return True

        headers = getattr(req, "headers", None)
        if headers is None:
            return False

        fwd = (headers.get("Forwarded") or "").lower()
        if "proto=https" in fwd:
            return True

        xfp = (headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        if xfp == "https":
            return True

        xssl = (headers.get("X-Forwarded-Ssl") or "").strip().lower()
        if xssl in ("on", "1", "true", "yes"):
            return True

        xsch = (headers.get("X-Url-Scheme") or "").strip().lower()
        if xsch == "https":
            return True

        cfv = headers.get("CF-Visitor") or ""
        if "https" in cfv.lower():
            return True

    except Exception:
        pass
    return False


def _norm_hostport(host: str, port: int | None) -> str:
    """Format host and optional port string, handling IPv6 bracket formatting."""
    if not host or not port:
        return ''
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 6:
            return f'[{host}]:{port}'
    except ValueError:
        pass
    return f'{host}:{port}'


def _server_host() -> str | None:
    """Return primary hostname or public IPv4 for panel server endpoints."""
    s = _load_panel_settings()
    if s.get('tls_enabled') and s.get('domain'):
        return s['domain']
    try:
        return _public_ipv4()
    except Exception:
        return None


def _panel_base() -> str:
    """
    Return canonical base URL ending with '/', using panel_settings and runtime configuration.
    """
    s = _load_panel_settings() or {}
    tls_enabled = bool(s.get('tls_enabled'))
    domain = (s.get('domain') or '').strip()

    req_host = ''
    try:
        from flask import request, has_request_context
        if has_request_context() and request:
            req_host = (request.host or '').split(':', 1)[0]
    except Exception:
        pass

    host = domain or req_host or 'localhost'

    def _env_port() -> int | None:
        b = (os.getenv('BIND') or '').strip()
        if b and ':' in b:
            try:
                return int(b.rsplit(':', 1)[1])
            except Exception:
                pass
        p = (os.getenv('PORT') or os.getenv('HTTPS_PORT') or '').strip()
        try:
            return int(p) if p else None
        except Exception:
            return None

    if tls_enabled:
        cfg_port = s.get('https_port')
        try:
            cfg_port = int(cfg_port) if cfg_port else None
        except Exception:
            cfg_port = None

        port = cfg_port or _env_port() or 443
        netloc = f"{host}:{port}" if port and port != 443 else host
        return f"https://{netloc}/"

    rt = _load_runtime() or {}
    rport = None
    try:
        rport = int(rt.get('port') or 0) or None
    except Exception:
        rport = None

    pub_ip = _public_ipv4() or req_host or 'localhost'
    if rport and rport != 80:
        return f"http://{pub_ip}:{rport}/"
    return f"http://{pub_ip}/"
