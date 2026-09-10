"""
OxWg Panel - HTTP Security and Rate-Limiting Protection
=======================================================
Protection against brute-force attacks, suspicious 4xx scanning, IP ban enforcement,
nftables firewall synchronization, client IP resolution, and cleanup.
"""
import os
import re
import time
import shutil
import subprocess
import ipaddress
import threading
import logging
from typing import Any

from core.paths import (
    _HTTP_4XX_STATE_FILE,
    _HTTP_4XX_LOCK_FILE,
    _HTTP_SECURITY_SETTINGS_FILE,
)
from core.file_utils import _json_load, _json_save
from services.panel_settings import _is_https

logger = logging.getLogger(__name__)

_HTTP_SECURITY_CLEANUP_STARTED = False
_HTTP_SECURITY_SETTINGS_CACHE: dict[str, Any] = {"stamp": -1, "settings": {}}

_HTTP_SECURITY_OFFENSE_RESET_SEC = 7 * 24 * 60 * 60
_HTTP_SECURITY_HISTORY_LIMIT = 500
_HTTP_SECURITY_TEMP_ALLOW_MAX_SEC = 7 * 24 * 60 * 60

_HTTP_SECURITY_NFT_TABLE = "wgpanel_security"
_HTTP_SECURITY_NFT_V4_SET = "blocked_v4"
_HTTP_SECURITY_NFT_V6_SET = "blocked_v6"

_HTTP_SECURITY_DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "response_mode": "block",
    "ip_source": "effective",
    "block_scope": "all",
    "threshold": 20,
    "window_seconds": 60,
    "sensitive_threshold": 3,
    "rate_limit_threshold": 10,
    "login_threshold": 5,
    "login_window_seconds": 600,
    "cooldown_seconds": 600,
    "block_seconds": 900,
    "max_block_seconds": 86400,
    "escalate": True,
    "enrich_ip": False,
    "firewall_enabled": False,
    "firewall_after_offenses": 3,
    "trusted_networks": ["127.0.0.1/32", "::1/128"],
    "deny_networks": [],
}


def _http_security_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    """Clamp integer value between minimum and maximum bounds."""
    try:
        return max(minimum, min(maximum, int(value)))
    except Exception:
        return default


def _http_security_normalize_ip(value: Any) -> str:
    """Normalize and validate IP address string, returning 'unknown' on error."""
    val = str(value or "").strip()
    if not val:
        return "unknown"
    try:
        return str(ipaddress.ip_address(val))
    except ValueError:
        return "unknown"


def _http_security_normalize_networks(value: Any) -> list[str]:
    """Normalize input networks list or comma/newline separated string into valid CIDR strings."""
    if isinstance(value, str):
        value = re.split(r"[\r\n,]+", value)
    if not isinstance(value, list):
        value = []

    cleaned: list[str] = []
    for item in value:
        raw = str(item or "").strip()
        if not raw:
            continue
        try:
            if "/" not in raw:
                ip = ipaddress.ip_address(raw)
                raw = f"{ip}/{32 if ip.version == 4 else 128}"
            else:
                raw = str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            continue
        if raw not in cleaned:
            cleaned.append(raw)
    return cleaned


def _load_http_security_settings() -> dict[str, Any]:
    """Load and normalize HTTP security configuration."""
    try:
        stamp = os.stat(_HTTP_SECURITY_SETTINGS_FILE).st_mtime_ns
    except OSError:
        stamp = 0

    if _HTTP_SECURITY_SETTINGS_CACHE["stamp"] == stamp and _HTTP_SECURITY_SETTINGS_CACHE["settings"]:
        return dict(_HTTP_SECURITY_SETTINGS_CACHE["settings"])

    raw = _json_load(_HTTP_SECURITY_SETTINGS_FILE, {})
    if not isinstance(raw, dict):
        raw = {}

    settings = dict(_HTTP_SECURITY_DEFAULTS)
    settings.update(raw)

    settings["enabled"] = bool(settings.get("enabled", True))
    settings["response_mode"] = (
        "block" if str(settings.get("response_mode") or "").lower() == "block" else "monitor"
    )
    settings["ip_source"] = (
        "effective" if str(settings.get("ip_source") or "").lower() == "effective" else "direct"
    )
    settings["block_scope"] = (
        "auth_admin" if str(settings.get("block_scope") or "").lower() == "auth_admin" else "all"
    )
    settings["threshold"] = _http_security_int(settings.get("threshold"), 20, 3, 500)
    settings["window_seconds"] = _http_security_int(settings.get("window_seconds"), 60, 10, 3600)
    settings["sensitive_threshold"] = _http_security_int(settings.get("sensitive_threshold"), 3, 1, 50)
    settings["rate_limit_threshold"] = _http_security_int(settings.get("rate_limit_threshold"), 10, 1, 200)
    settings["login_threshold"] = _http_security_int(settings.get("login_threshold"), 5, 2, 100)
    settings["login_window_seconds"] = _http_security_int(settings.get("login_window_seconds"), 600, 60, 86400)
    settings["cooldown_seconds"] = _http_security_int(settings.get("cooldown_seconds"), 600, 30, 86400)
    settings["block_seconds"] = _http_security_int(settings.get("block_seconds"), 900, 60, 604800)
    settings["max_block_seconds"] = _http_security_int(settings.get("max_block_seconds"), 86400, 60, 2592000)
    settings["max_block_seconds"] = max(settings["block_seconds"], settings["max_block_seconds"])
    settings["escalate"] = bool(settings.get("escalate", True))
    settings["enrich_ip"] = bool(settings.get("enrich_ip", False))
    settings["firewall_enabled"] = bool(settings.get("firewall_enabled", False))
    settings["firewall_after_offenses"] = _http_security_int(
        settings.get("firewall_after_offenses"), 3, 1, 20
    )
    settings["trusted_networks"] = _http_security_normalize_networks(settings.get("trusted_networks"))
    settings["deny_networks"] = _http_security_normalize_networks(settings.get("deny_networks"))

    _HTTP_SECURITY_SETTINGS_CACHE.update(stamp=stamp, settings=dict(settings))
    return settings


def _save_http_security_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Save normalized security settings."""
    _json_save(_HTTP_SECURITY_SETTINGS_FILE, settings)
    _HTTP_SECURITY_SETTINGS_CACHE["stamp"] = -1
    return _load_http_security_settings()


def _http_security_is_network_match(ip_str: str, networks: list[str]) -> bool:
    """Check if IP address falls within any CIDR network in the list."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for net_str in networks:
            try:
                if ip in ipaddress.ip_network(net_str, strict=False):
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False


def _http_security_is_trusted(ip_str: str, settings: dict[str, Any]) -> bool:
    """Check if client IP matches trusted network whitelist."""
    return _http_security_is_network_match(ip_str, settings.get("trusted_networks", []))


def _http_security_is_denied(ip_str: str, settings: dict[str, Any]) -> bool:
    """Check if client IP matches permanent deny network blacklist."""
    return _http_security_is_network_match(ip_str, settings.get("deny_networks", []))


def _http_security_is_temporarily_allowed(ip_str: str, state: dict[str, Any] | None = None) -> bool:
    """Check if client IP has an active temporary bypass permit."""
    if state is None:
        state = _json_load(_HTTP_4XX_STATE_FILE, {})
    if not isinstance(state, dict):
        return False
    allow_map = state.get("temporary_allow")
    if not isinstance(allow_map, dict):
        return False
    expires = int(allow_map.get(ip_str) or 0)
    return expires > int(time.time())


def _http_security_client_ip(settings: dict[str, Any], req: Any = None) -> str:
    """Resolve client IP from request, respecting ip_source setting."""
    if req is None:
        try:
            from flask import request
            req = request
        except Exception:
            return "127.0.0.1"

    if settings.get("ip_source") == "direct":
        return str(getattr(req, "remote_addr", None) or "unknown")

    headers = getattr(req, "headers", {})
    xff = headers.get("X-Forwarded-For")
    if xff:
        client = xff.split(",")[0].strip()
        if client:
            return client
    return str(getattr(req, "remote_addr", None) or "unknown")


def _http_security_scope_applies(path: str, block_scope: str) -> bool:
    """Check if request path is covered by configured block scope."""
    if block_scope != "auth_admin":
        return True
    path = path.lower()
    return bool(
        path.startswith("/api/admin")
        or path.startswith("/login")
        or path.startswith("/register")
    )


def _http_security_cleanup_loop() -> None:
    """Clean expired temporary blocks and counters."""
    while True:
        try:
            state = _json_load(_HTTP_4XX_STATE_FILE, {})
            if isinstance(state, dict):
                now = int(time.time())
                clients = state.get("clients", {})
                if isinstance(clients, dict):
                    expired_ips = [
                        ip for ip, data in clients.items()
                        if isinstance(data, dict) and int(data.get("blocked_until") or 0) <= now
                    ]
                    for ip in expired_ips:
                        clients.pop(ip, None)
                    if expired_ips:
                        _json_save(_HTTP_4XX_STATE_FILE, state)
        except Exception:
            pass
        time.sleep(30)


def _start_http_security_cleanup() -> None:
    """Start HTTP security state cleanup thread once per process."""
    global _HTTP_SECURITY_CLEANUP_STARTED
    if _HTTP_SECURITY_CLEANUP_STARTED:
        return
    _HTTP_SECURITY_CLEANUP_STARTED = True
    threading.Thread(
        target=_http_security_cleanup_loop,
        name="http-security-cleanup",
        daemon=True,
    ).start()


def _http_security_nft_install_command() -> str:
    """Detect OS package manager and return nftables installation command."""
    if shutil.which("apt-get"):
        return "sudo apt-get update && sudo apt-get install -y nftables"
    if shutil.which("dnf"):
        return "sudo dnf install -y nftables"
    if shutil.which("yum"):
        return "sudo yum install -y nftables"
    if shutil.which("pacman"):
        return "sudo pacman -S --needed nftables"
    return "Install the nftables package with your operating system package manager."


def _http_security_nft_status(settings: dict[str, Any] | None = None) -> dict[str, Any]:
    """Check nftables availability, permissions, and effective firewall status."""
    nft = shutil.which("nft")
    configured = bool((settings or {}).get("firewall_enabled")) if isinstance(settings, dict) else None

    base: dict[str, Any] = {
        "backend": "nftables",
        "available": bool(nft),
        "usable": False,
        "privileged": False,
        "configured": configured,
        "effective": False,
        "table": _HTTP_SECURITY_NFT_TABLE,
        "reason": "not_installed" if not nft else "checking",
        "detail": "",
        "install_command": _http_security_nft_install_command(),
        "check_command": "sudo nft list ruleset",
        "automatic_install": False,
    }

    if not nft:
        base["detail"] = (
            "The nft executable was not found. "
            "Application-level blocking is still active."
        )
        return base

    try:
        proc = subprocess.run(
            [nft, "list", "ruleset"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception as exc:
        base["reason"] = "check_failed"
        base["detail"] = str(exc)[:300]
        return base

    if proc.returncode == 0:
        base["usable"] = True
        base["privileged"] = True
        base["reason"] = "ready"
        base["detail"] = (
            "WG Panel can read/manage nftables through the current service permissions."
        )
        base["effective"] = bool(configured) if configured is not None else False
        return base

    detail = (proc.stderr or "nft list ruleset failed").strip()[:300]
    low = detail.lower()
    base["reason"] = (
        "permission_denied"
        if ("operation not permitted" in low or "permission denied" in low or "must be root" in low)
        else "unusable"
    )
    base["detail"] = detail
    return base


def _http_security_nft_run_script(script: str) -> tuple[bool, str]:
    """Execute nftables configuration rules via stdin pipe."""
    status = _http_security_nft_status()
    nft = shutil.which("nft")
    if not status.get("usable") or not nft:
        return False, "nftables is unavailable or the panel process lacks root/CAP_NET_ADMIN"
    try:
        proc = subprocess.run(
            [nft, "-f", "-"],
            input=str(script),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=4,
            check=False,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout or "nft failed").strip()[:300]
        return True, ""
    except Exception as exc:
        return False, str(exc)[:300]


def _http_security_nft_ensure() -> tuple[bool, str]:
    """Ensure nftables base table, sets, and input chain are created."""
    status = _http_security_nft_status()
    nft = shutil.which("nft")
    if not status.get("usable") or not nft:
        return False, "nftables is unavailable or the panel process lacks root/CAP_NET_ADMIN"
    check = subprocess.run(
        [nft, "list", "table", "inet", _HTTP_SECURITY_NFT_TABLE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=3,
        check=False,
    )
    if check.returncode == 0:
        return True, ""
    script = f"""
table inet {_HTTP_SECURITY_NFT_TABLE} {{
    set {_HTTP_SECURITY_NFT_V4_SET} {{ type ipv4_addr; flags timeout; }}
    set {_HTTP_SECURITY_NFT_V6_SET} {{ type ipv6_addr; flags timeout; }}
    chain input {{
        type filter hook input priority -10; policy accept;
        ip saddr @{_HTTP_SECURITY_NFT_V4_SET} drop
        ip6 saddr @{_HTTP_SECURITY_NFT_V6_SET} drop
    }}
}}
"""
    return _http_security_nft_run_script(script)


def _http_security_firewall_add(ip: str, seconds: int) -> tuple[bool, str]:
    """Add IP address to nftables kernel drop set with expiration timeout."""
    norm_ip = _http_security_normalize_ip(ip)
    if norm_ip == "unknown":
        return False, "invalid IP"
    ok, detail = _http_security_nft_ensure()
    if not ok:
        return False, detail
    version = ipaddress.ip_address(norm_ip).version
    set_name = _HTTP_SECURITY_NFT_V4_SET if version == 4 else _HTTP_SECURITY_NFT_V6_SET
    seconds = _http_security_int(seconds, 900, 60, 2592000)
    _http_security_nft_run_script(
        f"delete element inet {_HTTP_SECURITY_NFT_TABLE} {set_name} {{ {norm_ip} }}\n"
    )
    return _http_security_nft_run_script(
        f"add element inet {_HTTP_SECURITY_NFT_TABLE} {set_name} {{ {norm_ip} timeout {seconds}s }}\n"
    )


def _http_security_firewall_remove(ip: str) -> tuple[bool, str]:
    """Remove IP address from nftables drop set."""
    norm_ip = _http_security_normalize_ip(ip)
    if norm_ip == "unknown":
        return False, "invalid IP"
    status = _http_security_nft_status()
    if not status.get("usable"):
        return False, "nftables unavailable"
    version = ipaddress.ip_address(norm_ip).version
    set_name = _HTTP_SECURITY_NFT_V4_SET if version == 4 else _HTTP_SECURITY_NFT_V6_SET
    return _http_security_nft_run_script(
        f"delete element inet {_HTTP_SECURITY_NFT_TABLE} {set_name} {{ {norm_ip} }}\n"
    )


def _request_client_ip(req: Any = None) -> tuple[str, str]:
    """
    Return:
      1. Effective client IP
      2. Full proxy chain for diagnostics
    """
    if req is None:
        try:
            from flask import request
            req = request
        except Exception:
            return "127.0.0.1", ""

    headers = getattr(req, "headers", {})
    forwarded = (headers.get('X-Forwarded-For') or '').strip()
    proxy_chain = ', '.join(
        item.strip()
        for item in forwarded.split(',')
        if item.strip()
    )

    candidates = [
        headers.get('CF-Connecting-IP'),
        headers.get('True-Client-IP'),
        headers.get('X-Real-IP'),
        (proxy_chain.split(',', 1)[0].strip() if proxy_chain else None),
        getattr(req, "remote_addr", None),
    ]

    client_ip = next(
        (
            str(value).strip()
            for value in candidates
            if str(value or '').strip()
        ),
        'unknown',
    )
    return client_ip, proxy_chain


def _request_device_summary(req: Any = None) -> tuple[str, str]:
    """
    Return:
      1. Friendly browser/OS summary
      2. Raw User-Agent
    """
    if req is None:
        try:
            from flask import request
            req = request
        except Exception:
            return "Unknown browser · Unknown OS", ""

    headers = getattr(req, "headers", {})
    user_agent = (headers.get('User-Agent') or 'unknown').strip()
    lower = user_agent.lower()

    if 'edg/' in lower:
        browser = 'Microsoft Edge'
    elif 'opr/' in lower or 'opera' in lower:
        browser = 'Opera'
    elif 'firefox/' in lower:
        browser = 'Firefox'
    elif 'chrome/' in lower or 'crios/' in lower:
        browser = 'Chrome'
    elif 'safari/' in lower:
        browser = 'Safari'
    else:
        browser = 'Unknown browser'

    if 'windows nt' in lower:
        operating_system = 'Windows'
    elif 'android' in lower:
        operating_system = 'Android'
    elif 'iphone' in lower or 'ipad' in lower or 'ios' in lower:
        operating_system = 'iOS/iPadOS'
    elif 'mac os x' in lower or 'macintosh' in lower:
        operating_system = 'macOS'
    elif 'linux' in lower:
        operating_system = 'Linux'
    else:
        operating_system = 'Unknown OS'

    return f'{browser} · {operating_system}', user_agent[:500]


def _http_security_record_login_failure(username: str = "", failure_type: str = "credentials") -> None:
    """Record an authentication failure for security auditing."""
    try:
        from flask import current_app
        current_app.logger.debug("HTTP security recorded login failure for %s (%s)", username, failure_type)
    except Exception:
        pass


_HTTP_4XX_STATUSES = {400, 401, 403, 404, 405, 429}
_HTTP_SECURITY_GEO_CACHE: dict[str, Any] = {}
_HTTP_SECURITY_GEO_CACHE_LOCK = threading.Lock()


def _suspicious_4xx_ignored_path(path: str) -> bool:
    p = str(path or "").lower()
    if p.startswith("/static/"):
        return True
    if p in {"/favicon.ico", "/robots.txt", "/sitemap.xml"}:
        return True
    return False


def _http_security_sensitive_path(path: str) -> bool:
    p = str(path or "").lower()
    return any(p.startswith(prefix) for prefix in ("/api/admin", "/login", "/register"))


def _http_security_classify(path: str, status_code: int | None = None) -> str:
    p = str(path or "").lower()
    if status_code == 429:
        return "rate_limit"
    if p.startswith("/login"):
        return "login_fail"
    if p.startswith("/register"):
        return "register_fail"
    if p.startswith("/api/admin"):
        return "admin_probe"
    if p.startswith("/api/"):
        return "api_error"
    return "http_error"


def _http_security_temp_allows_locked(state: dict[str, Any], now: int | None = None) -> list[dict[str, Any]]:
    now = int(now or time.time())
    allows = state.get("temporary_allow")
    if not isinstance(allows, list):
        allows = []
    filtered = [
        item for item in allows
        if isinstance(item, dict)
        and _http_security_normalize_networks([item.get("network")])
        and int(item.get("expires_at") or 0) > now
    ]
    state["temporary_allow"] = filtered
    return filtered


def _http_security_add_history_locked(
    state: dict[str, Any],
    *,
    event_type: str,
    ip: str = "",
    category: str = "",
    action: str = "",
    reason: str = "",
    path: str = "",
    status: int = 0,
    details: dict[str, Any] | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    now = int(now or time.time())
    history = state.get("history")
    if not isinstance(history, list):
        history = []
    row = {
        "ts": now,
        "type": str(event_type or "event")[:48],
        "ip": _http_security_normalize_ip(ip) if ip else "",
        "category": str(category or "")[:64],
        "action": str(action or "")[:64],
        "reason": str(reason or "")[:320],
        "path": str(path or "")[:300],
        "status": int(status or 0),
        "details": details if isinstance(details, dict) else {},
    }
    history.append(row)
    state["history"] = history[-_HTTP_SECURITY_HISTORY_LIMIT:]
    return row


def _http_security_stat_add_locked(state: dict[str, Any], now: int, ip: str, **counts: int) -> None:
    buckets = state.get("stats_hours")
    if not isinstance(buckets, dict):
        buckets = {}
    hour = str((int(now) // 3600) * 3600)
    bucket = buckets.get(hour)
    if not isinstance(bucket, dict):
        bucket = {"ips": []}
    for key, value in counts.items():
        bucket[key] = int(bucket.get(key) or 0) + int(value or 0)
    normalized_ip = _http_security_normalize_ip(ip)
    ips = bucket.get("ips")
    if not isinstance(ips, list):
        ips = []
    if normalized_ip != "unknown" and normalized_ip not in ips and len(ips) < 1000:
        ips.append(normalized_ip)
    bucket["ips"] = ips
    buckets[hour] = bucket
    cutoff = int(now) - (72 * 3600)
    for key in list(buckets.keys()):
        try:
            if int(key) < cutoff:
                buckets.pop(key, None)
        except Exception:
            buckets.pop(key, None)
    state["stats_hours"] = buckets


def _http_security_apply_block_locked(
    record: dict[str, Any],
    settings: dict[str, Any],
    now: int,
    reason: str,
) -> tuple[bool, int, int]:
    current_block = int(record.get("blocked_until") or 0)
    if current_block > now:
        return False, 0, int(record.get("offenses") or 1)

    last_offense = int(record.get("last_offense") or 0)
    if last_offense and now - last_offense >= _HTTP_SECURITY_OFFENSE_RESET_SEC:
        record["offenses"] = 0

    offenses = max(0, int(record.get("offenses") or 0)) + 1
    record["offenses"] = offenses
    record["last_offense"] = now
    multiplier = (2 ** max(0, offenses - 1)) if settings.get("escalate") else 1
    block_seconds = min(settings["max_block_seconds"], settings["block_seconds"] * multiplier)
    record["blocked_until"] = now + block_seconds
    record["block_started_at"] = now
    record["block_reason"] = reason
    record["block_active"] = True
    return True, block_seconds, offenses


def _http_security_geo(ip: str, settings: dict[str, Any] | None = None) -> dict[str, Any]:
    settings = settings or _load_http_security_settings()
    if not settings.get("enrich_ip"):
        return {}
    ip = _http_security_normalize_ip(ip)
    if ip == "unknown":
        return {}
    try:
        address = ipaddress.ip_address(ip)
        if not address.is_global:
            return {}
    except Exception:
        return {}

    now = time.time()
    with _HTTP_SECURITY_GEO_CACHE_LOCK:
        cached = _HTTP_SECURITY_GEO_CACHE.get(ip)
        if isinstance(cached, dict) and now - float(cached.get("_ts") or 0) < 86400:
            return {k: v for k, v in cached.items() if k != "_ts"}

    result = {}
    try:
        import requests
        response = requests.get(f"https://ipwho.is/{ip}", timeout=3)
        if response.ok:
            payload = response.json() or {}
            if payload.get("success", True):
                connection = payload.get("connection") or {}
                result = {
                    "country": str(payload.get("country") or "")[:80],
                    "country_code": str(payload.get("country_code") or "")[:8],
                    "asn": str(connection.get("asn") or "")[:40],
                    "provider": str(connection.get("isp") or connection.get("org") or "")[:120],
                }
    except Exception:
        pass

    with _HTTP_SECURITY_GEO_CACHE_LOCK:
        _HTTP_SECURITY_GEO_CACHE[ip] = dict(result, _ts=now)
    return result


def _lock_state_file(lock_file_path: str):
    f = open(lock_file_path, "a+")
    try:
        import fcntl
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    except ImportError:
        try:
            import msvcrt
            f.seek(0)
            f.write("0")
            f.flush()
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        except (ImportError, OSError):
            pass
    return f


def _unlock_state_file(f):
    if f:
        try:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except ImportError:
            try:
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            except (ImportError, OSError):
                pass
        try:
            f.close()
        except Exception:
            pass


def _record_suspicious_4xx(response: Any) -> None:
    from flask import request, g, current_app
    from services.telegram_notifier import _send_telegram_event, _tg_human_duration

    if getattr(g, "http_security_blocked", False):
        return

    status_code = int(getattr(response, "status_code", 0) or 0)
    if status_code not in _HTTP_4XX_STATUSES:
        return

    request_path = str(request.path or "")
    if _suspicious_4xx_ignored_path(request_path):
        return

    settings = _load_http_security_settings()
    if not settings.get("enabled"):
        return

    client_ip = _http_security_client_ip(settings)
    if client_ip == "unknown":
        return
    if _http_security_is_denied(client_ip, settings):
        return
    state_snapshot = _json_load(_HTTP_4XX_STATE_FILE, {})
    if _http_security_is_trusted(client_ip, settings) or _http_security_is_temporarily_allowed(client_ip, state_snapshot):
        return

    now = int(time.time())
    window_start = now - settings["window_seconds"]
    sensitive_now = _http_security_sensitive_path(request_path)
    category_now = _http_security_classify(request_path, status_code)
    lock_handle = None
    should_alert = False
    did_block = False
    block_seconds = 0
    offenses = 0
    reason = ""
    trigger_category = category_now
    request_count = 0
    sensitive_count = 0
    rate_limit_count = 0
    status_counts: dict[str, int] = {}
    recent_paths: list[str] = []
    firewall_should_apply = False

    try:
        lock_handle = _lock_state_file(_HTTP_4XX_LOCK_FILE)
        state = _json_load(_HTTP_4XX_STATE_FILE, {})
        if not isinstance(state, dict):
            state = {}
        clients = state.get("clients")
        if not isinstance(clients, dict):
            clients = {}

        _http_security_temp_allows_locked(state, now)
        _http_security_stat_add_locked(
            state, now, client_ip,
            rejected=1,
            sensitive=(1 if sensitive_now else 0),
            rate_limited=(1 if status_code == 429 else 0),
        )

        stale_after = max(settings["cooldown_seconds"] * 4, settings["max_block_seconds"] * 2, 86400)
        for old_ip, old_record in list(clients.items()):
            if not isinstance(old_record, dict):
                clients.pop(old_ip, None)
                continue
            last_seen = int(old_record.get("last_seen") or 0)
            blocked_until = int(old_record.get("blocked_until") or 0)
            offenses_old = int(old_record.get("offenses") or 0)
            if blocked_until <= now and offenses_old <= 0 and now - last_seen > stale_after:
                clients.pop(old_ip, None)

        record = clients.get(client_ip)
        if not isinstance(record, dict):
            record = {"events": [], "login_events": [], "last_alert": 0, "last_seen": 0, "offenses": 0}

        events = record.get("events")
        if not isinstance(events, list):
            events = []
        events = [event for event in events if isinstance(event, dict) and int(event.get("ts") or 0) >= window_start]
        events.append({
            "ts": now,
            "status": status_code,
            "path": request_path[:240],
            "method": str(request.method or "")[:16],
            "sensitive": bool(sensitive_now),
            "category": category_now,
        })
        events = events[-300:]
        record["events"] = events
        record["last_seen"] = now

        request_count = len(events)
        sensitive_count = sum(1 for event in events if bool(event.get("sensitive")))
        rate_limit_count = sum(1 for event in events if int(event.get("status") or 0) == 429)
        for event in events:
            key = str(event.get("status") or "unknown")
            status_counts[key] = status_counts.get(key, 0) + 1
        for event in reversed(events):
            value = str(event.get("path") or "").strip()
            if value and value not in recent_paths:
                recent_paths.append(value)
            if len(recent_paths) >= 5:
                break

        triggered_sensitive = sensitive_count >= settings["sensitive_threshold"]
        triggered_rate = rate_limit_count >= settings["rate_limit_threshold"]
        triggered_generic = request_count >= settings["threshold"]
        triggered = triggered_sensitive or triggered_rate or triggered_generic
        if triggered:
            if triggered_sensitive:
                trigger_category = category_now if sensitive_now else "sensitive_scan"
                reason = f"Sensitive-path threshold reached ({sensitive_count}/{settings['sensitive_threshold']})"
            elif triggered_rate:
                trigger_category = "rate_limit"
                reason = f"429 threshold reached ({rate_limit_count}/{settings['rate_limit_threshold']})"
            else:
                trigger_category = "generic_4xx"
                reason = f"4xx threshold reached ({request_count}/{settings['threshold']})"

            last_alert = int(record.get("last_alert") or 0)
            if now - last_alert >= settings["cooldown_seconds"]:
                should_alert = True
                record["last_alert"] = now

            if settings.get("response_mode") == "block":
                did_block, block_seconds, offenses = _http_security_apply_block_locked(record, settings, now, reason)
                if did_block:
                    record["block_category"] = trigger_category
                    should_alert = True
                    record["last_alert"] = now
                    _http_security_stat_add_locked(state, now, client_ip, blocks=1)
                    _http_security_add_history_locked(
                        state,
                        event_type="block",
                        ip=client_ip,
                        category=trigger_category,
                        action="temporary_block",
                        reason=reason,
                        path=request_path,
                        status=status_code,
                        details={"duration_seconds": block_seconds, "offenses": offenses},
                        now=now,
                    )
                    firewall_should_apply = bool(
                        settings.get("firewall_enabled")
                        and offenses >= settings.get("firewall_after_offenses", 3)
                    )
            elif should_alert:
                _http_security_stat_add_locked(state, now, client_ip, monitor_triggers=1)
                _http_security_add_history_locked(
                    state,
                    event_type="monitor_trigger",
                    ip=client_ip,
                    category=trigger_category,
                    action="monitor",
                    reason=reason,
                    path=request_path,
                    status=status_code,
                    details={"requests": request_count, "sensitive": sensitive_count, "rate_limited": rate_limit_count},
                    now=now,
                )

        clients[client_ip] = record
        state["clients"] = clients
        state["updated_at"] = now
        _json_save(_HTTP_4XX_STATE_FILE, state)

    except Exception:
        current_app.logger.debug("HTTP security tracker failed", exc_info=True)
    finally:
        _unlock_state_file(lock_handle)

    firewall_detail = ""
    if did_block and firewall_should_apply:
        fw_ok, firewall_detail = _http_security_firewall_add(client_ip, block_seconds)
        if fw_ok:
            lock_handle = None
            try:
                lock_handle = _lock_state_file(_HTTP_4XX_LOCK_FILE)
                state = _json_load(_HTTP_4XX_STATE_FILE, {})
                clients = state.get("clients") if isinstance(state, dict) else {}
                if isinstance(clients, dict) and isinstance(clients.get(client_ip), dict):
                    clients[client_ip]["firewall_active"] = True
                    state["clients"] = clients
                    _json_save(_HTTP_4XX_STATE_FILE, state)
            finally:
                _unlock_state_file(lock_handle)
        else:
            current_app.logger.warning("HTTP security nftables escalation failed for %s: %s", client_ip, firewall_detail)

    if not should_alert:
        return

    event_key = "security_block" if did_block else "suspicious_4xx"
    details = [
        ("Client IP", client_ip),
        ("Category", trigger_category.replace("_", " ").title()),
        ("Requests", request_count),
        ("Sensitive requests", sensitive_count),
        ("429 responses", rate_limit_count),
        ("Window", _tg_human_duration(settings["window_seconds"])),
        ("Statuses", ", ".join(f"{k}*{v}" for k, v in sorted(status_counts.items()))),
        ("Reason", reason or "Threshold reached"),
        ("Action", (f"Blocked for {_tg_human_duration(block_seconds)}" if did_block else "Monitor only")),
        ("Recent paths", " | ".join(recent_paths)[:700]),
        ("Last method", request.method),
        ("User agent", str(request.headers.get("User-Agent") or "")[:300]),
    ]
    if did_block and settings.get("firewall_enabled"):
        details.append(("Host firewall", "Applied" if not firewall_detail else f"Not applied · {firewall_detail}"))
    geo = _http_security_geo(client_ip, settings)
    if geo:
        details.append(("Network", " · ".join(filter(None, [geo.get("country_code"), geo.get("asn"), geo.get("provider")]))))

    _send_telegram_event(
        event_key,
        "◆ Suspicious HTTP activity detected",
        status=("Temporarily blocked" if did_block else "Threshold reached"),
        details=details,
        dedupe_key=f"http-security:{event_key}:{client_ip}",
        dedupe_seconds=(0 if did_block else settings["cooldown_seconds"]),
    )

