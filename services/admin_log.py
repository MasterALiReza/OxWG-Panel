"""
OxWg Panel - Admin Action Logging
=================================
Audit logging and retrieval for administrator operations across Web UI, API, and Telegram channels.
"""
import os
import json
import secrets
from datetime import datetime, timezone
from typing import Any
from core.paths import ADMIN_LOG_FILE
from core.file_utils import _extend_file


def _whoami_logs() -> tuple[str, str]:
    """Safely extract (admin_id, admin_username) from current request context if available."""
    try:
        from flask_login import current_user as cu
        if cu and getattr(cu, "is_authenticated", False):
            aid = str(getattr(cu, "id", "") or getattr(cu, "username", "") or "")
            uname = getattr(cu, "username", None) or ""
            return aid, uname
    except Exception:
        pass

    try:
        from flask import session
        aid = str(session.get("user_id") or session.get("username") or "")
        uname = str(session.get("username") or "")
        return aid, uname
    except Exception:
        pass

    return "", ""


def _norm_adminlog(entry: dict[str, Any]) -> dict[str, Any]:
    """
    Format, normalize, and append an admin audit log entry to the JSONL log file.
    """
    channel = entry.get("channel")
    if not channel:
        try:
            from flask import request, current_app
            if hasattr(current_app, "login_manager") and ("session" in request.headers or request.cookies):
                channel = "web"
            else:
                channel = "api"
        except Exception:
            channel = "service"

    aid = str(entry.get("admin_id") or "")
    uname = str(entry.get("admin_username") or "")
    if not aid and not uname:
        aid, uname = _whoami_logs()

    ua = ""
    try:
        from flask import request
        if channel == "web" and request:
            ua = request.headers.get("User-Agent", "")
    except Exception:
        pass

    resource = entry.get("resource")
    if not isinstance(resource, dict):
        resource = {
            "peer_id": entry.get("peer_id"),
            "iface": entry.get("iface"),
            "scope": entry.get("scope"),
        }

    meta = entry.get("meta")
    if not isinstance(meta, dict):
        meta = {
            "bot_host": entry.get("bot_host") or "",
            "user_agent": ua,
        }

    row = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "request_id": entry.get("request_id") or secrets.token_hex(6),
        "channel": channel,
        "admin_id": aid,
        "admin_username": uname,
        "action": entry.get("action") or "",
        "resource": resource,
        "details": entry.get("details") or "",
        "result": entry.get("result") or "ok",
        "meta": meta,
    }

    _extend_file(ADMIN_LOG_FILE, json.dumps(row, ensure_ascii=False), source='admin')
    return row


def logpanel_action(action: str, details: str = "") -> dict[str, Any]:
    """Convenience helper to record a panel admin action."""
    return _norm_adminlog({"action": action, "details": details})


def _read_admin_logs(max_lines: int = 2000) -> list[dict[str, Any]]:
    """Read the most recent admin log entries from the JSONL log file."""
    rows = []
    if not os.path.isfile(ADMIN_LOG_FILE):
        return []

    try:
        with open(ADMIN_LOG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return rows[-max_lines:]
