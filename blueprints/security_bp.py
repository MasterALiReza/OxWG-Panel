"""
OxWg Panel - HTTP Protection & Security Blueprint (security_bp)
==============================================================
Rate-limiting configuration, active IP block management, unbanning, and security event logs.
"""
import re
import time
import ipaddress
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required

from auth import require_api_key_or_login
from core.paths import _HTTP_4XX_STATE_FILE, _HTTP_SECURITY_SETTINGS_FILE
from core.file_utils import _json_load, _json_save
from services.http_security import (
    _load_http_security_settings,
    _http_security_nft_status,
    _http_security_normalize_networks,
    _http_security_normalize_ip,
    _http_security_client_ip,
    _http_security_is_network_match,
    _http_security_firewall_remove,
    _HTTP_SECURITY_TEMP_ALLOW_MAX_SEC,
    _http_security_int,
)
from services.telegram_notifier import _send_telegram_event, _tg_human_duration

security_bp = Blueprint('security_bp', __name__)


def _active_blocks(state, settings=None):
    now = int(time.time())
    clients = state.get("clients") if isinstance(state, dict) else {}
    if not isinstance(clients, dict):
        return []
    res = []
    for ip, rec in clients.items():
        if isinstance(rec, dict) and int(rec.get("blocked_until") or 0) > now:
            res.append({
                "ip": ip,
                "blocked_until": int(rec.get("blocked_until")),
                "reason": rec.get("block_reason") or "Triggered security rule",
                "offenses": int(rec.get("offenses") or 1),
                "firewall_active": bool(rec.get("firewall_active")),
            })
    return res


def _temp_allows(state, now=None):
    now = now or int(time.time())
    rows = state.get("temporary_allow", []) if isinstance(state, dict) else []
    if isinstance(rows, dict):
        rows = [{"network": k, "expires_at": v} for k, v in rows.items()]
    return [r for r in rows if isinstance(r, dict) and int(r.get("expires_at") or 0) > now]


def _stats_24h(state):
    return state.get("stats_24h", {}) if isinstance(state, dict) else {}


@security_bp.get('/api/security/http-protection/capabilities')
@login_required
def http_security_capabilities_get():
    settings = _load_http_security_settings()
    return jsonify(
        ok=True,
        firewall=_http_security_nft_status(settings),
        geo={
            "enabled": bool(settings.get("enrich_ip")),
            "provider": "ipwho.is",
            "external_lookup": True,
            "display_only": True,
            "cache_seconds": 86400,
        },
    )


@security_bp.get('/api/security/http-protection')
@require_api_key_or_login
def http_security_settings_get():
    settings = _load_http_security_settings()
    state = _json_load(_HTTP_4XX_STATE_FILE, {})
    return jsonify(
        ok=True,
        settings=settings,
        active_blocks=_active_blocks(state, settings=settings),
        temporary_allow=_temp_allows(state),
        stats_24h=_stats_24h(state),
        firewall=_http_security_nft_status(settings),
    )


@security_bp.post('/api/security/http-protection')
@require_api_key_or_login
def http_security_settings_post():
    payload = request.get_json(silent=True) or {}
    allowed = {
        "enabled", "response_mode", "ip_source", "block_scope", "threshold", "window_seconds",
        "sensitive_threshold", "rate_limit_threshold", "login_threshold", "login_window_seconds",
        "cooldown_seconds", "block_seconds", "max_block_seconds", "escalate", "enrich_ip",
        "firewall_enabled", "firewall_after_offenses", "trusted_networks", "deny_networks",
    }
    partial = {k: payload[k] for k in allowed if k in payload}

    for key in ("trusted_networks", "deny_networks"):
        if key in partial:
            partial[key] = _http_security_normalize_networks(partial[key])

    proposed = _load_http_security_settings()
    proposed.update(partial)
    proposed["trusted_networks"] = _http_security_normalize_networks(proposed.get("trusted_networks"))
    proposed["deny_networks"] = _http_security_normalize_networks(proposed.get("deny_networks"))

    current_ip = _http_security_client_ip(proposed)
    if current_ip != "unknown" and _http_security_is_network_match(current_ip, proposed.get("deny_networks", [])):
        return jsonify(
            ok=False,
            error="would_block_current_admin",
            message="The permanent deny list contains your current client IP. Remove it before saving.",
            ip=current_ip,
        ), 409

    _json_save(_HTTP_SECURITY_SETTINGS_FILE, proposed)
    settings = _load_http_security_settings()
    state = _json_load(_HTTP_4XX_STATE_FILE, {})
    return jsonify(
        ok=True,
        settings=settings,
        active_blocks=_active_blocks(state, settings=settings),
        temporary_allow=_temp_allows(state),
        stats_24h=_stats_24h(state),
        firewall=_http_security_nft_status(settings),
    )


@security_bp.post('/api/security/http-protection/unban')
@require_api_key_or_login
def http_security_unban():
    payload = request.get_json(silent=True) or {}
    client_ip = _http_security_normalize_ip(payload.get("ip"))
    if client_ip == "unknown":
        return jsonify(ok=False, error="invalid_ip"), 400

    now = int(time.time())
    state = _json_load(_HTTP_4XX_STATE_FILE, {})
    if not isinstance(state, dict):
        state = {}
    clients = state.get("clients", {})
    if not isinstance(clients, dict):
        clients = {}

    released = False
    rec = clients.get(client_ip)
    if isinstance(rec, dict):
        released = int(rec.get("blocked_until") or 0) > now
        rec["blocked_until"] = 0
        rec["block_active"] = False
        rec["firewall_active"] = False
        clients[client_ip] = rec

    history = state.get("history", [])
    if isinstance(history, list):
        history.append({
            "type": "manual_release",
            "category": "release",
            "ip": client_ip,
            "ts": now,
            "reason": "Released by administrator",
        })
        state["history"] = history[-500:]

    state["clients"] = clients
    state["updated_at"] = now
    _json_save(_HTTP_4XX_STATE_FILE, state)

    try:
        _http_security_firewall_remove(client_ip)
    except Exception:
        pass

    if released:
        _send_telegram_event(
            "security_release",
            "HTTP security block released",
            status="Manually released",
            details=[("Client IP", client_ip)],
        )

    return jsonify(ok=True, ip=client_ip, active_blocks=_active_blocks(state))


@security_bp.get('/api/security/http-protection/events')
@require_api_key_or_login
def http_security_events_get():
    state = _json_load(_HTTP_4XX_STATE_FILE, {})
    history = state.get("history") if isinstance(state, dict) else []
    if not isinstance(history, list):
        history = []

    event_type = str(request.args.get("type") or "").strip().lower()
    category = str(request.args.get("category") or "").strip().lower()
    ip_filter = str(request.args.get("ip") or "").strip()
    limit = _http_security_int(request.args.get("limit"), 150, 1, 500)

    rows = []
    for row in reversed(history):
        if not isinstance(row, dict):
            continue
        if event_type and str(row.get("type") or "").lower() != event_type:
            continue
        if category and str(row.get("category") or "").lower() != category:
            continue
        if ip_filter and ip_filter not in str(row.get("ip") or ""):
            continue
        rows.append(dict(row))
        if len(rows) >= limit:
            break

    return jsonify(ok=True, events=rows, stats_24h=_stats_24h(state))


@security_bp.delete('/api/security/http-protection/events')
@login_required
def http_security_events_clear():
    state = _json_load(_HTTP_4XX_STATE_FILE, {})
    if not isinstance(state, dict):
        state = {}
    state["history"] = []
    state["updated_at"] = int(time.time())
    _json_save(_HTTP_4XX_STATE_FILE, state)
    return jsonify(ok=True)


@security_bp.post('/api/security/http-protection/temporary-allow')
@login_required
def http_security_temporary_allow_add():
    payload = request.get_json(silent=True) or {}
    raw = str(payload.get("network") or "").strip()
    duration = _http_security_int(payload.get("duration_seconds"), 3600, 60, _HTTP_SECURITY_TEMP_ALLOW_MAX_SEC)
    normalized = _http_security_normalize_networks([raw])
    if not normalized:
        return jsonify(ok=False, error="invalid_network"), 400
    network = normalized[0]
    now = int(time.time())
    expires_at = now + duration

    state = _json_load(_HTTP_4XX_STATE_FILE, {})
    if not isinstance(state, dict):
        state = {}
    rows = _temp_allows(state, now)
    rows = [r for r in rows if str(r.get("network")) != network]
    rows.append({"network": network, "expires_at": expires_at})
    state["temporary_allow"] = rows
    _json_save(_HTTP_4XX_STATE_FILE, state)
    return jsonify(ok=True, network=network, expires_at=expires_at, temporary_allow=rows)


@security_bp.post('/api/security/http-protection/temporary-allow/remove')
@login_required
def http_security_temporary_allow_remove():
    payload = request.get_json(silent=True) or {}
    normalized = _http_security_normalize_networks([payload.get("network")])
    if not normalized:
        return jsonify(ok=False, error="invalid_network"), 400
    network = normalized[0]
    now = int(time.time())

    state = _json_load(_HTTP_4XX_STATE_FILE, {})
    if not isinstance(state, dict):
        state = {}
    rows = _temp_allows(state, now)
    rows = [r for r in rows if str(r.get("network")) != network]
    state["temporary_allow"] = rows
    _json_save(_HTTP_4XX_STATE_FILE, state)
    return jsonify(ok=True, network=network, temporary_allow=rows)
