"""
OxWg Panel - Telegram Blueprint (telegram_bp)
=============================================
Manages Telegram bot integration, webhook settings, notifications,
admin management, heartbeat monitoring, and Telegram event logs.
"""
import os
import re
import json
from datetime import datetime, timezone
from pathlib import Path
import requests

from flask import (
    Blueprint,
    request,
    jsonify,
    current_app,
)
from flask_login import login_required

from core.extensions import csrf
from auth import require_api_key, require_api_key_or_login
from core.paths import (
    TELEGRAM_SETTINGS_FILE,
    TELEGRAM_ADMINS_FILE,
    TELEGRAM_LOG_FILE,
    TELEGRAM_ADMIN_LOG_FILE,
    TELEGRAM_HB_FILE,
)
from core.json_utils import _json_load, _json_save, _extend_file, _read_tail
from core.time_utils import now_ts, from_ts, isoz, _tg_parse_datetime
from services.panel_settings import _panel_timezone_name, _panel_display_datetime
from services.telegram_notifier import (
    _load_tg_settings,
    _save_tg_settings,
    _load_tg_admins,
    _save_tg_admins,
)
from blueprints.logs_bp import _last_cleared

telegram_bp = Blueprint('telegram_bp', __name__)

HEARTBEAT_WORD = "heartbeat"


def _now_iso() -> str:
    return isoz(datetime.now(timezone.utc)) or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_timestamp_iso(value):
    """Return a canonical UTC API instant without changing stored data."""
    parsed = _tg_parse_datetime(value)
    if parsed is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _panel_filter_datetime_utc_naive(value):
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
            parsed = _tg_parse_datetime(raw)
            if parsed is None:
                return None
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except Exception:
        return None


def _parse_tg(s: str):
    s = (s or '').rstrip('\n')
    m = re.match(r'^\[([0-9T:\-]{19}Z)\]\s*(.*)$', s)
    ts_iso, text = (m.group(1), m.group(2)) if m else (None, s)

    ts_dt = None
    if ts_iso:
        try:
            ts_dt = datetime.strptime(ts_iso, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            ts_dt = None

    low = text.lower()
    if HEARTBEAT_WORD in low:
        kind = 'heartbeat'
    elif 'error' in low:
        kind = 'error'
    elif 'warn' in low:
        kind = 'warning'
    else:
        kind = 'info'

    return {'ts_iso': ts_iso, 'ts_dt': ts_dt, 'text': text, 'kind': kind, 'raw': s}


def _in_range(dt, from_s, to_s):
    if not dt:
        return True
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    ok = True
    if from_s:
        boundary = _panel_filter_datetime_utc_naive(from_s)
        if boundary is not None:
            ok = ok and dt >= boundary
    if to_s:
        boundary = _panel_filter_datetime_utc_naive(to_s)
        if boundary is not None:
            ok = ok and dt <= boundary
    return ok


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@telegram_bp.route('/api/telegram/test', methods=['POST'])
@login_required
def tg_test():
    try:
        s = _load_tg_settings()
        if not s.get('enabled'):
            return jsonify(error="Telegram is disabled."), 400

        token = (s.get('bot_token') or '').strip()
        if not token:
            return jsonify(error="Bot token is not set."), 400

        admins = _load_tg_admins() or []
        recips = []
        for a in admins:
            chat_id = a.get('id') or a.get('tg_id') or a.get('chat_id')
            if chat_id and not a.get('muted'):
                recips.append(chat_id)

        if not recips:
            return jsonify(error="No active (unmuted) admins with valid IDs."), 400

        failures = []
        for chat_id in recips:
            try:
                r = requests.post(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    json={"chat_id": chat_id,
                          "text": "✅ <b>Test</b>: panel → Telegram notifications are working.",
                          "parse_mode": "HTML"},
                    timeout=6
                )
                if r.status_code != 200:
                    failures.append({"chat_id": chat_id, "status": r.status_code, "body": r.text[:200]})
            except Exception as e:
                failures.append({"chat_id": chat_id, "error": str(e)})

        if failures and len(failures) == len(recips):
            current_app.logger.warning("Telegram test failed: %s", failures)
            return jsonify(error="Telegram API rejected all recipients. Have you DMed /start to the bot?",
                           detail=failures[:3]), 502

        if failures:
            current_app.logger.warning("Telegram test partial failure: %s", failures)
            return jsonify(ok=False, sent=len(recips) - len(failures), failures=len(failures)), 207

        return jsonify(ok=True, sent=len(recips))
    except Exception:
        current_app.logger.exception("Telegram test error")
        return jsonify(error="Server error while sending test"), 500


@telegram_bp.get('/api/telegram/settings')
@login_required
def tg_settings_get():
    s = _load_tg_settings()
    return jsonify(
        enabled=s.get('enabled', False),
        has_token=bool(s.get('bot_token')),
        notify=s.get('notify', {})
    )


@telegram_bp.post('/api/telegram/settings')
@login_required
def tg_settings_post():
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get('enabled', False))
    notify = data.get('notify') or {}
    _save_tg_settings({'enabled': enabled, 'notify': notify})
    return jsonify(ok=True)


@telegram_bp.post('/api/telegram/token')
@login_required
def tg_token_set():
    data = request.get_json(silent=True) or {}
    tok = (data.get('bot_token') or '').strip()
    if not tok:
        return jsonify(error='bot_token required'), 400
    _save_tg_settings({'bot_token': tok})
    return jsonify(ok=True)


@telegram_bp.delete('/api/telegram/token')
@login_required
def tg_token_clear():
    s = _load_tg_settings()
    s['bot_token'] = ''
    _json_save(TELEGRAM_SETTINGS_FILE, s)
    return jsonify(ok=True)


@telegram_bp.get('/api/telegram/admins')
@require_api_key_or_login
def tg_admins_get():
    return jsonify(
        admins=_load_tg_admins(),
        display_timezone=_panel_timezone_name(),
        server_epoch=now_ts(),
    )


@telegram_bp.post('/api/telegram/admins')
@login_required
def tg_admins_post():
    data = request.get_json(silent=True) or {}
    tg_id = str(data.get('tg_id') or data.get('id') or '').strip()
    if not tg_id.isdigit():
        return jsonify(error='tg_id numeric'), 400
    username = (data.get('username') or '').lstrip('@').strip()
    note = (data.get('note') or '').strip()
    muted = bool(data.get('muted', False))

    admins = _load_tg_admins()
    found = next((a for a in admins if a.get('id') == tg_id), None)
    if found:
        found.update({
            'username': username,
            'note': note,
            'muted': muted,
        })
    else:
        admins.append({
            'id': tg_id,
            'username': username,
            'note': note,
            'muted': muted,
            'created_at': _now_iso(),
        })
    _save_tg_admins(admins)
    return jsonify(ok=True, admins=admins)


@telegram_bp.delete('/api/telegram/admins/<tg_id>')
@login_required
def tg_admins_del(tg_id):
    admins = [a for a in _load_tg_admins() if str(a.get('id')) != str(tg_id)]
    _save_tg_admins(admins)
    return jsonify(ok=True, admins=admins)


@telegram_bp.get('/api/telegram/logs')
@login_required
def tg_logs_get():
    fmt = (request.args.get('format') or 'json').lower().strip()
    level = (request.args.get('level') or '').lower().strip()
    q = (request.args.get('q') or '').lower().strip()
    from_s = request.args.get('from') or ''
    to_s = request.args.get('to') or ''
    limit = int(request.args.get('limit') or 500)

    tail = _read_tail(TELEGRAM_LOG_FILE, 20000) or ""
    lines = tail.splitlines()

    if fmt == 'txt':
        return jsonify(logs=tail if tail else '(no logs yet)')

    out = []
    for s in lines:
        rec = _parse_tg(s)
        if level and rec.get('kind') != level:
            continue
        if q and q not in rec.get('raw', '').lower():
            continue
        if not _in_range(rec.get('ts_dt'), from_s, to_s):
            continue
        out.append({
            "ts": rec.get("ts_iso"),
            "kind": rec.get("kind"),
            "text": rec.get("text"),
        })

    out = out[-max(50, min(limit, 2000)):]

    for row in out:
        if row.get('ts'):
            row['time_display'] = _panel_display_datetime(
                row['ts'],
                seconds=True,
            )

    return jsonify(
        logs=out,
        display_timezone=_panel_timezone_name(),
        server_epoch=now_ts(),
    )


@telegram_bp.delete('/api/telegram/logs')
@login_required
def tg_logs_del():
    try:
        open(TELEGRAM_LOG_FILE, 'w').close()
        _last_cleared("tg_app")
    except Exception:
        pass
    return jsonify(ok=True)


@telegram_bp.get('/api/telegram/status')
@login_required
def tg_status():
    hb = _json_load(TELEGRAM_HB_FILE, {})
    last = int(hb.get('ts') or 0)
    sec = max(15, int(current_app.config.get('TG_HEARTBEAT_SEC', 60) or 60))

    heartbeat_age = (max(0, now_ts() - last) if last else None)
    heartbeat_fresh = bool(last and heartbeat_age <= max(180, sec * 4))
    process_alive = False

    try:
        pid = int(hb.get('pid') or 0)
        if pid > 1:
            os.kill(pid, 0)
            process_alive = True
    except ProcessLookupError:
        process_alive = False
    except PermissionError:
        process_alive = True
    except Exception:
        process_alive = False

    online = bool(heartbeat_fresh or process_alive)

    if heartbeat_fresh:
        state = 'online'
    elif process_alive:
        state = 'running_heartbeat_stale'
    else:
        state = 'offline'

    return jsonify(
        bot_online=online,
        state=state,
        heartbeat_fresh=heartbeat_fresh,
        process_alive=process_alive,
        heartbeat_age_seconds=heartbeat_age,
        heartbeat_interval_seconds=sec,
        last_seen=(isoz(from_ts(last)) if last else None),
        pid=hb.get('pid'),
        version=hb.get('version'),
    )


@csrf.exempt
@telegram_bp.post('/api/telegram/heartbeat')
@require_api_key
def tg_heartbeat():
    data = request.get_json(silent=True) or {}
    rec = {
        'ts': now_ts(),
        'pid': data.get('pid'),
        'version': data.get('version') or 'unknown',
        'panel': data.get('panel') or '',
        'service': data.get('service') or 'telegram-bot',
    }

    _json_save(TELEGRAM_HB_FILE, rec)
    _extend_file(
        TELEGRAM_LOG_FILE,
        f"[{isoz(from_ts(rec['ts']))}] heartbeat pid={rec['pid']} v={rec['version']} service={rec['service']}",
        source='telegram',
    )

    return jsonify(
        ok=True,
        server_ts=rec['ts'],
    )


@telegram_bp.get('/api/telegram/admin_logs')
@login_required
def tg_admin_logs():
    tail = _read_tail(TELEGRAM_ADMIN_LOG_FILE, 20000) or ""
    rows = []
    for line in tail.splitlines():
        try:
            row = json.loads(line)
            normalized = _utc_timestamp_iso(row.get('ts'))
            if normalized:
                row['ts'] = normalized
                row['time_display'] = _panel_display_datetime(
                    normalized,
                    seconds=True,
                )
            rows.append(row)
        except Exception:
            continue

    return jsonify({
        'logs': rows,
        'display_timezone': _panel_timezone_name(),
        'server_epoch': now_ts(),
    })


@telegram_bp.delete('/api/telegram/admin_logs')
@login_required
def tg_adminlogs_clear():
    with open(TELEGRAM_ADMIN_LOG_FILE, 'w', encoding='utf-8') as f:
        pass
    return jsonify(ok=True)


@csrf.exempt
@telegram_bp.post('/api/telegram/admin_log')
@require_api_key
def tg_adminlog():
    data = request.get_json(silent=True) or {}
    rec = {
        "ts": _now_iso(),
        "admin_id": str(data.get("admin_id") or ""),
        "admin_username": data.get("admin_username") or "",
        "action": data.get("action") or "",
        "details": data.get("details") or "",
    }
    _extend_file(TELEGRAM_ADMIN_LOG_FILE, json.dumps(rec, ensure_ascii=False))
    _extend_file(TELEGRAM_LOG_FILE, f"[{rec['ts']}] admin {rec['admin_id']} {rec['action']} {rec['details']}")
    return jsonify(ok=True, recorded=True)
