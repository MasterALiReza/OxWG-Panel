"""
OxWg Panel - Logging Blueprint (logs_bp)
=======================================
Log viewers, settings, retention control, and log archive backups.
"""
import os
import json
import zipfile
import secrets
from io import BytesIO
from pathlib import Path
from datetime import datetime
from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    send_file,
    current_app,
)
from flask_login import login_required

from core.extensions import csrf
from core.paths import (
    APP_LOG_FILE,
    ADMIN_LOG_FILE,
    LOGS_SETTINGS_FILE,
    TELEGRAM_LOG_FILE,
)
from core.time_utils import now_ts
from core.file_utils import _read_tail, _extend_file
from auth import require_api_key_or_login
from services.panel_settings import (
    _panel_timezone_name,
    _panel_display_datetime,
    _panel_filename_stamp,
    _panel_filter_datetime_utc_naive,
)
from services.admin_log import (
    _norm_adminlog,
    _read_admin_logs,
    logpanel_action,
)
from services.log_retention import (
    _load_retention,
    _save_retention,
    _last_cleared,
    _may_autoclear,
)
from core.logging_setup import _applymute_log

logs_bp = Blueprint('logs_bp', __name__)


def _app_log_line(line: str):
    line = line.strip()
    if not line:
        return None
    try:
        if line.startswith('{') and line.endswith('}'):
            return json.loads(line)
    except Exception:
        pass
    return {
        "ts": None,
        "level": "INFO",
        "msg": line,
        "raw": line,
    }


@logs_bp.get('/logs')
@login_required
def logs_page():
    return render_template('logs.html')


@logs_bp.get('/api/logs/settings')
@login_required
def logs_settings_get():
    cfg = {}
    if LOGS_SETTINGS_FILE.exists():
        try:
            with open(LOGS_SETTINGS_FILE, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}

    cfg.setdefault('enabled', True)
    cfg.setdefault('include_debug', False)
    cfg.setdefault('persist', True)
    cfg.setdefault('telegram_notify', False)
    cfg.setdefault('retention_days', 7)
    cfg.setdefault('max_file_mb', 10)
    cfg.setdefault('rotate_files', 5)
    cfg.setdefault('mutes', [])
    cfg.setdefault('sources', {'app': True, 'admin': True, 'telegram': True, 'iface': True})
    cfg.setdefault('mute_save', False)
    cfg.setdefault('keep_last_lines', 0)

    return jsonify(cfg)


@logs_bp.post('/api/logs/settings')
@login_required
def logs_settings_post():
    payload = request.get_json(force=True, silent=True) or {}
    LOGS_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOGS_SETTINGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2)

    try:
        _applymute_log()
    except Exception:
        pass

    return jsonify(ok=True)


@logs_bp.get('/api/logs/retention')
@login_required
def logs_retention():
    return jsonify(retention=_load_retention())


@logs_bp.post('/api/logs/retention')
@login_required
def logs_retention_post():
    data = request.get_json(silent=True) or {}
    incoming = data.get("retention") or {}
    cur = _load_retention()
    for key in ("app", "tg_app", "tg_admin", "iface"):
        v = incoming.get(key)
        if isinstance(v, dict):
            if "max_mb" in v:
                cur[key]["max_mb"] = int(v.get("max_mb") or 0)
            if "max_days" in v:
                cur[key]["max_days"] = int(v.get("max_days") or 0)
    _save_retention(cur)
    return jsonify(ok=True, retention=cur)


@logs_bp.get('/api/logs/backup')
@login_required
def logs_backup():
    source = request.args.get('source', 'app')
    iface = request.args.get('iface', '')
    files = []
    inst = Path(current_app.instance_path)

    if source == 'app':
        files = [inst / 'app.log']
    elif source == 'admin':
        files = [inst / 'admin_logs.jsonl', inst / 'admin.log']
    elif source == 'telegram':
        files = [inst / 'telegram.log']
    elif source == 'iface' and iface:
        files = [inst / f'iface_{iface}.log']
    else:
        files = [inst / 'app.log']

    mem = BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        for p in files:
            if p.exists():
                z.write(p, arcname=p.name)
    mem.seek(0)
    ts = _panel_filename_stamp()
    return send_file(
        mem,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'logs_backup_{source}_{ts}.zip',
    )


@logs_bp.route('/api/app_logs', methods=['GET', 'DELETE'])
@login_required
def app_logs():
    if request.method == 'DELETE':
        try:
            open(APP_LOG_FILE, 'w', encoding='utf-8').close()
            _last_cleared("app")
        except Exception:
            pass
        return jsonify(ok=True)

    q = (request.args.get('q') or '').lower().strip()
    level = (request.args.get('level') or '').lower().strip()
    limit = max(10, min(int(request.args.get('limit') or 500), 2000))
    text = _read_tail(APP_LOG_FILE, 200_000)
    out = []
    for line in text.splitlines():
        rec = _app_log_line(line)
        if not rec:
            continue
        if level and rec.get('level', '').lower() != level:
            continue
        if q and q not in (rec.get('msg') or '').lower():
            continue
        if rec.get('ts'):
            rec['time_display'] = _panel_display_datetime(
                rec['ts'],
                seconds=True,
            )
        out.append(rec)

    return jsonify(
        logs=out[-limit:],
        display_timezone=_panel_timezone_name(),
        server_epoch=now_ts(),
    )


@logs_bp.route('/api/admin_logs', methods=['GET', 'POST', 'DELETE'])
@csrf.exempt
@require_api_key_or_login
def admin_logs():
    if request.method == 'DELETE':
        try:
            open(ADMIN_LOG_FILE, 'w', encoding='utf-8').close()
            _last_cleared("admin")
        except Exception:
            pass
        return jsonify(ok=True)

    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        _norm_adminlog(data)
        return jsonify(ok=True)

    # GET
    q = (request.args.get('q') or '').strip().lower()
    action = (request.args.get('action') or '').strip().lower()
    channel = (request.args.get('channel') or '').strip().lower()
    limit = max(10, min(int(request.args.get('limit') or 1000), 5000))
    from_s = request.args.get('from') or ''
    to_s = request.args.get('to') or ''
    logs = _read_admin_logs(max_lines=max(1000, limit * 5))

    from_dt = _panel_filter_datetime_utc_naive(from_s)
    to_dt = _panel_filter_datetime_utc_naive(to_s)

    def in_range(ts_iso: str) -> bool:
        t = _panel_filter_datetime_utc_naive(ts_iso)
        if t is None:
            return True
        if from_dt and t < from_dt:
            return False
        if to_dt and t > to_dt:
            return False
        return True

    def matches(rec: dict) -> bool:
        if q and q not in json.dumps(rec, ensure_ascii=False).lower():
            return False
        if action and (rec.get('action', '').lower() != action):
            return False
        if channel and (rec.get('channel', '').lower() != channel):
            return False
        ts = rec.get('ts')
        if ts and not in_range(ts):
            return False
        return True

    filtered = [rec for rec in logs if matches(rec)]
    out = filtered[-limit:]
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
