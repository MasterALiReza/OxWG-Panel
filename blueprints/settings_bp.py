"""
OxWg Panel - Settings & Runtime Blueprint (settings_bp)
======================================================
Panel configuration, timezone discovery, healthcheck, runtime worker settings, and panel restart.
"""
import os
import json
import subprocess
from datetime import datetime, timezone
from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    current_app,
)
from flask_login import login_required, current_user

from core.extensions import csrf
from core.time_utils import now_ts
from auth import admin_required, require_api_key_or_login
from services.panel_settings import (
    _load_panel_settings,
    _save_panel_settings,
    _load_runtime,
    _save_runtime,
    _panel_base,
    _is_https,
    _panel_timezone_name,
    _panel_timezone,
    _valid_timezone_name,
)

settings_bp = Blueprint('settings_bp', __name__)


def _template_settings_file():
    return os.path.join(current_app.instance_path, 'template_settings.json')


def _load_template_settings():
    os.makedirs(current_app.instance_path, exist_ok=True)
    try:
        with open(_template_settings_file(), 'r', encoding='utf-8') as f:
            j = json.load(f)
    except Exception:
        j = {}
    j.setdefault('selected', 'default')
    j.setdefault('socials', {
        'telegram': '',
        'whatsapp': '',
        'instagram': '',
        'phone': '',
        'website': '',
        'email': '',
    })
    return j


def _save_template_settings(j: dict):
    os.makedirs(current_app.instance_path, exist_ok=True)
    with open(_template_settings_file(), 'w', encoding='utf-8') as f:
        json.dump(j, f, indent=2)


def _int_or_none(v):
    try:
        return int(v) if v is not None and str(v).strip() != '' else None
    except Exception:
        return None


@settings_bp.get('/settings')
@login_required
def settings_page():
    return render_template('settings.html')


@settings_bp.route('/api/settings', methods=['GET', 'POST'])
@login_required
def api_settings():
    if request.method == 'GET':
        s = _load_panel_settings() or {}
        detected_https = bool(_is_https())
        certp = (s.get("tls_cert_path") or "").strip()
        keyp = (s.get("tls_key_path") or "").strip()
        tls_cert_exists = bool(certp and os.path.isfile(certp))
        tls_key_exists = bool(keyp and os.path.isfile(keyp))
        tls_effective = bool(getattr(current_app, "_tls_enabled_effective", False))

        domain = (s.get('domain') or '').strip()
        if not domain:
            try:
                from urllib.parse import urlparse
                env_panel = (os.getenv('PANEL') or '').strip()
                if env_panel:
                    domain = (urlparse(env_panel).hostname or '').strip() or domain
            except Exception:
                pass
            if not domain:
                domain = (request.host or '').split(':', 1)[0].strip()

        def _to_int(v):
            try:
                return int(v) if v is not None and v != "" else None
            except Exception:
                return None

        s_out = dict(s)
        s_out["http_port"] = _to_int(s.get("http_port"))
        s_out["https_port"] = _to_int(s.get("https_port"))

        return jsonify({
            **s_out,
            "tls_enabled": bool(s.get("tls_enabled")),
            "tls_effective": tls_effective,
            "tls_cert_exists": tls_cert_exists,
            "tls_key_exists": tls_key_exists,
            "domain": domain,
            "current_scheme": "https" if detected_https else "http",
            "cookie_secure": bool(current_app.config.get("SESSION_COOKIE_SECURE", False)),
            "detected_https": bool(detected_https),
        })

    data = request.get_json(silent=True) or {}
    cur = _load_panel_settings() or {}

    def _port(v):
        if v in (None, ""):
            return None
        try:
            i = int(v)
            return i if 1 <= i <= 65535 else None
        except Exception:
            return None

    tls_enabled = bool(data.get("tls_enabled", False))
    domain = (data.get("domain") or "").strip()
    force_https = bool(data.get("force_https_redirect", False))
    hsts = bool(data.get("hsts", False))
    requested_timezone = data.get("timezone") if "timezone" in data else cur.get("timezone")

    panel_timezone = _valid_timezone_name(requested_timezone)
    if not panel_timezone:
        return jsonify(
            ok=False,
            error="invalid_timezone",
            message="Timezone must be a valid IANA timezone such as Asia/Tehran or Europe/Amsterdam.",
        ), 400

    if not tls_enabled:
        force_https = False
        hsts = False

    http_port = _port(data.get("http_port"))
    https_port = _port(data.get("https_port"))

    if tls_enabled and https_port is None:
        https_port = _port(cur.get("https_port"))
    if (not tls_enabled) and http_port is None:
        http_port = _port(cur.get("http_port"))

    tls_cert_path = (data.get("tls_cert_path") if "tls_cert_path" in data else cur.get("tls_cert_path") or "").strip()
    tls_key_path = (data.get("tls_key_path") if "tls_key_path" in data else cur.get("tls_key_path") or "").strip()

    payload = {
        "tls_enabled": tls_enabled,
        "domain": domain,
        "force_https_redirect": force_https,
        "hsts": hsts,
        "http_port": http_port,
        "https_port": https_port,
        "tls_cert_path": tls_cert_path,
        "tls_key_path": tls_key_path,
        "timezone": panel_timezone,
    }

    _save_panel_settings(payload)

    try:
        next_url = _panel_base()
    except Exception:
        next_url = None

    return jsonify(ok=True, settings=payload, next_url=next_url, requires_restart=False)


@settings_bp.get("/api/timezone")
@require_api_key_or_login
def api_timezone():
    tz_name = _panel_timezone_name()
    tz = _panel_timezone()
    now_utc = datetime.now(timezone.utc)
    now_local = now_utc.astimezone(tz)

    return jsonify(
        ok=True,
        build="20260904-v9",
        timezone=tz_name,
        server_epoch=now_ts(),
        utc_now=now_utc.isoformat(timespec="seconds").replace("+00:00", "Z"),
        local_now=now_local.isoformat(timespec="seconds"),
        utc_offset=now_local.strftime("%z"),
    )


@settings_bp.get('/api/template_settings')
@login_required
def template_settings_get():
    return jsonify(_load_template_settings())


@settings_bp.post('/api/template_settings')
@login_required
def template_settings_post():
    data = request.get_json(silent=True) or {}
    cur = _load_template_settings()

    if 'selected' in data:
        sel = (data.get('selected') or '').strip().lower()
        if sel not in ('default', 'compact', 'minimal', 'pro'):
            return jsonify(error='invalid template'), 400
        cur['selected'] = sel

    if 'socials' in data:
        s = data.get('socials') or {}
        cur['socials'] = {
            'telegram': (s.get('telegram') or '').strip(),
            'whatsapp': (s.get('whatsapp') or '').strip(),
            'instagram': (s.get('instagram') or '').strip(),
            'phone': (s.get('phone') or '').strip(),
            'website': (s.get('website') or '').strip(),
            'email': (s.get('email') or '').strip(),
        }

    _save_template_settings(cur)
    return jsonify(ok=True, settings=cur)


@settings_bp.get("/api/healthz")
@require_api_key_or_login
def healthz():
    return jsonify(ok=True, ts=now_ts()), 200


@settings_bp.get('/api/runtime')
@login_required
@admin_required
def runtime_get():
    saved = _load_runtime() or {}
    port_env = os.getenv('PORT')
    eff = {
        'bind': os.getenv('BIND') or '',
        'port': int(port_env) if (port_env and port_env.isdigit()) else None,
        'workers': _int_or_none(os.getenv('WORKERS')),
        'threads': _int_or_none(os.getenv('THREADS')),
        'timeout': _int_or_none(os.getenv('TIMEOUT')),
        'graceful_timeout': _int_or_none(os.getenv('GRACEFUL_TIMEOUT')),
        'loglevel': (os.getenv('LOGLEVEL') or '').lower() or None,
    }
    return jsonify(saved=saved, effective=eff, requires_restart=True)


@settings_bp.post('/api/runtime')
@csrf.exempt
@login_required
@admin_required
def runtime_post():
    data = request.get_json(silent=True) or {}
    cur = _load_runtime() or {}
    new = dict(cur)

    try:
        if 'bind' in data and isinstance(data.get('bind'), str):
            raw_bind = data['bind']
            new['bind'] = raw_bind.strip() or (cur.get('bind') or '0.0.0.0')

        if 'port' in data and data['port'] is not None:
            raw_port = data['port']
            p = _int_or_none(raw_port)
            if p is None:
                raise ValueError(f"port must be a number (got {raw_port!r})")
            new['port'] = p

            b = (new.get('bind') or cur.get('bind') or os.getenv('BIND') or '0.0.0.0').strip()
            if ':' in b:
                host, _sep, _old = b.rpartition(':')
                host = host or '0.0.0.0'
                new['bind'] = f'{host}:{new["port"]}'
            else:
                new['bind'] = b

        if 'workers' in data and data['workers'] is not None:
            new['workers'] = _int_or_none(data['workers']) or 0
        if 'threads' in data and data['threads'] is not None:
            new['threads'] = _int_or_none(data['threads']) or 4
        if 'timeout' in data and data['timeout'] is not None:
            new['timeout'] = _int_or_none(data['timeout']) or 60
        if 'graceful_timeout' in data and data['graceful_timeout'] is not None:
            new['graceful_timeout'] = _int_or_none(data['graceful_timeout']) or 30
        if 'loglevel' in data and data['loglevel']:
            new['loglevel'] = str(data['loglevel']).strip().lower()

        if 'ssl_certfile' in data and data['ssl_certfile']:
            new['ssl_certfile'] = data['ssl_certfile'].strip()
        if 'ssl_keyfile' in data and data['ssl_keyfile']:
            new['ssl_keyfile'] = data['ssl_keyfile'].strip()

        _save_runtime(new)
        return jsonify(ok=True, saved=new, requires_restart=True)

    except Exception as exc:
        current_app.logger.warning("runtime_post failed: %s", exc)
        return jsonify(error=str(exc)), 400


@settings_bp.post("/api/panel/restart")
@login_required
@admin_required
def api_panel_restart():
    svc = os.getenv("PANEL_SERVICE_NAME", "wg-panel.service")
    try:
        try:
            next_base = _panel_base()
        except Exception:
            next_base = None

        current_app.logger.warning(
            "panel_restart requested by user=%s ip=%s service=%s",
            getattr(current_user, "username", "?"),
            request.remote_addr,
            svc,
        )

        subprocess.Popen(["systemctl", "restart", svc])
        return jsonify(ok=True, restarting=True, service=svc, next_url=next_base)
    except Exception as e:
        current_app.logger.exception("panel_restart failed: %s", e)
        return jsonify(error=str(e)), 500
