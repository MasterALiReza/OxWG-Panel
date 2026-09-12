"""
OxWg Panel - Short Links & Public Portal Blueprint (shortlinks_bp)
=================================================================
Public client portals, config downloads, template previews, and peer shortlink management.
"""
import re
from io import BytesIO
from flask import (
    Blueprint,
    render_template,
    jsonify,
    abort,
    send_file,
    make_response,
)
from flask_login import login_required

from core.extensions import db
from core.time_utils import now_ts, from_ts, to_ts, isoz
from models import Peer
from auth import require_api_key_or_login
from services.shortlink_service import (
    _peer_from_shortlink_token,
    _shortlink_response_for_peer,
)
from services.peer_lifecycle import (
    _expire,
    _accumulate_peer_usage,
    _effective_expiry_ts,
    _wg_transfer,
)
from services.config_generator import (
    _effective_client_endpoint,
    _peer_client_conf_or_502,
)
from services.panel_settings import (
    _panel_timezone_name,
    _panel_display_datetime,
)
from blueprints.settings_bp import _load_template_settings

shortlinks_bp = Blueprint('shortlinks_bp', __name__)


@shortlinks_bp.route('/api/peer/<int:pid>/shortlink', methods=['GET', 'POST'])
@require_api_key_or_login
def api_shortlink(pid):
    p = db.session.get(Peer, pid) or abort(404)
    return _shortlink_response_for_peer(p)


@shortlinks_bp.route('/api/peer/<path:public_key>/shortlink', methods=['GET', 'POST'])
@require_api_key_or_login
def api_shortlink_by_public_key(public_key):
    public_key = (public_key or '').strip()
    if not public_key:
        abort(404)
    if public_key.isdigit():
        peer = db.session.get(Peer, int(public_key))
    else:
        peer = Peer.query.filter_by(public_key=public_key).first()
    if not peer:
        abort(404)
    return _shortlink_response_for_peer(peer)


@shortlinks_bp.route('/u/<token>')
def user_peer_page(token):
    _peer_from_shortlink_token(token)

    ts = _load_template_settings()
    sel = (ts.get('selected') or 'default').lower()
    s = ts.get('socials') or {}

    tmap = {
        'default': 'user_peer.html',
        'compact': 'user_peer_compact.html',
        'minimal': 'user_peer_minimal.html',
        'pro': 'user_peer_pro.html',
    }
    tpl = tmap.get(sel, 'user_peer.html')

    return render_template(
        tpl,
        token=token,
        support_telegram=(s.get('telegram') or ''),
        support_whatsapp=(s.get('whatsapp') or ''),
        support_instagram=(s.get('instagram') or ''),
        support_phone=(s.get('phone') or ''),
        support_website=(s.get('website') or ''),
        support_email=(s.get('email') or ''),
    )


@shortlinks_bp.get('/preview/template/<name>')
@login_required
def preview_template(name):
    name = (name or '').lower()
    tmap = {
        'default': 'user_peer.html',
        'compact': 'user_peer_compact.html',
        'minimal': 'user_peer_minimal.html',
        'pro': 'user_peer_pro.html',
    }
    tpl = tmap.get(name)
    if not tpl:
        abort(404)

    socials = {
        'telegram': '@preview',
        'whatsapp': '',
        'instagram': '',
        'phone': '',
        'website': '',
        'email': '',
    }

    html = render_template(
        tpl,
        token="PREVIEW_TOKEN",
        preview=True,
        support_telegram=socials['telegram'],
        support_whatsapp=socials['whatsapp'],
        support_instagram=socials['instagram'],
        support_phone=socials['phone'],
        support_website=socials['website'],
        support_email=socials['email'],
    )

    stub = """
<script>
  (function() {
    try {
      window.PREVIEW = true;
      const now = Math.floor(Date.now()/1000);
      const mock = {
        ok: true,
        name: "b1",
        address: "10.66.66.2/24",
        endpoint: "167.71.78.88:57015",
        status: "offline",
        unlimited: false,
        limit_unit: "Mi",
        data_limit: 1024,
        used_bytes: 5632 * 1024 * 1024,
        expires_at_ts: now + 14*24*3600,
        ttl_seconds: 14*24*3600
      };
      const respond = (o) => Promise.resolve({
        ok: true, status: 200,
        json: async () => o, text: async () => JSON.stringify(o)
      });
      window.fetch = function(url, opts) {
        try {
          const u = (typeof url === 'string') ? url : (url && url.url) || '';
          if (u.includes('/api/u/') || u.includes('/api/peer/')) return respond(mock);
        } catch(_){}
        return respond({});
      };
      document.addEventListener('click', function(e){
        const a = e.target.closest('a[href]'); if (a) e.preventDefault();
      }, true);
    } catch(_){}
  })();
</script>"""

    idx = html.rfind('</body>')
    html = html[:idx] + stub + html[idx:] if idx != -1 else html + stub
    resp = make_response(html)
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['Content-Security-Policy'] = (
        "frame-ancestors 'self'; "
        "default-src 'none'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com data:; "
        "img-src 'self' data: blob:; "
        "connect-src 'none'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-src 'none'"
    )
    return resp


@shortlinks_bp.route('/api/u/<token>')
def user_peer(token):
    p = _peer_from_shortlink_token(token)
    if not p:
        abort(404)
    _expire()

    total = _wg_transfer(p)
    used_total, _delta, usage_changed = _accumulate_peer_usage(p, total)
    if usage_changed:
        db.session.commit()

    exp_ts = _effective_expiry_ts(p)
    ttl_seconds = max(0, exp_ts - now_ts()) if exp_ts else None
    used_db = int(getattr(p, 'used_bytes_total', 0) or 0)
    unit = getattr(p, 'data_limit_unit', 'Mi') or 'Mi'
    lim_val = int(getattr(p, 'data_limit_value', 0) or 0)
    lim_bytes = 0
    if lim_val and not getattr(p, 'unlimited', False):
        lim_bytes = lim_val * (1024 * 1024 if unit == 'Mi' else 1024 * 1024 * 1024)

    used_eff = used_db
    if lim_bytes:
        used_eff = min(used_eff, lim_bytes)

    if getattr(p, 'status', '') == 'blocked' and lim_bytes:
        used_eff = lim_bytes

    return jsonify({
        'name': p.name,
        'iface': p.iface.name if p.iface else '',
        'address': p.address,
        'endpoint': _effective_client_endpoint(p),
        'peer_endpoint': getattr(p, 'peer_endpoint', None) or '',
        'status': p.status,
        'unlimited': bool(getattr(p, 'unlimited', False)),
        'limit_unit': unit,
        'data_limit': lim_val,
        'used_bytes': used_eff,
        'used_bytes_db': used_db,
        'used_effective_bytes': used_eff,
        'time_limit_days': getattr(p, 'time_limit_days', None),
        'display_timezone': _panel_timezone_name(),
        'start_on_first_use': bool(getattr(p, 'start_on_first_use', False)),
        'first_used_at': isoz(getattr(p, 'first_used_at', None)),
        'first_used_at_display': _panel_display_datetime(getattr(p, 'first_used_at', None)),
        'expires_at': isoz(from_ts(exp_ts)),
        'expires_at_display': _panel_display_datetime(from_ts(exp_ts)),
        'first_used_at_ts': to_ts(getattr(p, 'first_used_at', None)),
        'expires_at_ts': exp_ts,
        'ttl_seconds': ttl_seconds,
        'allowed_ips': p.allowed_ips or '0.0.0.0/0, ::/0',
        'dns': p.dns or (p.iface.dns if p.iface else '') or '',
        'mtu': p.mtu or (p.iface.mtu if p.iface else None),
    })


@shortlinks_bp.route('/api/u/<token>/config')
def userpeer_config(token):
    p = _peer_from_shortlink_token(token)
    if not p:
        abort(404)

    exp_ts = _effective_expiry_ts(p)
    if (
        getattr(p, 'status', '') in ('blocked', 'offline')
        or (exp_ts and now_ts() >= exp_ts and not getattr(p, 'unlimited', False))
    ):
        return jsonify(
            ok=False,
            error='peer_inactive',
            message='This configuration is inactive, blocked, or expired.',
        ), 403

    cfg, err = _peer_client_conf_or_502(p)
    if err:
        return err

    safe_name = re.sub(
        r'[^A-Za-z0-9_.-]+',
        '_',
        p.name or f'peer-{p.id}',
    ).strip('._') or f'peer-{p.id}'

    mem = BytesIO(cfg.encode('utf-8'))
    response = send_file(
        mem,
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=f'{safe_name}.conf',
        max_age=0,
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = (
        'private, no-store, no-cache, must-revalidate, max-age=0'
    )
    return response
