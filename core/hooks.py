"""
OxWg Panel - Application Lifecycle Hooks
========================================
Registers all 15 global Flask request lifecycle hooks, error handlers, and context processors:
  1. @app.errorhandler(Exception): _unhandled
  2. @app.before_request: _csrf_protect_ui
  3. @app.context_processor: inject_nav_flags
  4. @app.context_processor: inject_panel_timezone
  5. @app.before_request: _dev_cookie
  6. @app.after_request: _log_request
  7. @app.after_request: cache_headers
  8. @app.after_request: inject_sec_headers
  9. @app.before_request: _https_redirect
 10. @app.after_request: _maybe_hsts
 11. @app.after_request: security_headers
 12. @app.before_request: _http_security_enforce_temporary_block
 13. @app.after_request: _suspicious_4xx_after_request
 14. @app.before_request: _cookie_scheme
 15. @app.before_request: _expiry_tick_on_requests
 Plus inject_brand for global template branding.
"""
import os
import time
from flask import (
    Flask,
    request,
    current_app,
    redirect,
    jsonify,
    make_response,
    g,
)
from werkzeug.exceptions import HTTPException

from core.extensions import csrf
from core.paths import _HTTP_4XX_STATE_FILE
from core.file_utils import _json_load
from services.panel_settings import _is_https, _load_panel_settings, _panel_timezone_name
from services.http_security import (
    _load_http_security_settings,
    _http_security_client_ip,
    _http_security_is_denied,
    _http_security_is_trusted,
    _http_security_is_temporarily_allowed,
    _http_security_scope_applies,
    _record_suspicious_4xx,
)
from services.peer_lifecycle import _run_expiry_once, _EXPIRY_INTERVAL_SEC

_EXPIRY_LAST_TS = 0.0


def _unhandled(e: Exception):
    """Global exception handler catching unhandled errors and logging them."""
    if isinstance(e, HTTPException):
        return e
    current_app.logger.exception("Unhandled exception")
    return "Internal Server Error", 500


def _csrf_protect_ui():
    """Enforce CSRF protection on UI POST/PUT/PATCH/DELETE methods, exempting /api/."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.path.startswith("/api/"):
            return
        csrf.protect()


def inject_nav_flags():
    """Inject sidebar and navigation flags into Jinja templates."""
    v = set(current_app.view_functions.keys())
    has_nodes = 'nodes' in v or 'nodes_bp.nodes' in v
    has_settings = (
        'settings_page' in v
        or 'settings_bp.settings_page' in v
        or 'settings_bp.settings' in v
        or 'settings' in v
    )
    return {'HAS_NODES': has_nodes, 'HAS_SETTINGS': has_settings}


def inject_panel_timezone():
    """Inject current panel timezone into Jinja templates."""
    try:
        timezone_name = _panel_timezone_name() or 'UTC'
    except Exception:
        timezone_name = 'UTC'
    return {'PANEL_TIMEZONE': timezone_name}


def inject_brand():
    """Inject panel branding constants into Jinja templates."""
    repo = os.getenv('PANEL_REPO', 'MasterALiReza/OxWG-Panel')
    return {
        'PANEL_BRAND_NAME': os.getenv('PANEL_BRAND_NAME', 'OxWg Panel'),
        'PANEL_SHORT_NAME': 'OxWg',
        'PANEL_REPO': repo,
        'PANEL_REPO_URL': f'https://github.com/{repo}',
    }


def _dev_cookie():
    """Sync session cookie secure flag with current HTTPS status in development."""
    current_app.config['SESSION_COOKIE_SECURE'] = bool(_is_https())


def _log_request(resp):
    """Log standard HTTP access format (method, path, status)."""
    try:
        current_app.logger.info('HTTP %s %s %s', request.method, request.path, resp.status_code)
    except Exception:
        pass
    return resp


def cache_headers(resp):
    """Set anti-caching headers on dynamic HTML and API endpoints."""
    if request.path == '/api/timezone':
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        resp.headers['Vary'] = 'Cookie, Authorization'
    elif resp.mimetype == 'text/html':
        resp.headers['Cache-Control'] = 'private, no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        resp.headers['Vary'] = 'Cookie'
    elif request.path.startswith('/static/') and (request.path.endswith('.css') or request.path.endswith('.js')):
        resp.headers['Cache-Control'] = 'no-cache, must-revalidate'
    return resp


def inject_sec_headers(resp):
    """Inject CSRF token cookie and default security headers."""
    from flask_wtf.csrf import generate_csrf
    secure_now = _is_https()
    try:
        resp.set_cookie(
            "csrf_token",
            generate_csrf(),
            samesite="Lax",
            secure=bool(secure_now),
            httponly=False,
        )
    except Exception as e:
        current_app.logger.debug("inject_sec_headers: failed to set csrf_token cookie: %s", e)

    resp.headers.setdefault('X-Frame-Options', 'DENY')
    try:
        s = _load_panel_settings()
        if s.get('hsts') and secure_now:
            resp.headers.setdefault(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload'
            )
    except Exception:
        pass

    try:
        if secure_now:
            ct = (resp.headers.get("Content-Type") or "").lower()
            if "text/html" in ct:
                add = "upgrade-insecure-requests; block-all-mixed-content"
                cur = (resp.headers.get("Content-Security-Policy") or "").strip()
                if cur:
                    if "upgrade-insecure-requests" not in cur:
                        resp.headers["Content-Security-Policy"] = cur.rstrip("; ") + "; " + add
                else:
                    resp.headers["Content-Security-Policy"] = add
    except Exception:
        pass

    return resp


def _https_redirect():
    """Redirect HTTP requests to HTTPS when force_https_redirect is enabled."""
    try:
        s = _load_panel_settings() or {}
        if not s.get("force_https_redirect"):
            return None

        xf_proto = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        if request.is_secure or xf_proto == "https":
            return None

        if not bool(getattr(current_app, "_tls_enabled_effective", False)):
            return None

        if (request.path or "").startswith("/api/"):
            return None

        host = (s.get("domain") or "").strip() or request.host.split(":", 1)[0]
        https_port = s.get("https_port")
        try:
            https_port = int(https_port) if https_port else 443
        except Exception:
            https_port = 443

        netloc = f"{host}:{https_port}" if https_port and https_port != 443 else host
        full = request.full_path
        if full.endswith("?"):
            full = full[:-1]

        return redirect(f"https://{netloc}{full}", code=301)
    except Exception as e:
        current_app.logger.warning("HTTPS redirect skipped: %s", e)
        return None


def _maybe_hsts(resp):
    """Apply HSTS header when connection is secure and hsts setting is enabled."""
    try:
        s = _load_panel_settings()
        if s.get('hsts') and request.is_secure:
            resp.headers.setdefault(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload'
            )
    except Exception:
        pass
    return resp


def security_headers(resp):
    """Set X-Frame-Options, Content-Security-Policy, and font CORS headers."""
    p = (request.path or '').lower()
    resp.headers['X-Frame-Options'] = 'DENY'

    if p.startswith('/preview/'):
        resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
        resp.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "style-src-elem 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; "
            "form-action 'none'; "
            "frame-ancestors 'self'"
        )

    if (
        p.endswith(('.woff2', '.woff', '.ttf', '.otf')) or
        p.startswith('/static/fonts/') or
        p.startswith('/static/vendor/fa/webfonts/')
    ):
        resp.headers.setdefault('Access-Control-Allow-Origin', '*')
        if p.endswith('.woff2'):
            resp.headers.setdefault('Content-Type', 'font/woff2')
        elif p.endswith('.woff'):
            resp.headers.setdefault('Content-Type', 'font/woff')
        elif p.endswith('.ttf'):
            resp.headers.setdefault('Content-Type', 'font/ttf')
        elif p.endswith('.otf'):
            resp.headers.setdefault('Content-Type', 'font/otf')

    return resp


def _http_security_enforce_temporary_block():
    """Enforce IP ban and temporary block before requests reach endpoints."""
    settings = _load_http_security_settings()
    if not settings.get("enabled"):
        return None

    client_ip = _http_security_client_ip(settings)
    if client_ip == "unknown":
        return None

    if _http_security_is_denied(client_ip, settings):
        g.http_security_blocked = True
        return make_response(jsonify(
            ok=False,
            error="permanently_blocked",
            message="This client is denied by the panel security policy.",
        ), 403)

    state = _json_load(_HTTP_4XX_STATE_FILE, {})
    if _http_security_is_trusted(client_ip, settings):
        return None
    if _http_security_is_temporarily_allowed(client_ip, state=state):
        return None
    if settings.get("response_mode") != "block":
        return None
    if not _http_security_scope_applies(request.path, settings.get("block_scope")):
        return None

    clients = state.get("clients") if isinstance(state, dict) else {}
    record = clients.get(client_ip) if isinstance(clients, dict) else None
    blocked_until = int((record or {}).get("blocked_until") or 0)
    now = int(time.time())

    if blocked_until <= now:
        return None

    g.http_security_blocked = True
    retry_after = max(1, blocked_until - now)
    response = make_response(jsonify(
        ok=False,
        error="temporarily_blocked",
        message="This client is temporarily blocked by panel HTTP security.",
        retry_after=retry_after,
    ), 403)
    response.headers["Retry-After"] = str(retry_after)
    return response


def _suspicious_4xx_after_request(response):
    """Monitor 4xx responses for suspicious scanning and brute-force patterns."""
    try:
        _record_suspicious_4xx(response)
    except Exception:
        current_app.logger.debug("Could not inspect 4xx response", exc_info=True)
    return response


def _cookie_scheme():
    """Synchronize session and remember cookie Secure flags with current request protocol."""
    secure_now = _is_https()
    current_app.config.update(
        SESSION_COOKIE_SECURE=secure_now,
        REMEMBER_COOKIE_SECURE=secure_now,
    )
    current_app.config["PREFERRED_URL_SCHEME"] = "https" if secure_now else "http"


def _expiry_tick_on_requests():
    """Request-triggered expiry fallback tick if background daemon thread is delayed."""
    global _EXPIRY_LAST_TS
    try:
        if (request.path or '').startswith('/static/'):
            return
        now = time.time()
        if (now - _EXPIRY_LAST_TS) < _EXPIRY_INTERVAL_SEC:
            return
        _EXPIRY_LAST_TS = now
        _run_expiry_once('request')
    except Exception:
        pass


def register_hooks(app: Flask) -> None:
    """Register all 15 lifecycle hooks on the Flask application."""
    # 1. Error handlers
    app.errorhandler(Exception)(_unhandled)

    # 2. Before request hooks
    app.before_request(_http_security_enforce_temporary_block)
    app.before_request(_dev_cookie)
    app.before_request(_cookie_scheme)
    app.before_request(_https_redirect)
    app.before_request(_csrf_protect_ui)
    app.before_request(_expiry_tick_on_requests)

    # 3. After request hooks
    app.after_request(_log_request)
    app.after_request(cache_headers)
    app.after_request(inject_sec_headers)
    app.after_request(_maybe_hsts)
    app.after_request(security_headers)
    app.after_request(_suspicious_4xx_after_request)

    # 4. Context processors
    app.context_processor(inject_nav_flags)
    app.context_processor(inject_panel_timezone)
    app.context_processor(inject_brand)
