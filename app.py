"""
OxWg Panel - Application Entry Point
====================================
Modular Flask application initialization, middleware configuration, lifecycle hooks,
blueprint registration, and backward-compatible re-exports.
"""
import os
import sys
import time
import logging
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from core.extensions import db, csrf, login_manager, init_extensions, Admin
from core.logging_setup import configure_logging, _applymute_log
from core.bootstrap import bootstrap
from core.hooks import (
    register_hooks,
    _unhandled,
    _csrf_protect_ui,
    inject_nav_flags,
    inject_panel_timezone,
    inject_brand,
    _dev_cookie,
    _log_request,
    cache_headers,
    inject_sec_headers,
    _https_redirect,
    _maybe_hsts,
    security_headers,
    _http_security_enforce_temporary_block,
    _suspicious_4xx_after_request,
    _cookie_scheme,
    _expiry_tick_on_requests,
)
from blueprints import register_blueprints

# ---------------------------------------------------------------------------
# Re-exports for Backward Compatibility
# ---------------------------------------------------------------------------
# Models
from models import (
    InterfaceConfig,
    Peer,
    PeerEvent,
    Node,
    Admin2FA,
    AdminAccount,
    Subscription,
    SubscriptionPeer,
    ShortLink,
)

# Core paths and constants
from core.paths import (
    BASE_DIR,
    INSTANCE_DIR,
    DB_PATH,
    APP_LOG_FILE,
    BACKUP_DIR,
    BACKUP_AUTO_DIR,
    BACKUP_PREFS_FILE,
    BACKUP_SCHEDULE_FILE,
    BACKUP_LAST_FILE,
    WG_CONFIG_DIR,
    TG_LOG_FILE,
    ADMIN_LOG_FILE,
    IFACE_LOG_DIR,
    PANEL_SETTINGS_FILE,
    PEER_PROFILES_FILE,
    PEER_PROFILE_FILE,
    LAST_PUBLIC_IP_FILE,
    ENDPOINT_PRESETS_FILE,
    GEO_CACHE_FILE,
    LOGS_SETTINGS_FILE,
)
from core.constants import (
    ACTIVE_WITHIN_SECONDS,
    PANEL_UPDATE_TTL,
    GEO_CACHE_TTL,
    LOG_TAIL_MAX_BYTES,
    MAX_ADMIN_LOGS,
    PUBLIC_IP_CACHE_TTL,
    PUBLIC_IPV6_CACHE_TTL,
    MAX_ENUMERATED_HOSTS,
    PANEL_BRAND_NAME,
    PANEL_SHORT_NAME,
)
from core.logging_setup import LOG_LEVEL
from core.crypto import FERNET_KEY

# Core utilities
from core.time_utils import (
    now_ts,
    from_ts,
    to_ts,
    isoz,
    add_days_ts,
    _utc_log_formatter,
)
from core.crypto import (
    fernet,
    hash_recovery,
    _probably_encrypt,
    _probably_decrypt,
    _read_api_key,
)
from core.ip_utils import (
    peer_address_host,
    _first_cidr,
    _safe_ip,
    _public_ipv4,
)
from core.file_utils import (
    _json_load,
    _json_save,
    _extend_file,
    _read_tail,
)

# Services
from database.migrations import SchemaMigrationError, _migrate_schema
from services.panel_settings import (
    _load_panel_settings,
    _save_panel_settings,
    _is_https,
    _load_runtime,
    _save_runtime,
)
from services.update_checker import (
    PANEL_VERSION,
    PANEL_REPO,
    _PANEL_UPDATE_CACHE,
)
from services.peer_lifecycle import (
    _on_boot,
    _run_expiry_once,
    repoint_endpoints,
    _start_expiry_enforcer,
    _wg_transfer,
    _wg_disable_peer_quiet as _wg_disable_quiet,
)
from services.log_retention import _start_retention, _clear_retention
from services.backup_service import _start_backup_scheduler
from services.http_security import _start_http_security_cleanup
from services.node_monitor import _node_notify_monitor
from services.wg_parser import (
    find_iface,
    iface_devname,
    _derive_wg_public_key,
    _copy_local_iface_from_parsed,
)
from blueprints.interfaces_bp import _iface_up, local_firewall_rules, _inject_firewall_rules
from blueprints.peers_bp import install_local_peer, allocate_peer_address
from services.shortlink_service import _shortlink_url, _peer_from_shortlink_token, _shortlink_for_peer
from services.telegram_notifier import _load_tg_settings, _save_tg_settings
from services.errors import (
    AddressAllocationError,
    WGPanelError,
    WireGuardError,
    ShortLinkError,
    NodeClientError,
    ClientConfigIncomplete,
)


def create_app(config_class: type = Config) -> Flask:
    """Application factory for OxWg Panel."""
    app_instance = Flask(__name__)
    app_instance.wsgi_app = ProxyFix(app_instance.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    app_instance.config.from_object(config_class)
    app_instance.config["PROPAGATE_EXCEPTIONS"] = True
    app_instance.config["WTF_CSRF_CHECK_DEFAULT"] = False
    app_instance.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
    )

    configure_logging(app_instance)
    init_extensions(app_instance)
    register_blueprints(app_instance)
    register_hooks(app_instance)

    return app_instance


# ---------------------------------------------------------------------------
# Global Application Instance
# ---------------------------------------------------------------------------
app = create_app()


# ---------------------------------------------------------------------------
# Production / CLI Runner
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import multiprocessing
    import ssl

    use_gunicorn = (os.getenv("USE_GUNICORN", "1") != "0") and (os.name != "nt")

    def _tls_paths():
        try:
            s = _load_panel_settings() or {}
        except Exception:
            s = {}
        cert = (s.get("tls_cert_path") or "").strip()
        key = (s.get("tls_key_path") or "").strip()
        return cert, key

    cert_path, key_path = _tls_paths()

    try:
        ps = _load_panel_settings() or {}
    except Exception:
        ps = {}

    def _valid_port(x, dflt):
        try:
            i = int(x)
            return i if 1 <= i <= 65535 else dflt
        except Exception:
            return dflt

    http_port = _valid_port(ps.get("http_port") or 8000, 8000)
    https_port = _valid_port(ps.get("https_port") or 443, 443)

    tls_toggle = bool(ps.get("tls_enabled"))
    tls_files = bool(
        cert_path
        and key_path
        and os.path.isfile(cert_path)
        and os.path.isfile(key_path)
    )
    tls_enabled = bool(tls_toggle and tls_files)

    try:
        rt = _load_runtime() or {}
    except Exception:
        rt = {}

    bind_from_rt = (rt.get("bind") or "").strip()
    try:
        port_from_rt = int(rt.get("port") or 0)
    except Exception:
        port_from_rt = 0

    host = (os.getenv("BIND_HOST") or "0.0.0.0").strip()

    if tls_enabled:
        bind = f"{host}:{https_port}"
    else:
        if bind_from_rt:
            bind = bind_from_rt
        else:
            eff_http_port = port_from_rt if port_from_rt else http_port
            eff_http_port = _valid_port(eff_http_port, 8000)
            bind = f"{host}:{eff_http_port}"

    app._tls_enabled_effective = bool(tls_enabled)
    app.config["PREFERRED_URL_SCHEME"] = "https" if tls_enabled else "http"
    cookie_secure = bool(tls_enabled)
    app.config.update(
        SESSION_COOKIE_SECURE=cookie_secure,
        REMEMBER_COOKIE_SECURE=cookie_secure,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    if not use_gunicorn:
        try:
            bootstrap(app)
        except SchemaMigrationError as e:
            app.logger.critical("Refusing to start: DB migration error: %s", e)
            sys.exit(1)
        except Exception as e:
            app.logger.exception("Bootstrap error: %s", e)

        ssl_ctx = (cert_path, key_path) if tls_enabled else None

        if tls_enabled:
            chosen_port = int(os.getenv("DEV_PORT", str(https_port)))
        else:
            try:
                rt2 = _load_runtime() or {}
                rt_port = int(rt2.get("port") or 0)
            except Exception:
                rt_port = 0
            http_base = rt_port if rt_port else http_port
            chosen_port = int(os.getenv("DEV_PORT", str(_valid_port(http_base, 8000))))

        app.run(
            host=os.getenv("DEV_HOST", "127.0.0.1"),
            port=chosen_port,
            debug=os.getenv("FLASK_DEBUG", "0") == "1",
            ssl_context=ssl_ctx,
        )
        sys.exit(0)

    from gunicorn.app.base import BaseApplication

    try:
        if int(rt.get("workers", 0)) > 0:
            os.environ["WORKERS"] = str(rt["workers"])
        if "threads" in rt:
            os.environ["THREADS"] = str(rt.get("threads", 4))
        if "timeout" in rt:
            os.environ["TIMEOUT"] = str(rt.get("timeout", 60))
        if "graceful_timeout" in rt:
            os.environ["GRACEFUL_TIMEOUT"] = str(rt.get("graceful_timeout", 30))
        if "loglevel" in rt:
            os.environ["LOGLEVEL"] = (rt.get("loglevel") or "info").lower()
    except Exception:
        pass

    class _Guni(BaseApplication):
        def __init__(self, wsgi_app, options=None):
            self.options = options or {}
            self.application = wsgi_app
            super().__init__()

        def load_config(self):
            cfg = {
                k: v
                for k, v in self.options.items()
                if k in self.cfg.settings and v is not None
            }
            for k, v in cfg.items():
                self.cfg.set(k.lower(), v)

        def load(self):
            return self.application

    def _env_int(name, dflt):
        try:
            return int(os.getenv(name) or dflt)
        except Exception:
            return dflt

    cpu_based_default_workers = multiprocessing.cpu_count() * 2 + 1
    workers = _env_int("WORKERS", cpu_based_default_workers)
    threads = _env_int("THREADS", 4)
    timeout = _env_int("TIMEOUT", 60)
    graceful_timeout = _env_int("GRACEFUL_TIMEOUT", 30)
    loglevel = (os.getenv("LOGLEVEL") or "info").lower()

    app.logger.handlers[:] = []
    app.logger.propagate = True
    log_level_val = os.getenv("LOG_LEVEL", "INFO").upper()
    try:
        app.logger.setLevel(getattr(logging, log_level_val, logging.INFO))
    except Exception:
        pass
    try:
        _applymute_log()
    except Exception:
        pass

    APP_START_TS = int(time.time())
    app.logger.info("Panel started (TLS=%s, bind=%s)", "on" if tls_enabled else "off", bind)

    options = {
        "bind": bind,
        "workers": workers,
        "worker_class": "gthread",
        "threads": threads,
        "timeout": timeout,
        "graceful_timeout": graceful_timeout,
        "accesslog": "-",
        "errorlog": "-",
        "loglevel": loglevel,
        "preload_app": False,
        "capture_output": True,
    }

    if tls_enabled:
        if not os.path.isfile(cert_path):
            raise RuntimeError(f"TLS cert not found: {cert_path}")
        if not os.path.isfile(key_path):
            raise RuntimeError(f"TLS key not found: {key_path}")
        options["certfile"] = cert_path
        options["keyfile"] = key_path

        app.config.update(
            SESSION_COOKIE_SECURE=True,
            REMEMBER_COOKIE_SECURE=True,
            SESSION_COOKIE_SAMESITE="Lax",
        )

    try:
        bootstrap(app)
    except SchemaMigrationError as e:
        app.logger.critical(
            "Refusing to start: the database schema could not be migrated: %s", e
        )
        raise SystemExit(1)
    except Exception as e:
        app.logger.exception("bootstrap failed: %s", e)

    _Guni(app, options).run()
