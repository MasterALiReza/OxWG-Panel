"""
OxWg Panel - Application Bootstrap
==================================
Initializes database schema, imports local WireGuard interface configurations,
performs boot-time peer synchronization and expiry checks, and starts background
workers with safe multi-process file-locking.
"""
import os
import glob
import logging
import tempfile
from typing import Any

from flask import Flask

from core.paths import ensure_dirs
from models import db, InterfaceConfig
from database.migrations import _migrate_schema, SchemaMigrationError
from services.wg_parser import find_iface, _derive_wg_public_key, _copy_local_iface_from_parsed
from services.peer_lifecycle import (
    _on_boot,
    _run_expiry_once,
    repoint_endpoints,
    _start_expiry_enforcer,
)
from services.log_retention import _start_retention, _clear_retention
from services.backup_service import _start_backup_scheduler
from services.http_security import _start_http_security_cleanup
from services.node_monitor import _node_notify_monitor

logger = logging.getLogger(__name__)

_WORKER_LOCK_HELD = False
_LOCK_FILE_OBJ: Any = None


def _acquire_worker_lock() -> bool:
    """Acquire a cross-process lock so only one worker process runs background threads."""
    global _WORKER_LOCK_HELD, _LOCK_FILE_OBJ
    if _WORKER_LOCK_HELD:
        return True

    lock_path = os.path.join(tempfile.gettempdir(), 'oxwg_background_workers.lock')
    try:
        import fcntl
        try:
            f = open(lock_path, 'a+')
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            _LOCK_FILE_OBJ = f
            _WORKER_LOCK_HELD = True
            return True
        except (BlockingIOError, OSError):
            return False
    except ImportError:
        # Windows fallback using msvcrt
        try:
            import msvcrt
            try:
                f = open(lock_path, 'a+')
                f.seek(0)
                f.write('0')
                f.flush()
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                _LOCK_FILE_OBJ = f
                _WORKER_LOCK_HELD = True
                return True
            except (OSError, IOError):
                return False
        except ImportError:
            _WORKER_LOCK_HELD = True
            return True


def bootstrap(app: Flask | None = None) -> None:
    """Bootstrap the application within its app context.

    1. Schema migrations via database.migrations
    2. Local firewall rules migration
    3. WireGuard config auto-import into InterfaceConfig
    4. Boot-time peer synchronization and endpoint repointing
    5. Background worker daemon threads (guarded by cross-process lock)
    6. Initial log retention cleanup
    """
    if app is None:
        from flask import current_app
        app = current_app

    with app.app_context():
        # 1. Ensure runtime directories & database migrations
        ensure_dirs()
        instance_p = getattr(app, 'instance_path', None)
        if instance_p:
            try:
                os.makedirs(instance_p, exist_ok=True)
            except Exception:
                pass
        _migrate_schema(instance_p)

        # 2. Local firewall rules migration
        try:
            from blueprints.interfaces_bp import local_firewall_rules
            firewall_summary = local_firewall_rules(app)
            logger.info("Legacy local firewall migration: %s", firewall_summary)
        except Exception as exc:
            logger.warning("Local firewall rules check failed: %s", exc)

        # 3. WireGuard configs auto-import
        p = (
            app.config.get("WG_CONF_PATH")
            or app.config.get("WIREGUARD_CONF_PATH")
            or "/etc/wireguard"
        )
        paths = (
            glob.glob(os.path.join(p, "*.conf"))
            if os.path.isdir(p)
            else ([p] if os.path.isfile(p) else [])
        )
        for conf in paths:
            try:
                parsed = find_iface(conf)
                if not parsed:
                    continue
                name = os.path.splitext(os.path.basename(conf))[0]
                existing = InterfaceConfig.query.filter_by(name=name).first()
                if not existing:
                    pk = _derive_wg_public_key(parsed.private_key)
                    if pk:
                        parsed.public_key = pk
                    db.session.add(parsed)
                    continue
                _copy_local_iface_from_parsed(existing, parsed)
            except Exception as exc:
                logger.warning("Error importing WireGuard interface %s: %s", conf, exc)

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

        # 4. Boot-time peer synchronization and expiry reconciliation
        try:
            _on_boot()
        except Exception as exc:
            logger.warning("_on_boot failed: %s", exc)

        try:
            _run_expiry_once('boot')
        except Exception as exc:
            logger.warning("_run_expiry_once('boot') failed: %s", exc)

        try:
            repoint_endpoints()
        except Exception as exc:
            logger.warning("repoint_endpoints failed: %s", exc)

        # 5. Background workers (guarded by cross-process lock)
        if _acquire_worker_lock():
            logger.info("Acquired worker lock; starting background daemon threads.")
            try:
                _start_retention()
            except Exception as exc:
                logger.warning("_start_retention failed: %s", exc)

            try:
                _start_expiry_enforcer(app)
            except Exception as exc:
                logger.warning("_start_expiry_enforcer failed: %s", exc)

            try:
                _start_backup_scheduler(app)
            except Exception as exc:
                logger.warning("_start_backup_scheduler failed: %s", exc)

            try:
                _start_http_security_cleanup()
            except Exception as exc:
                logger.warning("_start_http_security_cleanup failed: %s", exc)

            try:
                _node_notify_monitor(app)
            except Exception as exc:
                logger.warning("_node_notify_monitor failed: %s", exc)
        else:
            logger.info("Worker lock held by another process; skipping background thread start.")

        # 6. Retention cleanup
        try:
            _clear_retention()
        except Exception:
            pass

        try:
            db.session.remove()
        except Exception:
            pass
