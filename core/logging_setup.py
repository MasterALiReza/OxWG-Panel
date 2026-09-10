"""
OxWg Panel - Logging Infrastructure
===================================
Central logging configuration with strict UTC formatting and log-level management.
"""
import sys
import os
import logging
from logging.handlers import RotatingFileHandler
from core.paths import APP_LOG_FILE, INSTANCE_DIR
from core.file_utils import _load_log_settings
from core.time_utils import _utc_log_formatter

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


def configure_logging(app, log_file: str | None = None, log_level: str | None = None):
    """Configure rotating file handler, root logger, and library loggers with strict UTC formatting."""
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    target_file = log_file or APP_LOG_FILE

    if log_level is None:
        raw_level = getattr(app, 'config', {}).get('LOG_LEVEL') or os.getenv('LOG_LEVEL', 'INFO')
        log_level = str(raw_level).upper()

    numeric_level = getattr(logging, log_level, logging.INFO)

    # 1. Flask app logger
    if not app.logger.handlers:
        handler = RotatingFileHandler(
            target_file,
            maxBytes=1_000_000,
            backupCount=3,
            encoding='utf-8',
        )
        handler.setLevel(numeric_level)
        fmt = _utc_log_formatter("%(asctime)s [%(levelname)s] %(message)s")
        handler.setFormatter(fmt)
        app.logger.addHandler(handler)
        app.logger.setLevel(numeric_level)

    if hasattr(app, 'config'):
        app.config["PROPAGATE_EXCEPTIONS"] = True

    # 2. Root logger file handler & stream handler
    root_fmt = _utc_log_formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
    root = logging.getLogger()
    root.setLevel(numeric_level)

    if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        rfh = RotatingFileHandler(
            target_file,
            maxBytes=2_000_000,
            backupCount=5,
            encoding='utf-8',
        )
        rfh.setLevel(numeric_level)
        rfh.setFormatter(root_fmt)
        root.addHandler(rfh)

    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(root_fmt)
        sh.setLevel(numeric_level)
        root.addHandler(sh)

    # 3. Third-party library loggers
    for name in ('werkzeug', 'gunicorn.error', 'gunicorn.access', 'urllib3', 'requests', 'sqlalchemy.engine'):
        lg = logging.getLogger(name)
        lg.setLevel(numeric_level)
        lg.propagate = True

    _applymute_log()


def _applymute_log():
    """Mute or unmute RotatingFileHandlers according to log settings."""
    try:
        s = _load_log_settings() or {}
        allow = bool(s.get('enabled', True) and s.get('persist', True) and not s.get('mute_save', False))
        target_level = logging.CRITICAL + 10 if not allow else logging.INFO
        root = logging.getLogger()
        for h in root.handlers:
            if isinstance(h, RotatingFileHandler):
                h.setLevel(target_level)
    except Exception:
        pass

