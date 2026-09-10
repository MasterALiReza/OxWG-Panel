"""
OxWg Panel - Cryptographic and Key Management
=============================================
Fernet encryption for stored sensitive fields, API keys, and recovery codes.
"""
import os
import secrets
import string
import hashlib
import logging
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from core.paths import BASE_DIR

logger = logging.getLogger(__name__)

# Attempt to load environment variables from .env
env_file = os.path.join(BASE_DIR, '.env')
if os.path.isfile(env_file):
    load_dotenv(env_file)

FERNET_KEY = os.environ.get('FERNET_KEY')
_fernet = None
fernet = None

if FERNET_KEY:
    try:
        fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)
        _fernet = fernet
    except Exception as e:
        logger.warning("Could not initialize Fernet instance from FERNET_KEY: %s", e)


def _get_active_fernet():
    """Dynamically resolve active Fernet instance, picking up late-configured keys."""
    global FERNET_KEY, fernet, _fernet
    if _fernet is not None:
        return _fernet
    if fernet is not None:
        return fernet
    key = os.environ.get('FERNET_KEY')
    if key:
        try:
            fernet = Fernet(key.encode() if isinstance(key, str) else key)
            _fernet = fernet
            return fernet
        except Exception:
            return None
    return None


def get_fernet():
    """Return an active Fernet instance, raising RuntimeError if FERNET_KEY is not configured."""
    f = _get_active_fernet()
    if f is not None:
        return f
    raise RuntimeError("FERNET_KEY is not set. Generate one and export it before starting the app.")


def _probably_encrypt(s: str) -> str:
    """Encrypt string if Fernet key is configured, otherwise return unchanged."""
    f = _get_active_fernet()
    if f and s:
        try:
            return f.encrypt(s.encode()).decode()
        except Exception:
            return s
    return s


def _probably_decrypt(s: str) -> str:
    """Decrypt string if Fernet key is configured and valid, otherwise return unchanged."""
    f = _get_active_fernet()
    if f and s:
        try:
            return f.decrypt(s.encode()).decode()
        except Exception:
            return s
    return s


def _read_api_key(node) -> str:
    """Safely extract node API key, handling encrypted legacy enc$... prefixes."""
    raw = (getattr(node, 'api_key', None) or '').strip()
    if not raw:
        return ''

    # Backward compatibility for older stored values like enc$...
    if raw.startswith('enc$'):
        token = raw[4:].strip()
        f = _get_active_fernet()
        if f:
            try:
                return f.decrypt(token.encode()).decode()
            except Exception:
                pass

        try:
            from flask import current_app
            current_app.logger.warning(
                "Failed to decrypt legacy node api_key (id=%s)",
                getattr(node, 'id', '?')
            )
        except Exception:
            logger.warning(
                "Failed to decrypt legacy node api_key (id=%s)",
                getattr(node, 'id', '?')
            )
        return ''

    return _probably_decrypt(raw)



def hash_recovery(code: str) -> str:
    """Hash a recovery code with SHA-256."""
    return "sha256$" + hashlib.sha256(code.encode("utf-8")).hexdigest()


def verify_recovery(code: str, stored: str) -> bool:
    """Verify recovery code against stored sha256 or bcrypt hash."""
    if not stored:
        return False
    if stored.startswith("sha256$"):
        return stored == hash_recovery(code)
    try:
        import bcrypt as pybcrypt
        if stored.startswith("$2") or stored.startswith("$bcrypt$"):
            return pybcrypt.checkpw(code.encode("utf-8"), stored.encode("utf-8"))
    except Exception:
        pass
    return False


def _gen_recovery(n=10, length=10):
    """Generate cryptographically secure recovery codes."""
    alphabet = string.ascii_uppercase + string.digits
    return [''.join(secrets.choice(alphabet) for _ in range(length)) for _ in range(n)]
