"""
OxWg Panel - Core Extensions
============================
Central Flask extensions initialization and authentication loader.
"""
from models import db
from flask_login import LoginManager, UserMixin
from flask_wtf.csrf import CSRFProtect
from flask import url_for

csrf = CSRFProtect()
login_manager = LoginManager()
login_manager.login_view = 'auth_bp.login'


class Admin(UserMixin):
    """Admin user model for Flask-Login session management."""
    def __init__(self, username='admin'):
        self.id = '1'
        self.username = username
        self.is_admin = True
        self.is_superuser = True


@login_manager.user_loader
def load_user(user_id):
    """Load the single admin user for authentication sessions."""
    if user_id != '1':
        return None
    from models import AdminAccount
    acc = AdminAccount.query.first()
    if not acc:
        return None
    return Admin(acc.username)


def legacy_url_build_handler(error, endpoint, values):
    """
    Universal Fallback for legacy and un-namespaced endpoints in OxWg Panel.
    Preserves query parameters and external flags safely.
    """
    LEGACY_ENDPOINT_MAP = {
        # Legacy unprefixed names
        'login': 'auth_bp.login',
        'logout': 'auth_bp.logout',
        'register': 'auth_bp.register',
        'index': 'misc_bp.index',
        'users': 'peers_bp.users',
        'nodes': 'nodes_bp.nodes',
        'logs_page': 'logs_bp.logs_page',
        'backup_page': 'backup_bp.backup_page',
        'settings_page': 'settings_bp.settings_page',
        'api_timezone': 'settings_bp.api_timezone',
        'api_docs_page': 'misc_bp.api_docs_page',
        'subscription_public_config': 'subscriptions_bp.subscription_public_config',
        'subscription_public_api': 'subscriptions_bp.subscription_public_api',
        'subscription_public_page': 'subscriptions_bp.subscription_public_page',
        'user_peer_page': 'shortlinks_bp.user_peer_page',

        # Alternate non-_bp aliases (for defensive compatibility)
        'auth.login': 'auth_bp.login',
        'auth.logout': 'auth_bp.logout',
        'peers.users': 'peers_bp.users',
        'misc.index': 'misc_bp.index',
        'nodes.nodes': 'nodes_bp.nodes',
        'settings.settings_page': 'settings_bp.settings_page',
        'logs.logs_page': 'logs_bp.logs_page',
        'backup.backup_page': 'backup_bp.backup_page',
    }
    target = LEGACY_ENDPOINT_MAP.get(endpoint)
    if target:
        force_ext = getattr(getattr(error, 'adapter', None), 'force_external', False)
        ext = values.pop('_external', force_ext)
        return url_for(target, _external=ext, **values)
    raise error


def init_extensions(app):
    """Initialize all Flask extensions and register URL build fallback handler."""
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    if hasattr(app, 'url_build_error_handlers'):
        app.url_build_error_handlers.append(legacy_url_build_handler)
