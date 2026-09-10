"""blueprints - Modular Flask Blueprints for WG_Panel.

This package exposes all 17 domain blueprints and provides `register_blueprints(app)`
to attach them along with transparent URL building error handling for legacy `url_for`
backward compatibility.
"""

from typing import Any
from flask import Flask, url_for
from werkzeug.routing import BuildError

from blueprints.auth_bp import auth_bp
from blueprints.admin_bp import admin_bp
from blueprints.misc_bp import misc_bp
from blueprints.stats_bp import stats_bp
from blueprints.logs_bp import logs_bp
from blueprints.settings_bp import settings_bp
from blueprints.shortlinks_bp import shortlinks_bp
from blueprints.security_bp import security_bp
from blueprints.update_bp import update_bp
from blueprints.profiles_bp import profiles_bp
from blueprints.traffic_bp import traffic_bp
from blueprints.telegram_bp import telegram_bp
from blueprints.backup_bp import backup_bp
from blueprints.interfaces_bp import interfaces_bp
from blueprints.peers_bp import peers_bp
from blueprints.nodes_bp import nodes_bp
from blueprints.subscriptions_bp import subscriptions_bp

ALL_BLUEPRINTS = (
    auth_bp,
    admin_bp,
    misc_bp,
    stats_bp,
    logs_bp,
    settings_bp,
    shortlinks_bp,
    security_bp,
    update_bp,
    profiles_bp,
    traffic_bp,
    telegram_bp,
    backup_bp,
    interfaces_bp,
    peers_bp,
    nodes_bp,
    subscriptions_bp,
)

__all__ = [
    'auth_bp',
    'admin_bp',
    'misc_bp',
    'stats_bp',
    'logs_bp',
    'settings_bp',
    'shortlinks_bp',
    'security_bp',
    'update_bp',
    'profiles_bp',
    'traffic_bp',
    'telegram_bp',
    'backup_bp',
    'interfaces_bp',
    'peers_bp',
    'nodes_bp',
    'subscriptions_bp',
    'ALL_BLUEPRINTS',
    'register_blueprints',
]


def register_blueprints(app: Flask) -> None:
    """Register all 17 blueprints on the given Flask application.

    Also attaches a url_build_error_handler so that any legacy url_for('view_func')
    calls without blueprint prefix automatically resolve to the blueprint-prefixed
    route.
    """
    for bp in ALL_BLUEPRINTS:
        app.register_blueprint(bp)

    # Build legacy endpoint translation map
    endpoint_map: dict[str, str] = {}
    for rule in app.url_map.iter_rules():
        if '.' in rule.endpoint:
            _bp_name, func_name = rule.endpoint.split('.', 1)
            # Do not overwrite if multiple blueprints have the same func_name
            if func_name not in endpoint_map:
                endpoint_map[func_name] = rule.endpoint

    def _legacy_url_for_handler(error: BuildError, endpoint: str, values: dict[str, Any]) -> str | None:
        if '.' not in endpoint and endpoint in endpoint_map:
            return url_for(endpoint_map[endpoint], **values)
        return None

    if _legacy_url_for_handler not in app.url_build_error_handlers:
        app.url_build_error_handlers.append(_legacy_url_for_handler)
