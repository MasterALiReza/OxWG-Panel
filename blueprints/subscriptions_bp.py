"""subscriptions_bp - Blueprint for subscription management and public portal.

Extracts all subscription routes from app.py:
- /subscriptions (GET)
- /api/subscriptions/settings (GET, POST)
- /api/subscriptions/template-preview (POST)
- /api/subscriptions/<int:sid>/portal-settings (GET, POST, DELETE)
- /api/subscriptions/locations (GET)
- /api/subscriptions/inbounds_catalog (GET)
- /api/subscriptions (GET, POST)
- /api/subscriptions/<int:sid> (GET, PUT, DELETE)
- /api/subscriptions/<int:sid>/inbounds (POST)
- /api/subscriptions/<int:sid>/inbounds/<int:link_id> (PATCH, DELETE)
- /api/subscriptions/<int:sid>/disable (POST)
- /api/subscriptions/<int:sid>/enable (POST)
- /api/subscriptions/<int:sid>/reset_data (POST)
- /api/subscriptions/<int:sid>/reset_timer (POST)
- /api/subscriptions/<int:sid>/shortlink (GET)
- /s/<token> (GET)
- /s/<token>/api (GET)
- /s/<token>/config (GET)
- /s/<token>/inbound/<int:link_id>/config (GET)
- /s/<token>/inbound/<int:link_id>/qr (GET)
- /s/<token>/inbound/<int:link_id>/geo (GET)
"""

import ipaddress
import json
import os
import re
import socket
import subprocess
import time as _geo_time
from contextlib import contextmanager
from datetime import datetime
from io import BytesIO
from urllib.parse import urlparse as _geo_urlparse
import zipfile

import psutil
import qrcode
import requests
from flask import (
    Blueprint,
    abort,
    current_app,
    g,
    jsonify,
    render_template,
    request,
    send_file,
    url_for,
)
from sqlalchemy import func

try:
    import fcntl
except ImportError:
    fcntl = None

from flask_login import login_required
from auth import require_api_key_or_login
from core.constants import MAX_ENUMERATED_HOSTS
import secrets
from core.ip_utils import _public_ipv4, _safe_ip
from core.time_utils import from_ts, isoz, now_ts, to_ts
from core.extensions import db
from models import InterfaceConfig, Node, Peer, Subscription, SubscriptionPeer
from services.admin_log import logpanel_action
from services.config_generator import (
    _client_config_txt,
    _endpoint_fallback,
    _peer_client_conf_or_502,
    iface_endpoint_override,
    parse_endpoint_string,
    resolve_client_endpoint,
    resolve_client_endpoint_cheap,
)
from services.node_client import node_get, node_post
from services.panel_settings import _panel_display_datetime, _panel_timezone_name
from services.peer_lifecycle import (
    _accumulate_peer_usage,
    _clear_timer_cycle,
    _disable_peer,
    _effective_expiry_ts,
    _expire,
    _start_timer_cycle,
    _sync_effective_expiry,
    _wg_transfer,
    _wg_runtime_snapshot,
)
from services.wg_parser import generate_wg_keypair, iface_devname

from blueprints.interfaces_bp import (
    _available_ips,
    _check_iface_up,
    _iface_up,
    interface_ip_interface,
)
from blueprints.nodes_bp import (
    ensure_node_mirror_iface,
    node_install_peer,
)
from services.errors import ClientConfigIncomplete
from blueprints.peers_bp import (
    AddressAllocationError,
    AddressInvalid,
    NodePeerInstallError,
    PeerCreateCompensation,
    PeerRemovalError,
    _host_peer,
    _sync_peer,
    _wg_disable,
    _wg_enable,
    address_error_response,
    allocate_peer_address,
    install_local_peer,
    log_event,
    peer_removal_response,
    remove_peer_everywhere,
)

subscriptions_bp = Blueprint('subscriptions_bp', __name__)

SUBSCRIPTION_LAYOUTS = {
    'ps5',
    'mac',
    'app',
    'compact',
    'minimal',
    'showcase',
}

SUBSCRIPTION_LAYOUT_ALIASES = {
    'aurora': 'ps5',
    'cards': 'mac',
    'console': 'app',
    'split': 'showcase',
    'profile': 'showcase',
    'executive': 'mac',
    'flow': 'minimal',
}

GEO_CACHE_TTL = 7 * 24 * 3600


def _get_sub_settings_path():
    return os.path.join(current_app.instance_path, 'subscription_settings.json')


def _get_sub_overrides_path():
    return os.path.join(current_app.instance_path, 'subscription_portal_overrides.json')


def _get_geo_cache_path():
    return os.path.join(current_app.instance_path, 'subscription_geo_cache.json')


def _sub_bool(v):
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    return str(v).strip().lower() in {'1', 'true', 'yes', 'on'}


def _sub_float(v, default=0.0):
    try:
        return float(v or default)
    except Exception:
        return float(default)


def _sub_int(v, default=0):
    try:
        return int(float(v or default))
    except Exception:
        return int(default)


def _token():
    return secrets.token_urlsafe(16)


def _subscription_settings_default():
    return {
        'layout': 'ps5',
        'hero_style': 'banner',
        'page_width': 'wide',
        'density': 'comfortable',
        'config_style': 'cards',
        'config_columns': 'two',
        'section_order': 'usage_first',
        'module_order': [
            'configs',
            'usage',
            'install',
            'support',
        ],
        'module_enabled': {
            'configs': True,
            'usage': True,
            'install': True,
            'support': True,
        },
        'module_sizes': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },
        'module_mobile': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },
        'module_surface': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },
        'module_spacing': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },
        'module_radius': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },
        'module_heading': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },
        'module_mobile_position': {
            'configs': 'auto',
            'usage': 'auto',
            'install': 'auto',
            'support': 'auto',
        },
        'module_gap': 'standard',
        'background': 'orbits',
        'accent': 'mint',
        'primary_color': '#3addaa',
        'secondary_color': '#63a5ff',
        'online_color': '#22c55e',
        'offline_color': '#94a3b8',
        'warning_color': '#f59e0b',
        'danger_color': '#ef4444',
        'pill_color': '#64748b',
        'action_color': '#3addaa',
        'theme_default': 'auto',
        'surface': 'glass',
        'radius': 'rounded',
        'shadow': 'deep',
        'button_style': 'solid',
        'font_scale': 'standard',
        'background_intensity': 86,
        'card_opacity': 82,
        'display_mode': 'hybrid',
        'stat_size': 'standard',
        'show_percentage': True,
        'show_used_detail': True,
        'animation': 'cinematic',
        'entrance_animation': 'stagger',
        'hover_animation': 'lift',
        'toast_style': 'pill',
        'toast_position': 'bottom_center',
        'toast_motion': 'slide',
        'toast_duration': 2200,
        'motion_speed': 125,
        'motion_intensity': 150,
        'particle_density': 90,
        'show_quick_stats': True,
        'show_install': True,
        'show_support': True,
        'show_live_badge': True,
        'show_status_badge': True,
        'show_location_country': True,
        'show_download_action': True,
        'show_copy_action': True,
        'show_theme_action': True,
        'show_section_descriptions': True,
        'show_admin_notice': False,
        'show_account_details': False,
        'show_connection_overview': False,
        'notice_title': 'Service notice',
        'notice_text': '',
        'notice_tone': 'info',
        'notice_style': 'banner',
        'notice_position': 'after_summary',
        'portal_label': 'Secure WireGuard portal',
        'portal_icon': 'fas fa-bolt',
        'portal_title': '',
        'portal_subtitle': (
            'Your account is ready. Install WireGuard, '
            'then scan QR or import a config.'
        ),
        'title_align': 'left',
        'logo_size': 'medium',
        'usage_title': 'Usage overview',
        'configs_title': 'Configs',
        'install_title': 'Install WireGuard',
        'support_title': 'Support',
        'support_style': 'buttons',
        'support': {
            'telegram': '',
            'whatsapp': '',
            'phone': '',
            'email': '',
            'website': '',
            'instagram': '',
        },
    }


def _subscription_portal_icons():
    return {
        'fas fa-bolt',
        'fas fa-shield-halved',
        'fas fa-store',
        'fas fa-crown',
        'fas fa-rocket',
        'fas fa-globe',
        'fas fa-headset',
        'fas fa-wifi',
        'fas fa-gamepad',
        'fas fa-server',
        'fas fa-link',
        'fas fa-signal',
        'fas fa-gem',
        'fas fa-building',
        'fas fa-cloud',
        'fas fa-network-wired',
        'fas fa-lock',
        'fas fa-star',
    }


def _subscription_portal_icon(value):
    value = str(value or '').strip()
    return value if value in _subscription_portal_icons() else 'fas fa-bolt'


def _subscription_text(value, default='', max_len=160):
    value = str(value or '').strip()
    if not value:
        return default
    return value[:max_len]


def _subscription_choice(value, allowed, default):
    value = str(value or '').strip().lower()
    return value if value in allowed else default


def _subscription_number(value, default, minimum, maximum):
    try:
        number = int(float(value))
    except Exception:
        number = int(default)
    return max(minimum, min(maximum, number))


def _normalize_subscription_settings(incoming=None, *, base=None):
    incoming = incoming if isinstance(incoming, dict) else {}
    defaults = dict(base) if isinstance(base, dict) else _subscription_settings_default()
    d = _subscription_settings_default()

    for key, value in defaults.items():
        if key == 'support':
            continue
        d[key] = value

    d['support'] = dict(defaults.get('support') or d['support'])

    layout = str(
        incoming.get('layout') or incoming.get('selected') or d['layout']
    ).strip().lower()
    layout = SUBSCRIPTION_LAYOUT_ALIASES.get(layout, layout)
    d['layout'] = layout if layout in SUBSCRIPTION_LAYOUTS else 'ps5'

    d['hero_style'] = _subscription_choice(
        incoming.get('hero_style', d['hero_style']),
        {'panel', 'banner', 'minimal'},
        'panel',
    )
    d['page_width'] = _subscription_choice(
        incoming.get('page_width', d['page_width']),
        {'narrow', 'standard', 'wide'},
        'standard',
    )
    d['density'] = _subscription_choice(
        incoming.get('density', d['density']),
        {'comfortable', 'compact'},
        'comfortable',
    )
    d['config_style'] = _subscription_choice(
        incoming.get('config_style', d['config_style']),
        {'cards', 'list', 'compact'},
        'cards',
    )
    d['config_columns'] = _subscription_choice(
        incoming.get('config_columns', d['config_columns']),
        {'auto', 'one', 'two'},
        'auto',
    )
    d['section_order'] = _subscription_choice(
        incoming.get('section_order', d['section_order']),
        {'standard', 'configs_first', 'usage_first'},
        'standard',
    )

    allowed_modules = ('configs', 'usage', 'install', 'support')
    default_module_order = ['configs', 'usage', 'install', 'support']
    incoming_module_order = incoming.get('module_order', d.get('module_order', default_module_order))
    if not isinstance(incoming_module_order, (list, tuple)):
        incoming_module_order = []

    normalized_module_order = []
    for module_name in incoming_module_order:
        module_name = str(module_name or '').strip().lower()
        if module_name in allowed_modules and module_name not in normalized_module_order:
            normalized_module_order.append(module_name)

    for module_name in default_module_order:
        if module_name not in normalized_module_order:
            normalized_module_order.append(module_name)

    d['module_order'] = normalized_module_order[:4]
    module_keys = ('configs', 'usage', 'install', 'support')

    current_enabled = d.get('module_enabled') if isinstance(d.get('module_enabled'), dict) else {}
    incoming_enabled = incoming.get('module_enabled') if isinstance(incoming.get('module_enabled'), dict) else {}
    normalized_enabled = {}
    for module_name in module_keys:
        if module_name in incoming_enabled:
            val = incoming_enabled.get(module_name)
        else:
            val = current_enabled.get(module_name, True)
        normalized_enabled[module_name] = _sub_bool(val)

    if not any(normalized_enabled.values()):
        normalized_enabled['configs'] = True
    d['module_enabled'] = normalized_enabled

    allowed_module_sizes = {'auto', 'small', 'medium', 'large', 'full'}
    current_sizes = d.get('module_sizes') if isinstance(d.get('module_sizes'), dict) else {}
    incoming_sizes = incoming.get('module_sizes') if isinstance(incoming.get('module_sizes'), dict) else {}
    normalized_sizes = {}
    for module_name in module_keys:
        val = str(incoming_sizes.get(module_name, current_sizes.get(module_name, 'auto')) or 'auto').strip().lower()
        if val not in allowed_module_sizes:
            val = 'auto'
        normalized_sizes[module_name] = val
    d['module_sizes'] = normalized_sizes

    allowed_mobile_sizes = {'auto', 'half', 'full'}
    current_mobile = d.get('module_mobile') if isinstance(d.get('module_mobile'), dict) else {}
    incoming_mobile = incoming.get('module_mobile') if isinstance(incoming.get('module_mobile'), dict) else {}
    normalized_mobile = {}
    for module_name in module_keys:
        val = str(incoming_mobile.get(module_name, current_mobile.get(module_name, 'auto')) or 'auto').strip().lower()
        if val not in allowed_mobile_sizes:
            val = 'auto'
        normalized_mobile[module_name] = val
    d['module_mobile'] = normalized_mobile

    allowed_surfaces = {'auto', 'panel', 'soft', 'outline', 'flat', 'accent'}
    current_surfaces = d.get('module_surface') if isinstance(d.get('module_surface'), dict) else {}
    incoming_surfaces = incoming.get('module_surface') if isinstance(incoming.get('module_surface'), dict) else {}
    normalized_surfaces = {}
    for module_name in module_keys:
        val = str(incoming_surfaces.get(module_name, current_surfaces.get(module_name, 'auto')) or 'auto').strip().lower()
        if val not in allowed_surfaces:
            val = 'auto'
        normalized_surfaces[module_name] = val
    d['module_surface'] = normalized_surfaces

    allowed_spacing = {'auto', 'compact', 'comfortable', 'roomy'}
    current_spacing = d.get('module_spacing') if isinstance(d.get('module_spacing'), dict) else {}
    incoming_spacing = incoming.get('module_spacing') if isinstance(incoming.get('module_spacing'), dict) else {}
    normalized_spacing = {}
    for module_name in module_keys:
        val = str(incoming_spacing.get(module_name, current_spacing.get(module_name, 'auto')) or 'auto').strip().lower()
        if val not in allowed_spacing:
            val = 'auto'
        normalized_spacing[module_name] = val
    d['module_spacing'] = normalized_spacing

    def normalize_module_option_map(setting_key, allowed_values, default_value='auto', *, unique_non_default=False):
        current_values = d.get(setting_key) if isinstance(d.get(setting_key), dict) else {}
        incoming_values = incoming.get(setting_key) if isinstance(incoming.get(setting_key), dict) else {}
        normalized_values = {}
        used_values = set()
        for module_name in module_keys:
            val = str(incoming_values.get(module_name, current_values.get(module_name, default_value)) or default_value).strip().lower()
            if val not in allowed_values:
                val = default_value
            if unique_non_default and val != default_value:
                if val in used_values:
                    val = default_value
                else:
                    used_values.add(val)
            normalized_values[module_name] = val
        return normalized_values

    d['module_radius'] = normalize_module_option_map('module_radius', {'auto', 'square', 'soft', 'round'})
    d['module_heading'] = normalize_module_option_map('module_heading', {'auto', 'standard', 'compact', 'accent', 'hidden'})
    d['module_mobile_position'] = normalize_module_option_map('module_mobile_position', {'auto', '1', '2', '3', '4'}, unique_non_default=True)

    d['module_gap'] = _subscription_choice(incoming.get('module_gap', d.get('module_gap', 'auto')), {'auto', 'tight', 'standard', 'roomy'}, 'auto')
    d['background'] = _subscription_choice(
        incoming.get('background', d['background']),
        {'aurora', 'waves', 'network', 'orbits', 'mesh', 'nebula', 'lines', 'constellation', 'prism', 'circuit', 'pulse', 'none'},
        'aurora',
    )
    d['accent'] = _subscription_choice(
        incoming.get('accent', d['accent']),
        {'mint', 'blue', 'violet', 'coral', 'amber', 'mono', 'custom'},
        'mint',
    )
    d['theme_default'] = _subscription_choice(incoming.get('theme_default', d['theme_default']), {'auto', 'light', 'dark'}, 'auto')
    d['surface'] = _subscription_choice(incoming.get('surface', d['surface']), {'glass', 'solid', 'soft'}, 'glass')
    d['radius'] = _subscription_choice(incoming.get('radius', d['radius']), {'rounded', 'medium', 'square'}, 'rounded')
    d['shadow'] = _subscription_choice(incoming.get('shadow', d['shadow']), {'none', 'soft', 'deep'}, 'soft')
    d['button_style'] = _subscription_choice(incoming.get('button_style', d['button_style']), {'solid', 'outline', 'soft'}, 'solid')
    d['font_scale'] = _subscription_choice(incoming.get('font_scale', d['font_scale']), {'small', 'standard', 'large'}, 'standard')

    color_fields = (
        ('primary_color', 'custom_primary', '#3addaa'),
        ('secondary_color', 'custom_secondary', '#63a5ff'),
        ('online_color', None, '#22c55e'),
        ('offline_color', None, '#94a3b8'),
        ('warning_color', None, '#f59e0b'),
        ('danger_color', None, '#ef4444'),
        ('pill_color', None, '#64748b'),
        ('action_color', None, '#3addaa'),
    )
    for key, legacy_key, fallback in color_fields:
        cand = incoming.get(key)
        if cand in (None, '') and legacy_key:
            cand = incoming.get(legacy_key)
        if cand in (None, ''):
            cand = d.get(key) or fallback
        val = str(cand or '').strip()
        if not re.fullmatch(r'#[0-9A-Fa-f]{6}', val):
            val = fallback
        d[key] = val.lower()

    d['background_intensity'] = _subscription_number(incoming.get('background_intensity', d['background_intensity']), 86, 0, 100)
    d['card_opacity'] = _subscription_number(incoming.get('card_opacity', d['card_opacity']), 82, 50, 100)
    d['display_mode'] = _subscription_choice(
        incoming.get('display_mode', incoming.get('stats_style', d['display_mode'])),
        {'bars', 'rings', 'hybrid', 'focus', 'minimal', 'segments'},
        'hybrid',
    )
    d['stat_size'] = _subscription_choice(incoming.get('stat_size', d['stat_size']), {'compact', 'standard', 'large'}, 'standard')
    d['animation'] = _subscription_choice(
        incoming.get('animation', incoming.get('motion', d['animation'])),
        {'cinematic', 'immersive', 'rich', 'balanced', 'soft', 'drift', 'minimal', 'off'},
        'cinematic',
    )
    d['entrance_animation'] = _subscription_choice(incoming.get('entrance_animation', d['entrance_animation']), {'stagger', 'slide', 'fade', 'scale', 'none'}, 'stagger')
    d['hover_animation'] = _subscription_choice(incoming.get('hover_animation', d['hover_animation']), {'lift', 'glow', 'scale', 'none'}, 'lift')
    d['toast_style'] = _subscription_choice(incoming.get('toast_style', d['toast_style']), {'pill', 'card', 'glass', 'terminal', 'minimal'}, 'pill')
    d['toast_position'] = _subscription_choice(incoming.get('toast_position', d['toast_position']), {'bottom_center', 'bottom_right', 'top_right', 'top_center'}, 'bottom_center')
    d['toast_motion'] = _subscription_choice(incoming.get('toast_motion', d['toast_motion']), {'slide', 'pop', 'fade', 'bounce'}, 'slide')
    d['toast_duration'] = _subscription_number(incoming.get('toast_duration', d['toast_duration']), 2200, 1200, 6000)
    d['motion_speed'] = _subscription_number(incoming.get('motion_speed', d['motion_speed']), 125, 50, 180)
    d['motion_intensity'] = _subscription_number(incoming.get('motion_intensity', d['motion_intensity']), 150, 40, 200)
    d['particle_density'] = _subscription_number(incoming.get('particle_density', d['particle_density']), 90, 0, 120)

    for key in (
        'show_percentage', 'show_used_detail', 'show_quick_stats', 'show_install',
        'show_support', 'show_live_badge', 'show_status_badge', 'show_location_country',
        'show_download_action', 'show_copy_action', 'show_theme_action', 'show_section_descriptions',
        'show_admin_notice', 'show_account_details', 'show_connection_overview',
    ):
        if key in incoming:
            d[key] = _sub_bool(incoming.get(key))

    identity = incoming.get('identity') if isinstance(incoming.get('identity'), dict) else {}
    public = incoming.get('public') if isinstance(incoming.get('public'), dict) else {}

    def pick(*keys, default=None):
        for source in (incoming, identity, public):
            if not isinstance(source, dict):
                continue
            for key in keys:
                if key in source:
                    return source.get(key)
        return default

    d['portal_label'] = _subscription_text(pick('portal_label', 'badge_label', 'label', default=d['portal_label']), d['portal_label'], 80)
    d['portal_icon'] = _subscription_portal_icon(pick('portal_icon', 'badge_icon', 'icon', default=d['portal_icon']))
    d['portal_title'] = _subscription_text(pick('portal_title', 'title', default=d['portal_title']), '', 90)
    d['portal_subtitle'] = _subscription_text(pick('portal_subtitle', 'subtitle', default=d['portal_subtitle']), d['portal_subtitle'], 180)
    d['title_align'] = _subscription_choice(incoming.get('title_align', d['title_align']), {'left', 'center'}, 'left')
    d['logo_size'] = _subscription_choice(incoming.get('logo_size', d['logo_size']), {'small', 'medium', 'large'}, 'medium')
    d['usage_title'] = _subscription_text(incoming.get('usage_title', d['usage_title']), 'Usage overview', 80)
    d['configs_title'] = _subscription_text(incoming.get('configs_title', d['configs_title']), 'Configs', 80)
    d['install_title'] = _subscription_text(incoming.get('install_title', d['install_title']), 'Install WireGuard', 80)
    d['support_title'] = _subscription_text(incoming.get('support_title', d['support_title']), 'Support', 80)
    d['notice_title'] = _subscription_text(incoming.get('notice_title', d.get('notice_title', 'Service notice')), 'Service notice', 60)
    d['notice_text'] = _subscription_text(incoming.get('notice_text', d.get('notice_text', '')), '', 240)
    d['notice_tone'] = _subscription_choice(incoming.get('notice_tone', d.get('notice_tone', 'info')), {'info', 'maintenance', 'warning', 'success', 'neutral'}, 'info')
    d['notice_style'] = _subscription_choice(incoming.get('notice_style', d.get('notice_style', 'banner')), {'banner', 'card', 'strip'}, 'banner')
    d['notice_position'] = _subscription_choice(incoming.get('notice_position', d.get('notice_position', 'after_summary')), {'after_summary', 'before_modules', 'after_modules'}, 'after_summary')
    d['support_style'] = _subscription_choice(incoming.get('support_style', d['support_style']), {'buttons', 'list', 'compact'}, 'buttons')

    support = incoming.get('support') if isinstance(incoming.get('support'), dict) else {}
    socials = incoming.get('socials') if isinstance(incoming.get('socials'), dict) else {}
    existing_support = d.get('support') or {}
    normalized_support = {}
    for key in ('telegram', 'whatsapp', 'phone', 'email', 'website', 'instagram'):
        if key in support:
            val = support.get(key)
        elif key in socials:
            val = socials.get(key)
        else:
            val = existing_support.get(key, '')
        normalized_support[key] = str(val or '').strip()[:500]
    d['support'] = normalized_support

    return d


def _write_json_atomic(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = path + '.tmp'
    with open(temporary, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    os.replace(temporary, path)


def _load_subscription_settings():
    path = _get_sub_settings_path()
    os.makedirs(current_app.instance_path, exist_ok=True)
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            payload = json.load(handle) or {}
    except Exception:
        payload = {}
    return _normalize_subscription_settings(payload)


def _save_subscription_settings(data):
    current = _load_subscription_settings()
    saved = _normalize_subscription_settings(data, base=current)
    _write_json_atomic(_get_sub_settings_path(), saved)
    return saved


def _load_subscription_portal_overrides():
    path = _get_sub_overrides_path()
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            payload = json.load(handle) or {}
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _save_subscription_portal_overrides(data):
    if not isinstance(data, dict):
        data = {}
    _write_json_atomic(_get_sub_overrides_path(), data)


def _subscription_portal_override(sub):
    if not sub:
        return {}
    store = _load_subscription_portal_overrides()
    val = store.get(str(getattr(sub, 'id', '')))
    return val if isinstance(val, dict) else {}


def _effective_subscription_settings(sub=None):
    global_settings = _load_subscription_settings()
    if sub is None:
        return global_settings
    override = _subscription_portal_override(sub)
    if not override:
        return global_settings
    return _normalize_subscription_settings(override, base=global_settings)


def _sub_limit_bytes(sub):
    try:
        return sub.limit_bytes()
    except Exception:
        if not getattr(sub, 'data_limit_value', 0) or getattr(sub, 'unlimited', False):
            return None
        mult = 1024**2 if (getattr(sub, 'data_limit_unit', None) or 'Mi') == 'Mi' else 1024**3
        return int(sub.data_limit_value) * mult


def _sub_used_bytes(sub):
    total = 0
    dirty = False
    for link in list(getattr(sub, 'links', []) or []):
        peer = getattr(link, 'peer', None)
        if not peer:
            continue
        try:
            iface = getattr(peer, 'iface', None)
            is_node = bool(
                iface and (
                    getattr(iface, 'node_id', None) is not None or
                    re.match(r'^n\d+:', getattr(iface, 'name', '') or '')
                )
            )
            if is_node:
                used = int(getattr(peer, 'used_bytes_total', 0) or 0)
            else:
                live = _wg_transfer(peer)
                used, _delta, changed = _accumulate_peer_usage(peer, live)
                if changed:
                    dirty = True
        except Exception:
            used = int(getattr(peer, 'used_bytes_total', 0) or 0)
        total += int(used or 0)

    if dirty:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
    return int(total)


def _sub_ttl_seconds(sub):
    exp_ts = _effective_expiry_ts(sub)
    return max(0, exp_ts - now_ts()) if exp_ts else None


def _sub_public_url(sub):
    try:
        return url_for('subscriptions_bp.subscription_public_page', token=sub.token, _external=True)
    except Exception:
        return url_for('subscription_public_page', token=sub.token, _external=True)


def _sub_config_url(sub):
    try:
        return url_for('subscriptions_bp.subscription_public_config', token=sub.token, _external=True)
    except Exception:
        return url_for('subscription_public_config', token=sub.token, _external=True)


def _apply_subscription_timer(sub, *, restart=False):
    unlimited = bool(getattr(sub, 'unlimited', False))
    days = _sub_float(getattr(sub, 'time_limit_days', 0))
    if unlimited or not days:
        _clear_timer_cycle(sub)
        return

    start_on_first_use = bool(getattr(sub, 'start_on_first_use', False))
    if start_on_first_use:
        first_used_at = getattr(sub, 'first_used_at', None)
        if not first_used_at:
            _clear_timer_cycle(sub)
            return
        sub.timer_started_at = first_used_at
        _sync_effective_expiry(sub)
        return

    if restart:
        _start_timer_cycle(sub)
    else:
        if not getattr(sub, 'timer_started_at', None):
            sub.timer_started_at = getattr(sub, 'created_at', None) or from_ts(now_ts())
        _sync_effective_expiry(sub)


def _sync_peer_subscription(peer, sub, idx=None, rename=True):
    if rename:
        total = len(getattr(sub, 'links', []) or []) or 1
        base = (sub.name or 'subscription').strip() or 'subscription'
        if idx is not None and total > 1:
            peer.name = f'{base}-{idx + 1}'
        else:
            peer.name = base
    peer.data_limit_value = int(getattr(sub, 'data_limit_value', 0) or 0)
    peer.data_limit_unit = getattr(sub, 'data_limit_unit', None) or 'Gi'
    peer.time_limit_days = _sub_float(getattr(sub, 'time_limit_days', 0)) or None
    peer.start_on_first_use = bool(getattr(sub, 'start_on_first_use', False))
    peer.unlimited = bool(getattr(sub, 'unlimited', False))
    peer.phone_number = getattr(sub, 'phone_number', '') or ''
    peer.telegram_id = getattr(sub, 'telegram_id', '') or ''
    peer.timer_started_at = getattr(sub, 'timer_started_at', None)
    peer.expires_at = getattr(sub, 'expires_at', None)
    return peer


def _sync_all_subscription_peers(sub, rename=True):
    links = sorted(list(getattr(sub, 'links', []) or []), key=lambda l: (l.sort_order or 0, l.id or 0))
    for idx, link in enumerate(links):
        if link.peer:
            _sync_peer_subscription(link.peer, sub, idx=idx, rename=rename)


def _block_subscription_runtime(sub, reason='subscription_blocked'):
    changed = False
    for link in list(getattr(sub, 'links', []) or []):
        peer = getattr(link, 'peer', None)
        if not peer:
            continue
        if getattr(peer, 'status', None) == 'blocked':
            continue
        ok = False
        try:
            ok = bool(_disable_peer(peer, reason, status='blocked'))
        except Exception:
            ok = False
        if not ok:
            peer.status = 'blocked'
            try:
                log_event(peer, reason, 'status → blocked')
            except Exception:
                pass
        changed = True

    if changed:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
    return changed


def _subscription_peer_runtime(peer):
    iface = getattr(peer, 'iface', None)
    raw_iface_name = str(getattr(iface, 'name', '') or '').strip()
    public_key = str(getattr(peer, 'public_key', '') or '').strip()
    current_epoch = now_ts()

    try:
        handshake_window = max(30, int(os.environ.get('WG_SUBSCRIPTION_CONNECTED_WINDOW', '180') or 180))
    except Exception:
        handshake_window = 180

    result = {
        'connected': False,
        'conn_status': 'offline',
        'connection_status': 'disconnected',
        'connection_label': 'Disconnected',
        'conn_reason': 'no_recent_activity',
        'latest_handshake': 0,
        'latest_handshake_age': None,
        'last_activity_at': None,
        'runtime_available': True,
        'handshake_window': handshake_window,
    }

    if not iface or not public_key:
        result['runtime_available'] = False
        result['conn_reason'] = 'peer_runtime_missing'
        return result

    node_id = getattr(iface, 'node_id', None)
    legacy_node_match = re.match(r'^n(\d+):(.+)$', raw_iface_name)
    if node_id is None and legacy_node_match:
        try:
            node_id = int(legacy_node_match.group(1))
        except Exception:
            node_id = None

    is_node = bool(node_id is not None or legacy_node_match)

    if is_node:
        node = getattr(iface, 'node', None)
        if node is None and node_id is not None:
            node = db.session.get(Node, int(node_id))
        if node is None:
            result['runtime_available'] = False
            result['conn_reason'] = 'node_missing'
            return result

        cache = getattr(g, '_subscription_node_runtime_cache', None)
        if cache is None:
            cache = {}
            g._subscription_node_runtime_cache = cache

        cache_key = int(node.id)
        if cache_key not in cache:
            try:
                payload = node_get(node, '/api/peers', timeout=8) or {}
                rows = payload.get('peers') if isinstance(payload, dict) else []
                runtime_by_key = {}
                for row in rows or []:
                    if not isinstance(row, dict):
                        continue
                    row_pk = str(row.get('public_key') or row.get('id') or '').strip()
                    if row_pk:
                        runtime_by_key[row_pk] = row
                cache[cache_key] = {'ok': True, 'rows': runtime_by_key}
            except Exception as exc:
                current_app.logger.debug('Subscription runtime: node %s unavailable: %s', getattr(node, 'id', '?'), exc)
                cache[cache_key] = {'ok': False, 'rows': {}}

        node_cache = cache.get(cache_key) or {}
        if not node_cache.get('ok'):
            result['runtime_available'] = False
            result['conn_reason'] = 'node_unavailable'
            return result

        row = (node_cache.get('rows') or {}).get(public_key)
        if not isinstance(row, dict):
            result['conn_reason'] = 'peer_not_in_runtime'
            return result

        try:
            latest_handshake = max(0, int(row.get('latest_handshake') or 0))
        except Exception:
            latest_handshake = 0

        try:
            handshake_age = row.get('latest_handshake_age')
            if handshake_age is not None:
                handshake_age = max(0, int(handshake_age))
            elif latest_handshake > 0:
                handshake_age = max(0, current_epoch - latest_handshake)
            else:
                handshake_age = None
        except Exception:
            handshake_age = max(0, current_epoch - latest_handshake) if latest_handshake > 0 else None

        connected = bool(latest_handshake > 0 and handshake_age is not None and handshake_age <= handshake_window)
        try:
            rx_mib = float(row.get('rx_mib') or 0)
        except Exception:
            rx_mib = 0.0
        try:
            tx_mib = float(row.get('tx_mib') or 0)
        except Exception:
            tx_mib = 0.0

        result.update({
            'connected': connected,
            'conn_status': 'online' if connected else 'offline',
            'connection_status': 'connected' if connected else 'disconnected',
            'connection_label': 'Connected' if connected else 'Disconnected',
            'conn_reason': 'handshake' if connected else ('stale_handshake' if latest_handshake > 0 else 'no_handshake'),
            'latest_handshake': latest_handshake,
            'latest_handshake_age': handshake_age,
            'last_activity_at': (datetime.utcfromtimestamp(latest_handshake).isoformat() + 'Z') if latest_handshake > 0 else None,
            'rx_bytes': int(rx_mib * 1024 * 1024),
            'tx_bytes': int(tx_mib * 1024 * 1024),
            'node_reported_conn_status': row.get('conn_status') or row.get('connection_status') or row.get('status') or '',
            'node_reported_conn_reason': row.get('conn_reason') or '',
        })
        return result

    interface_name = raw_iface_name
    if not interface_name:
        result['runtime_available'] = False
        result['conn_reason'] = 'interface_missing'
        return result

    cache = getattr(g, '_subscription_local_runtime_cache', None)
    if cache is None:
        cache = {}
        g._subscription_local_runtime_cache = cache

    if interface_name not in cache:
        try:
            transfers, handshakes = _wg_runtime_snapshot([interface_name])
            cache[interface_name] = {'ok': True, 'transfers': transfers, 'handshakes': handshakes}
        except Exception as exc:
            current_app.logger.debug('Subscription runtime: local interface %s unavailable: %s', interface_name, exc)
            cache[interface_name] = {'ok': False, 'transfers': {}, 'handshakes': {}}

    local_cache = cache.get(interface_name) or {}
    if not local_cache.get('ok'):
        result['runtime_available'] = False
        result['conn_reason'] = 'wireguard_unavailable'
        return result

    transfers = local_cache.get('transfers') or {}
    handshakes = local_cache.get('handshakes') or {}
    latest_handshake = int(handshakes.get((interface_name, public_key), 0) or 0)
    handshake_age = max(0, current_epoch - latest_handshake) if latest_handshake > 0 else None
    connected = bool(latest_handshake > 0 and handshake_age is not None and handshake_age <= handshake_window)
    rx_bytes, tx_bytes = transfers.get((interface_name, public_key), (0, 0))

    result.update({
        'connected': connected,
        'conn_status': 'online' if connected else 'offline',
        'connection_status': 'connected' if connected else 'disconnected',
        'connection_label': 'Connected' if connected else 'Disconnected',
        'conn_reason': 'handshake' if connected else ('stale_handshake' if latest_handshake > 0 else 'no_handshake'),
        'latest_handshake': latest_handshake,
        'latest_handshake_age': handshake_age,
        'last_activity_at': (datetime.utcfromtimestamp(latest_handshake).isoformat() + 'Z') if latest_handshake > 0 else None,
        'rx_bytes': int(rx_bytes or 0),
        'tx_bytes': int(tx_bytes or 0),
    })
    return result


def _subscription_row(sub):
    used = int(_sub_used_bytes(sub) or 0)
    unlimited = bool(getattr(sub, 'unlimited', False))
    subscription_changed = False
    linked_first_use = []

    for link in getattr(sub, 'links', []) or []:
        peer = getattr(link, 'peer', None)
        if not peer:
            continue
        peer_first_used = getattr(peer, 'first_used_at', None)
        if peer_first_used:
            linked_first_use.append(peer_first_used)

    current_first_used = getattr(sub, 'first_used_at', None)
    if not current_first_used and linked_first_use:
        sub.first_used_at = min(linked_first_use)
        current_first_used = sub.first_used_at
        subscription_changed = True

    if not current_first_used and used > 0:
        sub.first_used_at = from_ts(now_ts())
        current_first_used = sub.first_used_at
        subscription_changed = True

    if subscription_changed:
        if unlimited:
            try:
                _clear_timer_cycle(sub)
            except Exception:
                pass
        else:
            _apply_subscription_timer(sub)
        _sync_all_subscription_peers(sub, rename=False)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception(
                'Failed to save subscription first-use date for subscription_id=%s',
                getattr(sub, 'id', '?'),
            )

    limit = _sub_limit_bytes(sub)
    remaining = None if limit is None else max(0, int(limit) - used)
    expired = False if unlimited else _subscription_time_expired(sub)

    if limit and used >= int(limit):
        _block_subscription_runtime(sub, 'subscription_limit_reached')
    elif expired:
        _block_subscription_runtime(sub, 'subscription_expired')

    locs = []
    links = sorted(
        list(getattr(sub, 'links', []) or []),
        key=lambda link: (getattr(link, 'sort_order', 0) or 0, getattr(link, 'id', 0) or 0),
    )
    runtime_counts = {'total': 0, 'enabled': 0, 'disabled': 0, 'blocked': 0}

    for link in links:
        peer = getattr(link, 'peer', None)
        if not peer:
            continue
        iface = getattr(peer, 'iface', None)
        raw_name = getattr(iface, 'name', '') or ''
        node_id = getattr(iface, 'node_id', None) if iface else None
        is_legacy_node_name = bool(raw_name.startswith('n') and ':' in raw_name)
        scope = 'node' if (node_id is not None or is_legacy_node_name) else 'local'
        interface_name = raw_name.split(':', 1)[1] if is_legacy_node_name else raw_name
        peer_status = str(getattr(peer, 'status', None) or 'offline').lower()

        runtime_counts['total'] += 1
        if peer_status == 'blocked':
            runtime_counts['blocked'] += 1
        elif peer_status == 'online':
            runtime_counts['enabled'] += 1
        else:
            runtime_counts['disabled'] += 1

        peer_first_used = getattr(peer, 'first_used_at', None)
        node = getattr(iface, 'node', None) if iface else None

        try:
            live = _subscription_peer_runtime(peer)
        except Exception:
            current_app.logger.debug('Could not read subscription runtime for peer_id=%s', getattr(peer, 'id', '?'), exc_info=True)
            live = {
                'connected': False,
                'conn_status': 'offline',
                'connection_status': 'disconnected',
                'connection_label': 'Disconnected',
                'conn_reason': 'runtime_error',
                'latest_handshake': 0,
                'latest_handshake_age': None,
                'last_activity_at': None,
                'runtime_available': False,
            }

        locs.append({
            'link_id': getattr(link, 'id', None),
            'peer_id': getattr(peer, 'id', None),
            'scope': scope,
            'node_id': node_id,
            'node_name': getattr(node, 'name', '') or '',
            'iface': interface_name,
            'name': getattr(peer, 'name', '') or '',
            'address': getattr(peer, 'address', '') or '',
            'endpoint': getattr(peer, 'endpoint', '') or '',
            'allowed_ips': getattr(peer, 'allowed_ips', '') or '',
            'dns': getattr(peer, 'dns', '') or '',
            'status': peer_status,
            'panel_status': peer_status,
            'connected': bool(live.get('connected')),
            'conn_status': live.get('conn_status') or 'offline',
            'connection_status': live.get('connection_status') or 'disconnected',
            'connection_label': live.get('connection_label') or 'Disconnected',
            'conn_reason': live.get('conn_reason') or 'no_recent_activity',
            'latest_handshake': int(live.get('latest_handshake') or 0),
            'latest_handshake_age': live.get('latest_handshake_age'),
            'last_activity_at': live.get('last_activity_at'),
            'runtime_available': bool(live.get('runtime_available', True)),
            'used_bytes': int(getattr(peer, 'used_bytes_total', 0) or 0),
            'first_used_at': isoz(peer_first_used),
            'first_used_at_display': _panel_display_datetime(peer_first_used),
            'first_used_at_ts': to_ts(peer_first_used),
            'location_label': getattr(link, 'location_label', '') or '',
            'country_code': getattr(link, 'country_code', '') or '',
            'flag': getattr(link, 'flag', '') or '',
        })

    connected_locations = [location for location in locs if bool(location.get('connected'))]
    runtime_locations = [location for location in locs if bool(location.get('runtime_available', True))]
    activity_locations = [location for location in locs if int(location.get('latest_handshake') or 0) > 0]
    active_location = None
    if connected_locations:
        active_location = max(connected_locations, key=lambda location: int(location.get('latest_handshake') or 0))
    elif activity_locations:
        active_location = max(activity_locations, key=lambda location: int(location.get('latest_handshake') or 0))

    connection = {
        'connected': bool(connected_locations),
        'status': 'connected' if connected_locations else 'disconnected',
        'label': 'Connected' if connected_locations else 'Disconnected',
        'connected_count': len(connected_locations),
        'runtime_count': len(runtime_locations),
        'total_count': len(locs),
        'active_peer_id': (active_location or {}).get('peer_id'),
        'active_peer_name': (active_location or {}).get('name') or '',
        'active_scope': (active_location or {}).get('scope') or '',
        'active_node_id': (active_location or {}).get('node_id'),
        'active_node_name': (active_location or {}).get('node_name') or '',
        'active_iface': (active_location or {}).get('iface') or '',
        'latest_handshake': int((active_location or {}).get('latest_handshake') or 0),
        'last_activity_at': (active_location or {}).get('last_activity_at'),
        'last_activity_age': (active_location or {}).get('latest_handshake_age'),
    }

    first_used_at = getattr(sub, 'first_used_at', None)
    created_at = getattr(sub, 'created_at', None)
    expires_at = from_ts(_effective_expiry_ts(sub)) if not unlimited else None
    ttl_seconds = None if unlimited else _sub_ttl_seconds(sub)

    return {
        'id': sub.id,
        'name': sub.name,
        'token': sub.token,
        'note': sub.note or '',
        'display_timezone': _panel_timezone_name(),
        'data_limit_value': int(getattr(sub, 'data_limit_value', 0) or 0),
        'data_limit_unit': getattr(sub, 'data_limit_unit', None) or 'Gi',
        'limit_bytes': limit,
        'used_bytes': used,
        'remaining_bytes': remaining,
        'usage_pct': round((used / int(limit)) * 100, 2) if limit else 0,
        'time_limit_days': _sub_float(getattr(sub, 'time_limit_days', 0)),
        'ttl_seconds': ttl_seconds,
        'start_on_first_use': bool(getattr(sub, 'start_on_first_use', False)),
        'created_at': isoz(created_at),
        'created_at_display': _panel_display_datetime(created_at),
        'created_at_ts': to_ts(created_at),
        'first_used_at': isoz(first_used_at),
        'first_used_at_display': _panel_display_datetime(first_used_at),
        'first_used_at_ts': to_ts(first_used_at),
        'expires_at': isoz(expires_at),
        'expires_at_display': _panel_display_datetime(expires_at),
        'expires_at_ts': to_ts(expires_at),
        'unlimited': unlimited,
        'phone_number': getattr(sub, 'phone_number', '') or '',
        'telegram_id': getattr(sub, 'telegram_id', '') or '',
        'enabled': bool(getattr(sub, 'enabled', True)),
        'runtime_counts': runtime_counts,
        'connection': connection,
        'connected': bool(connection.get('connected')),
        'connection_status': connection.get('status') or 'disconnected',
        'connection_label': connection.get('label') or 'Disconnected',
        'public_url': _sub_public_url(sub),
        'config_url': _sub_config_url(sub),
        'locations': locs,
    }


def _network_int_cidr(value):
    raw = str(value or '').split(',', 1)[0].strip()
    if not raw:
        return ''
    try:
        return str(ipaddress.ip_interface(raw).network)
    except Exception:
        return ''


def _apnd_allowed_route(allowed_ips, route):
    values = [item.strip() for item in str(allowed_ips or '').split(',') if item.strip()]
    route = str(route or '').strip()
    if not route:
        return ', '.join(values)
    if route not in values:
        values.append(route)
    return ', '.join(values)


def _peer_payload_subscription(sub, target, data, idx=0, total=1):
    name = (target.get('peer_name') or '').strip()
    if not name:
        base = (sub.name or data.get('name') or 'subscription').strip() or 'subscription'
        name = base if total <= 1 else f'{base}-{idx + 1}'

    allowed_ips = (data.get('allowed_ips') or '0.0.0.0/0, ::/0').strip()
    if bool(data.get('include_internal_network', False)):
        interface_cidr = (target.get('server_cidr') or target.get('interface_address') or target.get('iface_address') or target.get('address') or '')
        internal_network = _network_int_cidr(interface_cidr)
        allowed_ips = _apnd_allowed_route(allowed_ips, internal_network)

    return {
        'name': name,
        'allowed_ips': allowed_ips,
        'endpoint': parse_endpoint_string(data.get('endpoint')),
        'peer_endpoint': (data.get('peer_endpoint') or '').strip(),
        'persistent_keepalive': data.get('persistent_keepalive') or None,
        'mtu': data.get('mtu') or None,
        'dns': data.get('dns') or None,
        'data_limit_value': int(getattr(sub, 'data_limit_value', 0) or 0),
        'data_limit_unit': getattr(sub, 'data_limit_unit', None) or 'Gi',
        'time_limit_days': _sub_float(getattr(sub, 'time_limit_days', 0)) or None,
        'start_on_first_use': bool(getattr(sub, 'start_on_first_use', False)),
        'unlimited': bool(getattr(sub, 'unlimited', False)),
        'phone_number': getattr(sub, 'phone_number', '') or '',
        'telegram_id': getattr(sub, 'telegram_id', '') or '',
    }


def _create_subscription_peer(target, payload, compensation=None):
    scope = (target.get('scope') or 'local').lower()
    priv, pub = generate_wg_keypair()
    payload = dict(payload)
    peer_endpoint = (payload.pop('peer_endpoint', '') or '').strip()
    created_ts = now_ts()

    if scope == 'node':
        nid = _sub_int(target.get('node_id'))
        iface_name = (target.get('iface') or '').strip()
        if not nid or not iface_name:
            raise ValueError('node_id and iface are required for node target')

        node = db.session.get(Node, nid) or abort(404)
        iface = ensure_node_mirror_iface(
            node, iface_name,
            {
                'listen_port': _sub_int(target.get('listen_port'), 51820),
                'address': target.get('server_cidr') or target.get('interface_address'),
                'mtu': payload.get('mtu'),
                'dns': payload.get('dns'),
                'public_key': target.get('public_key'),
            },
            listen_port=_sub_int(target.get('listen_port'), 51820),
            server_cidr=target.get('server_cidr') or target.get('interface_address'),
            mtu=payload.get('mtu'),
            dns=payload.get('dns'),
        )

        if compensation is not None:
            compensation.register_node(node, pub)

        addr = node_install_peer(
            node, iface_name, iface,
            public_key=pub,
            requested_address=requested_peer_address_from_target(iface, target),
            peer_endpoint=peer_endpoint,
            keepalive=payload.get('persistent_keepalive') or 0,
            mtu=payload.get('mtu'),
            dns=payload.get('dns'),
            allowed_ips=payload.get('allowed_ips') or '0.0.0.0/0, ::/0',
        )
        peer = Peer(
            iface_id=iface.id,
            public_key=pub,
            private_key=priv,
            created_at=from_ts(created_ts),
            timer_started_at=from_ts(created_ts),
            address=addr,
            peer_endpoint=(peer_endpoint or None),
            status='online',
            **payload,
        )
        db.session.add(peer)
        db.session.flush()
        return peer

    iface_id = _sub_int(target.get('iface_id'))
    iface = db.session.get(InterfaceConfig, iface_id) if iface_id else None
    if not iface and target.get('iface'):
        iface = InterfaceConfig.query.filter_by(name=(target.get('iface') or '').strip()).first()
    if not iface:
        raise ValueError('iface_id is required for local target')

    with interface_allocation_lock(iface):
        requested = requested_peer_address_from_target(iface, target)
        addr = allocate_peer_address(iface, requested=requested)

        peer = Peer(
            iface_id=iface.id,
            public_key=pub,
            private_key=priv,
            created_at=from_ts(created_ts),
            timer_started_at=from_ts(created_ts),
            address=addr,
            peer_endpoint=(peer_endpoint or None),
            status='online',
            **payload,
        )
        db.session.add(peer)
        db.session.flush()
        install_local_peer(peer)
        if compensation is not None and hasattr(compensation, 'register_local'):
            compensation.register_local(peer)

    return peer


def _attach_subscription_target(sub, target, data, idx=0, total=1, compensation=None):
    if target.get('peer_id'):
        peer = db.session.get(Peer, int(target.get('peer_id'))) or abort(404)
        existing = SubscriptionPeer.query.filter_by(peer_id=peer.id).first()
        if existing and existing.subscription_id != sub.id:
            raise ValueError(f'Peer {peer.name} is already attached to another subscription')
        if existing:
            link = existing
        else:
            link = SubscriptionPeer(subscription_id=sub.id, peer_id=peer.id, owned=False)
            db.session.add(link)
            db.session.flush()
    else:
        payload = _peer_payload_subscription(sub, target, data, idx=idx, total=total)
        peer = _create_subscription_peer(target, payload, compensation=compensation)
        link = SubscriptionPeer(subscription_id=sub.id, peer_id=peer.id, owned=True)
        db.session.add(link)
        db.session.flush()

    link.sort_order = idx
    link.location_label = (target.get('location_label') or target.get('label') or target.get('location') or '').strip()
    link.country_code = (target.get('country_code') or '').strip()[:2].upper()
    link.flag = (target.get('flag') or '').strip()[:8]
    _sync_peer_subscription(link.peer, sub, idx=idx, rename=True)
    return link


def _update_subscription_payload(sub, data, reset_timer=False):
    if 'name' in data:
        sub.name = (data.get('name') or sub.name or 'Subscription').strip()
    if 'note' in data:
        sub.note = (data.get('note') or '').strip()
    if 'data_limit_value' in data:
        sub.data_limit_value = _sub_int(data.get('data_limit_value'), 0)
    if 'data_limit_unit' in data:
        sub.data_limit_unit = data.get('data_limit_unit') or 'Gi'
    if 'time_limit_days' in data:
        sub.time_limit_days = _sub_float(data.get('time_limit_days'), 0)
    if 'start_on_first_use' in data:
        sub.start_on_first_use = _sub_bool(data.get('start_on_first_use'))
    if 'unlimited' in data:
        sub.unlimited = _sub_bool(data.get('unlimited'))
    if 'phone_number' in data:
        sub.phone_number = (data.get('phone_number') or '').strip()
    if 'telegram_id' in data:
        sub.telegram_id = (data.get('telegram_id') or '').strip()
    if 'enabled' in data:
        sub.enabled = _sub_bool(data.get('enabled'))

    timer_policy_changed = any(k in data for k in ('time_limit_days', 'start_on_first_use', 'unlimited'))
    if reset_timer or timer_policy_changed:
        if reset_timer or not getattr(sub, 'start_on_first_use', False):
            sub.first_used_at = None
        _apply_subscription_timer(sub, restart=True)
    else:
        _apply_subscription_timer(sub)
    _sync_all_subscription_peers(sub, rename=True)


def _reset_subscription_data(sub):
    result = {
        'reset_peers': 0,
        'reactivated': 0,
        'still_blocked': 0,
        'enable_failed': 0,
        'errors': [],
    }
    timer_expired = _subscription_time_expired(sub)

    for link in list(getattr(sub, 'links', []) or []):
        peer = getattr(link, 'peer', None)
        if not peer:
            continue
        result['reset_peers'] += 1
        try:
            if getattr(peer.iface, 'node_id', None) is not None:
                node = peer.iface.node
                response = node_post(node, f'/api/peer/{peer.public_key}/reset_data', {}, timeout=12) or {}
                if not isinstance(response, dict):
                    raise RuntimeError('Node returned an invalid reset-data response')
                if response.get('ok') is False:
                    raise RuntimeError(response.get('detail') or response.get('error') or 'Node reset-data request failed')
                current_total = response.get('total_bytes')
                if current_total is None:
                    rx_bytes = int(response.get('rx_bytes') or 0)
                    tx_bytes = int(response.get('tx_bytes') or 0)
                    current_total = rx_bytes + tx_bytes
                peer.bytes_offset = max(0, int(current_total or 0))
            else:
                peer.bytes_offset = max(0, int(_wg_transfer(peer) or 0))
            peer.used_bytes_total = 0
        except Exception as exc:
            current_app.logger.exception('Subscription data reset failed for peer %s', getattr(peer, 'id', '?'))
            result['errors'].append({
                'peer_id': getattr(peer, 'id', None),
                'peer_name': getattr(peer, 'name', '') or '',
                'detail': str(exc),
            })
            continue

        if peer.status == 'blocked':
            if timer_expired:
                result['still_blocked'] += 1
            elif _enable_subscription(peer):
                result['reactivated'] += 1
            else:
                result['enable_failed'] += 1

        try:
            log_event(
                peer,
                'subscription_reset_data',
                f'Shared subscription data reset; new offset={int(peer.bytes_offset or 0)}',
            )
        except Exception:
            pass

    return result


def _reset_subscription_timer(sub):
    result = {
        'reset_peers': 0,
        'reactivated': 0,
        'still_blocked': 0,
        'enable_failed': 0,
        'errors': [],
    }
    sub.first_used_at = None
    _apply_subscription_timer(sub, restart=True)
    data_exhausted = _subscription_data_exhausted(sub)

    for link in list(getattr(sub, 'links', []) or []):
        peer = getattr(link, 'peer', None)
        if not peer:
            continue
        result['reset_peers'] += 1
        try:
            _sync_peer_subscription(peer, sub, rename=False)
        except Exception as exc:
            current_app.logger.exception('Subscription timer sync failed for peer %s', getattr(peer, 'id', '?'))
            result['errors'].append({
                'peer_id': getattr(peer, 'id', None),
                'peer_name': getattr(peer, 'name', '') or '',
                'detail': str(exc),
            })

        if peer.status == 'blocked':
            if data_exhausted:
                result['still_blocked'] += 1
            elif _enable_subscription(peer):
                result['reactivated'] += 1
            else:
                result['enable_failed'] += 1

        try:
            log_event(peer, 'subscription_reset_timer', 'Shared subscription timer reset')
        except Exception:
            pass

    return result


def _subscription_data_exhausted(sub):
    limit = _sub_limit_bytes(sub)
    return bool(limit and _sub_used_bytes(sub) >= limit)


def _subscription_time_expired(sub):
    ttl = _sub_ttl_seconds(sub)
    return bool(ttl is not None and ttl <= 0)


def _enable_subscription(peer):
    try:
        iface = getattr(peer, 'iface', None)
        if not iface:
            raise RuntimeError('Peer interface is missing.')

        if getattr(iface, 'node_id', None) is not None:
            node = getattr(iface, 'node', None)
            if not node:
                raise RuntimeError('Peer node is missing.')

            response = node_post(
                node,
                f'/api/peer/{peer.public_key}/enable',
                {'host_cidr': _host_peer(peer)},
                timeout=15,
            ) or {}
            if not isinstance(response, dict):
                raise RuntimeError('Node returned an invalid enable response.')
            if response.get('ok') is False:
                raise RuntimeError(response.get('detail') or response.get('error') or 'Node peer enable failed.')
        else:
            dev = iface_devname(iface)
            if not _iface_up(dev):
                try:
                    _check_iface_up(iface)
                except Exception:
                    pass
            _wg_enable(peer)
            _sync_peer(peer)

        peer.status = 'online'
        return True
    except Exception:
        current_app.logger.exception('Failed enabling subscription peer %s', getattr(peer, 'id', '?'))
        return False


def _disable_subscription(peer):
    try:
        iface = getattr(peer, 'iface', None)
        if not iface:
            raise RuntimeError('Peer interface is missing.')

        if getattr(iface, 'node_id', None) is not None:
            node = getattr(iface, 'node', None)
            if not node:
                raise RuntimeError('Peer node is missing.')

            response = node_post(
                node,
                f'/api/peer/{peer.public_key}/disable',
                {'host_cidr': _host_peer(peer)},
                timeout=15,
            ) or {}
            if not isinstance(response, dict):
                raise RuntimeError('Node returned an invalid disable response.')
            if response.get('ok') is False:
                raise RuntimeError(response.get('detail') or response.get('error') or 'Node peer disable failed.')
        else:
            _wg_disable(peer)

        peer.status = 'offline'
        return True
    except Exception:
        current_app.logger.exception('Failed disabling subscription peer %s', getattr(peer, 'id', '?'))
        return False


def _subscription_enabled(sub, enabled: bool):
    result = {
        'total': 0,
        'changed': 0,
        'failed': 0,
        'failed_peer_ids': [],
        'errors': [],
    }
    enabled = bool(enabled)

    for link in list(getattr(sub, 'links', []) or []):
        peer = getattr(link, 'peer', None)
        if not peer:
            continue
        result['total'] += 1
        if enabled:
            success = _enable_subscription(peer)
        else:
            success = _disable_subscription(peer)

        if success:
            result['changed'] += 1
            try:
                log_event(
                    peer,
                    'subscription_enabled' if enabled else 'subscription_disabled',
                    'Subscription enabled' if enabled else 'Subscription disabled',
                )
            except Exception:
                pass
        else:
            result['failed'] += 1
            result['failed_peer_ids'].append(getattr(peer, 'id', None))
            result['errors'].append({
                'peer_id': getattr(peer, 'id', None),
                'peer_name': getattr(peer, 'name', '') or '',
            })

    return result


def _flag_from_cc(cc: str) -> str:
    cc = (cc or '').strip().upper()
    if not re.match(r'^[A-Z]{2}$', cc):
        return '🌐'
    return ''.join(chr(127397 + ord(ch)) for ch in cc)


def _load_geo_cache() -> dict:
    try:
        with open(_get_geo_cache_path(), 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_geo_cache(data: dict):
    try:
        os.makedirs(current_app.instance_path, exist_ok=True)
        with open(_get_geo_cache_path(), 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def _i_public_host(host: str) -> bool:
    host = (host or '').strip().strip('[]')
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return bool(ip.is_global)
    except Exception:
        low = host.lower()
        return low not in ('localhost',) and not low.endswith('.local')


def _endpoint_host(endpoint: str) -> str:
    endpoint = (endpoint or '').strip()
    if not endpoint:
        return ''
    if endpoint.startswith('[') and ']' in endpoint:
        return endpoint[1:].split(']', 1)[0]
    if ':' in endpoint:
        return endpoint.rsplit(':', 1)[0]
    return endpoint


def _node_public_host(iface) -> str:
    try:
        nid = getattr(iface, 'node_id', None)
        if nid is None:
            nm = getattr(iface, 'name', '') or ''
            m = re.match(r'^n(\d+):', nm)
            nid = int(m.group(1)) if m else None
        if nid is None:
            return ''
        n = db.session.get(Node, int(nid))
        if not n:
            return ''
        try:
            h = node_get(n, '/api/health', timeout=5) or {}
            pub = (h.get('public_ipv4') or h.get('ipv4') or h.get('public_ip') or '').strip()
            if pub:
                return pub
        except Exception:
            pass
        return (_geo_urlparse(n.base_url or '').hostname or '').strip()
    except Exception:
        return ''


def _public_host_peer(peer) -> str:
    try:
        iface = peer.iface
    except Exception:
        iface = None

    iface_name = getattr(iface, 'name', '') or ''
    is_node = bool(
        iface and (
            getattr(iface, 'node_id', None) is not None or
            re.match(r'^n\d+:', iface_name)
        )
    )

    if is_node:
        host = _node_public_host(iface)
        if _i_public_host(host):
            return host
        try:
            nid = getattr(iface, 'node_id', None)
            if nid is None:
                m = re.match(r'^n(\d+):', iface_name)
                nid = int(m.group(1)) if m else None
            n = db.session.get(Node, int(nid)) if nid is not None else None
            if n:
                host = _endpoint_host(getattr(n, 'base_url', '') or '')
                if _i_public_host(host):
                    return host
        except Exception:
            pass
        return ''

    try:
        host = _public_ipv4(force=True)
    except TypeError:
        host = _public_ipv4()
    except Exception:
        host = ''

    if _i_public_host(host):
        return host

    if iface:
        host = _endpoint_host(_endpoint_fallback(iface))
        if _i_public_host(host):
            return host

    return ''


def _lookup_geo(host: str) -> dict:
    host = (host or '').strip().strip('[]')
    if not _i_public_host(host):
        return {'country': '', 'country_code': '', 'flag': '🌐'}

    now = int(_geo_time.time())
    cache = _load_geo_cache()
    old = cache.get(host) or {}
    if old and (now - int(old.get('ts') or 0) < GEO_CACHE_TTL):
        return old

    headers = {'User-Agent': 'WG-Panel/1.0 (+subscription geo)'}
    providers = [
        ('ipwho', f'https://ipwho.is/{host}'),
        ('ipapi', f'https://ipapi.co/{host}/json/'),
        ('ipapi2', f'http://ip-api.com/json/{host}?fields=status,country,countryCode'),
    ]

    for provider, url in providers:
        try:
            r = requests.get(url, headers=headers, timeout=4)
            if not r.ok:
                continue
            j = r.json() or {}
            country = ''
            cc = ''
            if provider == 'ipwho':
                if j.get('success') is False:
                    continue
                country = (j.get('country') or '').strip()
                cc = (j.get('country_code') or '').strip().upper()
            elif provider == 'ipapi':
                country = (j.get('country_name') or '').strip()
                cc = (j.get('country_code') or j.get('country') or '').strip().upper()
            else:
                if j.get('status') != 'success':
                    continue
                country = (j.get('country') or '').strip()
                cc = (j.get('countryCode') or '').strip().upper()

            if cc or country:
                geo = {'country': country or cc, 'country_code': cc, 'flag': _flag_from_cc(cc), 'ts': now}
                cache[host] = geo
                _save_geo_cache(cache)
                return geo
        except Exception:
            continue

    return {'country': '', 'country_code': '', 'flag': '🌐', 'ts': now}


def _peer_used_for_subscription(peer) -> int:
    try:
        iface = getattr(peer, 'iface', None)
        is_node = bool(
            iface and (
                getattr(iface, 'node_id', None) is not None or
                re.match(r'^n\d+:', getattr(iface, 'name', '') or '')
            )
        )
        if is_node:
            return int(getattr(peer, 'used_bytes_total', 0) or 0)
        total = _wg_transfer(peer)
        used, _delta, changed = _accumulate_peer_usage(peer, total)
        if changed:
            db.session.commit()
        return int(used)
    except Exception:
        return int(getattr(peer, 'used_bytes_total', 0) or 0)


def subscription_access(sub, used_bytes=None) -> dict:
    if not bool(getattr(sub, 'enabled', True)):
        return {
            'allowed': False,
            'reason': 'disabled',
            'message': 'This subscription has been disabled. Please contact support.',
        }

    if bool(getattr(sub, 'unlimited', False)):
        return {'allowed': True, 'reason': '', 'message': ''}

    expires_ts = _effective_expiry_ts(sub)
    if expires_ts and expires_ts <= now_ts():
        return {
            'allowed': False,
            'reason': 'expired',
            'message': 'This subscription has expired. Please renew it to continue.',
        }

    limit = sub.limit_bytes() if hasattr(sub, 'limit_bytes') else None
    if limit:
        try:
            used = int(_sub_used_bytes(sub) if used_bytes is None else used_bytes)
        except Exception:
            used = 0
        if used >= int(limit):
            return {
                'allowed': False,
                'reason': 'data_exhausted',
                'message': 'This subscription has used all of its data allowance.',
            }

    return {'allowed': True, 'reason': '', 'message': ''}


def _subscription_inbound_state(sub):
    links = getattr(sub, 'links', None) or []
    usable = sum(
        1 for link in links
        if getattr(link, 'peer', None) is not None
        and str(getattr(getattr(link, 'peer', None), 'status', '') or '').lower() != 'removed'
    )
    return {'inbound_count': usable, 'has_inbounds': usable > 0}


def _subscription_access_or_403(sub):
    access = subscription_access(sub)
    if access['allowed']:
        return None
    return jsonify(
        ok=False,
        error='subscription_access_revoked',
        reason=access['reason'],
        message=access['message'],
    ), 403


def _subscription_public_payload(sub) -> dict:
    try:
        _expire()
    except Exception:
        pass

    links = sorted(list(getattr(sub, 'links', []) or []), key=lambda x: (x.sort_order or 0, x.id or 0))
    limit_bytes = sub.limit_bytes() if hasattr(sub, 'limit_bytes') else None
    used_bytes = 0
    locs = []
    dirty = False

    for link in links:
        peer = getattr(link, 'peer', None)
        if not peer:
            continue
        used_bytes += _peer_used_for_subscription(peer)

    access = subscription_access(sub, used_bytes=used_bytes)
    access.update(_subscription_inbound_state(sub))
    may_disclose_topology = bool(access['allowed'])

    for link in links:
        peer = getattr(link, 'peer', None)
        if not peer:
            continue

        host = _public_host_peer(peer) if may_disclose_topology else ''
        cc = (getattr(link, 'country_code', '') or '').strip().upper()
        flag = (getattr(link, 'flag', '') or '').strip()
        label = (getattr(link, 'location_label', '') or '').strip()
        if host:
            geo = _lookup_geo(host)
            new_cc = (geo.get('country_code') or '').strip().upper()
            new_flag = geo.get('flag') or _flag_from_cc(new_cc)
            new_label = geo.get('country') or new_cc or ''
            if new_cc and new_cc != cc:
                cc = new_cc
                flag = new_flag
                label = new_label
                link.country_code = cc
                link.flag = flag
                link.location_label = label
                dirty = True
            elif new_cc and not cc:
                cc = new_cc
                flag = new_flag
                label = new_label
                link.country_code = cc
                link.flag = flag
                link.location_label = label
                dirty = True

        endpoint = ''
        if may_disclose_topology and getattr(peer, 'iface', None):
            endpoint = resolve_client_endpoint_cheap(peer.iface, explicit=getattr(peer, 'endpoint', ''))
        elif may_disclose_topology:
            endpoint = getattr(peer, 'endpoint', '') or ''

        locs.append({
            'link_id': link.id,
            'peer_id': peer.id,
            'name': peer.name,
            'status': peer.status,
            'endpoint': endpoint,
            'public_host': host,
            'location_label': label,
            'country_code': cc,
            'flag': flag or _flag_from_cc(cc),
        })

    if dirty:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    exp_ts = _effective_expiry_ts(sub)
    ttl_seconds = max(0, exp_ts - now_ts()) if exp_ts else None
    if limit_bytes is not None:
        used_bytes = min(int(used_bytes), int(limit_bytes))

    return {
        'id': sub.id,
        'name': sub.name,
        'token': sub.token,
        'display_timezone': _panel_timezone_name(),
        'enabled': bool(getattr(sub, 'enabled', True)),
        'unlimited': bool(getattr(sub, 'unlimited', False)),
        'limit_bytes': limit_bytes,
        'used_bytes': int(used_bytes),
        'data_limit_value': getattr(sub, 'data_limit_value', 0) or 0,
        'data_limit_unit': getattr(sub, 'data_limit_unit', 'Gi') or 'Gi',
        'start_on_first_use': bool(getattr(sub, 'start_on_first_use', False)),
        'first_used_at': isoz(getattr(sub, 'first_used_at', None)),
        'first_used_at_display': _panel_display_datetime(getattr(sub, 'first_used_at', None)),
        'expires_at': isoz(from_ts(exp_ts)),
        'expires_at_display': _panel_display_datetime(from_ts(exp_ts)),
        'expires_at_ts': exp_ts,
        'ttl_seconds': ttl_seconds,
        'access': access,
        'locations': locs,
    }


def _subscription_settings_public(sub=None):
    settings = _effective_subscription_settings(sub)
    support = settings.get('support') or {}
    result = dict(settings)
    result['socials'] = {
        'telegram': support.get('telegram', ''),
        'whatsapp': support.get('whatsapp', ''),
        'instagram': support.get('instagram', ''),
        'phone': support.get('phone', ''),
        'website': support.get('website', ''),
        'email': support.get('email', ''),
    }
    result['has_override'] = bool(sub and _subscription_portal_override(sub))
    return result


def _private_networks():
    networks = []
    try:
        for interface_name, addresses in psutil.net_if_addrs().items():
            if interface_name == 'lo':
                continue
            for address in addresses:
                if getattr(address, 'family', None) != socket.AF_INET:
                    continue
                ip_value = (getattr(address, 'address', '') or '').split('%', 1)[0]
                netmask = getattr(address, 'netmask', None)
                if not ip_value or not netmask:
                    continue
                try:
                    interface = ipaddress.ip_interface(f"{ip_value}/{netmask}")
                    if interface.ip.is_loopback or interface.ip.is_link_local or interface.ip.is_unspecified:
                        continue
                    if not interface.ip.is_private:
                        continue
                    network = str(interface.network)
                    if network not in networks:
                        networks.append(network)
                except (ValueError, TypeError):
                    continue
    except Exception:
        current_app.logger.exception('Failed to detect local private networks')
    return networks


def resolve_requested_peer_address(iface, value, *, allow_legacy_interface_address=False):
    text = str(value or '').strip()
    if not text:
        return None
    try:
        candidate = ipaddress.ip_interface(text)
    except ValueError:
        raise AddressInvalid(f'{text} is not a valid IP address.')
    ip_iface = interface_ip_interface(iface)
    if allow_legacy_interface_address and ip_iface is not None and candidate.ip == ip_iface.ip:
        return None
    return text


def requested_peer_address_from_target(iface, target):
    explicit = str((target or {}).get('peer_address') or '').strip()
    if explicit:
        return resolve_requested_peer_address(iface, explicit)
    return resolve_requested_peer_address(
        iface,
        (target or {}).get('address'),
        allow_legacy_interface_address=True,
    )


@contextmanager
def interface_allocation_lock(iface):
    name = re.sub(r'[^A-Za-z0-9_.:-]+', '_', str(getattr(iface, 'name', '') or 'iface'))
    handle = None
    lock_dir = os.path.join(current_app.instance_path, 'locks')
    try:
        os.makedirs(lock_dir, exist_ok=True)
        handle = open(os.path.join(lock_dir, f'{name}.alloc.lock'), 'w')
        if fcntl:
            fcntl.flock(handle, fcntl.LOCK_EX)
    except Exception:
        current_app.logger.warning('Could not take allocation lock for %s', name, exc_info=True)
        handle = None

    try:
        yield
    finally:
        if handle is not None:
            if fcntl:
                try:
                    fcntl.flock(handle, fcntl.LOCK_UN)
                except Exception:
                    pass
            handle.close()


# ==============================================================================
# Routes (24 non-static rules)
# ==============================================================================

@subscriptions_bp.get('/subscriptions')
@login_required
def subscriptions_page():
    return render_template('subscriptions.html')


@subscriptions_bp.route('/api/subscriptions/settings', methods=['GET', 'POST'])
@require_api_key_or_login
def api_subscription_settings():
    if request.method == 'GET':
        return jsonify(_load_subscription_settings())
    saved = _save_subscription_settings(request.get_json(silent=True) or {})
    return jsonify(ok=True, settings=saved)


@subscriptions_bp.post('/api/subscriptions/template-preview')
@require_api_key_or_login
def api_subscription_template_preview():
    payload = request.get_json(silent=True) or {}
    raw_settings = payload.get('settings') if isinstance(payload.get('settings'), dict) else {}
    subscription_id = payload.get('subscription_id')
    sub = None

    if subscription_id not in (None, '', 0, '0'):
        try:
            subscription_id = int(subscription_id)
            sub = db.session.get(Subscription, subscription_id)
        except Exception:
            sub = None

    if sub is not None:
        base_settings = _effective_subscription_settings(sub)
    else:
        base_settings = _load_subscription_settings()

    cfg = _normalize_subscription_settings(raw_settings, base=base_settings)

    if sub is not None:
        preview_sub = sub
        try:
            preview_data = _subscription_public_payload(sub)
        except Exception:
            preview_data = {}
    else:
        from types import SimpleNamespace
        preview_sub = SimpleNamespace(id=0, name='premium-user', token='preview')
        gib = 1024 ** 3
        preview_data = {
            'id': 0,
            'name': 'premium-user',
            'token': 'preview',
            'enabled': True,
            'unlimited': False,
            'limit_bytes': 10 * gib,
            'used_bytes': int(2.4 * gib),
            'data_limit_value': 10,
            'data_limit_unit': 'Gi',
            'start_on_first_use': False,
            'first_used_at': '2026-08-07T09:30:00Z',
            'expires_at': '2026-08-31T18:00:00Z',
            'expires_at_ts': None,
            'ttl_seconds': 12 * 86400 + 4 * 3600,
            'access': {
                'allowed': True,
                'reason': '',
                'message': '',
                'has_inbounds': True,
            },
            'locations': [
                {
                    'link_id': 1,
                    'peer_id': 1,
                    'name': 'Amsterdam',
                    'status': 'online',
                    'endpoint': '',
                    'public_host': '',
                    'location_label': 'Netherlands',
                    'country_code': 'NL',
                    'flag': '🇳🇱',
                },
                {
                    'link_id': 2,
                    'peer_id': 2,
                    'name': 'Frankfurt',
                    'status': 'online',
                    'endpoint': '',
                    'public_host': '',
                    'location_label': 'Germany',
                    'country_code': 'DE',
                    'flag': '🇩🇪',
                },
                {
                    'link_id': 3,
                    'peer_id': 3,
                    'name': 'Backup',
                    'status': 'offline',
                    'endpoint': '',
                    'public_host': '',
                    'location_label': 'Netherlands',
                    'country_code': 'NL',
                    'flag': '🇳🇱',
                },
            ],
        }

    support = cfg.get('support') or {}
    portal_title = cfg.get('portal_title') or preview_sub.name

    return render_template(
        'subscription_public.html',
        preview_mode=True,
        sub=preview_sub,
        data=preview_data,
        portal_settings=cfg,
        sub_layout=cfg.get('layout', 'aurora'),
        sub_display_mode=cfg.get('display_mode', 'hybrid'),
        sub_animation=cfg.get('animation', 'balanced'),
        sub_background=cfg.get('background', 'aurora'),
        portal_label=cfg.get('portal_label', 'Secure WireGuard portal'),
        portal_icon=cfg.get('portal_icon', 'fas fa-bolt'),
        portal_title=portal_title,
        portal_subtitle=cfg.get(
            'portal_subtitle',
            'Your account is ready. Install WireGuard, then scan QR or import a config.',
        ),
        support_portal_label=cfg.get('portal_label', 'Secure WireGuard portal'),
        support_portal_icon=cfg.get('portal_icon', 'fas fa-bolt'),
        support_portal_title=portal_title,
        support_portal_subtitle=cfg.get(
            'portal_subtitle',
            'Your account is ready. Install WireGuard, then scan QR or import a config.',
        ),
        support_telegram=support.get('telegram', ''),
        support_whatsapp=support.get('whatsapp', ''),
        support_instagram=support.get('instagram', ''),
        support_phone=support.get('phone', ''),
        support_website=support.get('website', ''),
        support_email=support.get('email', ''),
    )


@subscriptions_bp.route(
    '/api/subscriptions/<int:sid>/portal-settings',
    methods=['GET', 'POST', 'DELETE'],
)
@require_api_key_or_login
def api_subscription_portal_settings(sid):
    sub = db.session.get(Subscription, sid) or abort(404)
    store = _load_subscription_portal_overrides()
    key = str(sub.id)

    if request.method == 'GET':
        override = store.get(key) if isinstance(store.get(key), dict) else {}
        return jsonify(
            ok=True,
            subscription_id=sub.id,
            subscription_name=sub.name,
            has_override=bool(override),
            override=override,
            settings=_effective_subscription_settings(sub),
            global_settings=_load_subscription_settings(),
        )

    if request.method == 'DELETE':
        existed = key in store
        store.pop(key, None)
        _save_subscription_portal_overrides(store)
        return jsonify(
            ok=True,
            removed=existed,
            subscription_id=sub.id,
            settings=_load_subscription_settings(),
        )

    payload = request.get_json(silent=True) or {}
    global_settings = _load_subscription_settings()
    normalized = _normalize_subscription_settings(payload, base=global_settings)
    override = {}

    for field in payload.keys():
        if field == 'support' and isinstance(payload.get('support'), dict):
            override['support'] = {
                support_key: normalized['support'].get(support_key, '')
                for support_key in payload['support'].keys()
                if support_key in normalized['support']
            }
        elif field in normalized and field != 'socials':
            override[field] = normalized[field]

    store[key] = override
    _save_subscription_portal_overrides(store)
    return jsonify(
        ok=True,
        subscription_id=sub.id,
        subscription_name=sub.name,
        has_override=True,
        override=override,
        settings=_effective_subscription_settings(sub),
    )


@subscriptions_bp.get('/api/subscriptions/locations')
@require_api_key_or_login
def api_subscriptions_locations():
    local_locations = []
    for iface in InterfaceConfig.query.order_by(InterfaceConfig.name).all():
        iface_name = getattr(iface, 'name', '') or ''
        is_node_interface = getattr(iface, 'node_id', None) is not None or (iface_name.startswith('n') and ':' in iface_name)
        if is_node_interface:
            continue

        interface_address = getattr(iface, 'address', None) or ''
        endpoint_override = iface_endpoint_override(iface)
        endpoint_value = resolve_client_endpoint(iface)

        local_locations.append({
            'scope': 'local',
            'iface_id': iface.id,
            'iface': iface_name,
            'label': iface_name,
            'interface_address': interface_address,
            'server_cidr': interface_address,
            'endpoint': endpoint_value,
            'endpoint_override': endpoint_override,
            'endpoint_source': 'override' if endpoint_override else ('auto' if endpoint_value else 'none'),
            'scope_networks': _private_networks(),
            'listen_port': iface.listen_port,
            'dns': iface.dns or '',
            'mtu': iface.mtu,
            'available': len(_available_ips(iface)),
        })

    node_locations = []
    for node in Node.query.order_by(Node.name).all():
        interfaces = []
        try:
            remote_payload = node_get(node, '/api/interfaces', timeout=10) or {}
            if isinstance(remote_payload, dict):
                node_scope_networks = remote_payload.get('scope_networks') or []
            else:
                node_scope_networks = []

            if not isinstance(node_scope_networks, list):
                node_scope_networks = [v.strip() for v in str(node_scope_networks or '').split(',') if v.strip()]
            node_scope_networks = list(dict.fromkeys(node_scope_networks))

            if isinstance(remote_payload, dict):
                remote_interfaces = remote_payload.get('interfaces') or []
            else:
                remote_interfaces = remote_payload or []

            if not isinstance(remote_interfaces, list):
                remote_interfaces = []

            for item in remote_interfaces:
                if not isinstance(item, dict):
                    continue
                remote_name = (item.get('name') or item.get('iface') or '').strip()
                if not remote_name:
                    continue

                mirror_name = f'n{node.id}:{remote_name}'
                mirror = InterfaceConfig.query.filter_by(name=mirror_name).first()
                interface_address = item.get('address') or (mirror.address if mirror else '') or ''
                endpoint_override = iface_endpoint_override(mirror) if mirror is not None else ''

                interfaces.append({
                    'scope': 'node',
                    'node_id': node.id,
                    'node_name': node.name,
                    'iface_id': mirror.id if mirror else None,
                    'iface': remote_name,
                    'label': f'{node.name} · {remote_name}',
                    'interface_address': interface_address,
                    'server_cidr': interface_address,
                    'scope_networks': list(dict.fromkeys((item.get('scope_networks') if isinstance(item.get('scope_networks'), list) else node_scope_networks) or node_scope_networks)),
                    'listen_port': item.get('listen_port'),
                    'dns': item.get('dns') or '',
                    'mtu': item.get('mtu'),
                    'endpoint': endpoint_override,
                    'endpoint_override': endpoint_override,
                    'endpoint_source': 'override' if endpoint_override else 'auto',
                    'available': len(item.get('available_ips') or []),
                })
        except Exception:
            current_app.logger.exception('Failed to load subscription interfaces from node_id=%s', node.id)
            mirrored_interfaces = InterfaceConfig.query.filter(InterfaceConfig.name.like(f'n{node.id}:%')).all()
            for iface in mirrored_interfaces:
                stored_name = iface.name or ''
                remote_name = stored_name.split(':', 1)[1] if ':' in stored_name else stored_name
                interface_address = iface.address or ''
                endpoint_override = iface_endpoint_override(iface)

                interfaces.append({
                    'scope': 'node',
                    'node_id': node.id,
                    'node_name': node.name,
                    'iface_id': iface.id,
                    'iface': remote_name,
                    'label': f'{node.name} · {remote_name}',
                    'interface_address': interface_address,
                    'server_cidr': interface_address,
                    'listen_port': iface.listen_port,
                    'dns': iface.dns or '',
                    'mtu': iface.mtu,
                    'endpoint': endpoint_override,
                    'endpoint_override': endpoint_override,
                    'endpoint_source': 'override' if endpoint_override else 'auto',
                    'available': len(_available_ips(iface)),
                })

        node_locations.append({
            'id': node.id,
            'name': node.name,
            'online': bool(node.enabled),
            'interfaces': interfaces,
        })

    return jsonify(local=local_locations, nodes=node_locations)


@subscriptions_bp.get('/api/subscriptions/inbounds_catalog')
@require_api_key_or_login
def api_subscriptions_inbounds_catalog():
    inbounds = []
    for p in Peer.query.order_by(Peer.name).all():
        iface = p.iface
        raw = iface.name if iface else ''
        node_id = getattr(iface, 'node_id', None) if iface else None
        linked = SubscriptionPeer.query.filter_by(peer_id=p.id).first()
        inbounds.append({
            'peer_id': p.id,
            'scope': 'node' if node_id is not None or (raw.startswith('n') and ':' in raw) else 'local',
            'node_id': node_id,
            'node_name': getattr(iface.node, 'name', '') if getattr(iface, 'node', None) else '',
            'iface': raw.split(':', 1)[1] if raw.startswith('n') and ':' in raw else raw,
            'name': p.name,
            'address': p.address,
            'endpoint': resolve_client_endpoint_cheap(iface, explicit=p.endpoint),
            'allowed_ips': p.allowed_ips or '',
            'dns': p.dns or '',
            'status': p.status or 'offline',
            'used_bytes': int(getattr(p, 'used_bytes_total', 0) or 0),
            'phone_number': p.phone_number or '',
            'telegram_id': p.telegram_id or '',
            'already_linked': bool(linked),
            'subscription_id': linked.subscription_id if linked else None,
            'location_label': linked.location_label if linked else '',
        })
    return jsonify(inbounds=inbounds)


@subscriptions_bp.route('/api/subscriptions', methods=['GET', 'POST'])
@require_api_key_or_login
def api_subscriptions():
    if request.method == 'GET':
        rows = Subscription.query.order_by(Subscription.created_at.desc()).all()
        db.session.commit()
        return jsonify(subscriptions=[_subscription_row(s) for s in rows])

    data = request.get_json(silent=True) or {}
    created_ts = now_ts()
    sub = Subscription(
        name=(data.get('name') or 'Subscription').strip(),
        token=_token(),
        created_at=from_ts(created_ts),
        timer_started_at=from_ts(created_ts),
        note=(data.get('note') or '').strip(),
        data_limit_value=_sub_int(data.get('data_limit_value'), 0),
        data_limit_unit=(data.get('data_limit_unit') or 'Gi'),
        time_limit_days=_sub_float(data.get('time_limit_days'), 0),
        start_on_first_use=_sub_bool(data.get('start_on_first_use')),
        unlimited=_sub_bool(data.get('unlimited')),
        phone_number=(data.get('phone_number') or '').strip(),
        telegram_id=(data.get('telegram_id') or '').strip(),
        enabled=True,
    )
    _apply_subscription_timer(sub)
    db.session.add(sub)
    db.session.flush()

    targets = data.get('targets') or []
    compensation = PeerCreateCompensation()
    try:
        for idx, target in enumerate(targets):
            _attach_subscription_target(
                sub, target or {}, data, idx=idx, total=len(targets),
                compensation=compensation,
            )
        _sync_all_subscription_peers(sub, rename=True)
        db.session.commit()
        return jsonify(ok=True, subscription=_subscription_row(sub)), 201
    except AddressAllocationError as e:
        cleanup_failures = compensation.rollback()
        db.session.rollback()
        if cleanup_failures:
            return jsonify(
                error='subscription_create_cleanup_failed',
                detail=str(e),
                address_error=e.error_code,
                cleanup_complete=False,
                cleanup_failures=cleanup_failures,
            ), 502
        return address_error_response(e)
    except NodePeerInstallError as e:
        cleanup_failures = compensation.rollback()
        db.session.rollback()
        return jsonify(
            error=e.code,
            detail=e.detail,
            cleanup_complete=not cleanup_failures,
            cleanup_failures=cleanup_failures,
        ), 502 if cleanup_failures else e.status
    except Exception as e:
        cleanup_failures = compensation.rollback()
        db.session.rollback()
        current_app.logger.exception('subscription create failed')
        return jsonify(
            error='subscription_create_failed',
            detail=str(e),
            cleanup_complete=not cleanup_failures,
            cleanup_failures=cleanup_failures,
        ), 502 if cleanup_failures else 500


@subscriptions_bp.get('/api/subscriptions/<int:sid>')
@require_api_key_or_login
def api_subscription_get(sid):
    sub = db.session.get(Subscription, sid) or abort(404)
    return jsonify(subscription=_subscription_row(sub))


@subscriptions_bp.put('/api/subscriptions/<int:sid>')
@require_api_key_or_login
def api_subscription_update(sid):
    sub = db.session.get(Subscription, sid) or abort(404)
    data = request.get_json(silent=True) or {}
    try:
        _update_subscription_payload(sub, data, reset_timer=_sub_bool(data.get('reset_timer')))
        db.session.commit()
        return jsonify(ok=True, subscription=_subscription_row(sub))
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception('subscription update failed')
        return jsonify(error='subscription_update_failed', detail=str(e)), 500


@subscriptions_bp.post('/api/subscriptions/<int:sid>/inbounds')
@require_api_key_or_login
def api_subscription_add_inbounds(sid):
    sub = db.session.get(Subscription, sid) or abort(404)
    data = request.get_json(silent=True) or {}
    targets = data.get('targets') or []
    compensation = PeerCreateCompensation()
    try:
        base = db.session.query(func.max(SubscriptionPeer.sort_order)).filter_by(subscription_id=sub.id).scalar() or 0
        for off, target in enumerate(targets):
            _attach_subscription_target(
                sub, target or {}, data,
                idx=base + off + 1,
                total=len(getattr(sub, 'links', []) or []) + len(targets),
                compensation=compensation,
            )
        _sync_all_subscription_peers(sub, rename=True)
        db.session.commit()
        return jsonify(ok=True, subscription=_subscription_row(sub))
    except AddressAllocationError as e:
        cleanup_failures = compensation.rollback()
        db.session.rollback()
        if cleanup_failures:
            return jsonify(
                error='subscription_add_inbound_cleanup_failed',
                detail=str(e),
                address_error=e.error_code,
                cleanup_complete=False,
                cleanup_failures=cleanup_failures,
            ), 502
        return address_error_response(e)
    except NodePeerInstallError as e:
        cleanup_failures = compensation.rollback()
        db.session.rollback()
        return jsonify(
            error=e.code,
            detail=e.detail,
            cleanup_complete=not cleanup_failures,
            cleanup_failures=cleanup_failures,
        ), 502 if cleanup_failures else e.status
    except Exception as e:
        cleanup_failures = compensation.rollback()
        db.session.rollback()
        current_app.logger.exception('subscription add inbound failed')
        return jsonify(
            error='subscription_add_inbound_failed',
            detail=str(e),
            cleanup_complete=not cleanup_failures,
            cleanup_failures=cleanup_failures,
        ), 502 if cleanup_failures else 500


@subscriptions_bp.patch('/api/subscriptions/<int:sid>/inbounds/<int:link_id>')
@require_api_key_or_login
def api_subscription_patch_inbound(sid, link_id):
    link = SubscriptionPeer.query.filter_by(id=link_id, subscription_id=sid).first() or abort(404)
    data = request.get_json(silent=True) or {}
    link.location_label = (data.get('location_label') or '').strip()
    db.session.commit()
    return jsonify(ok=True, subscription=_subscription_row(link.subscription))


@subscriptions_bp.delete('/api/subscriptions/<int:sid>/inbounds/<int:link_id>')
@require_api_key_or_login
def api_subscription_remove_inbound(sid, link_id):
    link = SubscriptionPeer.query.filter_by(id=link_id, subscription_id=sid).first() or abort(404)
    sub = link.subscription
    delete_peer = _sub_bool(request.args.get('delete_peer'))
    peer = link.peer

    if delete_peer and peer:
        if not bool(getattr(link, 'owned', False)):
            return jsonify(
                ok=False,
                error='peer_not_owned',
                detail=(
                    f'Peer {peer.name} was attached to this subscription, not created '
                    f'by it. Detach it here and delete it from the peers page instead.'
                ),
            ), 409

        try:
            remove_peer_everywhere(peer)
        except PeerRemovalError as e:
            current_app.logger.error(
                'subscription inbound peer delete failed at %s stage: %s', e.phase, e
            )
            return peer_removal_response(e, peer_id=peer.id)
    else:
        db.session.delete(link)
        db.session.flush()

    _sync_all_subscription_peers(sub, rename=True)
    db.session.commit()
    return jsonify(ok=True, subscription=_subscription_row(sub))


@subscriptions_bp.delete('/api/subscriptions/<int:sid>')
@require_api_key_or_login
def api_subscription_delete(sid):
    sub = db.session.get(Subscription, sid) or abort(404)
    delete_peers = request.args.get('delete_peers')
    delete_peers = True if delete_peers is None else _sub_bool(delete_peers)

    owned, attached = [], []
    for link in list(sub.links or []):
        if not link.peer:
            continue
        if delete_peers and bool(getattr(link, 'owned', False)):
            owned.append(link.peer)
        else:
            attached.append(link.peer)

    deleted, failures = 0, []
    for peer in owned:
        peer_id = peer.id
        peer_name = peer.name
        try:
            remove_peer_everywhere(peer)
            deleted += 1
        except PeerRemovalError as e:
            current_app.logger.error(
                'subscription %s: peer %s could not be removed at the %s stage: %s',
                sid, peer_id, e.phase, e,
            )
            failures.append({'peer_id': peer_id, 'name': peer_name, 'phase': e.phase, 'detail': str(e)})

    if failures:
        db.session.rollback()
        return jsonify(
            ok=False,
            error='subscription_delete_incomplete',
            deleted=deleted,
            detached=0,
            failed=len(failures),
            failures=failures,
        ), 502

    try:
        db.session.delete(sub)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception('subscription delete failed')
        return jsonify(error='subscription_delete_failed', detail=str(e)), 500

    return jsonify(
        ok=True,
        deleted_peers=bool(delete_peers),
        deleted=deleted,
        detached=len(attached),
        failed=0,
    )


@subscriptions_bp.post('/api/subscriptions/<int:sid>/disable')
@require_api_key_or_login
def api_subscription_disable(sid):
    sub = db.session.get(Subscription, sid) or abort(404)
    try:
        result = _subscription_enabled(sub, False)
        if result['total'] > 0 and result['changed'] == 0:
            db.session.rollback()
            return jsonify(
                ok=False,
                error='subscription_disable_failed',
                detail='None of the attached configs could be disabled.',
                result=result,
            ), 409

        sub.enabled = False
        db.session.commit()

        partial = result['failed'] > 0
        if partial:
            message = 'Subscription was disabled, but one or more attached configs could not be stopped.'
        elif result['changed']:
            message = 'Subscription and all attached configs were disabled.'
        else:
            message = 'Subscription was disabled. It has no attached configs.'

        try:
            logpanel_action(
                'subscription_disable',
                (
                    f'sid={sub.id}; '
                    f'total={result["total"]}; '
                    f'disabled={result["changed"]}; '
                    f'failed={result["failed"]}; '
                    'data_preserved=1; timer_preserved=1'
                ),
            )
        except Exception:
            pass

        return jsonify(
            ok=not partial,
            partial=partial,
            enabled=False,
            data_reset=False,
            timer_reset=False,
            message=message,
            result=result,
            subscription=_subscription_row(sub),
        ), 207 if partial else 200
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception('Subscription disable failed: %s', sid)
        return jsonify(ok=False, error='subscription_disable_failed', detail=str(exc)), 500


@subscriptions_bp.post('/api/subscriptions/<int:sid>/enable')
@require_api_key_or_login
def api_subscription_enable(sid):
    sub = db.session.get(Subscription, sid) or abort(404)
    try:
        runtime_result = _subscription_enabled(sub, True)
        if runtime_result['total'] > 0 and runtime_result['changed'] == 0:
            db.session.rollback()
            return jsonify(
                ok=False,
                error='subscription_enable_failed',
                detail='None of the attached configs could be enabled.',
                result={'runtime': runtime_result},
            ), 409

        data_result = _reset_subscription_data(sub)
        timer_result = _reset_subscription_timer(sub)
        sub.enabled = True
        db.session.commit()

        failure_count = (
            int(runtime_result.get('failed', 0) or 0)
            + int(data_result.get('enable_failed', 0) or 0)
            + int(timer_result.get('enable_failed', 0) or 0)
            + len(data_result.get('errors', []) or [])
            + len(timer_result.get('errors', []) or [])
        )
        partial = failure_count > 0

        if partial:
            message = (
                'Subscription was enabled and its timer and data were reset, '
                'but one or more attached configs reported an error.'
            )
        elif runtime_result['changed']:
            message = 'Subscription and all attached configs were enabled. Data usage and timer were reset.'
        else:
            message = 'Subscription was enabled. Data usage and timer were reset.'

        try:
            logpanel_action(
                'subscription_enable',
                (
                    f'sid={sub.id}; '
                    f'total={runtime_result["total"]}; '
                    f'enabled={runtime_result["changed"]}; '
                    f'failed={failure_count}; '
                    'data_reset=1; timer_reset=1'
                ),
            )
        except Exception:
            pass

        return jsonify(
            ok=not partial,
            partial=partial,
            enabled=True,
            data_reset=True,
            timer_reset=True,
            message=message,
            result={
                'runtime': runtime_result,
                'data': data_result,
                'timer': timer_result,
            },
            subscription=_subscription_row(sub),
        ), 207 if partial else 200
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception('Subscription enable failed: %s', sid)
        return jsonify(ok=False, error='subscription_enable_failed', detail=str(exc)), 500


@subscriptions_bp.post('/api/subscriptions/<int:sid>/reset_data')
@require_api_key_or_login
def api_subscription_reset_data(sid):
    sub = db.session.get(Subscription, sid) or abort(404)
    try:
        result = _reset_subscription_data(sub)
        db.session.commit()
        timer_expired = _subscription_time_expired(sub)

        if result['errors']:
            message = 'Data was reset for some configs, but one or more node counters could not be read.'
        elif timer_expired and result['still_blocked']:
            message = 'Data was reset, but the subscription remains blocked because its timer is expired. Reset the timer as well.'
        elif result['enable_failed']:
            message = 'Data was reset, but one or more configs could not be re-enabled.'
        elif result['reactivated']:
            message = 'Data was reset and blocked configs were re-enabled.'
        else:
            message = 'Subscription data was reset.'

        return jsonify(
            ok=not bool(result['errors']),
            partial=bool(result['errors']),
            message=message,
            reason=(
                'timer_expired'
                if timer_expired and result['still_blocked']
                else ('enable_failed' if result['enable_failed'] else None)
            ),
            result=result,
            subscription=_subscription_row(sub),
        ), 207 if result['errors'] else 200
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception('Subscription reset data failed')
        return jsonify(error='subscription_reset_data_failed', detail=str(exc)), 500


@subscriptions_bp.post('/api/subscriptions/<int:sid>/reset_timer')
@require_api_key_or_login
def api_subscription_reset_timer(sid):
    sub = db.session.get(Subscription, sid) or abort(404)
    try:
        result = _reset_subscription_timer(sub)
        db.session.commit()
        data_exhausted = _subscription_data_exhausted(sub)

        if data_exhausted and result['still_blocked']:
            message = 'Timer was reset, but the subscription remains blocked because its data allowance is exhausted. Reset data as well.'
        elif result['enable_failed']:
            message = 'Timer was reset, but one or more configs could not be re-enabled.'
        elif result['reactivated']:
            message = 'Timer was reset and blocked configs were re-enabled.'
        else:
            message = 'Subscription timer was reset.'

        return jsonify(
            ok=not bool(result['errors']),
            partial=bool(result['errors']),
            message=message,
            reason=(
                'data_exhausted'
                if data_exhausted and result['still_blocked']
                else ('enable_failed' if result['enable_failed'] else None)
            ),
            result=result,
            subscription=_subscription_row(sub),
        ), 207 if result['errors'] else 200
    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception('Subscription reset timer failed')
        return jsonify(error='subscription_reset_timer_failed', detail=str(exc)), 500


@subscriptions_bp.get('/api/subscriptions/<int:sid>/shortlink')
@require_api_key_or_login
def api_subscription_shortlink(sid):
    sub = db.session.get(Subscription, sid) or abort(404)
    return jsonify(url=_sub_public_url(sub), config_url=_sub_config_url(sub), token=sub.token)


@subscriptions_bp.get('/s/<token>')
def subscription_public_page(token):
    sub = Subscription.query.filter_by(token=token).first() or abort(404)
    cfg = _subscription_settings_public(sub)
    socials = cfg.get('socials') or {}
    portal_title = cfg.get('portal_title') or sub.name

    return render_template(
        'subscription_public.html',
        sub=sub,
        data=_subscription_public_payload(sub),
        portal_settings=cfg,
        sub_layout=cfg.get('layout', 'aurora'),
        sub_display_mode=cfg.get('display_mode', 'hybrid'),
        sub_animation=cfg.get('animation', 'balanced'),
        sub_background=cfg.get('background', 'aurora'),
        portal_label=cfg.get('portal_label', 'Secure WireGuard portal'),
        portal_icon=cfg.get('portal_icon', 'fas fa-bolt'),
        portal_title=portal_title,
        portal_subtitle=cfg.get(
            'portal_subtitle',
            'Your account is ready. Install WireGuard, then scan QR or import a config.',
        ),
        support_portal_label=cfg.get('portal_label', 'Secure WireGuard portal'),
        support_portal_icon=cfg.get('portal_icon', 'fas fa-bolt'),
        support_portal_title=portal_title,
        support_portal_subtitle=cfg.get(
            'portal_subtitle',
            'Your account is ready. Install WireGuard, then scan QR or import a config.',
        ),
        support_telegram=socials.get('telegram', ''),
        support_whatsapp=socials.get('whatsapp', ''),
        support_instagram=socials.get('instagram', ''),
        support_phone=socials.get('phone', ''),
        support_website=socials.get('website', ''),
        support_email=socials.get('email', ''),
    )


@subscriptions_bp.get('/s/<token>/api', endpoint='subscription_public_api')
def subscription_public_api(token):
    sub = Subscription.query.filter_by(token=token).first() or abort(404)
    return jsonify(subscription=_subscription_public_payload(sub))


@subscriptions_bp.get('/s/<token>/config', endpoint='subscription_public_config')
def subscription_public_config(token):
    sub = Subscription.query.filter_by(token=token).first() or abort(404)
    revoked = _subscription_access_or_403(sub)
    if revoked:
        return revoked

    mem = BytesIO()
    used_names = set()
    skipped_incomplete = 0

    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        for index, link in enumerate(
            sorted(sub.links, key=lambda x: (x.sort_order or 0, x.id or 0)),
            start=1,
        ):
            peer = getattr(link, 'peer', None)
            if not peer:
                continue

            safe_peer = re.sub(r'[^A-Za-z0-9_.-]+', '_', peer.name or f'peer-{peer.id}').strip('._')
            base = safe_peer or f'peer-{peer.id}'
            safe_location = re.sub(
                r'[^A-Za-z0-9_.-]+',
                '_',
                getattr(link, 'location_label', '') or '',
            ).strip('._')

            if safe_location:
                candidate = f'{base}-{safe_location}'
            else:
                candidate = base

            entry = f'{candidate}.conf'
            normalized = entry.lower()

            if normalized in used_names:
                entry = f'{candidate}-{index}.conf'
                normalized = entry.lower()

            if normalized in used_names:
                entry = f'{base}-peer{peer.id}.conf'
                normalized = entry.lower()

            suffix = 2
            while normalized in used_names:
                entry = f'{base}-peer{peer.id}-{suffix}.conf'
                normalized = entry.lower()
                suffix += 1

            try:
                cfg = _client_config_txt(peer)
            except ClientConfigIncomplete as exc:
                skipped_incomplete += 1
                current_app.logger.error(
                    'Skipping subscription config for peer id=%s iface=%s: %s',
                    getattr(peer, 'id', '?'),
                    getattr(getattr(peer, 'iface', None), 'name', '?'),
                    exc.reason,
                )
                continue

            used_names.add(normalized)
            z.writestr(entry, cfg)

    mem.seek(0)
    if not used_names and skipped_incomplete:
        return jsonify(
            ok=False,
            error='server_public_key_unavailable',
            message='No client configs could be built because a server PublicKey is missing.',
        ), 502

    fname = re.sub(r'[^A-Za-z0-9_.-]+', '_', sub.name or 'subscription').strip('._') or 'subscription'
    return send_file(
        mem,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'{fname}.zip',
    )


@subscriptions_bp.get('/s/<token>/inbound/<int:link_id>/config')
def subscription_public_inbound_config(token, link_id):
    sub = Subscription.query.filter_by(token=token).first() or abort(404)
    revoked = _subscription_access_or_403(sub)
    if revoked:
        return revoked

    link = SubscriptionPeer.query.filter_by(id=link_id, subscription_id=sub.id).first() or abort(404)
    peer = link.peer or abort(404)

    cfg, err = _peer_client_conf_or_502(peer)
    if err:
        return err

    safe_name = re.sub(r'[^A-Za-z0-9_.-]+', '_', peer.name or f'peer-{peer.id}').strip('._') or f'peer-{peer.id}'
    mem = BytesIO(cfg.encode('utf-8'))
    response = send_file(
        mem,
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=f'{safe_name}.conf',
        max_age=0,
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'private, no-store, no-cache, must-revalidate, max-age=0'
    return response


@subscriptions_bp.get('/s/<token>/inbound/<int:link_id>/qr')
def subscription_public_inbound_qr(token, link_id):
    sub = Subscription.query.filter_by(token=token).first() or abort(404)
    revoked = _subscription_access_or_403(sub)
    if revoked:
        return revoked

    link = SubscriptionPeer.query.filter_by(id=link_id, subscription_id=sub.id).first() or abort(404)
    peer = link.peer or abort(404)
    cfg, err = _peer_client_conf_or_502(peer)
    if err:
        return err

    img = qrcode.make(cfg)
    bio = BytesIO()
    img.save(bio, format='PNG')
    bio.seek(0)
    return send_file(bio, mimetype='image/png')


@subscriptions_bp.get('/s/<token>/inbound/<int:link_id>/geo')
def subscription_public_inbound_geo(token, link_id):
    sub = Subscription.query.filter_by(token=token).first() or abort(404)
    revoked = _subscription_access_or_403(sub)
    if revoked:
        return revoked

    link = SubscriptionPeer.query.filter_by(id=link_id, subscription_id=sub.id).first() or abort(404)
    peer = link.peer or abort(404)

    host = _public_host_peer(peer)
    geo = _lookup_geo(host)

    cc = (geo.get('country_code') or '').strip().upper()
    flag = geo.get('flag') or _flag_from_cc(cc)
    country = geo.get('country') or cc or ''

    changed = False
    if cc and (link.country_code or '').strip().upper() != cc:
        link.country_code = cc
        changed = True

    if flag and flag != '🌐' and (link.flag or '').strip() != flag:
        link.flag = flag
        changed = True

    if country and (link.location_label or '').strip() != country:
        link.location_label = country
        changed = True

    if changed:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    return jsonify(
        country=country,
        country_code=cc,
        flag=flag,
        public_host=host,
    )
