"""
OxWg Panel - Subscription Service
=================================
Evaluation of subscription status, quota enforcement, inbound topology links, and public payload generation.
"""
import re
import json
import logging
from typing import Any

from models import db, Subscription, Peer
from core.time_utils import now_ts, from_ts, isoz
from core.paths import GEO_CACHE_FILE
from services.panel_settings import _panel_timezone_name
from services.peer_lifecycle import _effective_expiry_ts

logger = logging.getLogger(__name__)


def _flag_from_cc(cc: str) -> str:
    """Convert ISO-3166 2-letter country code into unicode regional indicator flag emoji."""
    cc = (cc or '').strip().upper()
    if not re.match(r'^[A-Z]{2}$', cc):
        return '🌐'
    return ''.join(chr(127397 + ord(ch)) for ch in cc)


def _load_geo_cache() -> dict[str, Any]:
    """Load cached IP geolocation lookups."""
    try:
        with open(GEO_CACHE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_geo_cache(data: dict[str, Any]) -> None:
    """Save IP geolocation lookups to cache."""
    try:
        from core.file_utils import _json_save
        _json_save(GEO_CACHE_FILE, data)
    except Exception:
        pass


def subscription_access(sub: Subscription | Any, used_bytes: int | None = None) -> dict[str, Any]:
    """
    Evaluate whether a subscription may access and fetch active configurations.
    Returns: {'allowed': bool, 'reason': str, 'message': str}
    """
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

    limit = None
    if hasattr(sub, 'limit_bytes'):
        limit = sub.limit_bytes() if callable(sub.limit_bytes) else sub.limit_bytes

    if limit:
        used = int(used_bytes if used_bytes is not None else getattr(sub, 'used_bytes_total', 0) or 0)
        if used >= int(limit):
            return {
                'allowed': False,
                'reason': 'data_exhausted',
                'message': 'This subscription has used all of its data allowance.',
            }

    return {'allowed': True, 'reason': '', 'message': ''}


def _subscription_inbound_state(sub: Subscription | Any) -> dict[str, Any]:
    """Inspect whether a subscription has active inbound peer links."""
    links = getattr(sub, 'links', None) or []
    usable = sum(
        1 for link in links
        if getattr(link, 'peer', None) is not None
        and str(getattr(getattr(link, 'peer', None), 'status', '') or '').lower() != 'removed'
    )
    return {'inbound_count': usable, 'has_inbounds': usable > 0}


def _subscription_access_or_403(sub: Subscription | Any) -> tuple[dict[str, Any], int] | None:
    """Return JSON error response and 403 status code if subscription access is revoked, else None."""
    access = subscription_access(sub)
    if access['allowed']:
        return None

    return (
        {
            'ok': False,
            'error': 'subscription_access_revoked',
            'reason': access['reason'],
            'message': access['message'],
        },
        403,
    )


def _subscription_public_payload(sub: Subscription | Any) -> dict[str, Any]:
    """Construct structured dictionary for the public subscription landing page."""
    links = sorted(list(getattr(sub, 'links', []) or []), key=lambda x: (getattr(x, 'sort_order', 0) or 0, getattr(x, 'id', 0) or 0))
    limit_bytes = sub.limit_bytes() if hasattr(sub, 'limit_bytes') and callable(sub.limit_bytes) else getattr(sub, 'limit_bytes', None)

    used_bytes = 0
    locs = []

    for link in links:
        peer = getattr(link, 'peer', None)
        if not peer:
            continue
        used_bytes += int(getattr(peer, 'used_bytes_total', 0) or 0)

    access = subscription_access(sub, used_bytes=used_bytes)
    access.update(_subscription_inbound_state(sub))
    may_disclose = bool(access['allowed'])

    for link in links:
        peer = getattr(link, 'peer', None)
        if not peer:
            continue

        cc = (getattr(link, 'country_code', '') or '').strip().upper()
        flag = getattr(link, 'flag', '') or _flag_from_cc(cc)
        label = (getattr(link, 'location_label', '') or getattr(peer, 'name', '')).strip()

        locs.append({
            'link_id': getattr(link, 'id', None),
            'peer_id': peer.id,
            'name': peer.name,
            'status': peer.status,
            'endpoint': (getattr(peer, 'endpoint', '') or '') if may_disclose else '',
            'location_label': label,
            'country_code': cc,
            'flag': flag,
        })

    exp_ts = _effective_expiry_ts(sub)
    ttl_seconds = max(0, exp_ts - now_ts()) if exp_ts else None

    if limit_bytes is not None:
        used_bytes = min(int(used_bytes), int(limit_bytes))

    return {
        'id': sub.id,
        'name': sub.name,
        'token': getattr(sub, 'token', ''),
        'display_timezone': _panel_timezone_name(),
        'enabled': bool(getattr(sub, 'enabled', True)),
        'unlimited': bool(getattr(sub, 'unlimited', False)),
        'limit_bytes': limit_bytes,
        'used_bytes': int(used_bytes),
        'data_limit_value': getattr(sub, 'data_limit_value', 0) or 0,
        'data_limit_unit': getattr(sub, 'data_limit_unit', 'Gi') or 'Gi',
        'start_on_first_use': bool(getattr(sub, 'start_on_first_use', False)),
        'first_used_at': isoz(getattr(sub, 'first_used_at', None)),
        'expires_at': isoz(from_ts(exp_ts)),
        'expires_at_ts': exp_ts,
        'ttl_seconds': ttl_seconds,
        'access': access,
        'locations': locs,
    }
