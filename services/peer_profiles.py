"""
OxWg Panel - Peer Profiles Management
=====================================
Configuration profiles for client WireGuard peers (DNS, AllowedIPs, Keepalive, MTU, etc.).
"""
import os
import json
from pathlib import Path
from typing import Any
from core.paths import PEER_PROFILES_FILE, PEER_PROFILE_FILE
from core.file_utils import _json_load, _json_save

_DEF_PROFILE: dict[str, Any] = {
    'dns': '1.1.1.1, 1.0.0.1',
    'allowed_ips': '0.0.0.0/0, ::/0',
    'persistent_keepalive': None,
    'mtu': None,
    'endpoint': '',
    'peer_endpoint': '',
    'data_limit_value': 0,
    'data_limit_unit': 'Gi',
    'start_on_first_use': False,
    'unlimited': False,
    'time_limit_days': 0,
    'time_limit_hours': 0,
    'time_limit_minutes': 0,
}


def _migrate_single_profile() -> None:
    """Migrate legacy single peer_profile.json to multi-profile peer_profiles.json."""
    if not os.path.exists(PEER_PROFILES_FILE) and os.path.exists(PEER_PROFILE_FILE):
        try:
            with open(PEER_PROFILE_FILE, 'r', encoding='utf-8') as f:
                single = json.load(f)
        except Exception:
            single = {}
        base = dict(_DEF_PROFILE)
        base.update({k: single.get(k, base[k]) for k in base.keys()})
        data = {"active": "Default", "profiles": {"Default": base}}
        _json_save(PEER_PROFILES_FILE, data)


def _load_profiles() -> dict[str, Any]:
    """Load peer profiles store from disk, guaranteeing 'Default' profile presence."""
    Path(PEER_PROFILES_FILE).parent.mkdir(parents=True, exist_ok=True)
    _migrate_single_profile()
    d = _json_load(PEER_PROFILES_FILE, {})
    if not isinstance(d, dict):
        d = {}
    if 'profiles' not in d or not isinstance(d['profiles'], dict):
        d['profiles'] = {}
    d.setdefault('active', 'Default')
    if 'Default' not in d['profiles']:
        d['profiles']['Default'] = dict(_DEF_PROFILE)
    return d


def _save_profiles(d: dict[str, Any]) -> None:
    """Save peer profiles store atomically to disk."""
    Path(PEER_PROFILES_FILE).parent.mkdir(parents=True, exist_ok=True)
    _json_save(PEER_PROFILES_FILE, d)


def _get_profile(name: str | None) -> dict[str, Any]:
    """Retrieve full peer profile dictionary by name, falling back to active profile."""
    d = _load_profiles()
    name = (name or d.get('active') or 'Default')
    prof = dict(_DEF_PROFILE)
    prof.update(d['profiles'].get(name, {}))
    return prof


def _set_profile(name: str, data: dict[str, Any]) -> None:
    """Update or create a named peer profile."""
    d = _load_profiles()
    base = dict(_DEF_PROFILE)
    for k in base.keys():
        if k in data:
            base[k] = data[k]
    d['profiles'][name] = base
    _save_profiles(d)


def _set_active_profile(name: str) -> bool:
    """Set the currently active peer profile name."""
    d = _load_profiles()
    if name in d['profiles']:
        d['active'] = name
        _save_profiles(d)
        return True
    return False


def _delete_profile(name: str) -> bool:
    """Delete a named peer profile (cannot delete 'Default')."""
    clean_name = str(name or '').strip()
    if not clean_name or clean_name == 'Default':
        return False
    d = _load_profiles()
    if clean_name not in d.get('profiles', {}):
        return False
    if d.get('active') == clean_name:
        d['active'] = 'Default'
    d['profiles'].pop(clean_name, None)
    _save_profiles(d)
    return True


def _panel_default_dns() -> str:
    """Return default DNS configured in the active peer profile."""
    return (_get_profile(None).get('dns') or '1.1.1.1, 1.0.0.1').strip()
