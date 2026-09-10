"""
OxWg Panel - Subscription Profiles Management
==============================================
Management of reusable subscription profile presets for client portal configurations.
"""
from pathlib import Path
from typing import Any
from core.paths import SUBSCRIPTION_PROFILES_FILE
from core.file_utils import _json_load, _json_save


def _sanitize_subscription_profile(profile: Any) -> dict[str, Any]:
    """Sanitize and structure raw subscription profile dictionary."""
    if not isinstance(profile, dict):
        profile = {}

    include = profile.get('include')
    if not isinstance(include, dict):
        include = {}

    cleaned: dict[str, Any] = {
        'include': {
            'client': bool(include.get('client')),
            'advanced': bool(include.get('advanced')),
            'interfaces': bool(include.get('interfaces')),
            'template': bool(include.get('template')),
        }
    }

    for section_name in ('client', 'advanced', 'template'):
        section = profile.get(section_name)
        if isinstance(section, dict):
            cleaned[section_name] = section

    interfaces = profile.get('interfaces')
    if isinstance(interfaces, list):
        cleaned['interfaces'] = [
            item for item in interfaces[:200]
            if isinstance(item, dict)
        ]

    return cleaned


def _load_subscription_profiles() -> dict[str, Any]:
    """Load and normalize subscription profiles from disk."""
    Path(SUBSCRIPTION_PROFILES_FILE).parent.mkdir(parents=True, exist_ok=True)
    data = _json_load(SUBSCRIPTION_PROFILES_FILE, {})
    if not isinstance(data, dict):
        data = {}

    profiles = data.get('profiles')
    if not isinstance(profiles, dict):
        profiles = {}

    cleaned_profiles: dict[str, Any] = {}
    for profile_name, profile_data in profiles.items():
        clean_name = str(profile_name or '').strip()
        if not clean_name:
            continue
        cleaned_profiles[clean_name] = (
            profile_data if isinstance(profile_data, dict) else {}
        )

    active_name = str(data.get('active') or '').strip()
    if active_name and active_name not in cleaned_profiles:
        active_name = ''

    if not active_name and cleaned_profiles:
        active_name = next(iter(sorted(cleaned_profiles.keys(), key=str.lower)))

    return {
        'active': active_name,
        'profiles': cleaned_profiles,
    }


def _save_subscription_profiles(data: dict[str, Any]) -> None:
    """Atomically persist subscription profiles to disk."""
    Path(SUBSCRIPTION_PROFILES_FILE).parent.mkdir(parents=True, exist_ok=True)
    profiles = data.get('profiles') if isinstance(data, dict) else {}
    if not isinstance(profiles, dict):
        profiles = {}

    active_name = str((data.get('active') if isinstance(data, dict) else '') or '').strip()

    payload = {
        'active': active_name,
        'profiles': profiles,
    }
    _json_save(SUBSCRIPTION_PROFILES_FILE, payload)


def _subscription_profile_rows(data: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Generate dropdown/list metadata rows for subscription profiles."""
    store = data or _load_subscription_profiles()
    active_name = str(store.get('active') or '').strip()
    profiles = store.get('profiles') or {}

    return [
        {
            'name': profile_name,
            'default': (profile_name == active_name),
            'active': (profile_name == active_name),
        }
        for profile_name in sorted(profiles.keys(), key=str.lower)
    ]


def _get_subscription_profile(name: str) -> dict[str, Any] | None:
    """Get a single subscription profile by name."""
    store = _load_subscription_profiles()
    clean_name = str(name or '').strip()
    return (store.get('profiles') or {}).get(clean_name)


def _set_subscription_profile(name: str, profile_data: dict[str, Any], activate: bool = False) -> dict[str, Any]:
    """Create or update a subscription profile by name."""
    clean_name = str(name or '').strip()
    cleaned = _sanitize_subscription_profile(profile_data)
    store = _load_subscription_profiles()
    store['profiles'][clean_name] = cleaned
    if activate or not store.get('active'):
        store['active'] = clean_name
    _save_subscription_profiles(store)
    return cleaned


def _delete_subscription_profile(name: str) -> bool:
    """Delete a subscription profile by name."""
    clean_name = str(name or '').strip()
    store = _load_subscription_profiles()
    profiles = store.get('profiles') or {}
    if clean_name not in profiles:
        return False

    del profiles[clean_name]
    if store.get('active') == clean_name:
        remaining = sorted(profiles.keys(), key=str.lower)
        store['active'] = remaining[0] if remaining else ''
    _save_subscription_profiles(store)
    return True


def _set_active_subscription_profile(name: str) -> bool:
    """Set active subscription profile."""
    clean_name = str(name or '').strip()
    store = _load_subscription_profiles()
    if clean_name in (store.get('profiles') or {}):
        store['active'] = clean_name
        _save_subscription_profiles(store)
        return True
    return False
