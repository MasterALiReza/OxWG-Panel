"""
OxWg Panel - Profiles Blueprint (profiles_bp)
============================================
Peer profiles and subscription studio profiles management.
"""
from flask import Blueprint, request, jsonify
from flask_login import login_required

from services.peer_profiles import (
    _load_profiles,
    _get_profile,
    _set_profile,
    _set_active_profile,
    _delete_profile,
)
from services.subscription_profiles import (
    _load_subscription_profiles,
    _get_subscription_profile,
    _set_subscription_profile,
    _delete_subscription_profile,
    _set_active_subscription_profile,
    _subscription_profile_rows,
)

profiles_bp = Blueprint('profiles_bp', __name__)


# ---------------------- Peer Profiles ----------------------

@profiles_bp.route('/api/peer_profile', methods=['GET'])
@login_required
def get_apipeer_profile():
    name = request.args.get('name')
    prof = _get_profile(name)
    return jsonify(prof)


@profiles_bp.route('/api/peer_profile', methods=['POST'])
@login_required
def save_apipeer_profile():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or 'Default').strip()
    profile_data = data.get('profile') or data
    res = _set_profile(name, profile_data)
    return jsonify(ok=True, profile=res)


@profiles_bp.route('/api/peer_profile', methods=['DELETE'])
@login_required
def delete_apipeer_profile():
    name = (request.args.get('name') or (request.get_json(silent=True) or {}).get('name') or '').strip()
    if not name:
        return jsonify(error="name required"), 400
    ok = _delete_profile(name)
    return jsonify(ok=ok)


@profiles_bp.route('/api/peer_profile/activate', methods=['POST'])
@login_required
def activate_apipeer_profile():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    ok = _set_active_profile(name)
    return jsonify(ok=ok)


@profiles_bp.route('/api/peer_profile/rename', methods=['POST'])
@login_required
def rename_apipeer_profile():
    data = request.get_json(silent=True) or {}
    old_name = (data.get('old_name') or '').strip()
    new_name = (data.get('new_name') or '').strip()
    if not old_name or not new_name:
        return jsonify(error="old_name and new_name required"), 400
    prof = _get_profile(old_name)
    _set_profile(new_name, prof)
    _delete_profile(old_name)
    return jsonify(ok=True)


@profiles_bp.get('/api/peer_profiles')
@login_required
def list_apipeer_profiles():
    data = _load_profiles()
    active = data.get('active', 'Default')
    profiles = data.get('profiles', {})
    return jsonify(active=active, profiles=profiles)


# ------------------- Subscription Profiles -------------------

@profiles_bp.get('/api/subscription_profiles')
@login_required
def subscription_profiles_list():
    rows = _subscription_profile_rows()
    data = _load_subscription_profiles()
    return jsonify(ok=True, active=data.get('active', 'Default'), profiles=rows)


@profiles_bp.post('/api/subscription_profiles')
@login_required
def subscription_profile_save():
    payload = request.get_json(silent=True) or {}
    name = (payload.get('name') or '').strip()
    data = payload.get('data') or payload
    if not name:
        return jsonify(error="name required"), 400
    saved = _set_subscription_profile(name, data)
    return jsonify(ok=True, profile=saved)


@profiles_bp.get('/api/subscription_profiles/<path:profile_name>')
@login_required
def subscription_profile_get(profile_name):
    prof = _get_subscription_profile(profile_name)
    if not prof:
        return jsonify(error="Profile not found"), 404
    return jsonify(ok=True, profile=prof)


@profiles_bp.delete('/api/subscription_profiles/<path:profile_name>')
@login_required
def subscription_profile_delete(profile_name):
    ok = _delete_subscription_profile(profile_name)
    return jsonify(ok=ok)


@profiles_bp.post('/api/subscription_profiles/<path:profile_name>/activate')
@login_required
def subscription_profile_activate(profile_name):
    ok = _set_active_subscription_profile(profile_name)
    return jsonify(ok=ok)


@profiles_bp.post('/api/subscription_profiles/<path:profile_name>/rename')
@login_required
def subscription_profile_rename(profile_name):
    payload = request.get_json(silent=True) or {}
    new_name = (payload.get('new_name') or '').strip()
    if not new_name:
        return jsonify(error="new_name required"), 400
    prof = _get_subscription_profile(profile_name)
    if not prof:
        return jsonify(error="Profile not found"), 404
    _set_subscription_profile(new_name, prof)
    _delete_subscription_profile(profile_name)
    return jsonify(ok=True)
