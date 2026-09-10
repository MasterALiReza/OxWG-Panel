"""
OxWg Panel - Miscellaneous Blueprint (misc_bp)
=============================================
Landing dashboard index, API documentation, and WireGuard endpoint presets.
"""
import os
import json
from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    current_app,
)
from flask_login import login_required
from auth import require_api_key_or_login
from core.ip_utils import _public_ipv4

misc_bp = Blueprint('misc_bp', __name__)


def _presets_file():
    return os.path.join(current_app.instance_path, 'endpoint_presets.json')


def _load_presets():
    try:
        with open(_presets_file(), 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []


def _save_presets(presets):
    try:
        os.makedirs(current_app.instance_path, exist_ok=True)
        with open(_presets_file(), 'w', encoding='utf-8') as f:
            json.dump(presets, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        current_app.logger.warning("Couldn't save endpoint presets: %s", e)


@misc_bp.route('/')
@login_required
def index():
    return render_template('index.html')


@misc_bp.get('/api-docs')
@login_required
def api_docs_page():
    return render_template('api_docs.html')


@misc_bp.route('/api/endpoint_presets', methods=['GET', 'POST', 'DELETE'])
@require_api_key_or_login
def endpoint_presets():
    if request.method == 'GET':
        return jsonify(presets=_load_presets(), public_ipv4=_public_ipv4())

    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        host = (data.get('host') or '').strip()
        port = int(data.get('port') or 0)
        label = (data.get('label') or '').strip() or f"{host}:{port}"
        if not host or port <= 0:
            return jsonify(error='host and port required'), 400
        presets = _load_presets()
        updated = False
        for p in presets:
            if p.get('host') == host and int(p.get('port') or 0) == port:
                p.update({'label': label})
                updated = True
                break
        if not updated:
            presets.append({'label': label, 'host': host, 'port': port})
        _save_presets(presets)
        return jsonify(success=True, presets=presets)

    # DELETE
    data = request.get_json(silent=True) or {}
    host = (data.get('host') or '').strip()
    port = int(data.get('port') or 0)
    presets = [
        p for p in _load_presets()
        if not (p.get('host') == host and int(p.get('port') or 0) == port)
    ]
    _save_presets(presets)
    return jsonify(success=True, presets=presets)
