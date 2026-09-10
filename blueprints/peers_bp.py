"""
OxWg Panel - Peers Blueprint (peers_bp)
=======================================
Comprehensive WireGuard peer lifecycle management:
CRUD operations, bulk peer provisioning, activation/deactivation,
traffic & timer resets, configuration exports (.conf / QR code),
and peer audit event logging.
"""
import os
import re
import math
import qrcode
import logging
import ipaddress
import subprocess
import base64
from io import BytesIO
from datetime import datetime, timezone
from typing import Any

from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    abort,
    flash,
    redirect,
    url_for,
    make_response,
    send_file,
    current_app,
)
from flask_login import login_required

from models import (
    db,
    Peer,
    PeerEvent,
    InterfaceConfig,
    Node,
    SubscriptionPeer,
    ShortLink,
)
from forms import PeerForm
from core.extensions import csrf
from auth import require_api_key, require_api_key_or_login
from core.time_utils import now_ts, from_ts, to_ts, add_days_ts
from core.ip_utils import _public_ipv4, _first_cidr, _safe_ip
from services.wg_parser import iface_devname, _iface_is_node
from services.config_generator import (
    _effective_client_endpoint,
    _peer_client_conf_or_502,
    parse_endpoint_string,
    EndpointValidationError,
)
from services.peer_lifecycle import (
    _expire,
    _wg_transfer,
    _conv_time_limit,
    _effective_expiry_ts,
    _disable_peer,
)
from services.shortlink_service import _shortlink_for_peer
from services.node_client import node_post, node_delete
from blueprints.logs_bp import logpanel_action
from blueprints.interfaces_bp import (
    _iface_up,
    _available_ips,
    interface_ip_interface,
    _reserved_hosts,
    _usable_hosts,
)

peers_bp = Blueprint('peers_bp', __name__)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions & Shared Classes
# ---------------------------------------------------------------------------

class AddressAllocationError(Exception):
    def __init__(self, message, error_code='address_allocation_failed', http_status=409):
        super().__init__(message)
        self.error_code = error_code
        self.http_status = http_status


class AddressInvalid(AddressAllocationError):
    def __init__(self, message):
        super().__init__(message, error_code='address_invalid', http_status=400)


class AddressConflict(AddressAllocationError):
    def __init__(self, message):
        super().__init__(message, error_code='address_conflict', http_status=409)


class AddressPoolExhausted(AddressAllocationError):
    def __init__(self, message):
        super().__init__(message, error_code='address_pool_exhausted', http_status=409)


class PeerRemovalError(Exception):
    def __init__(self, phase, message, status=500):
        super().__init__(message)
        self.phase = phase
        self.status = status


class NodePeerInstallError(Exception):
    def __init__(self, code, status, detail):
        super().__init__(detail)
        self.code = code
        self.status = status
        self.detail = detail


class PeerCreateCompensation:
    def __init__(self):
        self.node_rollbacks = []

    def register_node(self, node, pub):
        self.node_rollbacks.append((node, pub))

    def rollback(self):
        failures = []
        for node, pub in self.node_rollbacks:
            try:
                _rollback_node_created_peer(node, pub)
            except Exception as e:
                failures.append({'node_id': getattr(node, 'id', None), 'pub': pub, 'error': str(e)})
        return failures


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log_event(peer: Peer, event: str, details: str = ''):
    try:
        e = PeerEvent(
            peer_id=peer.id,
            timestamp=from_ts(now_ts()),
            event=event,
            details=details,
        )
        db.session.add(e)
        db.session.commit()
    except Exception:
        db.session.rollback()


def _host_peer(peer: Peer) -> str:
    addr = getattr(peer, 'address', '') or ''
    return addr.split(',')[0].strip() if addr else ''


def _wg_enable(peer: Peer):
    iface = getattr(peer, 'iface', None)
    if not iface:
        return
    dev = iface_devname(iface)
    host_cidr = _host_peer(peer)
    if not dev or not host_cidr:
        return
    try:
        ip = str(ipaddress.ip_interface(host_cidr).ip)
        cmd = ['wg', 'set', dev, 'peer', peer.public_key, 'allowed-ips', f"{ip}/32"]
        if getattr(peer, 'peer_endpoint', None):
            cmd.extend(['endpoint', peer.peer_endpoint])
        if getattr(peer, 'persistent_keepalive', None):
            cmd.extend(['persistent-keepalive', str(peer.persistent_keepalive)])
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass


def _wg_disable(peer: Peer):
    iface = getattr(peer, 'iface', None)
    if not iface:
        return
    dev = iface_devname(iface)
    if not dev:
        return
    try:
        subprocess.run(['wg', 'set', dev, 'peer', peer.public_key, 'remove'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass


def _sync_peer(peer: Peer):
    # Stub for config sync if needed
    pass


def _wg_peer_keys(dev: str) -> set:
    keys = set()
    try:
        out = subprocess.check_output(
            ['wg', 'show', dev, 'allowed-ips'],
            stderr=subprocess.DEVNULL, timeout=2.0
        ).decode()
        for line in out.splitlines():
            key = line.split('\t', 1)[0].strip()
            if key:
                keys.add(key)
    except Exception:
        pass
    return keys


def _peer_is_on_node(peer: Peer) -> bool:
    iface = getattr(peer, 'iface', None)
    return bool(iface and _iface_is_node(iface))


def _rollback_node_created_peer(node, public_key):
    try:
        node_delete(node, f'/api/peer/{public_key}')
    except Exception:
        pass


def _delete_peer_rows(peer: Peer):
    try:
        ShortLink.query.filter_by(peer_id=peer.id).delete(synchronize_session=False)
        SubscriptionPeer.query.filter_by(peer_id=peer.id).delete(synchronize_session=False)
        PeerEvent.query.filter_by(peer_id=peer.id).delete(synchronize_session=False)
        db.session.delete(peer)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        raise PeerRemovalError('database', str(e), 500)


def remove_peer_everywhere(peer: Peer):
    if _peer_is_on_node(peer):
        node = getattr(getattr(peer, 'iface', None), 'node', None)
        if node is not None:
            try:
                node_delete(node, f'/api/peer/{peer.public_key}')
            except Exception as e:
                raise PeerRemovalError('node', str(e), 502)
    else:
        dev = iface_devname(peer.iface) if getattr(peer, 'iface', None) else ''
        if dev and _iface_up(dev):
            try:
                _wg_disable(peer)
            except Exception as e:
                raise PeerRemovalError('runtime', str(e), 502)
    return _delete_peer_rows(peer)


def peer_removal_response(exc: PeerRemovalError, peer_id=None):
    return jsonify(
        ok=False,
        error='peer_removal_failed',
        phase=exc.phase,
        detail=str(exc),
        peer_id=peer_id,
        recoverable=True,
    ), exc.status


def _validate_requested_host(ip_iface, requested):
    if not requested:
        return None
    raw = str(requested).strip()
    if not raw:
        return None
    host_str = raw.split('/')[0].strip()
    try:
        host = ipaddress.ip_address(host_str)
    except ValueError:
        raise AddressInvalid(f'{raw!r} is not a valid IP address.')
    net = ip_iface.network
    if host not in net:
        raise AddressInvalid(f'{host} is outside the interface network {net}.')
    return host


def allocate_peer_address(iface, requested=None, *, exclude_peer_id=None, exclude_address=None, extra_reserved=()):
    ip_iface = interface_ip_interface(iface)
    if ip_iface is None:
        raise AddressInvalid(f'Interface {getattr(iface, "name", "?")} has no usable Address= setting.')
    net = ip_iface.network
    reserved = _reserved_hosts(
        iface, ip_iface,
        exclude_peer_id=exclude_peer_id,
        exclude_address=exclude_address,
        extra=extra_reserved,
    )
    host = _validate_requested_host(ip_iface, requested)
    if host is not None:
        if host in reserved:
            raise AddressConflict(f'{host} is already in use on {getattr(iface, "name", "?")}.')
        return f'{host}/{net.prefixlen}'
    for candidate in _usable_hosts(net):
        if candidate not in reserved:
            return f'{candidate}/{net.prefixlen}'
    raise AddressPoolExhausted(f'No free client address left in {net}.')


def address_error_response(exc: AddressAllocationError):
    return jsonify(error=exc.error_code, detail=str(exc)), exc.http_status


def install_local_peer(peer: Peer):
    _wg_enable(peer)


def _peer_by_public_key_or_404(public_key: str) -> Peer:
    return Peer.query.filter_by(public_key=public_key).first() or abort(404)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@peers_bp.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    form = PeerForm()
    ifaces = InterfaceConfig.query.order_by(InterfaceConfig.name.asc()).all()
    form.iface.choices = [(i.id, i.name) for i in ifaces]
    sel_iface = None

    if request.method == 'POST' and form.iface.data:
        sel_iface = db.session.get(InterfaceConfig, form.iface.data)
    else:
        arg_iface_id = request.args.get('iface_id', type=int)
        arg_iface_nm = (request.args.get('iface') or '').strip()
        if arg_iface_id:
            sel_iface = db.session.get(InterfaceConfig, arg_iface_id)
            if sel_iface:
                form.iface.data = sel_iface.id
        elif arg_iface_nm:
            sel_iface = InterfaceConfig.query.filter_by(name=arg_iface_nm).first()
            if sel_iface:
                form.iface.data = sel_iface.id
        if not sel_iface and form.iface.choices:
            sel_iface = db.session.get(InterfaceConfig, form.iface.choices[0][0])
            if sel_iface:
                form.iface.data = sel_iface.id

    if hasattr(form.address, 'choices'):
        form.address.choices = [(ip, ip) for ip in (_available_ips(sel_iface) if sel_iface else [])]

    if request.method == 'GET':
        if hasattr(form, 'time_limit_hours') and form.time_limit_hours.data is None:
            form.time_limit_hours.data = 0
        if sel_iface:
            if form.mtu.data is None:
                form.mtu.data = sel_iface.mtu
            if form.dns.data is None:
                form.dns.data = sel_iface.dns

    if request.method == 'POST' and not form.validate_on_submit():
        for field_name, errs in form.errors.items():
            field = getattr(form, field_name, None)
            label = field.label.text if field and hasattr(field, 'label') else field_name
            for err in errs:
                flash(f"{label}: {err}", 'error')
        logger.warning("Peer form validation failed: errors=%s form_data=%s", form.errors, request.form.to_dict())

    if form.validate_on_submit():
        iface = sel_iface or (db.session.get(InterfaceConfig, form.iface.data) if form.iface.data else None)
        if not iface:
            flash('Please select an interface.', 'error')
            return render_template('users.html', form=form)

        try:
            priv = subprocess.check_output(['wg', 'genkey'], stderr=subprocess.DEVNULL, timeout=3).strip().decode()
            pub = subprocess.check_output(['wg', 'pubkey'], input=(priv + '\n').encode(), stderr=subprocess.DEVNULL, timeout=3).strip().decode()
        except Exception:
            import base64
            priv = base64.b64encode(os.urandom(32)).decode()
            pub = base64.b64encode(os.urandom(32)).decode()

        try:
            addr = allocate_peer_address(iface, requested=(form.address.data or '').strip() or None)
        except AddressAllocationError as e:
            flash(str(e), 'error')
            return render_template('users.html', form=form)

        combined_days = _conv_time_limit({
            'time_limit_days': form.time_limit_days.data if hasattr(form, 'time_limit_days') else None,
            'time_limit_hours': form.time_limit_hours.data if hasattr(form, 'time_limit_hours') else None,
        })
        created_ts = now_ts()

        p = Peer(
            iface_id=iface.id,
            name=form.name.data.strip(),
            public_key=pub,
            private_key=priv,
            address=addr,
            allowed_ips=(form.allowed_ips.data or '0.0.0.0/0, ::/0').strip(),
            endpoint=(form.endpoint.data or '').strip() or None,
            peer_endpoint=(form.peer_endpoint.data or '').strip() or None,
            persistent_keepalive=form.persistent_keepalive.data if hasattr(form, 'persistent_keepalive') else 25,
            mtu=form.mtu.data if hasattr(form, 'mtu') and form.mtu.data else None,
            dns=(form.dns.data or '').strip() or None,
            status='online',
            created_at=from_ts(created_ts),
            timer_started_at=from_ts(created_ts),
            unlimited=bool(getattr(form, 'unlimited', None) and form.unlimited.data),
            start_on_first_use=bool(getattr(form, 'start_on_first_use', None) and form.start_on_first_use.data),
            time_limit_days=combined_days,
            data_limit_value=int(getattr(form, 'data_limit', None) and form.data_limit.data or 0),
            data_limit_unit=(getattr(form, 'limit_unit', None) and form.limit_unit.data) or 'Mi',
            phone_number=(getattr(form, 'phone_number', None) and form.phone_number.data or '').strip(),
            telegram_id=(getattr(form, 'telegram_id', None) and form.telegram_id.data or '').strip(),
        )
        if p.time_limit_days and not p.start_on_first_use and not p.unlimited:
            p.expires_at = from_ts(add_days_ts(created_ts, float(p.time_limit_days)))

        db.session.add(p)
        db.session.commit()
        install_local_peer(p)
        log_event(p, 'created', f'Created on iface {iface.name}')
        try:
            _shortlink_for_peer(p)
        except Exception:
            pass
        flash(f'Peer {p.name} created successfully.', 'success')
        return redirect(url_for('peers_bp.users'))

    return render_template('users.html', form=form)


@peers_bp.route('/api/peers', methods=['GET'])
@require_api_key_or_login
def panel_peers():
    try:
        _expire()
    except Exception:
        pass

    query = Peer.query
    iface_id = request.args.get('iface_id', type=int)
    iface_nm = (request.args.get('iface') or '').strip()
    if iface_id is not None:
        query = query.filter(Peer.iface_id == iface_id)
    elif iface_nm:
        query = query.join(InterfaceConfig).filter(InterfaceConfig.name == iface_nm)

    peers = query.all()
    output = []
    for p in peers:
        output.append({
            'id': p.id,
            'name': p.name,
            'public_key': p.public_key,
            'address': p.address,
            'status': p.status,
            'iface_id': p.iface_id,
            'iface_name': getattr(p.iface, 'name', '') if p.iface else '',
            'unlimited': p.unlimited,
            'data_limit_value': p.data_limit_value,
            'data_limit_unit': p.data_limit_unit,
            'time_limit_days': p.time_limit_days,
            'expires_at': p.expires_at.isoformat() if p.expires_at else None,
            'endpoint': _effective_client_endpoint(p),
            'peer_endpoint': p.peer_endpoint or '',
            'phone_number': p.phone_number or '',
            'telegram_id': p.telegram_id or '',
        })
    return jsonify(peers=output), 200


@peers_bp.route('/api/peers', methods=['POST'])
@require_api_key_or_login
def peers_create():
    data = request.get_json(silent=True) or {}
    scope = (data.get('scope') or 'local').strip().lower()

    if scope == 'node':
        nid = int(data.get('node_id') or data.get('nodeId') or 0)
        iface_name = (data.get('iface_name') or data.get('ifaceName') or data.get('iface') or '').strip()
        if not nid or not iface_name:
            return jsonify(error='node_id and iface_name required for node scope'), 400
        n = Node.query.get_or_404(nid)

        try:
            priv = subprocess.check_output(['wg', 'genkey'], stderr=subprocess.DEVNULL, timeout=3).strip().decode()
            pub = subprocess.check_output(['wg', 'pubkey'], input=(priv + '\n').encode(), stderr=subprocess.DEVNULL, timeout=3).strip().decode()
        except Exception:
            import base64
            priv = base64.b64encode(os.urandom(32)).decode()
            pub = base64.b64encode(os.urandom(32)).decode()

        mirror_name = f"n{nid}:{iface_name}"
        mirror = InterfaceConfig.query.filter_by(name=mirror_name).first()
        if not mirror:
            mirror = InterfaceConfig(name=mirror_name, node_id=nid, address="10.0.0.1/24", listen_port=51820)
            db.session.add(mirror)
            db.session.flush()

        addr = (data.get('address') or '').strip() or "10.0.0.2/32"
        p = Peer(
            iface_id=mirror.id,
            name=(data.get('name') or '').strip() or 'peer',
            public_key=pub,
            private_key=priv,
            address=addr,
            allowed_ips=(data.get('allowed_ips') or '0.0.0.0/0, ::/0').strip(),
            status='online',
            created_at=from_ts(now_ts()),
            timer_started_at=from_ts(now_ts()),
        )
        db.session.add(p)
        db.session.commit()
        return jsonify(ok=True, success=True, id=p.id, public_key=p.public_key, address=p.address), 200

    # Local scope
    iface_id = data.get('iface_id')
    if not iface_id:
        return jsonify(error='iface_id required'), 400
    try:
        iface_id = int(iface_id)
    except Exception:
        return jsonify(error='invalid iface_id'), 400

    iface = db.session.get(InterfaceConfig, iface_id)
    if not iface:
        return jsonify(error='Interface not found'), 404

    try:
        priv = subprocess.check_output(['wg', 'genkey'], stderr=subprocess.DEVNULL, timeout=3).strip().decode()
        pub = subprocess.check_output(['wg', 'pubkey'], input=(priv + '\n').encode(), stderr=subprocess.DEVNULL, timeout=3).strip().decode()
    except Exception:
        import base64
        priv = base64.b64encode(os.urandom(32)).decode()
        pub = base64.b64encode(os.urandom(32)).decode()

    try:
        addr = allocate_peer_address(iface, requested=(data.get('address') or '').strip())
    except AddressAllocationError as e:
        return address_error_response(e)

    created_ts = now_ts()
    combined_days = _conv_time_limit(data)
    unlimited = bool(data.get('unlimited', False))
    start_on_first_use = bool(data.get('start_on_first_use', False))

    p = Peer(
        iface_id=iface.id,
        name=(data.get('name') or '').strip() or 'peer',
        public_key=pub,
        private_key=priv,
        address=addr,
        allowed_ips=(data.get('allowed_ips') or '0.0.0.0/0, ::/0').strip(),
        endpoint=data.get('endpoint') or None,
        peer_endpoint=(data.get('peer_endpoint') or '').strip() or None,
        dns=(data.get('dns') or '').strip() or None,
        mtu=int(data.get('mtu')) if data.get('mtu') else None,
        status='online',
        created_at=from_ts(created_ts),
        timer_started_at=from_ts(created_ts),
        unlimited=unlimited,
        start_on_first_use=start_on_first_use,
        time_limit_days=combined_days,
        data_limit_value=int(data.get('data_limit_value') or data.get('data_limit') or 0),
        data_limit_unit=data.get('data_limit_unit') or 'Mi',
        phone_number=(data.get('phone_number') or data.get('phone') or '').strip(),
        telegram_id=(data.get('telegram_id') or data.get('telegram') or '').strip(),
    )
    if p.time_limit_days and not p.start_on_first_use and not p.unlimited:
        p.expires_at = from_ts(add_days_ts(created_ts, float(p.time_limit_days)))

    db.session.add(p)
    db.session.commit()
    install_local_peer(p)
    log_event(p, 'created', f'Created on iface {iface.name}')

    return jsonify(
        success=True,
        ok=True,
        id=p.id,
        public_key=p.public_key,
        address=p.address,
        endpoint=_effective_client_endpoint(p),
    ), 200


@csrf.exempt
@peers_bp.route('/api/peers/bulk', methods=['POST'])
@require_api_key_or_login
def panel_peers_bulk():
    data = request.get_json(silent=True) or {}
    count = int(data.get('count') or data.get('bulkPeerCount') or 0)
    if count < 1:
        return jsonify(error="count is required"), 400

    iface_id = data.get('iface_id')
    if not iface_id:
        return jsonify(error='iface_id required'), 400
    iface = db.session.get(InterfaceConfig, int(iface_id))
    if not iface:
        return jsonify(error='Interface not found'), 404

    prefix = (data.get('prefix') or data.get('name_prefix') or 'peer').strip()
    created = []
    for idx in range(count):
        try:
            priv = subprocess.check_output(['wg', 'genkey'], stderr=subprocess.DEVNULL, timeout=3).strip().decode()
            pub = subprocess.check_output(['wg', 'pubkey'], input=(priv + '\n').encode(), stderr=subprocess.DEVNULL, timeout=3).strip().decode()
        except Exception:
            import base64
            priv = base64.b64encode(os.urandom(32)).decode()
            pub = base64.b64encode(os.urandom(32)).decode()

        try:
            addr = allocate_peer_address(iface)
        except AddressAllocationError as e:
            break

        p = Peer(
            iface_id=iface.id,
            name=f"{prefix}-{idx+1}",
            public_key=pub,
            private_key=priv,
            address=addr,
            status='online',
            created_at=from_ts(now_ts()),
            timer_started_at=from_ts(now_ts()),
        )
        db.session.add(p)
        created.append(p)

    db.session.commit()
    for p in created:
        install_local_peer(p)
    return jsonify(ok=True, count=len(created)), 200


@peers_bp.route('/api/peer/<int:pid>', methods=['PUT'])
@csrf.exempt
@require_api_key_or_login
def api_edit(pid):
    p = db.session.get(Peer, pid) or abort(404)
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify(ok=False, error='invalid_payload'), 400

    if 'name' in data:
        p.name = str(data['name']).strip()
    if 'allowed_ips' in data:
        p.allowed_ips = str(data['allowed_ips']).strip()
    if 'endpoint' in data:
        p.endpoint = str(data['endpoint']).strip() or None
    if 'peer_endpoint' in data:
        p.peer_endpoint = str(data['peer_endpoint']).strip() or None
    if 'persistent_keepalive' in data:
        try:
            p.persistent_keepalive = int(data['persistent_keepalive']) if data['persistent_keepalive'] not in (None, '') else None
        except Exception:
            pass
    if 'mtu' in data:
        try:
            p.mtu = int(data['mtu']) if data['mtu'] not in (None, '') else None
        except Exception:
            pass
    if 'dns' in data:
        p.dns = str(data['dns']).strip() or None
    if 'phone_number' in data:
        p.phone_number = str(data['phone_number']).strip()
    if 'telegram_id' in data:
        p.telegram_id = str(data['telegram_id']).strip()

    db.session.commit()
    log_event(p, 'edited', 'Peer settings updated')
    return jsonify(ok=True, success=True)


@peers_bp.route('/api/peer/<int:pid>', methods=['DELETE'])
@csrf.exempt
@require_api_key_or_login
def api_delete(pid):
    p = db.session.get(Peer, pid) or abort(404)
    try:
        remove_peer_everywhere(p)
    except PeerRemovalError as e:
        return peer_removal_response(e, peer_id=pid)
    logpanel_action("peer_delete", f"pid={pid}")
    return jsonify(success=True, ok=True)


@peers_bp.post('/api/peer/<int:pid>/clear_total')
@login_required
def peer_clear_total(pid):
    p = db.session.get(Peer, pid) or abort(404)
    prev = int(getattr(p, 'used_bytes_total', 0) or 0)
    p.used_bytes_total = 0
    db.session.commit()
    log_event(p, 'clear_total', f'Lifetime cleared (was {prev} bytes)')
    return jsonify(success=True, cleared=prev)


@csrf.exempt
@peers_bp.route('/api/peer/<int:pid>/disable', methods=['POST'])
@require_api_key_or_login
def api_disable(pid):
    p = db.session.get(Peer, pid) or abort(404)
    _wg_disable(p)
    p.status = 'offline'
    db.session.commit()
    log_event(p, 'disabled')
    logpanel_action("peer_disable", f"pid={p.id}")
    return jsonify(success=True)


@csrf.exempt
@peers_bp.route('/api/peer/<int:pid>/enable', methods=['POST'])
@require_api_key_or_login
def api_enable(pid):
    p = db.session.get(Peer, pid) or abort(404)
    _wg_enable(p)
    p.status = 'online'
    db.session.commit()
    log_event(p, 'enabled')
    logpanel_action("peer_enable", f"pid={p.id}")
    return jsonify(success=True)


@peers_bp.route('/api/peer/<int:pid>/logs', methods=['GET'])
@login_required
def peer_logs(pid):
    p = db.session.get(Peer, pid) or abort(404)
    rows = (
        PeerEvent.query
        .filter_by(peer_id=pid)
        .order_by(PeerEvent.timestamp.desc())
        .limit(500)
        .all()
    )
    out = []
    for r in rows:
        out.append({
            'event': r.event,
            'details': r.details,
            'timestamp': r.timestamp.isoformat() if r.timestamp else None,
        })
    return jsonify(logs=out)


@peers_bp.delete('/api/peer/<int:pid>/logs')
@login_required
def clear_peer_logs(pid):
    p = db.session.get(Peer, pid) or abort(404)
    try:
        cnt = PeerEvent.query.filter_by(peer_id=pid).delete(synchronize_session=False) or 0
        db.session.commit()
        logpanel_action("peer_logs_clear", f"pid={p.id}; {cnt} events")
        return jsonify(ok=True, deleted=int(cnt))
    except Exception as e:
        db.session.rollback()
        return jsonify(ok=False, error="clear_failed", detail=str(e)), 500


@peers_bp.route('/api/peer/<int:pid>/reset_data', methods=['POST'])
@require_api_key
def reset_data(pid):
    p = db.session.get(Peer, pid) or abort(404)
    try:
        current = int(_wg_transfer(p) or 0)
    except Exception:
        current = 0
    p.bytes_offset = max(0, current)
    p.used_bytes_total = 0
    db.session.commit()
    log_event(p, 'reset_data', f'Traffic usage reset; runtime offset={current}')
    return jsonify(success=True, status=p.status, timer_preserved=True, data_reset=True)


@peers_bp.route('/api/peer/<int:pid>/reset_timer', methods=['POST'])
@require_api_key
def api_reset_timer(pid):
    p = db.session.get(Peer, pid) or abort(404)
    created_ts = now_ts()
    p.timer_started_at = from_ts(created_ts)
    if p.time_limit_days and not p.unlimited:
        p.expires_at = from_ts(add_days_ts(created_ts, float(p.time_limit_days)))
    if p.status == 'expired':
        p.status = 'online'
        _wg_enable(p)
    db.session.commit()
    log_event(p, 'reset_timer', 'Timer reset')
    return jsonify(success=True, status=p.status)


@peers_bp.get("/api/peer/<path:public_key>/config")
@csrf.exempt
@require_api_key_or_login
def api_peer_config_by_public_key(public_key):
    peer = _peer_by_public_key_or_404(public_key)
    cfg, err = _peer_client_conf_or_502(peer)
    if err:
        return err
    if not cfg or not cfg.strip():
        return jsonify(ok=False, error="config_empty", message="The peer configuration is empty."), 404

    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", peer.name or f"peer-{peer.id}").strip("._") or f"peer-{peer.id}"
    response = make_response(cfg.strip() + "\n", 200)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store, no-cache, must-revalidate, max-age=0"
    if request.args.get("download") == "1":
        response.headers["Content-Disposition"] = f'attachment; filename="{safe_name}.conf"'
    return response


@peers_bp.get("/api/peer/<path:public_key>/config_qr")
@csrf.exempt
@require_api_key_or_login
def api_peer_config_qr_by_public_key(public_key):
    peer = _peer_by_public_key_or_404(public_key)
    cfg, err = _peer_client_conf_or_502(peer)
    if err:
        return err
    if not cfg or not cfg.strip():
        return jsonify(ok=False, error="config_empty", message="The peer configuration is empty."), 404

    img = qrcode.make(cfg)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")
