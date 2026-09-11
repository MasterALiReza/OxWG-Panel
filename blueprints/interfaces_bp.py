"""
OxWg Panel - Interfaces Blueprint (interfaces_bp)
=================================================
Manages WireGuard network interfaces (local and remote mirror):
creation, discovery, settings (port, MTU, DNS), start/stop,
IP availability, endpoint defaults, and operational logs.
"""
import os
import re
import glob
import shlex
import socket
import logging
import subprocess
import ipaddress
import base64
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from flask import (
    Blueprint,
    request,
    jsonify,
    abort,
    current_app,
)
from flask_login import login_required

from models import (
    db,
    InterfaceConfig,
    Peer,
    SubscriptionPeer,
    ShortLink,
)
from core.extensions import csrf
from auth import require_api_key_or_login
from core.paths import IFACE_LOG_DIR
from core.ip_utils import _first_cidr, _safe_ip, _private_networks
from core.file_utils import _extend_file
from core.constants import MAX_ENUMERATED_HOSTS
from services.wg_parser import (
    find_iface,
    iface_devname,
    _derive_wg_public_key,
    _copy_local_iface_from_parsed,
    _iface_is_node,
)
from services.config_generator import (
    EndpointValidationError,
    _parse_endpoint_host,
    _parse_endpoint_port,
    iface_endpoint_override,
    _endpoint_fallback,
    remote_iface_name,
    _node_endpoint_fallback,
    resolve_client_endpoint,
)
from blueprints.logs_bp import _last_cleared, _load_retention, _may_autoclear, logpanel_action

interfaces_bp = Blueprint('interfaces_bp', __name__)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions & Shared Classes
# ---------------------------------------------------------------------------

class EndpointApplyError(Exception):
    """Applying an endpoint default to existing peers could not start."""
    def __init__(self, code, status, detail):
        super().__init__(detail)
        self.code = code
        self.status = status
        self.detail = detail


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sub_bool(val: Any, default: bool = False) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ('1', 'true', 'yes', 'on', 'y', 't'):
        return True
    if s in ('0', 'false', 'no', 'off', 'n', 'f'):
        return False
    return default


def _iface_up(name: str) -> bool:
    try:
        subprocess.check_call(
            ['wg', 'show', name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.5,
        )
        return True
    except Exception:
        return False


def _iface_down(name: str) -> None:
    try:
        subprocess.check_call(
            ['wg-quick', 'down', name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=6.0,
        )
        return
    except Exception:
        pass
    try:
        subprocess.run(
            ['ip', 'link', 'del', 'dev', name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        pass


def _check_iface_up(iface: InterfaceConfig) -> None:
    if not iface:
        return
    if getattr(iface, 'node_id', None) is not None or (':' in (iface.name or '')):
        return
    dev = iface_devname(iface)
    if _iface_up(dev):
        return
    cmd = ['wg-quick', 'up', dev]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20.0)
        if proc.returncode != 0:
            raise RuntimeError(proc.stdout.decode('utf-8', 'ignore'))
    except FileNotFoundError:
        raise RuntimeError("WireGuard utility 'wg-quick' not found on system PATH (requires Linux WireGuard installation).")


def _ifacelog_path(iid: int) -> str:
    Path(IFACE_LOG_DIR).mkdir(parents=True, exist_ok=True)
    return os.path.join(IFACE_LOG_DIR, f"iface_{int(iid)}.log")


def _iface_log(iid: int, text: str) -> None:
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace('+00:00', 'Z')
    _extend_file(_ifacelog_path(iid), f"[{ts}] {text}")


def interface_ip_interface(iface):
    if not iface:
        return None
    addr_field = getattr(iface, 'address', None)
    cidr = _first_cidr(addr_field)
    if not cidr:
        return None
    try:
        return ipaddress.ip_interface(cidr)
    except ValueError:
        return None


def _usable_hosts(net):
    for index, host in enumerate(net.hosts()):
        if index >= MAX_ENUMERATED_HOSTS:
            return
        yield host


def _db_peer_hosts(iface, exclude_peer_id=None):
    hosts = set()
    iface_id = getattr(iface, 'id', None)
    if not iface_id:
        return hosts
    query = db.session.query(Peer.address, Peer.address_host).filter(Peer.iface_id == iface_id)
    if exclude_peer_id:
        query = query.filter(Peer.id != exclude_peer_id)
    for address, address_host in query:
        host = _safe_ip(address_host) or _safe_ip(address)
        if host is not None:
            hosts.add(host)
    return hosts


def _reserved_hosts(iface, ip_iface, *, exclude_peer_id=None, exclude_address=None, extra=()):
    net = ip_iface.network
    reserved = {ip_iface.ip}
    point_to_point = 31 if net.version == 4 else 127
    if net.prefixlen < point_to_point:
        reserved.add(net.network_address)
        if net.version == 4:
            reserved.add(net.broadcast_address)
    reserved |= _db_peer_hosts(iface, exclude_peer_id=exclude_peer_id)
    for value in extra or ():
        host = _safe_ip(value)
        if host is not None:
            reserved.add(host)
    own_host = _safe_ip(exclude_address)
    if own_host is not None and own_host != ip_iface.ip:
        reserved.discard(own_host)
    return reserved


def _available_ips(iface, limit=MAX_ENUMERATED_HOSTS):
    if not iface:
        return []
    try:
        ip_iface = interface_ip_interface(iface)
        if ip_iface is None:
            return []
        net = ip_iface.network
        reserved = _reserved_hosts(iface, ip_iface)
        out = []
        for host in _usable_hosts(net):
            if host in reserved:
                continue
            out.append(f'{host}/{net.prefixlen}')
            if len(out) >= limit:
                break
        return out
    except Exception as e:
        current_app.logger.exception("_available_ips failed for iface=%r: %s", getattr(iface, "name", None), e)
        return []


def parse_endpoint_override(host, port):
    host_raw = '' if host is None else str(host).strip()
    port_raw = '' if port is None else str(port).strip()
    if not host_raw and not port_raw:
        return (None, None)
    if not host_raw or not port_raw:
        raise EndpointValidationError(
            'endpoint_partial',
            'Send host and port together, or send both empty to clear the override.',
        )
    return (_parse_endpoint_host(host_raw), _parse_endpoint_port(port_raw))


def _endpoint_default_payload(iface, *, scope=None, node=None, remote_iface=None):
    if scope is None:
        scope = 'node' if getattr(iface, 'node_id', None) is not None else 'local'
    host = (getattr(iface, 'endpoint_host', None) or '').strip() or None
    port = getattr(iface, 'endpoint_port', None)
    override = iface_endpoint_override(iface)
    auto = ''
    try:
        if scope == 'node':
            auto = (_node_endpoint_fallback(
                node or getattr(iface, 'node', None),
                remote_iface_name(iface),
                remote_iface,
            ) or '').strip()
        else:
            auto = (_endpoint_fallback(iface) or '').strip()
    except Exception:
        auto = ''

    effective = override or auto
    payload = {
        'scope': scope,
        'iface_id': iface.id,
        'iface': remote_iface_name(iface) if scope == 'node' else (iface.name or ''),
        'listen_port': iface.listen_port,
        'endpoint_host': host,
        'endpoint_port': int(port) if port else None,
        'endpoint_override': override,
        'auto_endpoint': auto,
        'effective_endpoint': effective,
        'endpoint_source': 'override' if override else ('auto' if auto else 'none'),
    }
    if scope == 'node':
        payload['node_id'] = getattr(iface, 'node_id', None)
    if not effective:
        payload['warning'] = (
            'No endpoint could be determined. Exported configs will have no '
            'Endpoint line until an override is saved.'
        )
    return payload


def _local_iface_or_error(iid):
    iface = db.session.get(InterfaceConfig, iid)
    if iface is None:
        return None, (jsonify(ok=False, error='iface_not_found', detail=f'Interface {iid} was not found.'), 404)
    if getattr(iface, 'node_id', None) is not None or ':' in (getattr(iface, 'name', '') or ''):
        return None, (jsonify(ok=False, error='remote_interface', detail='This interface belongs to a remote node. Use the node interface API instead.'), 400)
    return iface, None


def _apply_request_flags(data):
    data = data if isinstance(data, dict) else {}
    return (
        _sub_bool(data.get('dry_run')),
        _sub_bool(data.get('overwrite_explicit')),
    )


def _apply_endpoint_default(iface, *, dry_run, overwrite_explicit, scope='local', node=None, remote_iface=None):
    effective = resolve_client_endpoint(iface, node=node, remote_iface=remote_iface)
    if not effective:
        raise EndpointApplyError(
            'endpoint_unavailable', 409,
            'No endpoint could be determined for this interface, so there is nothing to apply.',
        )

    peers = Peer.query.filter_by(iface_id=iface.id).all()
    explicit = [p for p in peers if (p.endpoint or '').strip()]
    candidates = peers if overwrite_explicit else [p for p in peers if not (p.endpoint or '').strip()]
    targets = [p for p in candidates if (p.endpoint or '').strip() != effective]

    result = {
        'scope': scope,
        'iface': remote_iface_name(iface) if scope == 'node' else (iface.name or ''),
        'effective_endpoint': effective,
        'total_peers': len(peers),
        'eligible': len(targets),
        'skipped_explicit': 0 if overwrite_explicit else len(explicit),
        'dry_run': bool(dry_run),
    }
    if dry_run:
        result['would_update'] = len(targets)
        return result

    for peer in targets:
        peer.endpoint = effective
    db.session.commit()

    current_app.logger.info(
        'Applied endpoint %s to %s peers on interface %s',
        effective, len(targets), iface.name,
    )
    result['updated'] = len(targets)
    return result


def _egress_interface() -> str:
    try:
        output = subprocess.check_output(
            ['ip', '-4', 'route', 'show', 'default'],
            stderr=subprocess.DEVNULL,
            timeout=4.0,
        ).decode('utf-8', 'ignore').strip()
        parts = output.split()
        if 'dev' in parts:
            idx = parts.index('dev') + 1
            if idx < len(parts):
                candidate = parts[idx].strip()
                if candidate and candidate != 'lo' and not re.match(r'^(wg|tun|tap|docker|br-|veth)', candidate, re.I):
                    return candidate
    except Exception:
        pass

    try:
        output = subprocess.check_output(
            ['ip', 'route', 'get', '8.8.8.8'],
            stderr=subprocess.DEVNULL,
            timeout=4.0,
        ).decode('utf-8', 'ignore').strip()
        parts = output.split()
        if 'dev' in parts:
            idx = parts.index('dev') + 1
            if idx < len(parts):
                candidate = parts[idx].strip()
                if candidate and candidate != 'lo' and not re.match(r'^(wg|tun|tap|docker|br-|veth)', candidate, re.I):
                    return candidate
    except Exception:
        pass

    try:
        if os.path.exists('/proc/net/route'):
            with open('/proc/net/route', 'r', encoding='utf-8') as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if len(fields) >= 2 and fields[1] == '00000000':
                        dev = fields[0]
                        if dev and dev != 'lo' and not re.match(r'^(wg|tun|tap|docker|br-|veth)', dev, re.I):
                            return dev
    except Exception:
        pass

    return 'eth0'


def _wireguard_network(address_field: str) -> str:
    for raw_value in re.split(r"[\s,]+", str(address_field or "").strip()):
        value = raw_value.strip()
        if not value:
            continue
        if "/" not in value:
            value = f"{value}/24"
        try:
            interface = ipaddress.ip_interface(value)
            if interface.version == 4:
                return str(interface.network)
        except ValueError:
            continue
    return ""


def _wg_firewall_rules(interface_name: str, address_field: str) -> tuple[str, str]:
    network = _wireguard_network(address_field)
    if not network:
        network = "10.0.0.0/24"
    egress = _egress_interface() or "eth0"
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", egress):
        egress = "eth0"

    post_up = "\n".join([
        "sysctl -w net.ipv4.ip_forward=1",
        "iptables -A FORWARD -i %i -j ACCEPT",
        "iptables -A FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        f"iptables -t nat -A POSTROUTING -s {network} -o {egress} -j MASQUERADE",
    ])
    post_down = "\n".join([
        "iptables -D FORWARD -i %i -j ACCEPT",
        "iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        f"iptables -t nat -D POSTROUTING -s {network} -o {egress} -j MASQUERADE",
    ])
    return post_up, post_down


def _inject_firewall_rules(
    config_path: str,
    interface_name: str,
    address_field: str,
) -> dict:
    if not os.path.isfile(config_path):
        return {
            "changed": False,
            "reason": "config_missing",
        }

    try:
        with open(config_path, "r", encoding="utf-8", errors="replace") as handle:
            original = handle.read()
    except OSError as exc:
        return {
            "changed": False,
            "reason": "read_failed",
            "detail": str(exc),
        }

    in_interface = False
    has_post_up = False
    has_post_down = False

    for raw_line in original.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_interface = line[1:-1].strip().lower() == "interface"
            continue
        if not in_interface or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip().lower()
        if key == "postup":
            has_post_up = True
        elif key == "postdown":
            has_post_down = True

    if has_post_up or has_post_down:
        return {
            "changed": False,
            "reason": "custom_rules_present",
            "has_post_up": has_post_up,
            "has_post_down": has_post_down,
        }

    try:
        post_up, post_down = _wg_firewall_rules(interface_name, address_field)
    except ValueError as exc:
        return {
            "changed": False,
            "reason": "rule_generation_failed",
            "detail": str(exc),
        }

    lines = original.splitlines()
    insert_at = None
    inside_interface = False
    found_interface = False

    for index, raw_line in enumerate(lines):
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            if section == "interface":
                inside_interface = True
                found_interface = True
                continue
            if inside_interface:
                insert_at = index
                break

    if not found_interface:
        return {
            "changed": False,
            "reason": "interface_section_missing",
        }

    if insert_at is None:
        insert_at = len(lines)

    additions = [
        *[f"PostUp = {cmd.strip()}" for cmd in str(post_up or "").splitlines() if cmd.strip()],
        *[f"PostDown = {cmd.strip()}" for cmd in str(post_down or "").splitlines() if cmd.strip()],
        "",
    ]

    new_lines = lines[:insert_at] + additions + lines[insert_at:]
    updated = "\n".join(new_lines).rstrip() + "\n"
    directory = os.path.dirname(config_path) or "."

    fd, temporary_path = tempfile.mkstemp(prefix=".wg-panel-firewall.", dir=directory)
    try:
        try:
            original_mode = os.stat(config_path).st_mode & 0o777
        except OSError:
            original_mode = 0o600

        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())

        os.chmod(temporary_path, original_mode)
        os.replace(temporary_path, config_path)
        temporary_path = ""
    finally:
        if temporary_path and os.path.exists(temporary_path):
            try:
                os.unlink(temporary_path)
            except OSError:
                pass

    runtime_applied = False
    runtime_error = ""

    if _iface_up(interface_name):
        try:
            errors = []
            for raw_command in str(post_up or "").splitlines():
                raw_command = raw_command.strip()
                if not raw_command:
                    continue
                command = raw_command.replace("%i", shlex.quote(interface_name))
                result = subprocess.run(
                    ["/bin/sh", "-c", command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=20,
                    check=False,
                )
                if result.returncode != 0:
                    errors.append((result.stdout or command).strip())

            runtime_applied = len(errors) == 0
            if errors:
                runtime_error = "\n".join(errors)[-2000:]
        except Exception as exc:
            runtime_error = str(exc)

    return {
        "changed": True,
        "reason": "managed_rules_added",
        "post_up": post_up,
        "runtime_applied": runtime_applied,
        "runtime_error": runtime_error,
    }


def _append_managed_iface_keys(new_lines: list[str], updates: dict[str, Any], keys_to_replace: set[str], seen_keys: set[str]):
    for key in ('listen_port', 'dns', 'mtu', 'table'):
        if key in keys_to_replace and key not in seen_keys:
            val = updates.get(key)
            if val not in (None, ''):
                directive = {'listen_port': 'ListenPort', 'dns': 'DNS', 'mtu': 'MTU', 'table': 'Table'}[key]
                new_lines.append(f"{directive} = {val}")
    for key in ('pre_up', 'pre_down', 'post_up', 'post_down'):
        if key in keys_to_replace and key not in seen_keys:
            val = updates.get(key)
            if val:
                directive = {'pre_up': 'PreUp', 'pre_down': 'PreDown', 'post_up': 'PostUp', 'post_down': 'PostDown'}[key]
                for line_cmd in str(val).splitlines():
                    if line_cmd.strip():
                        new_lines.append(f"{directive} = {line_cmd.strip()}")


def _update_iface_conf_file(iface, updates: dict[str, Any]) -> bool:
    """Safely update [Interface] section of the WireGuard configuration file."""
    conf_path = getattr(iface, 'path', None) or ''
    if not conf_path or not os.path.isfile(conf_path):
        wg_dir = current_app.config.get('WG_CONF_PATH', '/etc/wireguard')
        if os.path.isdir(wg_dir):
            candidate = os.path.join(wg_dir, f"{iface.name}.conf")
            if os.path.isfile(candidate):
                conf_path = candidate
    if not conf_path or not os.path.isfile(conf_path):
        return False

    try:
        with open(conf_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return False

    lines = content.splitlines()
    new_lines = []
    in_interface = False
    seen_keys = set()
    seen_multi_keys = set()

    keys_to_replace = {k for k in ('listen_port', 'dns', 'mtu', 'table', 'pre_up', 'pre_down', 'post_up', 'post_down') if k in updates}

    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()

        if stripped.startswith('[') and stripped.endswith(']'):
            sec = stripped[1:-1].strip().lower()
            if sec == 'interface':
                in_interface = True
                new_lines.append(raw)
                i += 1
                continue
            else:
                if in_interface:
                    _append_managed_iface_keys(new_lines, updates, keys_to_replace, seen_keys)
                    in_interface = False
                new_lines.append(raw)
                i += 1
                continue

        if in_interface and '=' in stripped and not stripped.startswith('#'):
            k, _ = [s.strip() for s in stripped.split('=', 1)]
            lk = k.lower()
            mapped = {
                'listenport': 'listen_port',
                'dns': 'dns',
                'mtu': 'mtu',
                'table': 'table',
                'preup': 'pre_up',
                'predown': 'pre_down',
                'postup': 'post_up',
                'postdown': 'post_down',
            }.get(lk)

            if mapped and mapped in keys_to_replace:
                seen_keys.add(mapped)
                if mapped in ('pre_up', 'pre_down', 'post_up', 'post_down'):
                    if mapped not in seen_multi_keys:
                        seen_multi_keys.add(mapped)
                        val = updates.get(mapped)
                        if val:
                            directive = {'pre_up': 'PreUp', 'pre_down': 'PreDown', 'post_up': 'PostUp', 'post_down': 'PostDown'}[mapped]
                            for line_cmd in str(val).splitlines():
                                if line_cmd.strip():
                                    new_lines.append(f"{directive} = {line_cmd.strip()}")
                else:
                    val = updates.get(mapped)
                    if val not in (None, ''):
                        directive = {'listen_port': 'ListenPort', 'dns': 'DNS', 'mtu': 'MTU', 'table': 'Table'}[mapped]
                        new_lines.append(f"{directive} = {val}")
                i += 1
                continue

        new_lines.append(raw)
        i += 1

    if in_interface:
        _append_managed_iface_keys(new_lines, updates, keys_to_replace, seen_keys)

    updated_content = '\n'.join(new_lines).rstrip() + '\n'
    directory = os.path.dirname(conf_path) or '.'
    fd, tmp_path = tempfile.mkstemp(prefix='.wg-conf.', dir=directory)
    try:
        try:
            orig_mode = os.stat(conf_path).st_mode & 0o777
        except OSError:
            orig_mode = 0o600
        with os.fdopen(fd, 'w', encoding='utf-8') as h:
            h.write(updated_content)
            h.flush()
            os.fsync(h.fileno())
        os.chmod(tmp_path, orig_mode)
        os.replace(tmp_path, conf_path)
        tmp_path = ''
        return True
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return False


def local_firewall_rules(app=None) -> dict:
    """Upgrade old local WireGuard configs postup/down."""
    cfg = app.config if app else current_app.config
    configured_path = (
        cfg.get("WG_CONF_PATH")
        or cfg.get("WIREGUARD_CONF_PATH")
        or "/etc/wireguard"
    )

    if os.path.isdir(configured_path):
        paths = sorted(glob.glob(os.path.join(configured_path, "*.conf")))
    elif os.path.isfile(configured_path):
        paths = [configured_path]
    else:
        paths = []

    summary = {
        "checked": 0,
        "updated": 0,
        "skipped": 0,
        "failed": 0,
    }

    log = app.logger if app else current_app.logger
    for config_path in paths:
        parsed = find_iface(config_path)
        if not parsed:
            summary["skipped"] += 1
            continue

        summary["checked"] += 1
        result = _inject_firewall_rules(
            config_path,
            parsed.name,
            parsed.address,
        )

        if result.get("changed"):
            summary["updated"] += 1
            log.info(
                "Added automatic firewall rules to legacy interface %s; runtime_applied=%s",
                parsed.name,
                result.get("runtime_applied"),
            )
            if result.get("runtime_error"):
                log.warning(
                    "Legacy interface %s was updated, but its runtime firewall rules could not be applied immediately: %s",
                    parsed.name,
                    result["runtime_error"],
                )
        elif result.get("reason") in {"custom_rules_present", "config_missing"}:
            summary["skipped"] += 1
        else:
            summary["failed"] += 1
            log.warning(
                "Could not add firewall rules to legacy interface %s: %s",
                parsed.name,
                result,
            )

    return summary


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@interfaces_bp.get("/api/get-interfaces")
@require_api_key_or_login
def get_interfaces():
    paths = []
    p = current_app.config.get('WG_CONF_PATH', '/etc/wireguard')
    if os.path.isdir(p):
        paths = glob.glob(os.path.join(p, '*.conf'))
    elif os.path.isfile(p):
        paths = [p]

    for conf in paths:
        name = os.path.splitext(os.path.basename(conf))[0]
        parsed = find_iface(conf)
        if not parsed:
            continue

        existing = InterfaceConfig.query.filter_by(name=name).first()
        if not existing:
            pk = _derive_wg_public_key(parsed.private_key)
            if pk:
                parsed.public_key = pk
            db.session.add(parsed)
        else:
            _copy_local_iface_from_parsed(existing, parsed)
            db.session.add(existing)

    db.session.commit()
    all_ifaces = InterfaceConfig.query.all()
    out = []
    scope_networks = _private_networks()
    for iface in all_ifaces:
        if getattr(iface, 'node_id', None) is not None:
            continue
        dev = iface_devname(iface)
        override = iface_endpoint_override(iface)
        out.append({
            'id': iface.id,
            'name': iface.name,
            'dev': dev,
            'address': iface.address or '',
            'server_cidr': iface.address or '',
            'scope_networks': scope_networks,
            'listen_port': iface.listen_port,
            'mtu': iface.mtu,
            'dns': iface.dns,
            'table': getattr(iface, 'table', None) or '',
            'pre_up': getattr(iface, 'pre_up', None) or '',
            'pre_down': getattr(iface, 'pre_down', None) or '',
            'post_up': getattr(iface, 'post_up', None) or '',
            'post_down': getattr(iface, 'post_down', None) or '',
            'available_ips': _available_ips(iface),
            'is_up': _iface_up(dev),
            'endpoint_host': (getattr(iface, 'endpoint_host', None) or '').strip() or None,
            'endpoint_port': int(iface.endpoint_port) if getattr(iface, 'endpoint_port', None) else None,
            'endpoint_override': override,
            'auto_endpoint': '',
            'effective_endpoint': override,
            'endpoint_source': 'override' if override else 'none',
        })
    return jsonify({'interfaces': out})


@interfaces_bp.post("/api/interfaces")
@login_required
def create_local_interface():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or data.get("iface") or data.get("interface_name") or "").strip()
    address = str(data.get("address") or "").strip()
    dns = str(data.get("dns") or "").strip() or None
    auto_up = bool(data.get("auto_up", True))
    auto_firewall = bool(data.get("auto_firewall", True))

    if not name:
        return jsonify(ok=False, error="interface_name_required", detail="Interface name is required."), 400
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", name):
        return jsonify(ok=False, error="invalid_name", detail=f"Invalid interface name {name!r}."), 400
    if not address:
        return jsonify(ok=False, error="address_required", detail="WireGuard interface address is required."), 400

    address_parts = [v.strip() for v in re.split(r"[\s,]+", address) if v.strip()]
    parsed_addresses = []
    for value in address_parts:
        try:
            parsed_addresses.append(ipaddress.ip_interface(value))
        except ValueError:
            return jsonify(ok=False, error="invalid_address", detail=f"{value!r} is not a valid CIDR."), 400

    address = ", ".join(str(v) for v in parsed_addresses)

    try:
        listen_port = int(data.get("listen_port"))
    except (TypeError, ValueError):
        return jsonify(ok=False, error="invalid_listen_port", detail="Listen port must be between 1 and 65535."), 400
    if not 1 <= listen_port <= 65535:
        return jsonify(ok=False, error="invalid_listen_port", detail="Listen port must be between 1 and 65535."), 400

    raw_mtu = data.get("mtu")
    try:
        mtu = int(raw_mtu) if raw_mtu not in (None, "") and str(raw_mtu).strip() else None
    except (TypeError, ValueError):
        return jsonify(ok=False, error="invalid_mtu", detail="MTU must be a number between 576 and 9000."), 400
    if mtu is not None and not 576 <= mtu <= 9000:
        return jsonify(ok=False, error="invalid_mtu", detail="MTU must be between 576 and 9000."), 400

    existing = InterfaceConfig.query.filter_by(name=name).first()
    if existing:
        return jsonify(ok=False, error="interface_exists", detail=f"Interface {name} already exists in the panel."), 409

    wg_dir = current_app.config.get("WG_CONF_PATH") or "/etc/wireguard"
    if os.path.isfile(wg_dir):
        wg_dir = os.path.dirname(wg_dir)
    try:
        os.makedirs(wg_dir, exist_ok=True)
    except Exception as exc:
        return jsonify(ok=False, error="wireguard_directory_failed", detail=str(exc)), 500

    conf_path = os.path.join(wg_dir, f"{name}.conf")
    if os.path.exists(conf_path):
        return jsonify(ok=False, error="config_exists", detail=f"{conf_path} already exists."), 409

    if _iface_up(name):
        return jsonify(ok=False, error="interface_exists_system", detail=f"Interface {name} already exists on the OS."), 409

    table = str(data.get("table") or "").strip() or None
    pre_up = str(data.get("pre_up") or "").strip() or None
    pre_down = str(data.get("pre_down") or "").strip() or None
    custom_post_up = str(data.get("post_up") or "").strip() or None
    custom_post_down = str(data.get("post_down") or "").strip() or None

    post_up = custom_post_up or ""
    post_down = custom_post_down or ""
    if not post_up and not post_down and auto_firewall:
        try:
            post_up, post_down = _wg_firewall_rules(name, address)
        except Exception as exc:
            current_app.logger.warning("Could not auto-generate firewall rules for %s: %s", name, exc)
            post_up = ""
            post_down = ""

    try:
        private_key = subprocess.check_output(["wg", "genkey"], stderr=subprocess.DEVNULL, timeout=5).decode().strip()
    except Exception:
        # Fallback key generation if wg binary is missing in dev
        import base64
        private_key = base64.b64encode(os.urandom(32)).decode()

    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {address}",
        f"ListenPort = {listen_port}",
    ]
    if mtu is not None:
        lines.append(f"MTU = {mtu}")
    if dns:
        lines.append(f"DNS = {dns}")
    if table:
        lines.append(f"Table = {table}")
    for cmd in str(pre_up or "").splitlines():
        if cmd.strip():
            lines.append(f"PreUp = {cmd.strip()}")
    for cmd in str(pre_down or "").splitlines():
        if cmd.strip():
            lines.append(f"PreDown = {cmd.strip()}")
    for cmd in str(post_up or "").splitlines():
        if cmd.strip():
            lines.append(f"PostUp = {cmd.strip()}")
    for cmd in str(post_down or "").splitlines():
        if cmd.strip():
            lines.append(f"PostDown = {cmd.strip()}")
    lines.append("")

    try:
        with open(conf_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
    except Exception as exc:
        return jsonify(ok=False, error="write_config_failed", detail=str(exc)), 500

    iface = InterfaceConfig(
        name=name,
        path=conf_path,
        address=address,
        listen_port=listen_port,
        private_key=private_key,
        mtu=mtu,
        dns=dns,
        table=table,
        pre_up=pre_up or None,
        pre_down=pre_down or None,
        post_up=post_up or None,
        post_down=post_down or None,
    )
    try:
        db.session.add(iface)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        try:
            os.remove(conf_path)
        except Exception:
            pass
        return jsonify(ok=False, error="database_save_failed", detail=str(exc)), 500

    if auto_up:
        try:
            subprocess.run(["wg-quick", "up", name], timeout=15, check=False)
        except Exception:
            pass

    return jsonify(
        ok=True,
        id=iface.id,
        name=name,
        address=address,
        listen_port=listen_port,
        table=table or "",
        pre_up=pre_up or "",
        pre_down=pre_down or "",
        post_up=post_up or "",
        post_down=post_down or "",
        is_up=_iface_up(name),
    ), 201


@interfaces_bp.route('/api/iface/<int:iface_id>/available_ips')
@require_api_key_or_login
def iface_available_ips(iface_id):
    iface = db.session.get(InterfaceConfig, iface_id) or abort(404)
    return jsonify(available_ips=_available_ips(iface))


@csrf.exempt
@interfaces_bp.route('/api/iface/<int:iface_id>/enable', methods=['POST'])
@require_api_key_or_login
def iface_enable(iface_id):
    iface = db.session.get(InterfaceConfig, iface_id) or abort(404)
    try:
        _check_iface_up(iface)
    except Exception as e:
        current_app.logger.error("Interface enable failed for %s: %s", iface.name, e)
        return jsonify(
            success=False,
            error="interface_enable_failed",
            detail=str(e),
        ), 409
    return jsonify(success=True, is_up=True)


@csrf.exempt
@interfaces_bp.route('/api/iface/<int:iface_id>/disable', methods=['POST'])
@require_api_key_or_login
def iface_disable(iface_id):
    iface = db.session.get(InterfaceConfig, iface_id) or abort(404)
    _iface_down(iface.name)
    return jsonify(success=True, is_up=False)


@csrf.exempt
@interfaces_bp.route('/api/iface/<int:iface_id>', methods=['DELETE'])
@require_api_key_or_login
def iface_delete(iface_id):
    iface = db.session.get(InterfaceConfig, iface_id) or abort(404)
    if getattr(iface, 'node_id', None) is not None or ':' in (iface.name or ''):
        return jsonify(
            success=False,
            error='node_interface_delete_not_supported_here',
            detail='Delete node interfaces through the node interface API.'
        ), 400

    data = request.get_json(silent=True) or {}
    delete_peers = _sub_bool(
        data.get('delete_peers') if 'delete_peers' in data else request.args.get('delete_peers')
    )

    peers = Peer.query.filter_by(iface_id=iface.id).all()
    peer_count = len(peers)
    if peer_count and not delete_peers:
        return jsonify(
            success=False,
            error='interface_has_peers',
            detail=f'Interface {iface.name} has {peer_count} peer(s).',
            peer_count=peer_count,
            require_delete_peers=True,
        ), 409

    dev = iface_devname(iface)
    conf_path = iface.path or ''
    try:
        _iface_down(dev)
    except Exception:
        pass

    peer_ids = [p.id for p in peers]
    if peer_ids:
        ShortLink.query.filter(ShortLink.peer_id.in_(peer_ids)).delete(synchronize_session=False)
        SubscriptionPeer.query.filter(SubscriptionPeer.peer_id.in_(peer_ids)).delete(synchronize_session=False)
        Peer.query.filter(Peer.iface_id == iface.id).delete(synchronize_session=False)

    if conf_path and os.path.isfile(conf_path):
        try:
            os.remove(conf_path)
        except Exception:
            pass

    log_path = _ifacelog_path(iface.id)
    if log_path and os.path.isfile(log_path):
        try:
            os.remove(log_path)
        except Exception:
            pass

    db.session.delete(iface)
    db.session.commit()
    return jsonify(success=True, deleted=iface.name)


@interfaces_bp.route('/api/iface/<int:iid>', methods=['GET', 'POST'])
@require_api_key_or_login
def iface_settings(iid):
    iface = db.session.get(InterfaceConfig, iid) or abort(404)
    if getattr(iface, 'node_id', None) is not None or ':' in (getattr(iface, 'name', '') or ''):
        return jsonify(ok=False, error='remote_interface', detail='This interface belongs to a remote node.'), 400

    dev = iface_devname(iface)

    if request.method == 'GET':
        return jsonify(
            ok=True,
            id=iface.id,
            name=iface.name,
            path=iface.path,
            address=iface.address,
            listen_port=iface.listen_port,
            dns=iface.dns,
            mtu=iface.mtu,
            table=getattr(iface, 'table', None) or '',
            pre_up=getattr(iface, 'pre_up', None) or '',
            pre_down=getattr(iface, 'pre_down', None) or '',
            post_up=getattr(iface, 'post_up', None) or '',
            post_down=getattr(iface, 'post_down', None) or '',
            is_up=_iface_up(dev),
            **{
                k: v for k, v in _endpoint_default_payload(iface).items()
                if k not in ('iface_id', 'iface', 'listen_port', 'scope')
            },
        )

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify(ok=False, error='invalid_payload', detail='JSON object required.'), 400

    updates = {}
    if 'dns' in data:
        updates['dns'] = str(data['dns']).strip() if data['dns'] not in (None, '') else None
    if 'mtu' in data and data['mtu'] not in (None, ''):
        try:
            updates['mtu'] = int(data['mtu'])
        except (TypeError, ValueError):
            return jsonify(ok=False, error='invalid_mtu', detail='MTU must be integer.'), 400
    if 'listen_port' in data and data['listen_port'] not in (None, ''):
        try:
            updates['listen_port'] = int(data['listen_port'])
        except (TypeError, ValueError):
            return jsonify(ok=False, error='invalid_listen_port', detail='Port must be integer.'), 400
    if 'table' in data:
        updates['table'] = str(data['table']).strip() if data['table'] not in (None, '') else None
    if 'pre_up' in data:
        updates['pre_up'] = str(data['pre_up']).strip() if data['pre_up'] not in (None, '') else None
    if 'pre_down' in data:
        updates['pre_down'] = str(data['pre_down']).strip() if data['pre_down'] not in (None, '') else None
    if 'post_up' in data:
        updates['post_up'] = str(data['post_up']).strip() if data['post_up'] not in (None, '') else None
    if 'post_down' in data:
        updates['post_down'] = str(data['post_down']).strip() if data['post_down'] not in (None, '') else None

    for k, v in updates.items():
        setattr(iface, k, v)
    db.session.commit()

    # Atomically update WireGuard .conf file
    _update_iface_conf_file(iface, updates)

    return jsonify(
        ok=True,
        changed=True,
        interface={
            'id': iface.id,
            'name': iface.name,
            'listen_port': iface.listen_port,
            'dns': iface.dns,
            'mtu': iface.mtu,
            'table': getattr(iface, 'table', None) or '',
            'pre_up': getattr(iface, 'pre_up', None) or '',
            'pre_down': getattr(iface, 'pre_down', None) or '',
            'post_up': getattr(iface, 'post_up', None) or '',
            'post_down': getattr(iface, 'post_down', None) or '',
            'is_up': _iface_up(dev),
        },
    )


@interfaces_bp.get('/api/iface/<int:iid>/status')
@login_required
def iface_status(iid):
    iface = db.session.get(InterfaceConfig, iid) or abort(404)
    dev = iface_devname(iface)
    return jsonify({'is_up': _iface_up(dev), 'name': iface.name, 'dev': dev})


@interfaces_bp.route('/api/iface/<int:iid>/logs', methods=['GET', 'DELETE'])
@login_required
def iface_logs(iid):
    p = _ifacelog_path(iid)
    if request.method == 'DELETE':
        try:
            if os.path.exists(p):
                open(p, 'w').close()
            _last_cleared("iface")
        except Exception:
            return jsonify(ok=False, error="clear_failed"), 500
        return jsonify(ok=True)

    txt = ''
    if os.path.isfile(p):
        try:
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                txt = f.read()[-20000:]
        except Exception:
            txt = ''
    return jsonify(logs=txt)


@interfaces_bp.post('/api/iface/<int:iid>/<action>')
@require_api_key_or_login
def iface_updown(iid, action):
    iface = db.session.get(InterfaceConfig, iid) or abort(404)
    if action not in ('up', 'down'):
        return jsonify(ok=False, error='invalid_action', detail='Action must be up or down.'), 400
    if getattr(iface, 'node_id', None) is not None or ':' in (getattr(iface, 'name', '') or ''):
        return jsonify(ok=False, error='remote_interface', detail='This interface belongs to a node. Use the node interface endpoint.'), 400

    dev = iface_devname(iface)

    try:
        if action == 'up':
            _check_iface_up(iface)
            is_up = _iface_up(dev)
            if not is_up:
                raise RuntimeError(f'Interface {dev} did not become active.')
            try:
                subprocess.run(['systemctl', 'enable', f'wg-quick@{dev}.service'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
            except Exception:
                pass
            _iface_log(iid, f'Interface {dev} brought up from Settings.')
            return jsonify(ok=True, action='up', name=dev, is_up=True, message=f'Interface {dev} is active.')

        # action == 'down'
        if not _iface_up(dev):
            return jsonify(ok=True, action='down', name=dev, is_up=False, message=f'Interface {dev} is already down.')

        proc = subprocess.run(['wg-quick', 'down', dev],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20, check=False)
        output = (proc.stdout or '').strip()
        _iface_log(iid, f'$ wg-quick down {dev}\n{output}'.rstrip())
        is_up = _iface_up(dev)
        if proc.returncode != 0 and is_up:
            return jsonify(ok=False, error='wg_quick_down_failed', detail=output or f'wg-quick down {dev} failed.', is_up=True), 409

        try:
            subprocess.run(['systemctl', 'disable', f'wg-quick@{dev}.service'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
        except Exception:
            pass

        return jsonify(ok=True, action='down', name=dev, is_up=False, message=f'Interface {dev} is down.')

    except subprocess.TimeoutExpired as exc:
        current_app.logger.exception('Interface %s timed out: %s', action, dev)
        _iface_log(iid, f'Interface {action} timed out: {exc}')
        return jsonify(ok=False, error='interface_command_timeout', detail=str(exc), name=dev, is_up=_iface_up(dev)), 504

    except (RuntimeError, FileNotFoundError) as exc:
        current_app.logger.error('Interface %s failed for %s: %s', action, dev, exc)
        _iface_log(iid, f'Interface {action} failed: {exc}')
        return jsonify(ok=False, error=f'interface_{action}_failed', detail=str(exc), name=dev, is_up=_iface_up(dev),
                       hint='Open Interface Logs for the complete output.'), 409

    except Exception as exc:
        current_app.logger.exception('Unexpected interface %s failure for %s', action, dev)
        _iface_log(iid, f'Unexpected interface {action} error: {exc}')
        return jsonify(ok=False, error=f'interface_{action}_error', detail=str(exc), name=dev, is_up=_iface_up(dev)), 500


@interfaces_bp.get('/api/iface/<int:iid>/endpoint-default')
@require_api_key_or_login
def api_iface_endpoint_default_get(iid):
    iface, error = _local_iface_or_error(iid)
    if error is not None:
        return error
    return jsonify(ok=True, **_endpoint_default_payload(iface))


@interfaces_bp.put('/api/iface/<int:iid>/endpoint-default')
@require_api_key_or_login
def api_iface_endpoint_default_put(iid):
    iface, error = _local_iface_or_error(iid)
    if error is not None:
        return error
    data = request.get_json(silent=True) or {}
    try:
        host, port = parse_endpoint_override(data.get('host'), data.get('port'))
    except EndpointValidationError as exc:
        return jsonify(ok=False, error=exc.code, detail=exc.detail), 400

    iface.endpoint_host = host
    iface.endpoint_port = port
    db.session.commit()
    return jsonify(ok=True, **_endpoint_default_payload(iface))


@interfaces_bp.post('/api/iface/<int:iid>/endpoint-default/apply')
@require_api_key_or_login
def api_iface_endpoint_default_apply(iid):
    iface, error = _local_iface_or_error(iid)
    if error is not None:
        return error
    dry_run, overwrite_explicit = _apply_request_flags(request.get_json(silent=True))
    try:
        result = _apply_endpoint_default(
            iface, dry_run=dry_run, overwrite_explicit=overwrite_explicit,
        )
    except EndpointApplyError as exc:
        return jsonify(ok=False, error=exc.code, detail=exc.detail), exc.status
    except Exception as exc:
        db.session.rollback()
        return jsonify(ok=False, error='endpoint_apply_failed', detail=str(exc)), 500

    return jsonify(ok=True, **result)
