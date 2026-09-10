"""
OxWg Panel - WireGuard Client Configuration Generator
======================================================
Generation of client WireGuard .conf text, endpoint resolution, and DNS inheritance.
"""
import re
import ipaddress
import logging
from typing import Any

from models import Peer, InterfaceConfig
from services.errors import ClientConfigIncomplete
from services.peer_profiles import _panel_default_dns
from services.wg_parser import _valid_wg_key, _derive_wg_public_key
from services.panel_settings import _norm_hostport, _server_host

logger = logging.getLogger(__name__)

_DNS_LABEL_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
_HOST_FORBIDDEN = ('://', '/', '@', '?', '#', '\\')


class EndpointValidationError(ValueError):
    """Validation error for peer or interface endpoint strings."""
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _effective_dns(peer: Peer | Any) -> str:
    """
    Resolve effective DNS for a peer:
    Peer DNS -> Interface DNS -> Active Panel Profile Default DNS.
    """
    iface = getattr(peer, 'iface', None)
    return (
        getattr(peer, 'dns', None)
        or (getattr(iface, 'dns', None) if iface is not None else None)
        or _panel_default_dns()
        or '1.1.1.1, 1.0.0.1'
    ).strip()


def _server_publickey(iface: InterfaceConfig | Any, *, persist: bool = False) -> str:
    """
    Resolve the server public key for an interface (local or remote node).
    Returns validated public key string or empty string.
    """
    if iface is None:
        return ''

    iface_id = getattr(iface, 'id', None)
    cache = None
    if iface_id is not None:
        try:
            from flask import g
            cache = getattr(g, '_server_pubkey_cache', None)
            if cache is None:
                g._server_pubkey_cache = cache = {}
        except Exception:
            cache = None
        if cache is not None and iface_id in cache:
            return cache[iface_id]

    result = _resolve_server_publickey(iface, persist=persist)
    if cache is not None and iface_id is not None:
        cache[iface_id] = result
    return result


def _resolve_server_publickey(iface: Any, *, persist: bool = False) -> str:
    from services.wg_parser import (
        _iface_is_node,
        _fetch_node_iface_public_key,
        _persist_iface_public_key,
    )

    if _iface_is_node(iface):
        stored = _valid_wg_key(getattr(iface, 'public_key', None) or '')
        pk = _fetch_node_iface_public_key(iface) if not stored else ''
        if not pk and stored:
            return stored
        if pk:
            if persist and pk != stored:
                _persist_iface_public_key(iface, pk)
            return pk
        return stored or ''

    pk = _derive_wg_public_key(getattr(iface, 'private_key', None))
    if pk:
        stored = _valid_wg_key(getattr(iface, 'public_key', None) or '')
        if persist and pk != stored:
            _persist_iface_public_key(iface, pk)
        return pk

    stored = _valid_wg_key(getattr(iface, 'public_key', None) or '')
    if stored:
        return stored

    return ''


def _parse_endpoint_host(value: str) -> str:
    """Normalize and validate endpoint host (domain or IPv4/IPv6)."""
    if any(ch.isspace() for ch in value):
        raise EndpointValidationError('endpoint_host_whitespace', 'The host may not contain whitespace.')

    for token in _HOST_FORBIDDEN:
        if token in value:
            raise EndpointValidationError('endpoint_host_not_a_host', 'The host must be a bare name or IP address.')

    bracketed = value.startswith('[') and value.endswith(']')
    candidate = value[1:-1] if bracketed else value

    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        pass

    if bracketed:
        raise EndpointValidationError('endpoint_host_invalid', 'Bracketed hosts must be valid IPv6 addresses.')

    if ':' in candidate:
        raise EndpointValidationError('endpoint_host_has_port', 'Host must not contain a port.')

    name = candidate[:-1] if candidate.endswith('.') else candidate
    if not name or len(name) > 253:
        raise EndpointValidationError('endpoint_host_invalid', 'Host length must be between 1 and 253 characters.')

    for label in name.split('.'):
        if not _DNS_LABEL_RE.match(label):
            raise EndpointValidationError('endpoint_host_invalid', f'Invalid DNS label: {label}')

    return name.lower()


def _parse_endpoint_port(value: Any) -> int:
    """Parse and validate endpoint port number."""
    if isinstance(value, bool):
        raise EndpointValidationError('endpoint_port_invalid', 'Port must be an integer.')
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        raise EndpointValidationError('endpoint_port_invalid', 'Port must be an integer.')

    if not 1 <= port <= 65535:
        raise EndpointValidationError('endpoint_port_range', 'Port must be between 1 and 65535.')
    return port


def parse_endpoint_string(value: str) -> str:
    """Parse string 'host:port' into validated endpoint representation."""
    text_value = (value or '').strip()
    if not text_value:
        return ''

    from services.peer_lifecycle import _host_port
    host, port = _host_port(text_value)
    if not host or not port:
        raise EndpointValidationError('endpoint_invalid', 'The endpoint must be host:port.')

    host_clean = _parse_endpoint_host(host)
    port_clean = _parse_endpoint_port(port)
    return _norm_hostport(host_clean, port_clean)


def _safe_explicit_endpoint(explicit: str | None) -> str:
    """Clean and validate explicit peer endpoint override."""
    explicit = (explicit or '').strip()
    if not explicit:
        return ''
    try:
        return parse_endpoint_string(explicit)
    except EndpointValidationError as exc:
        logger.warning('Ignoring malformed peer endpoint %r: %s', explicit, exc.detail)
        return ''


def iface_endpoint_override(iface: Any) -> str:
    """Return interface saved endpoint override if complete."""
    if iface is None:
        return ''
    host = (getattr(iface, 'endpoint_host', None) or '').strip()
    port = getattr(iface, 'endpoint_port', None)
    if not host or not port:
        return ''
    return _norm_hostport(host, int(port))


def _endpoint_fallback(iface: Any) -> str:
    """Fallback endpoint for local interface (server host + listen_port)."""
    host = _server_host()
    port = getattr(iface, 'listen_port', None)
    return _norm_hostport(host, port) if host and port else ''


def remote_iface_name(iface: Any) -> str:
    """'wg0' from a node mirror row named 'n3:wg0'; the plain name otherwise."""
    name = (getattr(iface, 'name', '') or '').strip()
    return name.split(':', 1)[1] if ':' in name else name


def _node_endpoint_fallback(
    node: Any,
    iface_name: str,
    remote_iface: Any = None,
    interfaces_payload: Any = None,
) -> str:
    remote_iface = remote_iface if isinstance(remote_iface, dict) else {}
    interfaces_payload = interfaces_payload if isinstance(interfaces_payload, dict) else {}

    host = str(interfaces_payload.get('public_ipv4') or '').strip()
    if not host and node:
        try:
            from services.node_client import node_get
            health = node_get(node, '/api/health', timeout=6) or {}
            if isinstance(health, dict):
                host = str(health.get('public_ipv4') or '').strip()
        except Exception:
            host = ''

    if not host and node:
        try:
            from urllib.parse import urlparse
            parsed = urlparse((getattr(node, 'base_url', '') or '').strip())
            host = (parsed.hostname or '').strip()
        except Exception:
            host = ''

    port = remote_iface.get('listen_port')
    if not port and node and iface_name:
        try:
            from services.node_client import node_get
            data = node_get(node, f'/api/iface/{iface_name}', timeout=6) or {}
            if isinstance(data, dict):
                port = data.get('listen_port')
        except Exception:
            pass

    return _norm_hostport(host, int(port)) if host and port else ''


def resolve_client_endpoint_cheap(iface: Any, explicit: str | None = None) -> str:
    """Resolve client endpoint cheaply without performing remote network requests."""
    safe_explicit = _safe_explicit_endpoint(explicit)
    if safe_explicit:
        return safe_explicit

    if iface is None:
        return ''

    override = iface_endpoint_override(iface)
    if override:
        return override

    from services.wg_parser import _iface_is_node
    if _iface_is_node(iface):
        return ''

    try:
        return (_endpoint_fallback(iface) or '').strip()
    except Exception:
        return ''


def resolve_client_endpoint(
    iface: Any,
    explicit: str | None = None,
    *,
    node: Any = None,
    remote_iface: Any = None,
) -> str:
    """Resolve effective WireGuard endpoint for peer."""
    safe_explicit = _safe_explicit_endpoint(explicit)
    if safe_explicit:
        return safe_explicit

    if iface is None:
        return ''

    override = iface_endpoint_override(iface)
    if override:
        return override

    try:
        from services.wg_parser import _iface_is_node
        if _iface_is_node(iface):
            return (_node_endpoint_fallback(
                node or getattr(iface, 'node', None),
                remote_iface_name(iface),
                remote_iface,
            ) or '').strip()

        return (_endpoint_fallback(iface) or '').strip()
    except Exception:
        return ''


def _effective_client_endpoint(peer: Peer | Any) -> str:
    """Resolve client endpoint for peer."""
    return resolve_client_endpoint(
        getattr(peer, 'iface', None),
        explicit=getattr(peer, 'endpoint', None),
    )


def _client_conf_txt(peer: Peer | Any) -> str:
    """Generate standard WireGuard client configuration file text."""
    iface = getattr(peer, 'iface', None)
    server_pub = _server_publickey(iface)
    if not server_pub:
        raise ClientConfigIncomplete('server_public_key_unavailable')

    dns_val = _effective_dns(peer)
    ep = _effective_client_endpoint(peer)
    mtu_val = getattr(peer, 'mtu', None) or (getattr(iface, 'mtu', None) if iface else None)

    lines = [
        "[Interface]",
        f"PrivateKey = {getattr(peer, 'private_key', '')}",
        f"Address = {getattr(peer, 'address', '')}",
    ]
    if dns_val:
        lines.append(f"DNS = {dns_val}")
    if mtu_val:
        lines.append(f"MTU = {mtu_val}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_pub}")
    if ep:
        lines.append(f"Endpoint = {ep}")
    allowed_ips = getattr(peer, 'allowed_ips', None) or '0.0.0.0/0, ::/0'
    lines.append(f"AllowedIPs = {allowed_ips}")
    keepalive = getattr(peer, 'persistent_keepalive', None)
    if keepalive:
        lines.append(f"PersistentKeepalive = {keepalive}")
    lines.append("")

    return "\n".join(lines)


def _client_config_txt(peer: Peer | Any) -> str:
    """Alias for _client_conf_txt."""
    return _client_conf_txt(peer)


def _peer_client_conf_or_502(peer: Peer | Any) -> tuple[str | None, tuple[Any, int] | None]:
    """
    Attempt to build client configuration text.
    Returns (conf_text, None) on success, or (None, (error_dict, 502)) on missing server public key.
    """
    try:
        return _client_conf_txt(peer), None
    except ClientConfigIncomplete as exc:
        return None, (
            {
                'ok': False,
                'error': 'server_public_key_unavailable',
                'message': 'The server PublicKey for this interface is not available.',
            },
            502,
        )
