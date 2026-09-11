"""
OxWg Panel - WireGuard Parser and Public Key Derivation
======================================================
Parsing of WireGuard .conf configuration files and deterministic cryptographic key derivation.
"""
import os
import re
import json
import logging
import subprocess
from typing import Any
from models import InterfaceConfig

logger = logging.getLogger(__name__)

_WG_KEY_RE = re.compile(r'^[A-Za-z0-9+/]{43}=$')
_PUBKEY_CACHE: dict[str, str] = {}


def _valid_wg_key(value: Any) -> str:
    """Validate 44-character Base64 WireGuard key representation."""
    s = str(value or '').strip()
    return s if s and _WG_KEY_RE.fullmatch(s) else ''


def _derive_wg_public_key(priv: str) -> str:
    """
    Derive Curve25519 public key from private key using 'wg pubkey'.
    Memoizes results in memory for performance.
    """
    priv = (priv or '').strip()
    if not priv or priv == '(remote)':
        return ''

    if priv in _PUBKEY_CACHE:
        return _PUBKEY_CACHE[priv]

    try:
        from flask import g
        if hasattr(g, '_wg_pubkey_cache') and priv in g._wg_pubkey_cache:
            return g._wg_pubkey_cache[priv]
    except Exception:
        pass

    try:
        out = subprocess.check_output(
            ['wg', 'pubkey'],
            input=(priv + '\n').encode(),
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        )
        pk = _valid_wg_key(out.decode().strip())
    except Exception:
        pk = ''

    if not pk:
        try:
            import base64
            from cryptography.hazmat.primitives.asymmetric import x25519
            raw = base64.b64decode(priv)
            if len(raw) == 32:
                k = x25519.X25519PrivateKey.from_private_bytes(raw)
                pk = _valid_wg_key(base64.b64encode(k.public_key().public_bytes_raw()).decode('ascii'))
        except Exception:
            pk = ''

    if pk:
        _PUBKEY_CACHE[priv] = pk
        try:
            from flask import g
            if not hasattr(g, '_wg_pubkey_cache'):
                g._wg_pubkey_cache = {}
            g._wg_pubkey_cache[priv] = pk
        except Exception:
            pass

    return pk


def generate_wg_keypair() -> tuple[str, str]:
    """
    Generate a new WireGuard (Curve25519) private and public keypair.
    Uses 'wg genkey' / 'wg pubkey' if available, otherwise pure Python X25519.
    """
    try:
        priv = subprocess.check_output(
            ['wg', 'genkey'],
            stderr=subprocess.DEVNULL,
            timeout=3.0,
        ).strip().decode()
        pub = _derive_wg_public_key(priv)
        if priv and pub:
            return priv, pub
    except Exception:
        pass

    import base64
    from cryptography.hazmat.primitives.asymmetric import x25519
    key = x25519.X25519PrivateKey.generate()
    priv = base64.b64encode(key.private_bytes_raw()).decode('ascii')
    pub = base64.b64encode(key.public_key().public_bytes_raw()).decode('ascii')
    return priv, pub


def _assign_iface_public_key(iface: Any, value: str) -> str:
    """Assign validated public key to interface model object."""
    pk = _valid_wg_key(value)
    if iface is not None and pk and getattr(iface, 'public_key', None) != pk:
        iface.public_key = pk
    return pk


def find_iface(path: str) -> InterfaceConfig | None:
    """
    Parse a standard WireGuard interface configuration file (.conf).
    Returns populated InterfaceConfig instance or None if required fields are missing.
    """
    if not os.path.isfile(path):
        return None

    post_up, post_down = [], []
    address = listen_port = private_key = mtu = dns = None
    in_iface = False

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('[') and line.endswith(']'):
                    in_iface = (line[1:-1].strip().lower() == 'interface')
                    continue
                if not in_iface or '=' not in line:
                    continue

                key, val = [s.strip() for s in line.split('=', 1)]
                lk = key.lower()
                if lk == 'address':
                    address = val
                elif lk == 'listenport':
                    try:
                        listen_port = int(val)
                    except Exception:
                        pass
                elif lk == 'privatekey':
                    private_key = val
                elif lk == 'mtu':
                    try:
                        mtu = int(val)
                    except Exception:
                        pass
                elif lk == 'dns':
                    dns = val
                elif lk == 'postup':
                    post_up.append(val)
                elif lk == 'postdown':
                    post_down.append(val)
    except Exception:
        return None

    if not (address and listen_port and private_key):
        return None

    return InterfaceConfig(
        name=os.path.splitext(os.path.basename(path))[0],
        path=path,
        address=address,
        listen_port=listen_port,
        private_key=private_key,
        mtu=mtu,
        dns=dns,
        post_up='\n'.join(post_up),
        post_down='\n'.join(post_down),
    )


def _copy_local_iface_from_parsed(existing: Any, parsed: Any) -> Any:
    """Sync attributes from parsed interface configuration onto an existing DB model."""
    new_priv = getattr(parsed, 'private_key', None)
    if (existing.private_key or '') != (new_priv or ''):
        existing.public_key = None
    existing.path = parsed.path
    existing.address = parsed.address
    existing.listen_port = parsed.listen_port
    existing.private_key = new_priv
    existing.mtu = parsed.mtu
    existing.dns = parsed.dns
    existing.post_up = parsed.post_up
    existing.post_down = parsed.post_down

    pk = _derive_wg_public_key(new_priv)
    if pk:
        _assign_iface_public_key(existing, pk)
    return existing


def _iface_is_node(iface: Any) -> bool:
    """Check if interface belongs to a remote node."""
    if iface is None:
        return False
    if isinstance(iface, str):
        return ':' in iface
    name = getattr(iface, 'name', '') or ''
    return getattr(iface, 'node_id', None) is not None or (':' in name)


def iface_devname(iface: Any) -> str:
    """Return device name without node prefix (e.g. 'wg0' from 'n1:wg0')."""
    if iface is None:
        return ''
    name = iface if isinstance(iface, str) else (getattr(iface, 'name', '') or '')
    if not name and not isinstance(iface, str):
        path = getattr(iface, 'path', '') or ''
        name = os.path.splitext(os.path.basename(path))[0]
    return name.split(':')[-1]


def _node_id_from_iface(iface: Any) -> int | None:
    """Extract node id integer from interface object or interface name."""
    if iface is None:
        return None
    nid = getattr(iface, 'node_id', None)
    if nid is not None:
        try:
            return int(nid)
        except Exception:
            return None
    name = iface if isinstance(iface, str) else (getattr(iface, 'name', '') or '')
    if ':' not in name:
        return None
    parts = name.split(':')
    for p in parts[:-1]:
        if p.startswith('node') and p[4:].isdigit():
            return int(p[4:])
        if p.startswith('n') and p[1:].isdigit():
            return int(p[1:])
        if p.isdigit():
            return int(p)
    return None


def _public_key_from_node_payload(payload: Any) -> str:
    """Extract and validate WireGuard public key from remote node response payload."""
    if isinstance(payload, str):
        direct = _valid_wg_key(payload)
        if direct:
            return direct
        try:
            payload = json.loads(payload)
        except Exception:
            return ''
    if isinstance(payload, dict):
        return _valid_wg_key(payload.get('public_key') or '')
    return ''


def _persist_iface_public_key(iface: Any, pk: str) -> str:
    """Assign and best-effort persist public key to the database."""
    pk = _assign_iface_public_key(iface, pk)
    iface_id = getattr(iface, 'id', None) if iface is not None else None
    if not pk or not iface_id:
        return pk
    try:
        from models import db
        from sqlalchemy import text
        with db.engine.begin() as conn:
            conn.execute(
                text('UPDATE interface_config SET public_key = :pk WHERE id = :iface_id'),
                {'pk': pk, 'iface_id': iface_id},
            )
    except Exception:
        pass
    return pk


def _fetch_node_iface_public_key(iface: Any) -> str:
    """Fetch public key for a remote node interface via node agent HTTP API."""
    nid = _node_id_from_iface(iface)
    if nid is None:
        return ''
    try:
        from models import db, Node
        n = db.session.get(Node, nid)
    except Exception:
        n = None
    if n is None:
        return ''

    dev = iface_devname(iface)
    use_list = False

    try:
        from services.node_client import node_get
        j = node_get(n, f'/api/iface/{dev}/pubkey', timeout=6)
        pk = _public_key_from_node_payload(j)
        if pk:
            return pk
        if isinstance(j, dict) and (j.get('error') or '') == 'pubkey_unavailable':
            use_list = True
    except Exception:
        use_list = True

    if not use_list:
        return ''

    try:
        from services.node_client import node_get
        data = node_get(n, '/api/interfaces?fast=1', timeout=6) or {}
        rows = data.get('interfaces') if isinstance(data, dict) else data
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            if str(row.get('name') or '') == str(dev):
                pk = _valid_wg_key(row.get('public_key') or '')
                if pk:
                    return pk
                break
    except Exception:
        pass

    return ''
