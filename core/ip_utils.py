"""
OxWg Panel - IP and Network Utilities
=====================================
Public IP discovery, CIDR parsing, address host normalization, and caching.
"""
import re
import time
import requests
import ipaddress

_public_ip_cache = {'ip': None, 'ts': 0}
_ipv6_cache = {"ts": 0, "val": ""}


def _public_ipv4(force=False):
    """Retrieve and cache external public IPv4 address."""
    now = time.time()
    if not force and _public_ip_cache['ip'] and (now - _public_ip_cache['ts'] < 3600):
        return _public_ip_cache['ip']
    try:
        ip = requests.get('https://api.ipify.org', timeout=2).text.strip()
        if ip:
            _public_ip_cache['ip'] = ip
            _public_ip_cache['ts'] = now
            return ip
    except Exception:
        pass
    return _public_ip_cache['ip']


def _public_ipv6():
    """Retrieve and cache external public IPv6 address."""
    try:
        now = time.time()
        if _ipv6_cache["val"] and (now - _ipv6_cache["ts"] < 600):
            v = (_ipv6_cache["val"] or "").strip()
            try:
                ip = ipaddress.ip_address(v)
                if ip.version == 6 and ip.is_global:
                    return v
            except Exception:
                pass
            _ipv6_cache.update(ts=now, val="")

        r = requests.get("https://api64.ipify.org", timeout=1.5)
        if not r.ok:
            return _ipv6_cache["val"]

        v = (r.text or "").strip()
        try:
            ip = ipaddress.ip_address(v)
            if ip.version == 6 and ip.is_global:
                _ipv6_cache.update(ts=now, val=v)
                return v
        except Exception:
            pass

        _ipv6_cache.update(ts=now, val="")
        return ""
    except Exception:
        return _ipv6_cache.get("val") or ""


def _safe_ip(cidr):
    """Safely extract IP object from IP address or CIDR string."""
    try:
        return ipaddress.ip_interface(cidr).ip
    except Exception:
        return None


def _first_cidr(address_field: str | None) -> str | None:
    """Extract the first valid IPv4 CIDR from comma-separated list, with IPv6 fallback."""
    if not address_field:
        return None
    parts = [p.strip() for p in re.split(r'[,\s]+', address_field) if p.strip()]
    v4, vX = None, None
    for p in parts:
        if '/' not in p:
            continue
        try:
            net = ipaddress.ip_network(p, strict=False)
            if net.version == 4 and not v4:
                v4 = p
            if not vX:
                vX = p
        except Exception:
            continue
    return v4 or vX


def peer_address_host(address):
    """Normalize a peer CIDR into canonical host string representation."""
    host = _safe_ip(address)
    return str(host) if host is not None else None


def _private_networks() -> list[str]:
    """Return a list of detected private IPv4 network CIDRs on this host."""
    import socket
    import psutil
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
                except Exception:
                    continue
    except Exception:
        pass
    return networks
