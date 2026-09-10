"""
OxWg Panel - URL and SSRF Safety Utilities
==========================================
Validation for redirects, remote node base URLs, and URL scheme normalization.
"""
import socket
import ipaddress
from urllib.parse import urlparse, urljoin


def _http_url(u: str) -> bool:
    """Validate that string is a non-empty HTTP/HTTPS URL."""
    try:
        p = urlparse((u or '').strip())
        return p.scheme in ('http', 'https') and bool(p.netloc)
    except Exception:
        return False


def _safe_url(target: str, host_url: str = None) -> bool:
    """Ensure redirect target URL stays on the same host."""
    try:
        if host_url is None:
            from flask import request, has_request_context
            if has_request_context():
                host_url = request.host_url
            else:
                return False
        ref = urlparse(host_url)
        test = urlparse(urljoin(host_url, target or ''))
        return (test.scheme in ('http', 'https')) and (ref.netloc == test.netloc)
    except Exception:
        return False


def _norm_base_url(u: str) -> str:
    """Normalize base URL by trimming trailing slashes and whitespace."""
    u = (u or '').strip()
    return u[:-1] if u.endswith('/') else u


def _validate_node_base_url(base_url: str) -> tuple[bool, str]:
    """Validate a node base_url to eliminate SSRF risks.

    Rules:
      - Must be a valid http:// or https:// URL.
      - Must not resolve to loopback/private/link-local/reserved/multicast/unspecified IPs.
      - Cloud metadata IP (169.254.169.254) is forbidden.
    """
    base_url = (base_url or '').strip().rstrip('/')
    if not _http_url(base_url):
        return False, 'invalid base_url'

    try:
        p = urlparse(base_url)
        scheme = (p.scheme or '').lower()

        if scheme not in ('http', 'https'):
            return False, 'nodes must use http or https'

        host = (p.hostname or '').strip()
        if not host:
            return False, 'invalid host'

        if host in ('localhost', '127.0.0.1', '::1'):
            return False, 'loopback hosts are not allowed'

        infos = []
        try:
            infos = socket.getaddrinfo(
                host,
                p.port or (443 if scheme == 'https' else 80),
                type=socket.SOCK_STREAM,
            )
        except Exception:
            infos = []

        for info in infos:
            addr = info[4][0]
            try:
                ip = ipaddress.ip_address(addr)
            except Exception:
                continue

            if (
                ip.is_loopback
                or ip.is_private
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                return False, f'host resolves to non-public IP ({ip})'

        if host == '169.254.169.254':
            return False, 'metadata IP is not allowed'

        return True, ''
    except Exception as e:
        return False, f'URL validation error: {e}'
