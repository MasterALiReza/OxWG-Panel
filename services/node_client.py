"""
OxWg Panel - Remote Node HTTP Client
====================================
HTTP client communication for managing remote WireGuard node agents.
"""
from typing import Any
import json
import requests
from core.crypto import _read_api_key


def _node_payload(r: requests.Response) -> Any:
    """Safely extract payload from a node HTTP response as JSON or text."""
    ctype = (r.headers.get('content-type') or '').split(';', 1)[0].strip().lower()
    if ctype == 'application/json' or ctype.endswith('+json'):
        try:
            return r.json()
        except ValueError:
            return r.text
    text = r.text
    stripped = (text or '').lstrip()
    if stripped[:1] in '{[':
        try:
            return json.loads(text)
        except ValueError:
            pass
    return text


def node_get(n: Any, path: str, timeout: int | float = 6) -> Any:
    """Execute GET request on a remote node agent."""
    r = requests.get(
        f"{n.base_url}{path}",
        headers={'Authorization': f'Bearer {_read_api_key(n)}'},
        timeout=timeout,
    )
    r.raise_for_status()
    return _node_payload(r)


def node_post(n: Any, path: str, payload: Any = None, timeout: int | float = 8) -> Any:
    """Execute POST request with JSON payload on a remote node agent."""
    r = requests.post(
        f"{n.base_url}{path}",
        headers={
            'Authorization': f'Bearer {_read_api_key(n)}',
            'Content-Type': 'application/json',
        },
        json=payload or {},
        timeout=timeout,
    )
    r.raise_for_status()
    return _node_payload(r)


def node_delete(n: Any, path: str, payload: Any = None, timeout: int | float = 8) -> Any:
    """Execute DELETE request on a remote node agent."""
    headers = {
        'Authorization': f'Bearer {_read_api_key(n)}',
    }
    kwargs: dict[str, Any] = {
        'headers': headers,
        'timeout': timeout,
    }
    if payload is not None:
        headers['Content-Type'] = 'application/json'
        kwargs['json'] = payload

    r = requests.delete(f"{n.base_url}{path}", **kwargs)
    r.raise_for_status()
    return _node_payload(r)
