"""
OxWg Panel - Short Link Service
===============================
Generation, routing, and database management for client peer shortlinks (/u/<token>).
"""
import secrets
from datetime import datetime, timezone
from typing import Any
from models import db, Peer, ShortLink
from services.panel_settings import _panel_base


def _token() -> str:
    """Generate cryptographically secure 16-byte URL-safe token."""
    return secrets.token_urlsafe(16)


def _shortlink_url(token: str) -> str:
    """
    Construct canonical external URL for a shortlink token.
    Uses Flask url_for if inside request context, otherwise panel_base.
    """
    try:
        from flask import url_for, has_request_context
        if has_request_context():
            try:
                return url_for('shortlinks_bp.user_peer_page', token=token, _external=True)
            except Exception:
                return url_for('user_peer_page', token=token, _external=True)
    except Exception:
        pass

    base = _panel_base().rstrip('/')
    return f"{base}/u/{token}"


def _peer_from_shortlink_token(token: str) -> Peer | None:
    """
    Lookup peer by shortlink token, updating last_used_at timestamp.
    Returns Peer instance or None.
    """
    token = (token or "").strip()
    if not token:
        return None

    link = ShortLink.query.filter_by(token=token).first()
    if not link:
        return None

    try:
        link.last_used_at = datetime.now(timezone.utc)
        db.session.commit()
    except Exception:
        db.session.rollback()

    return db.session.get(Peer, link.peer_id)


def _shortlink_from_peer_id(pid: int | str) -> tuple[str | None, str | None]:
    """Return (token, url) for an existing peer id, or (None, None)."""
    try:
        pid_int = int(pid)
    except Exception:
        return None, None

    link = ShortLink.query.filter_by(peer_id=pid_int).first()
    if not link:
        return None, None

    return link.token, _shortlink_url(link.token)


def _shortlink_for_peer(peer: Peer) -> tuple[str | None, str | None]:
    """Retrieve existing or generate and persist new shortlink for a Peer."""
    if not peer or not getattr(peer, "id", None):
        return None, None

    existing = ShortLink.query.filter_by(peer_id=peer.id).first()
    if existing:
        return existing.token, _shortlink_url(existing.token)

    token = None
    for _ in range(12):
        candidate = _token()
        if not ShortLink.query.filter_by(token=candidate).first():
            token = candidate
            break

    if not token:
        token = secrets.token_urlsafe(24)

    link = ShortLink(token=token, peer_id=peer.id)
    try:
        db.session.add(link)
        db.session.commit()
    except Exception:
        db.session.rollback()
        existing = ShortLink.query.filter_by(peer_id=peer.id).first()
        if existing:
            return existing.token, _shortlink_url(existing.token)
        raise

    return token, _shortlink_url(token)


def _shortlink_response_for_peer(peer: Peer) -> Any:
    """
    Return shortlink response for peer.
    If inside Flask request context, returns jsonify or aborts 404.
    Outside Flask context, returns dict {'url': ..., 'token': ...} or None.
    """
    token, url = _shortlink_for_peer(peer)
    try:
        from flask import has_request_context, jsonify, abort
        if has_request_context():
            if not token or not url:
                abort(404)
            return jsonify(url=url, token=token)
    except Exception:
        pass

    if not token or not url:
        return None
    return {'url': url, 'token': token}


def _delete_shortlinks_for_peer_ids(peer_ids: list[Any]) -> int:
    """Batch delete all shortlinks referencing the specified peer IDs."""
    ids = []
    for x in peer_ids or []:
        try:
            ids.append(int(x))
        except Exception:
            pass

    if not ids:
        return 0

    removed = (
        ShortLink.query
        .filter(ShortLink.peer_id.in_(ids))
        .delete(synchronize_session=False)
    )
    db.session.flush()
    return int(removed or 0)
