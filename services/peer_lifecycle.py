"""
OxWg Panel - Peer Lifecycle and Expiry Enforcer
===============================================
Peer expiration tracking, traffic accumulation, automatic timer triggering, and boot reconciliation.
"""
import os
import time
import threading
import subprocess
import logging
import ipaddress
from typing import Any
from datetime import datetime, timezone

from models import db, Peer
from core.time_utils import now_ts, from_ts, to_ts, add_days_ts
from core.ip_utils import _public_ipv4
from core.paths import LAST_PUBLIC_IP_FILE
from services.telegram_notifier import _send_telegram_event

logger = logging.getLogger(__name__)

_EXPIRY_LOCK = threading.Lock()
_EXPIRY_THREAD_STARTED = False
_APP_REF: Any = None


def set_app(app: Any) -> None:
    """Register the Flask application instance for background threads."""
    global _APP_REF
    _APP_REF = app


def _get_app_context():
    """Retrieve active or configured Flask application context."""
    global _APP_REF
    if _APP_REF is not None:
        return _APP_REF.app_context()
    try:
        from flask import current_app
        if current_app:
            return current_app.app_context()
    except Exception:
        pass
    from contextlib import nullcontext
    return nullcontext()


try:
    _EXPIRY_INTERVAL_SEC = max(5, int(os.getenv('WG_EXPIRY_INTERVAL_SEC', '15')))
except Exception:
    _EXPIRY_INTERVAL_SEC = 15


def _conv_time_limit(payload: dict[str, Any] | Any) -> float:
    """Return requested peer duration as fractional days from dictionary or model."""
    try:
        if isinstance(payload, dict):
            raw_days = max(0.0, float(payload.get('time_limit_days') or 0))
            has_components = 'time_limit_hours' in payload or 'time_limit_minutes' in payload
            days = float(int(raw_days)) if has_components else raw_days
            hours = max(0.0, min(23.0, float(payload.get('time_limit_hours') or 0)))
            minutes = max(0.0, min(59.0, float(payload.get('time_limit_minutes') or 0)))
        else:
            raw_days = max(0.0, float(getattr(payload, 'time_limit_days', 0) or 0))
            hours = max(0.0, min(23.0, float(getattr(payload, 'time_limit_hours', 0) or 0)))
            minutes = max(0.0, min(59.0, float(getattr(payload, 'time_limit_minutes', 0) or 0)))
            has_components = (hours > 0 or minutes > 0)
            days = float(int(raw_days)) if has_components else raw_days

        return float(days + (hours / 24.0) + (minutes / 1440.0))
    except Exception:
        return 0.0


def _timer_duration_days(record: Any) -> float | None:
    """Return valid timer duration in days or None."""
    days = _conv_time_limit(record)
    return days if days > 0 else None


def _timer_anchor_ts(record: Any) -> int | None:
    """Return the UTC epoch anchor for the current timer cycle."""
    if bool(getattr(record, 'start_on_first_use', False)):
        return to_ts(getattr(record, 'first_used_at', None))

    return (
        to_ts(getattr(record, 'timer_started_at', None))
        or to_ts(getattr(record, 'created_at', None))
    )


def _effective_expiry_ts(record: Any) -> int | None:
    """Calculate effective expiration timestamp from anchor and duration."""
    if bool(getattr(record, 'unlimited', False)):
        return None

    days = _timer_duration_days(record)
    anchor_ts = _timer_anchor_ts(record)
    if not days or not anchor_ts:
        return None

    return add_days_ts(anchor_ts, days)


def _sync_effective_expiry(record: Any) -> bool:
    """Persist canonical expiry timestamp onto the model instance."""
    expected_ts = _effective_expiry_ts(record)
    current_ts = to_ts(getattr(record, 'expires_at', None))
    if current_ts == expected_ts:
        return False

    record.expires_at = from_ts(expected_ts)
    return True


def _start_timer_cycle(record: Any, anchor_ts: int | None = None) -> bool:
    """Start or restart a peer timer cycle."""
    anchor_ts = int(anchor_ts or now_ts())
    record.timer_started_at = from_ts(anchor_ts)
    return _sync_effective_expiry(record)


def _clear_timer_cycle(record: Any) -> None:
    """Reset timer cycle tracking."""
    record.timer_started_at = None
    record.expires_at = None


def _wg_rx_tx(peer: Any) -> tuple[int, int]:
    """Read transfer byte counters (rx, tx) for peer from wg subprocess."""
    try:
        iface = getattr(peer, 'iface', None)
        iface_name = getattr(iface, 'name', '') if iface else ''
        if not iface_name:
            return 0, 0
        out = subprocess.check_output(
            ['wg', 'show', iface_name, 'transfer'],
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        ).decode().splitlines()
        for ln in out:
            parts = ln.split()
            if len(parts) >= 3 and parts[0] == peer.public_key:
                return int(parts[1]), int(parts[2])
    except Exception:
        pass
    return 0, 0


def _wg_transfer(peer: Any) -> int:
    """Sum rx and tx transfer bytes for peer."""
    rx, tx = _wg_rx_tx(peer)
    return rx + tx


def _latest_handshake(peer: Any) -> int:
    """Query WireGuard for latest handshake epoch timestamp for peer."""
    try:
        iface = getattr(peer, 'iface', None)
        iface_name = getattr(iface, 'name', '') if iface else ''
        if not iface_name:
            return 0
        out = subprocess.check_output(
            ['wg', 'show', iface_name, 'latest-handshakes'],
            stderr=subprocess.DEVNULL,
            timeout=2.0,
        ).decode().splitlines()
        for ln in out:
            parts = ln.split()
            if len(parts) >= 2 and parts[0] == peer.public_key:
                return int(parts[1]) if parts[1].isdigit() else 0
    except Exception:
        pass
    return 0


def _accumulate_peer_usage(peer: Any, live_total: int | None = None) -> tuple[int, int, bool]:
    """
    Persist WireGuard cumulative traffic across server/interface reboots.
    Returns: (used_total_bytes, live_delta_bytes, changed)
    """
    if peer is None:
        return 0, 0, False
    changed = False
    try:
        live = int(_wg_transfer(peer) if live_total is None else (live_total or 0))
    except Exception:
        live = 0
    live = max(0, live)

    try:
        offset = int(getattr(peer, 'bytes_offset', 0) or 0)
    except Exception:
        offset = 0

    try:
        persisted = int(getattr(peer, 'used_bytes_total', 0) or 0)
    except Exception:
        persisted = 0

    offset = max(0, offset)
    persisted = max(0, persisted)

    if live < offset:
        offset = 0
        if int(getattr(peer, 'bytes_offset', 0) or 0) != 0:
            peer.bytes_offset = 0
            changed = True

    delta = max(0, live - offset)
    if delta > 0:
        persisted += delta
        peer.used_bytes_total = persisted
        peer.bytes_offset = live
        changed = True
    else:
        if getattr(peer, 'used_bytes_total', None) is None:
            peer.used_bytes_total = persisted
            changed = True
        if getattr(peer, 'bytes_offset', None) is None:
            peer.bytes_offset = live
            changed = True

    return int(persisted), int(delta), bool(changed)


def _wg_runtime_snapshot(iface_names: Any) -> tuple[dict[tuple[str, str], tuple[int, int]], dict[tuple[str, str], int]]:
    """
    Query WireGuard runtime dump for given interface names.
    Returns (transfers_map, handshakes_map) keyed by (iface_name, public_key).
    """
    transfers: dict[tuple[str, str], tuple[int, int]] = {}
    handshakes: dict[tuple[str, str], int] = {}
    names = {str(name or '').strip() for name in (iface_names or []) if str(name or '').strip()}

    for iface_name in sorted(names):
        try:
            dev = iface_name.split(':')[-1]
            lines = subprocess.check_output(
                ['wg', 'show', dev, 'dump'],
                stderr=subprocess.DEVNULL,
                timeout=2.0,
            ).decode(errors='replace').splitlines()

            for line in lines[1:]:
                columns = line.split('\t')
                if len(columns) < 8:
                    columns = line.split()
                if len(columns) < 8:
                    continue
                public_key = columns[0].strip()
                if not public_key:
                    continue
                try:
                    latest_handshake = int(columns[4] or 0)
                except (TypeError, ValueError):
                    latest_handshake = 0
                try:
                    rx_bytes = int(columns[5] or 0)
                    tx_bytes = int(columns[6] or 0)
                except (TypeError, ValueError):
                    rx_bytes = 0
                    tx_bytes = 0
                key = (iface_name, public_key)
                transfers[key] = (rx_bytes, tx_bytes)
                handshakes[key] = latest_handshake
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, OSError):
            continue

    return transfers, handshakes


def _peer_ip_plain(peer: Any) -> str:
    """Extract plain IP from peer address string."""
    addr = getattr(peer, 'address', '') or ''
    if not addr:
        return ''
    return addr.split('/')[0].split(',')[0].strip()


def _peer_ping_ok(peer: Any, timeout_sec: float = 0.8) -> bool:
    """Ping peer IP via interface device name."""
    ip = _peer_ip_plain(peer)
    if not ip:
        return False

    try:
        from services.wg_parser import iface_devname
        dev = iface_devname(getattr(peer, 'iface', None))
    except Exception:
        dev = getattr(getattr(peer, 'iface', None), 'name', '') or ''

    if not dev:
        return False

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 6:
            cmd = ['ping', '-6', '-I', dev, '-c', '1', '-W', '1', ip]
        else:
            cmd = ['ping', '-I', dev, '-c', '1', '-W', '1', ip]

        return subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(1.0, float(timeout_sec) + 0.5)
        ).returncode == 0
    except Exception:
        return False


def _peer_conn_status(
    peer: Any,
    *,
    live_total: int | None = None,
    latest_handshake: int | None = None,
    handshake_window: int | None = None,
    allow_probe: bool = True,
) -> dict[str, Any]:
    """Determine the peer's live WireGuard connection state."""
    now = now_ts()

    try:
        if handshake_window is None:
            handshake_window = int(os.environ.get('WG_ONLINE_HANDSHAKE_WINDOW', '45'))
        else:
            handshake_window = int(handshake_window)
    except (TypeError, ValueError):
        handshake_window = 45

    handshake_window = max(5, handshake_window)

    probe_first = str(
        os.environ.get('WG_ONLINE_PROBE_FIRST', '1')
    ).strip().lower() not in ('0', 'false', 'no', 'off')

    handshake_fallback = str(
        os.environ.get('WG_ONLINE_HANDSHAKE_FALLBACK', '1')
    ).strip().lower() in ('1', 'true', 'yes', 'on')

    try:
        if latest_handshake is None:
            handshake = int(_latest_handshake(peer) or 0)
        else:
            handshake = int(latest_handshake or 0)
    except (TypeError, ValueError):
        handshake = 0
    except Exception:
        handshake = 0

    handshake = max(0, handshake)

    handshake_age = (
        max(0, now - handshake)
        if handshake > 0
        else None
    )

    handshake_fresh = bool(
        handshake > 0
        and handshake_age is not None
        and handshake_age <= handshake_window
    )

    try:
        if live_total is None:
            live = int(_wg_transfer(peer) or 0)
        else:
            live = int(live_total or 0)
    except (TypeError, ValueError):
        live = 0
    except Exception:
        live = 0

    live = max(0, live)

    try:
        offset = int(getattr(peer, 'bytes_offset', 0) or 0)
    except (TypeError, ValueError):
        offset = 0

    offset = max(0, offset)
    traffic_now = live > offset

    panel_status = str(getattr(peer, 'status', '') or '').strip().lower()
    panel_enabled = panel_status == 'online'
    panel_blocked = panel_status == 'blocked'

    ping_ok = False
    probed = False

    if allow_probe and panel_enabled and probe_first:
        probed = True
        try:
            ping_ok = bool(_peer_ping_ok(peer))
        except Exception:
            ping_ok = False

        if ping_ok:
            online = True
            reason = 'probe'
        elif handshake_fallback and handshake_fresh:
            online = True
            reason = 'handshake'
        elif traffic_now:
            online = True
            reason = 'traffic'
        else:
            online = False
            reason = 'probe_failed'
    else:
        if panel_blocked:
            online = False
            reason = 'blocked'
        elif handshake_fresh:
            online = True
            reason = 'handshake'
        elif traffic_now:
            online = True
            reason = 'traffic'
        elif not panel_enabled:
            online = False
            reason = 'disabled'
        else:
            online = False
            reason = 'no_recent_activity'

    connection_status = 'online' if online else 'offline'

    return {
        'conn_status': connection_status,
        'connection_status': connection_status,
        'latest_handshake': handshake,
        'latest_handshake_age': handshake_age,
        'conn_reason': reason,
        'conn_probe': bool(probed),
        'probe_ok': bool(ping_ok),
        'traffic_now': bool(traffic_now),
        'live_total': int(live),
        'handshake_fresh': bool(handshake_fresh),
        'handshake_window': int(handshake_window),
    }


def _wg_disable_peer_quiet(peer: Any) -> None:
    """Disable peer on local WireGuard interface quietly."""
    try:
        iface = getattr(peer, 'iface', None)
        if iface and getattr(iface, 'name', None):
            subprocess.run(
                ['wg', 'set', iface.name, 'peer', peer.public_key, 'remove'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2.0,
            )
    except Exception:
        pass


def _disable_peer(peer: Any, reason: str = 'manual', status: str = 'offline') -> bool:
    """
    Disable peer on local WireGuard interface or remote node agent,
    update status, and append PeerEvent.
    """
    try:
        iface = getattr(peer, 'iface', None)
        from services.wg_parser import _iface_is_node, _node_id_from_iface
        if _iface_is_node(iface):
            nid = _node_id_from_iface(iface)
            if nid is not None:
                try:
                    from models import Node
                    n = db.session.get(Node, nid)
                    if n:
                        from services.node_client import node_post
                        payload = {}
                        try:
                            addr = getattr(peer, 'address', '')
                            if addr:
                                import ipaddress
                                ip = ipaddress.ip_interface(addr).ip
                                mask = 32 if ip.version == 4 else 128
                                payload['host_cidr'] = f"{ip}/{mask}"
                        except Exception:
                            pass
                        node_post(n, f'/api/peer/{peer.public_key}/disable', payload)
                except Exception as exc:
                    logger.warning("Disable peer on remote node failed for peer %s: %s", getattr(peer, 'id', '?'), exc)
        else:
            _wg_disable_peer_quiet(peer)

        peer.status = status
        try:
            from models import PeerEvent
            ev = PeerEvent(peer_id=peer.id, event_type=reason, detail=f'status → {status}')
            db.session.add(ev)
        except Exception:
            pass
        return True
    except Exception as exc:
        logger.exception("Disable failed for peer %s: %s", getattr(peer, 'id', '?'), exc)
        return False


def _expire() -> bool:
    """
    Check all peers for first-use handshakes, time-limit expiration, and data quota exhaustion.
    Disables expired peers and queues notifications.
    """
    now = now_ts()
    changed = False
    pending_notifications: list[dict[str, Any]] = []

    from services.wg_parser import _iface_is_node

    for peer in Peer.query.all():
        # First-use tracking: track for ALL peers on initial handshake
        if not getattr(peer, 'first_used_at', None):
            hs = _latest_handshake(peer)
            if hs and hs > 0:
                peer.first_used_at = from_ts(hs)
                peer.timer_started_at = from_ts(hs)
                if (
                    getattr(peer, 'start_on_first_use', False)
                    and getattr(peer, 'time_limit_days', None)
                    and not getattr(peer, 'unlimited', False)
                ):
                    first_use_expiry_ts = add_days_ts(hs, _conv_time_limit(peer))
                    peer.expires_at = from_ts(first_use_expiry_ts)

                try:
                    from models import PeerEvent
                    ev = PeerEvent(peer_id=peer.id, event_type='first_use', detail='First WireGuard handshake recorded')
                    db.session.add(ev)
                except Exception:
                    pass
                changed = True

        # Immediate timer auto-start if created
        if (
            not getattr(peer, 'start_on_first_use', False)
            and getattr(peer, 'time_limit_days', None)
            and not getattr(peer, 'expires_at', None)
            and not getattr(peer, 'unlimited', False)
        ):
            if not getattr(peer, 'timer_started_at', None):
                peer.timer_started_at = getattr(peer, 'created_at', None) or from_ts(now)
            _sync_effective_expiry(peer)
            changed = True

        # Accumulate usage if local interface
        iface = getattr(peer, 'iface', None)
        is_node = _iface_is_node(iface)
        total_bytes = None
        if not is_node:
            total_bytes = _wg_transfer(peer)
            used_effective, _delta, usage_changed = _accumulate_peer_usage(peer, total_bytes)
            if usage_changed:
                changed = True
        else:
            used_effective = int(getattr(peer, 'used_bytes_total', 0) or 0)

        # Time-limit enforcement
        expiry_ts = _effective_expiry_ts(peer)
        if to_ts(getattr(peer, 'expires_at', None)) != expiry_ts:
            peer.expires_at = from_ts(expiry_ts)
            changed = True

        if expiry_ts and now >= expiry_ts and peer.status != 'blocked':
            disabled = _disable_peer(peer, 'expired', status='blocked')
            if disabled:
                pending_notifications.append({
                    'event_key': 'peer_expired',
                    'title': f"Peer '{peer.name}' expired",
                    'status': 'Disabled',
                    'details': [
                        ("Peer", f"{peer.name} · ID {peer.id}"),
                        ("Reason", "Time limit expired"),
                        ("Interface", getattr(iface, 'name', '') or ''),
                        ("Address", getattr(peer, 'address', '') or ''),
                    ],
                    'dedupe_key': f"peer-expired:{peer.id}",
                    'dedupe_seconds': 0,
                })
            changed = True

        # Data-limit enforcement
        limit_bytes = getattr(peer, 'limit_bytes', None)
        if callable(limit_bytes):
            limit_bytes = limit_bytes()
        if (
            limit_bytes is not None
            and not getattr(peer, 'unlimited', False)
            and peer.status != 'blocked'
            and used_effective >= int(limit_bytes)
        ):
            if not is_node and total_bytes is None:
                total_bytes = _wg_transfer(peer)
                _accumulate_peer_usage(peer, total_bytes)

            disabled = _disable_peer(peer, 'limit_reached', status='blocked')
            if disabled:
                pending_notifications.append({
                    'event_key': 'peer_limit',
                    'title': f"Peer '{peer.name}' data limit exceeded",
                    'status': 'Disabled',
                    'details': [
                        ("Peer", f"{peer.name} · ID {peer.id}"),
                        ("Used", f"{used_effective} bytes"),
                        ("Limit", f"{limit_bytes} bytes"),
                        ("Interface", getattr(iface, 'name', '') or ''),
                    ],
                    'dedupe_key': f"peer-limit:{peer.id}",
                    'dedupe_seconds': 0,
                })
            changed = True

    if changed:
        try:
            db.session.commit()
            # Dispatch queued notifications only AFTER commit succeeds
            for notif in pending_notifications:
                _send_telegram_event(
                    notif['event_key'],
                    notif['title'],
                    status=notif.get('status', ''),
                    details=notif.get('details'),
                    dedupe_key=notif.get('dedupe_key', ''),
                    dedupe_seconds=notif.get('dedupe_seconds', 60),
                )
        except Exception:
            db.session.rollback()

    return changed


def _run_expiry_once(source: str = 'manual') -> bool:
    """Run peer expiry check once, non-overlapping."""
    if not _EXPIRY_LOCK.acquire(blocking=False):
        return False

    try:
        _expire()
        return True
    except Exception as exc:
        try:
            db.session.rollback()
        except Exception:
            pass
        logger.exception("Expiry enforcement failed (%s): %s", source, exc)
        return False
    finally:
        try:
            _EXPIRY_LOCK.release()
        except Exception:
            pass


def _expiry_enforcer_loop(app: Any = None) -> None:
    """Background worker loop enforcing peer expiry periodically."""
    if app is not None:
        set_app(app)
    while True:
        try:
            with _get_app_context():
                _run_expiry_once('background')
        except Exception:
            pass
        time.sleep(_EXPIRY_INTERVAL_SEC)


def _start_expiry_enforcer(app: Any = None) -> None:
    """Start background peer expiry enforcer thread."""
    global _EXPIRY_THREAD_STARTED
    if app is not None:
        set_app(app)
    if _EXPIRY_THREAD_STARTED:
        return
    _EXPIRY_THREAD_STARTED = True
    t = threading.Thread(
        target=_expiry_enforcer_loop,
        args=(app,),
        name='peer-expiry-enforcer',
        daemon=True,
    )
    t.start()


def _on_boot() -> None:
    """Sync all peers on boot."""
    for peer in Peer.query.all():
        try:
            if peer.status in ('offline', 'blocked'):
                _disable_peer(peer, 'boot_reconcile', status=peer.status)
        except Exception as exc:
            logger.warning("Reconcile peer %s failed: %s", getattr(peer, 'name', '?'), exc)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()


def _read_lastip() -> str:
    """Read last known public IP from disk."""
    try:
        if os.path.isfile(LAST_PUBLIC_IP_FILE):
            with open(LAST_PUBLIC_IP_FILE, 'r', encoding='utf-8') as f:
                return (f.read() or '').strip()
    except Exception:
        pass
    return ''


def _write_lastip(ip: str) -> None:
    """Persist public IP to disk."""
    try:
        with open(LAST_PUBLIC_IP_FILE, 'w', encoding='utf-8') as f:
            f.write((ip or '').strip())
    except Exception:
        pass


def _host_port(ep: str) -> tuple[str, int | None]:
    """Parse endpoint string into host and optional port."""
    if not ep:
        return ('', None)
    s = ep.strip()
    if s.startswith('['):
        if ']' in s:
            host, rest = s[1:].split(']', 1)
            port = rest.lstrip(':') or None
            return (host, int(port) if port and port.isdigit() else None)
        return (s, None)
    if ':' in s:
        host, port = s.rsplit(':', 1)
        return (host, int(port) if port.isdigit() else None)
    return (s, None)


def repoint_endpoints() -> None:
    """Update stale peer endpoints if host public IP address changed."""
    cur = _public_ipv4(force=True) or ''
    prev = _read_lastip()
    if not cur or not prev or cur == prev:
        if cur and cur != prev:
            _write_lastip(cur)
        return

    changed = 0
    for p in Peer.query.all():
        host, port = _host_port(p.endpoint or '')
        if host == prev:
            p.endpoint = f"{cur}:{port}" if port else cur
            changed += 1

    if changed:
        try:
            db.session.commit()
            logger.info("Repointed %s peer endpoints from %s to %s", changed, prev, cur)
        except Exception:
            db.session.rollback()

    _write_lastip(cur)
