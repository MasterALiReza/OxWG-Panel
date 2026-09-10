"""
OxWg Panel - System & Peer Statistics Blueprint (stats_bp)
=========================================================
System resource metrics, mini dashboard stats, peer counts, and daemon status.
"""
import os
import time
import re
import socket
import platform
import subprocess
import ipaddress
from flask import Blueprint, jsonify, current_app
from flask_login import login_required
import psutil

from core.extensions import db
from core.time_utils import now_ts, isoz, from_ts
from core.ip_utils import _public_ipv4, _public_ipv6
from core.paths import TELEGRAM_HB_FILE
from core.file_utils import _json_load
from models import Peer, InterfaceConfig
from auth import require_api_key, require_api_key_or_login

stats_bp = Blueprint('stats_bp', __name__)

_prev_net = {"ts": 0, "rx": 0, "tx": 0}


def _rate_mb(cur, prev, dt):
    if dt <= 0:
        return 0.0
    return max(0.0, ((cur - prev) / dt) / (1024 * 1024))


def _global_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except Exception:
        return False


def _wg_endpoint_ips(timeout=1.5):
    ips = set()
    try:
        p = subprocess.run(
            ["wg", "show", "all", "endpoints"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if p.returncode != 0:
            return ips

        for line in (p.stdout or '').splitlines():
            line = line.strip()
            if not line or "(none)" in line:
                continue
            tok = line.split()[-1]
            host = tok
            if host.startswith('['):
                host = host.split(']')[0].lstrip('[')
            else:
                if ':' in host:
                    host = host.rsplit(':', 1)[0]
            if _global_ip(host):
                ips.add(host)
    except Exception:
        pass
    return ips


@stats_bp.get('/api/app_status')
@login_required
def app_status():
    started = globals().get('APP_START_TS', int(time.time()))
    uptime = now_ts() - int(started)
    hb = _json_load(TELEGRAM_HB_FILE, {})
    last = int(hb.get('ts') or 0)
    sec = int(current_app.config.get('TG_HEARTBEAT_SEC', 60) or 60)
    bot_online = (now_ts() - last) <= max(120, sec * 2)

    return jsonify({
        'app': {
            'online': True,
            'since': isoz(from_ts(started)),
            'uptime': uptime,
        },
        'telegram': {
            'online': bool(bot_online),
            'last_seen': isoz(from_ts(last)) if last else None,
        },
    })


@stats_bp.get('/api/peer_counts')
@login_required
def api_peer_counts():
    counts = {
        'total': Peer.query.count(),
        'online': Peer.query.filter_by(status='online').count(),
        'offline': Peer.query.filter_by(status='offline').count(),
        'blocked': Peer.query.filter_by(status='blocked').count(),
    }
    return jsonify(counts=counts)


@stats_bp.get('/api/stats/mini')
@require_api_key
def stats_mini():
    try:
        cpu = round(psutil.cpu_percent(interval=0.2) or 0.0, 1)
        mem = round(psutil.virtual_memory().percent or 0.0, 1)
        try:
            disk = round(psutil.disk_usage(os.path.abspath(os.sep)).percent or 0.0, 1)
        except Exception:
            disk = 0.0

        uptime_secs = max(0, int(time.time() - psutil.boot_time()))

        if uptime_secs >= 48 * 3600:
            days = uptime_secs // 86400
            hours = (uptime_secs % 86400) // 3600
            uptime_value = int(days)
            uptime_unit = 'd'
            uptime_str = f'{days}d' + (f' {hours}h' if hours else '')
        else:
            hours = uptime_secs // 3600
            uptime_value = int(hours)
            uptime_unit = 'h'
            uptime_str = f'{hours}h'

        active_within_seconds = 180
        now_epoch = int(time.time())
        handshake_map = {}

        try:
            process = subprocess.run(
                ['wg', 'show', 'all', 'latest-handshakes'],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if process.returncode == 0:
                for raw_line in (process.stdout or '').splitlines():
                    parts = raw_line.split()
                    if len(parts) < 3:
                        continue
                    iface_name = parts[0]
                    public_key = parts[1]
                    try:
                        timestamp = int(parts[2] or 0)
                    except Exception:
                        timestamp = 0
                    handshake_map[(iface_name, public_key)] = timestamp
        except Exception:
            handshake_map = {}

        activity = {'active': 0, 'idle': 0, 'blocked': 0, 'total': 0}

        rows = (
            db.session.query(
                Peer.status,
                Peer.public_key,
                InterfaceConfig.name,
            )
            .join(InterfaceConfig, Peer.iface_id == InterfaceConfig.id)
            .all()
        )

        for stored_status, public_key, iface_name in rows:
            activity['total'] += 1
            stored_status = str(stored_status or '').lower()
            iface_name = str(iface_name or '')

            if stored_status == 'blocked':
                activity['blocked'] += 1
                continue

            is_node = bool(re.match(r'^n\d+:', iface_name))
            if is_node:
                if stored_status == 'online':
                    activity['active'] += 1
                else:
                    activity['idle'] += 1
                continue

            device_name = iface_name.split(':')[-1]
            handshake = int(
                handshake_map.get((device_name, public_key))
                or handshake_map.get((iface_name, public_key))
                or 0
            )

            if handshake and (now_epoch - handshake <= active_within_seconds):
                activity['active'] += 1
            else:
                activity['idle'] += 1

        counts = {
            'active': activity['active'],
            'idle': activity['idle'],
            'blocked': activity['blocked'],
            'total': activity['total'],
            'activity_window_seconds': active_within_seconds,
            'online': activity['active'],
            'offline': activity['idle'],
        }

        return jsonify({
            'cpu': cpu,
            'mem': mem,
            'disk': disk,
            'uptime_value': uptime_value,
            'uptime_unit': uptime_unit,
            'uptime_str': uptime_str,
            'counts': counts,
        }), 200

    except Exception:
        current_app.logger.exception('Mini stats failed')
        return jsonify(error='stats_unavailable'), 503


@stats_bp.route('/api/stats')
@login_required
def api_stats():
    global _prev_net
    cpu_pct = psutil.cpu_percent(interval=None)
    cores = psutil.cpu_count(logical=False) or psutil.cpu_count()
    threads = psutil.cpu_count(logical=True)
    try:
        l1, l5, l15 = os.getloadavg()
    except Exception:
        l1 = l5 = l15 = 0.0
    load_pct = round((l1 / max(1, threads or 1)) * 100, 1)

    vm = psutil.virtual_memory()
    try:
        swap = psutil.swap_memory()
        swap_used_mb = round(swap.used / (1024 * 1024), 1)
        swap_total_mb = round(swap.total / (1024 * 1024), 1)
        swap_percent = swap.percent
    except Exception:
        swap_used_mb = swap_total_mb = swap_percent = 0.0

    mem = {
        "percent": vm.percent,
        "used_mb": round(vm.used / (1024 * 1024), 1),
        "free_mb": round(vm.available / (1024 * 1024), 1),
        "total_mb": round(vm.total / (1024 * 1024), 1),
        "swap_used_mb": swap_used_mb,
        "swap_total_mb": swap_total_mb,
        "swap_percent": swap_percent,
    }

    try:
        du = psutil.disk_usage(os.path.abspath(os.sep))
        disk = {
            "percent": du.percent,
            "used_gb": round(du.used / (1024**3), 2),
            "free_gb": round(du.free / (1024**3), 2),
            "total_gb": round(du.total / (1024**3), 2),
        }
    except Exception:
        disk = {"percent": 0.0, "used_gb": 0.0, "free_gb": 0.0, "total_gb": 0.0}

    now = time.time()
    try:
        io = psutil.net_io_counters()
        dt = now - (_prev_net["ts"] or now)
        rx_rate = _rate_mb(io.bytes_recv, _prev_net["rx"], dt) if _prev_net["ts"] else 0.0
        tx_rate = _rate_mb(io.bytes_sent, _prev_net["tx"], dt) if _prev_net["ts"] else 0.0
        _prev_net = {"ts": now, "rx": io.bytes_recv, "tx": io.bytes_sent}
        net = {
            "rx_rate_mb": round(rx_rate, 2),
            "tx_rate_mb": round(tx_rate, 2),
            "rx_total_mb": round(io.bytes_recv / (1024 * 1024), 1),
            "tx_total_mb": round(io.bytes_sent / (1024 * 1024), 1),
        }
    except Exception:
        net = {"rx_rate_mb": 0.0, "tx_rate_mb": 0.0, "rx_total_mb": 0.0, "tx_total_mb": 0.0}

    try:
        conns = psutil.net_connections(kind='inet')
        total_conn = len(conns)
        uniq_remote = len({c.raddr.ip for c in conns if c.raddr})
    except Exception:
        conns = []
        total_conn = uniq_remote = 0

    listen_ports = {
        c.laddr.port
        for c in conns
        if getattr(c, "status", None) == psutil.CONN_LISTEN and getattr(c, "laddr", None)
    }

    public_ips = set()
    try:
        for c in conns:
            if not (getattr(c, "raddr", None) and getattr(c, "laddr", None)):
                continue
            if c.status == psutil.CONN_ESTABLISHED and c.laddr.port in listen_ports:
                ip = c.raddr.ip
                if _global_ip(ip):
                    public_ips.add(ip)
    except Exception:
        pass

    public_ips |= _wg_endpoint_ips()
    unique_public = {
        "count": len(public_ips),
        "list": sorted(public_ips)[:20],
    }

    uptime = max(0, int(time.time() - psutil.boot_time()))
    ipv4 = _public_ipv4() or ''
    ipv6 = _public_ipv6()
    if ipv6 and (':' not in str(ipv6) or str(ipv6).strip() == str(ipv4).strip()):
        ipv6 = ''
    hostname = socket.gethostname()
    platform_str = platform.platform()
    kernel = platform.release()
    arch = platform.machine()
    cpu_model = platform.processor() or ""

    counts = {
        "online": db.session.query(Peer).filter_by(status='online').count(),
        "offline": db.session.query(Peer).filter_by(status='offline').count(),
        "blocked": db.session.query(Peer).filter_by(status='blocked').count(),
    }

    return jsonify({
        "cpu": round(cpu_pct, 1),
        "cores": cores,
        "threads": threads,
        "load": [round(l1, 2), round(l5, 2), round(l15, 2)],
        "load_pct": load_pct,
        "mem": mem,
        "disk": disk,
        "rx": net["rx_rate_mb"],
        "tx": net["tx_rate_mb"],
        "net": net,
        "uptime": uptime,
        "hostname": hostname,
        "platform": platform_str,
        "kernel": kernel,
        "arch": arch,
        "cpu_model": cpu_model,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "counts": counts,
        "connections": {
            "total": total_conn,
            "unique": uniq_remote,
        },
        "unique_public_ips": unique_public,
    })
