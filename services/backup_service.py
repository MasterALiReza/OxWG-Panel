"""
OxWg Panel - Backup Scheduler and State Service
===============================================
Automated backup scheduler loop, backup preferences persistence, and retention management.
"""
import os
import re
import json
import time
import socket
import zipfile
import requests
import threading
import logging
from io import BytesIO
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Any
from zoneinfo import ZoneInfo
from calendar import monthrange

from flask import current_app
from core.paths import (
    BASE_DIR,
    DB_PATH,
    INSTANCE_DIR,
    BACKUP_PREFS_FILE,
    BACKUP_SCHEDULE_FILE,
    BACKUP_LAST_FILE,
    BACKUP_AUTO_DIR,
    _BACKUP_SCHEDULER_STATE_FILE,
    _BACKUP_SCHEDULER_LOCK_FILE,
)
from core.file_utils import _json_load, _json_save
from core.crypto import _read_api_key
from services.update_checker import PANEL_VERSION
from services.panel_settings import _panel_filename_stamp, _panel_timezone_name
from services.telegram_notifier import (
    _load_tg_admins,
    _load_tg_settings,
    _tg_human_bytes,
    _tg_now_text,
    _tg_event_escape,
)
from models import (
    db,
    Node,
    InterfaceConfig,
    Peer,
    Subscription,
    SubscriptionPeer,
    ShortLink,
)

logger = logging.getLogger(__name__)

_BACKUP_SCHEDULER_STARTED = False
_BACKUP_THREAD_LOCK = threading.Lock()


def _db_path() -> str | None:
    return DB_PATH if os.path.isfile(DB_PATH) else None


def _jsonl_bundle(z: zipfile.ZipFile):
    try:
        inst_path = current_app.instance_path if current_app else INSTANCE_DIR
    except Exception:
        inst_path = INSTANCE_DIR
    inst = Path(inst_path)
    keep_suffix = {'.json', '.jsonl'}
    for p in inst.glob('*'):
        if p.is_file() and p.suffix.lower() in keep_suffix:
            z.write(p, arcname=f'instance/{p.name}')


def _env_bundle(z: zipfile.ZipFile):
    """Include panel .env in full backups for migration."""
    env_path = Path(BASE_DIR) / '.env'
    if env_path.is_file():
        z.write(env_path, arcname='env/.env')


def _backup_prefs_default() -> dict[str, Any]:
    """Default backup preferences."""
    return {"include_wg": True, "send_to_telegram": False}


def _load_backup_settings() -> dict[str, Any]:
    """Load backup preferences from disk."""
    return _json_load(BACKUP_PREFS_FILE, _backup_prefs_default())


def _save_backup_settings(p: dict[str, Any]) -> dict[str, Any]:
    """Update and persist backup preferences."""
    cur = _load_backup_settings()
    cur.update({
        "include_wg": bool(p.get("include_wg", cur.get("include_wg", True))),
        "send_to_telegram": bool(p.get("send_to_telegram", cur.get("send_to_telegram", False))),
    })
    _json_save(BACKUP_PREFS_FILE, cur)
    return cur


def _load_backup_last() -> dict[str, Any]:
    return _json_load(BACKUP_LAST_FILE, {})


def _record_backup(kind: str, when_ts: int | None = None) -> None:
    last = _load_backup_last()
    if when_ts is None:
        iso = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
    else:
        iso = datetime.fromtimestamp(int(when_ts), tz=timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
    last[f"{kind}_last"] = iso
    _json_save(BACKUP_LAST_FILE, last)


def _tg_chatid() -> str | None:
    admins = _load_tg_admins() or []
    for a in admins:
        if not a.get('muted') and str(a.get('id') or '').strip():
            return str(a['id'])
    return None


def _send_zip_telegram(
    data_bytes: bytes,
    filename: str,
    chat_id: str | None = None,
    caption: str | None = None,
) -> tuple[bool, str]:
    settings = _load_tg_settings()
    if not settings.get("enabled"):
        return False, "Telegram disabled."

    token = (settings.get("bot_token") or "").strip()
    if not token:
        return False, "Telegram token missing."

    selected_chat_id = str(chat_id or _tg_chatid() or "").strip()
    if not selected_chat_id:
        return False, "No active Telegram administrator selected."

    active_admin_ids = {
        str(admin.get("id") or "").strip()
        for admin in (_load_tg_admins() or [])
        if not admin.get("muted") and str(admin.get("id") or "").strip()
    }
    if selected_chat_id not in active_admin_ids:
        return False, "Selected Telegram recipient is not an active panel administrator."

    size_bytes = len(data_bytes or b"")
    if not caption:
        try:
            size_text = _tg_human_bytes(size_bytes)
        except Exception:
            size_text = f"{size_bytes} bytes"

        created_at = _tg_now_text()
        caption = "\n".join([
            "<b>OxWg Panel backup</b>",
            "",
            "<b>Status</b> · Completed",
            f"<b>File</b> · <code>{_tg_event_escape(filename)}</code>",
            f"<b>Size</b> · {_tg_event_escape(size_text)}",
            f"<b>Created</b> · {_tg_event_escape(created_at)}",
        ])

    if len(caption) > 1000:
        caption = caption[:997] + "..."

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendDocument",
            data={
                "chat_id": selected_chat_id,
                "disable_notification": "true",
                "caption": caption,
                "parse_mode": "HTML",
            },
            files={"document": (filename, data_bytes, "application/zip")},
            timeout=60,
        )
        try:
            payload = response.json() or {}
        except Exception:
            payload = {}

        if response.ok and payload.get("ok"):
            return True, "Backup document sent to Telegram."

        description = str(payload.get("description") or response.text or "")[:300]
        return False, f"Telegram error {response.status_code}: {description}"
    except Exception as exc:
        return False, f"Telegram exception: {exc}"


def _node_backup_wg_zip(node: Node, timeout: int = 25) -> bytes:
    url = f"{node.base_url.rstrip('/')}/api/backup/wg"
    r = requests.get(
        url,
        headers={'Authorization': f'Bearer {_read_api_key(node)}'},
        timeout=timeout,
    )
    r.raise_for_status()
    return r.content or b''


def _bundle_node_wg_backups(z: zipfile.ZipFile) -> list[dict]:
    results = []
    nodes = Node.query.order_by(Node.id.asc()).all()

    for node in nodes:
        rec = {
            "node_id": node.id,
            "name": node.name,
            "base_url": node.base_url,
            "ok": False,
            "files": [],
            "env_file": False,
            "error": "",
        }

        try:
            z.writestr(
                f"nodes/{node.id}/meta.json",
                json.dumps(
                    {
                        "node_id": node.id,
                        "name": node.name,
                        "base_url": node.base_url,
                        "enabled": bool(node.enabled),
                        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace('+00:00', 'Z'),
                    },
                    indent=2,
                ),
            )

            if not node.enabled:
                rec["error"] = "node_disabled"
                results.append(rec)
                continue

            raw = _node_backup_wg_zip(node)
            if not raw:
                rec["error"] = "empty_node_backup"
                results.append(rec)
                continue

            try:
                with zipfile.ZipFile(BytesIO(raw), "r") as nz:
                    members = nz.namelist()
                    for member in members:
                        if member.startswith("wg/") and member.endswith(".conf"):
                            filename = os.path.basename(member)
                            if not filename:
                                continue
                            data = nz.read(member)
                            z.writestr(f"nodes/{node.id}/wg/{filename}", data)
                            rec["files"].append(filename)
                            continue

                        if member == "env/.env":
                            try:
                                data = nz.read(member)
                                if data:
                                    z.writestr(f"nodes/{node.id}/env/.env", data)
                                    rec["env_file"] = True
                            except Exception as e:
                                logger.warning(
                                    "Node env backup skipped node=%s url=%s error=%s",
                                    getattr(node, "id", "?"),
                                    getattr(node, "base_url", ""),
                                    e,
                                )
                            continue

                rec["files"] = sorted(set(rec["files"]))
                rec["ok"] = bool(rec["files"] or rec["env_file"])
                if not rec["ok"]:
                    rec["error"] = "node_backup_had_no_wg_or_env"

            except zipfile.BadZipFile:
                rec["error"] = "node_backup_not_zip"
            except Exception as e:
                rec["error"] = f"node_backup_read_failed: {e}"

        except Exception as e:
            rec["error"] = str(e)
            logger.warning(
                "Node backup failed node=%s url=%s error=%s",
                getattr(node, "id", "?"),
                getattr(node, "base_url", ""),
                e,
            )

        results.append(rec)

    return results


def build_full_backup_archive(include_wg: bool = True) -> tuple[bytes, str, list[dict]]:
    """
    Build a complete backup archive in memory.
    Returns (zip_bytes, filename, node_wg_results).
    """
    mem = BytesIO()
    node_wg_results: list[dict] = []

    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        dbp = _db_path()
        if dbp and os.path.isfile(dbp):
            z.write(dbp, arcname=f'db/{os.path.basename(dbp)}')

        _jsonl_bundle(z)
        _env_bundle(z)

        local_wg_count = 0
        if include_wg:
            try:
                wgdir = (current_app.config.get('WG_CONF_PATH') if current_app else None) or '/etc/wireguard/'
            except Exception:
                wgdir = '/etc/wireguard/'
            try:
                for p in Path(wgdir).glob('*.conf'):
                    if p.is_file():
                        z.write(p, arcname=f'wg/{p.name}')
                        local_wg_count += 1
            except Exception as e:
                logger.debug("Local WG bundle skipped: %s", e)

            try:
                node_wg_results = _bundle_node_wg_backups(z)
            except Exception as e:
                logger.warning("Node backup bundle skipped: %s", e)
                node_wg_results = [{
                    'ok': False,
                    'files': [],
                    'env_file': False,
                    'error': str(e),
                }]

        created_at = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
        z.writestr('meta/created.txt', created_at)
        z.writestr('meta/host.txt', socket.gethostname())
        try:
            db_uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '') if current_app else ''
            wg_conf = (current_app.config.get('WG_CONF_PATH') if current_app else None) or '/etc/wireguard/'
        except Exception:
            db_uri = ''
            wg_conf = '/etc/wireguard/'
        z.writestr(
            'meta/app.json',
            json.dumps({
                'db_uri': db_uri,
                'wg_conf_path': wg_conf,
            }, indent=2)
        )
        z.writestr('meta/node_wg_backup.json', json.dumps(node_wg_results, indent=2))

        try:
            manifest_counts = {
                'nodes': Node.query.count(),
                'interfaces': InterfaceConfig.query.count(),
                'peers': Peer.query.count(),
                'subscriptions': Subscription.query.count(),
                'subscription_peers': SubscriptionPeer.query.count(),
                'short_links': ShortLink.query.count(),
            }
        except Exception:
            manifest_counts = {}

        node_wg_count = sum(len(rec.get('files') or []) for rec in (node_wg_results or []))
        node_env_count = sum(1 for rec in (node_wg_results or []) if rec.get('env_file'))
        panel_env_exists = bool((Path(BASE_DIR) / '.env').is_file())

        z.writestr(
            'meta/manifest.json',
            json.dumps({
                'created_at': created_at,
                'kind': 'full',
                'panel_version': PANEL_VERSION,
                'contains': {
                    'database': bool(dbp and os.path.isfile(dbp)),
                    'instance_json': True,
                    'env_file': bool(panel_env_exists),
                    'remote_node_env': bool(node_env_count > 0),
                    'short_links': True,
                    'subscriptions': True,
                    'nodes_metadata': True,
                    'local_wireguard_conf': bool(include_wg and local_wg_count > 0),
                    'remote_node_wireguard_conf': bool(include_wg and node_wg_count > 0),
                },
                'counts': {
                    **manifest_counts,
                    'local_wg_files': int(local_wg_count or 0),
                    'node_wg_files': int(node_wg_count or 0),
                    'node_env_files': int(node_env_count or 0),
                },
                'node_wg_backup': node_wg_results,
            }, indent=2)
        )

    ts = _panel_filename_stamp()
    fname = f'wgpanel_full_backup_{ts}.zip'
    return mem.getvalue(), fname, node_wg_results


def _load_backup_schedule() -> dict[str, Any]:
    """Load backup schedule settings from disk."""
    d = _json_load(BACKUP_SCHEDULE_FILE, {})
    return {
        "enabled": bool(d.get("enabled", False)),
        "freq": str(d.get("freq", "daily")),
        "time": str(d.get("time", "03:00")),
        "timezone": _panel_timezone_name(),
        "dow": list(map(str, d.get("dow", []))),
        "dom": int(d.get("dom", 1)),
        "cron": str(d.get("cron", "")),
        "keep": max(1, int(d.get("keep", 7))),
        "include_wg": bool(d.get("include_wg", True)),
        "send_to_telegram": bool(d.get("send_to_telegram", False)),
        "telegram_chat_id": str(d.get("telegram_chat_id", "") or "").strip(),
    }


def _save_backup_schedule(s: dict[str, Any]) -> dict[str, Any]:
    """Save backup schedule settings to disk and return normalized schedule."""
    cur = _load_backup_schedule()
    cur.update({
        "enabled": bool(s.get("enabled", cur.get("enabled", False))),
        "freq": str(s.get("freq", cur.get("freq", "daily"))),
        "time": str(s.get("time", cur.get("time", "03:00"))),
        "timezone": str(s.get("timezone", cur.get("timezone", _panel_timezone_name()))),
        "dow": list(map(str, s.get("dow", cur.get("dow", [])))),
        "dom": int(s.get("dom", cur.get("dom", 1))),
        "cron": str(s.get("cron", cur.get("cron", ""))),
        "keep": max(1, int(s.get("keep", cur.get("keep", 7)))),
        "include_wg": bool(s.get("include_wg", cur.get("include_wg", True))),
        "send_to_telegram": bool(s.get("send_to_telegram", cur.get("send_to_telegram", False))),
        "telegram_chat_id": str(s.get("telegram_chat_id", cur.get("telegram_chat_id", "")) or "").strip(),
    })
    _json_save(BACKUP_SCHEDULE_FILE, cur)
    return cur


def execute_auto_backup(schedule: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Execute a complete automated backup, store it in instance/backups,
    prune older backups, and optionally dispatch to Telegram.
    """
    if schedule is None:
        schedule = _load_backup_schedule()

    include_wg = bool(schedule.get("include_wg", True))
    send_tg = bool(schedule.get("send_to_telegram", False))
    chat_id = schedule.get("telegram_chat_id")
    keep = max(1, int(schedule.get("keep", 7)))

    data, fname, node_results = build_full_backup_archive(include_wg=include_wg)
    saved_meta = _save_autobackup(data, keep=keep)
    _record_backup("full")

    tg_ok = None
    tg_msg = ""
    if send_tg:
        tg_ok, tg_msg = _send_zip_telegram(data, fname, chat_id=chat_id or None)
        if tg_ok is False:
            logger.warning("Scheduled backup Telegram send failed: %s", tg_msg)

    try:
        from services.admin_log import _norm_adminlog
        _norm_adminlog({
            "action": "backup_auto_scheduled",
            "details": f"file={saved_meta.get('name', fname)} size={len(data)}B wg={int(include_wg)} tg={int(send_tg)}",
            "channel": "system",
        })
    except Exception:
        pass

    return {
        "ok": True,
        "filename": saved_meta.get("name", fname),
        "size": len(data),
        "saved_meta": saved_meta,
        "telegram_sent": tg_ok,
        "telegram_message": tg_msg,
    }


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


def _cron_field_match(val: int, expr: str, min_v: int, max_v: int) -> bool:
    """Evaluate a single 5-field cron component."""
    expr = (expr or '').strip()
    if expr in ('*', '?'):
        return True
    if '/' in expr:
        base, step = expr.split('/', 1)
        step_i = int(step)
        start = min_v if base in ('*', '') else int(base)
        return (val >= start) and ((val - start) % step_i == 0) and (val <= max_v)
    if ',' in expr:
        return any(_cron_field_match(val, sub, min_v, max_v) for sub in expr.split(','))
    if '-' in expr:
        lo, hi = [int(x) for x in expr.split('-', 1)]
        return lo <= val <= hi
    try:
        return val == int(expr)
    except ValueError:
        return False


def _backup_due_slot(schedule: dict[str, Any], now_utc: datetime | None = None) -> str | None:
    """
    Check if a scheduled backup is due in the current minute window.
    Evaluates in the configured schedule timezone.
    Returns slot identifier string if due, else None.
    """
    if not schedule.get("enabled"):
        return None

    now_utc = now_utc or datetime.now(timezone.utc)

    tz_name = (schedule.get("timezone") or _panel_timezone_name() or "UTC").strip()
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = ZoneInfo("UTC")

    local_time = now_utc.astimezone(tz)
    freq = (schedule.get("freq") or "daily").lower()

    if freq == "custom":
        fields = (schedule.get("cron") or "").split()
        if len(fields) != 5:
            return None
        minute, hour, day, month, weekday = fields
        cron_weekday = (local_time.weekday() + 1) % 7
        matched = all((
            _cron_field_match(local_time.minute, minute, 0, 59),
            _cron_field_match(local_time.hour, hour, 0, 23),
            _cron_field_match(local_time.day, day, 1, 31),
            _cron_field_match(local_time.month, month, 1, 12),
            (
                _cron_field_match(cron_weekday, weekday, 0, 7)
                or (cron_weekday == 0 and _cron_field_match(7, weekday, 0, 7))
            ),
        ))
        if not matched:
            return None
        return f"custom:{local_time:%Y-%m-%dT%H:%M}"

    slot_time = schedule.get("time", "03:00")
    try:
        shour, sminute = [int(x) for x in slot_time.split(":", 1)]
    except Exception:
        shour, sminute = 3, 0

    if local_time.hour != shour or local_time.minute != sminute:
        return None

    if freq == "daily":
        return local_time.strftime("%Y-%m-%d")
    if freq == "weekly":
        dow_list = [int(x) for x in schedule.get("dow", []) if str(x).isdigit()]
        if not dow_list or local_time.weekday() in dow_list:
            return local_time.strftime("%Y-%W")
    if freq == "monthly":
        target_dom = int(schedule.get("dom", 1))
        if local_time.day == target_dom:
            return local_time.strftime("%Y-%m")

    return None


def _save_autobackup(data_bytes: bytes, keep: int | None = None) -> dict[str, Any]:
    """Save automated backup ZIP data and prune older backups."""
    root = Path(BACKUP_AUTO_DIR)
    root.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    name = f"auto_full_{ts}.zip"
    path = root / name

    with open(path, "wb") as f:
        f.write(data_bytes)

    st = path.stat()
    if keep is None:
        try:
            sched = _load_backup_schedule()
            keep = int(sched.get("keep", 7))
        except Exception:
            keep = 7

    keep_count = max(1, int(keep or 1))
    files = sorted(root.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    for p in files[keep_count:]:
        try:
            p.unlink()
        except OSError:
            pass

    return {"name": name, "size": st.st_size, "ts": int(st.st_mtime)}


def _backup_scheduler_loop(app: Any = None) -> None:
    """
    Background worker loop for scheduled automated backups.
    Acquires file lock to ensure single execution across worker processes.
    """
    if app is not None:
        set_app(app)
    lock_handle = None
    try:
        import fcntl
        lock_handle = open(_BACKUP_SCHEDULER_LOCK_FILE, "a+", encoding="utf-8")
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (ImportError, OSError):
        # On Windows or if lock already held by another worker
        pass
    except Exception:
        if lock_handle:
            try:
                lock_handle.close()
            except Exception:
                pass
        return

    while True:
        try:
            with _get_app_context():
                schedule = _load_backup_schedule()
                slot = _backup_due_slot(schedule)
                state = _json_load(_BACKUP_SCHEDULER_STATE_FILE, {})
                if not isinstance(state, dict):
                    state = {}

                if slot and state.get("last_slot") != slot:
                    # Slot is due; update state and execute backup
                    state["last_slot"] = slot
                    state["last_run_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    _json_save(_BACKUP_SCHEDULER_STATE_FILE, state)
                    logger.info("Triggered scheduled backup for slot %s", slot)
                    try:
                        execute_auto_backup(schedule)
                    except Exception as e:
                        logger.exception("Scheduled auto backup execution failed: %s", e)
        except Exception as exc:
            logger.warning("Backup scheduler tick failed: %s", exc)

        time.sleep(30)


def _start_backup_scheduler(app: Any = None) -> None:
    """Start background backup scheduler thread once per process."""
    global _BACKUP_SCHEDULER_STARTED
    if app is not None:
        set_app(app)
    with _BACKUP_THREAD_LOCK:
        if _BACKUP_SCHEDULER_STARTED:
            return
        _BACKUP_SCHEDULER_STARTED = True

        thread = threading.Thread(
            target=_backup_scheduler_loop,
            args=(app,),
            name="backup-scheduler",
            daemon=True,
        )
        thread.start()

