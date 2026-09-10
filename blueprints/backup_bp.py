"""
OxWg Panel - Backup Blueprint (backup_bp)
=========================================
Manages manual and automated backups (SQLite DB, instance configuration, WireGuard configs,
and remote node archives), backup inspection, restoration, and automated scheduling.
"""
import os
import re
import json
import socket
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from calendar import monthrange
import requests

from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    send_file,
    current_app,
)
from flask_login import login_required

from models import (
    db,
    Node,
    InterfaceConfig,
    Peer,
    Subscription,
    SubscriptionPeer,
    ShortLink,
)
from auth import (
    admin_required,
    require_api_key,
    require_api_key_or_login,
)
from core.crypto import _read_api_key
from core.paths import (
    BASE_DIR,
    DB_PATH,
    BACKUP_PREFS_FILE,
    BACKUP_SCHEDULE_FILE,
    BACKUP_LAST_FILE,
    BACKUP_AUTO_DIR,
)
from core.json_utils import _json_load, _json_save
from services.update_checker import PANEL_VERSION
from services.panel_settings import _panel_filename_stamp, _panel_timezone_name
from services.telegram_notifier import (
    _load_tg_admins,
    _load_tg_settings,
    _tg_human_bytes,
    _tg_now_text,
    _tg_event_escape,
)
from services.backup_service import (
    _load_backup_settings,
    _save_backup_settings,
    _load_backup_schedule,
    _save_backup_schedule,
    _save_autobackup,
)
from blueprints.logs_bp import _norm_adminlog

backup_bp = Blueprint('backup_bp', __name__)


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _db_path() -> str | None:
    return DB_PATH if os.path.isfile(DB_PATH) else None


def _jsonl_bundle(z: zipfile.ZipFile):
    inst = Path(current_app.instance_path)
    keep_suffix = {'.json', '.jsonl'}
    for p in inst.glob('*'):
        if p.is_file() and p.suffix.lower() in keep_suffix:
            z.write(p, arcname=f'instance/{p.name}')


def _env_bundle(z: zipfile.ZipFile):
    """Include panel .env in full backups for migration."""
    env_path = Path(BASE_DIR) / '.env'
    if env_path.is_file():
        z.write(env_path, arcname='env/.env')


def _backup_prefs_load():
    return _load_backup_settings()


def _backup_prefs_save(p):
    return _save_backup_settings(p)


def _load_backup_last():
    return _json_load(BACKUP_LAST_FILE, {})


def _record_backup(kind: str, when_ts: int | None = None):
    last = _load_backup_last()
    if when_ts is None:
        iso = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
    else:
        iso = datetime.fromtimestamp(int(when_ts), tz=timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
    last[f"{kind}_last"] = iso
    _json_save(BACKUP_LAST_FILE, last)


def _tg_chatid():
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
            "<b>WG Panel backup</b>",
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
                                current_app.logger.warning(
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
            current_app.logger.warning(
                "Node backup failed node=%s url=%s error=%s",
                getattr(node, "id", "?"),
                getattr(node, "base_url", ""),
                e,
            )

        results.append(rec)

    return results


def _node_wg_payloads_zip(z: zipfile.ZipFile, names: list[str]) -> dict[int, dict]:
    payloads: dict[int, dict] = {}
    for member in names:
        match = re.match(r'^nodes/(\d+)/wg/([^/]+\.conf)$', member)
        if match:
            node_id = int(match.group(1))
            filename = os.path.basename(match.group(2))
            try:
                text = z.read(member).decode('utf-8', 'replace')
            except Exception:
                continue
            payload = payloads.setdefault(node_id, {'files': {}, 'env_file': None})
            payload['files'][filename] = text
            continue

        match_env = re.match(r'^nodes/(\d+)/env/\.env$', member)
        if match_env:
            node_id = int(match_env.group(1))
            try:
                text = z.read(member).decode('utf-8', 'replace')
            except Exception:
                continue
            payload = payloads.setdefault(node_id, {'files': {}, 'env_file': None})
            payload['env_file'] = text

    return payloads


def _restore_node_wg_zip(z: zipfile.ZipFile, names: list[str]) -> list[dict]:
    payloads = _node_wg_payloads_zip(z, names)
    results = []

    for node_id, payload in payloads.items():
        node = db.session.get(Node, node_id)
        files = payload.get('files') or {}
        env_file = payload.get('env_file')

        rec = {
            'node_id': node_id,
            'ok': False,
            'files': sorted(files.keys()),
            'env_file': bool(env_file),
            'error': '',
        }

        if not node:
            rec['error'] = 'node_not_found_in_current_db'
            results.append(rec)
            continue

        try:
            url = f"{node.base_url.rstrip('/')}/api/backup/wg/restore"
            response = requests.post(
                url,
                headers={
                    'Authorization': f'Bearer {_read_api_key(node)}',
                    'Content-Type': 'application/json',
                },
                json={
                    'files': files,
                    'env_file': env_file,
                    'bring_up': False,
                },
                timeout=35,
            )

            try:
                body = response.json()
            except Exception:
                body = {'raw': response.text[:500]}

            if not response.ok:
                rec['error'] = f'HTTP {response.status_code}: {str(body)[:500]}'
            else:
                rec['ok'] = bool(body.get('ok', True))
                rec['result'] = body

        except Exception as exc:
            rec['error'] = str(exc)

        results.append(rec)

    return results


def _next_run(sched: dict) -> str | None:
    if not sched.get("enabled"):
        return None

    tzname = (sched.get("timezone") or "UTC").strip() or "UTC"
    try:
        tz = ZoneInfo(tzname)
    except Exception:
        tz = ZoneInfo("UTC")

    now_utc = datetime.now(timezone.utc)
    now_local = now_utc.astimezone(tz)

    try:
        hh, mm = (sched.get("time") or "03:00").split(":")
        hh, mm = int(hh), int(mm)
    except Exception:
        hh, mm = 3, 0

    def at_local(base_local, h, m):
        return base_local.replace(hour=h, minute=m, second=0, microsecond=0)

    freq = (sched.get("freq") or "daily").lower()
    cand_local = None

    if freq == "daily":
        cand_local = at_local(now_local, hh, mm)
        if cand_local <= now_local:
            cand_local += timedelta(days=1)

    elif freq == "weekly":
        dows = [int(x) for x in (sched.get("dow") or [])] or [1]
        best = None
        for d in range(8):
            tmp = at_local(now_local, hh, mm) + timedelta(days=d)
            if tmp.weekday() in dows and tmp > now_local:
                best = tmp
                break
        cand_local = best

    elif freq == "monthly":
        dom = max(1, min(31, int(sched.get("dom") or 1)))
        y, m = now_local.year, now_local.month
        day = min(dom, monthrange(y, m)[1])
        cand_local = at_local(now_local.replace(day=day), hh, mm)
        if cand_local <= now_local:
            m = 1 if m == 12 else m + 1
            y = y + 1 if m == 1 else y
            day = min(dom, monthrange(y, m)[1])
            cand_local = at_local(now_local.replace(year=y, month=m, day=day), hh, mm)

    if not cand_local:
        return None

    cand_utc = cand_local.astimezone(timezone.utc)
    return cand_utc.isoformat(timespec="seconds").replace("+00:00", "Z")


def _backup_restore_impl():
    f = request.files.get('file')
    if not f or not (f.filename or "").lower().endswith('.zip'):
        return jsonify(
            ok=False,
            error='no_file',
            message='Please upload a .zip backup file.'
        ), 400

    kind_req = (request.form.get('kind') or 'auto').lower().strip()
    restore_wg = (request.form.get('restore_wg') or '0') == '1'
    server_settings_mode = (request.form.get('server_settings_mode') or 'keep').lower().strip()
    if server_settings_mode not in ('keep', 'saved', 'custom'):
        server_settings_mode = 'keep'

    def _form_int(name, default=None):
        try:
            v = request.form.get(name)
            if v in (None, ''):
                return default
            i = int(v)
            return i if 1 <= i <= 65535 else default
        except Exception:
            return default

    custom_port = _form_int('custom_port')
    custom_http_port = _form_int('custom_http_port')
    custom_https_port = _form_int('custom_https_port')
    custom_bind = (request.form.get('custom_bind') or '').strip()
    custom_domain = (request.form.get('custom_domain') or '').strip()
    custom_scheme = (request.form.get('custom_scheme') or 'http').lower().strip()
    custom_wg_path = (request.form.get('custom_wg_path') or '').strip()
    if custom_scheme not in ('http', 'https'):
        custom_scheme = 'http'

    tmp = tempfile.NamedTemporaryFile(delete=False)
    try:
        f.save(tmp)
        tmp.flush()
        tmp.close()

        try:
            z = zipfile.ZipFile(tmp.name, 'r')
        except Exception:
            return jsonify(
                ok=False,
                error='invalid_zip',
                message='File is not a valid ZIP backup.'
            ), 400

        try:
            names = z.namelist()
            has_db = any(n.startswith('db/') and not n.endswith('/') for n in names)
            has_inst = any(n.startswith('instance/') and not n.endswith('/') for n in names)
            has_wg = any(n.startswith('wg/') and n.endswith('.conf') for n in names)
            has_node_wg = any(n.startswith('nodes/') and '/wg/' in n and n.endswith('.conf') for n in names)

            kind = kind_req
            if kind == 'auto':
                if has_db and has_inst:
                    kind = 'full'
                elif has_db:
                    kind = 'db'
                elif has_inst:
                    kind = 'settings'
                else:
                    return jsonify(
                        ok=False,
                        error='unknown_layout',
                        message='Backup ZIP does not look like a panel backup.'
                    ), 400

            if kind not in ('db', 'settings', 'full'):
                return jsonify(
                    ok=False,
                    error='invalid_restore_kind',
                    message='Restore kind must be auto, db, settings, or full.'
                ), 400

            inst = Path(current_app.instance_path)
            db_dir = inst / "restore_tmp_db"
            inst_dir = inst
            if server_settings_mode == 'custom' and custom_wg_path:
                wg_dir = Path(custom_wg_path)
            else:
                wg_dir = Path(current_app.config.get('WG_CONF_PATH') or '/etc/wireguard/')

            restored = {
                "db": False,
                "settings": False,
                "wg": False,
                "node_wg": False,
            }
            warnings = []
            node_restore_results = []
            restore_ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            snapshot_root = inst / "restore_snapshots" / restore_ts
            backed_up = set()

            def _backup_existing(dest: Path, kind_name: str, rel_tail: str):
                try:
                    if not dest.exists() or not dest.is_file():
                        return
                    key = str(dest.resolve())
                    if key in backed_up:
                        return
                    snap_path = snapshot_root / kind_name / rel_tail
                    snap_path.parent.mkdir(parents=True, exist_ok=True)
                    if snap_path.exists():
                        i = 2
                        while True:
                            alt = snap_path.with_name(snap_path.name + f".{i}")
                            if not alt.exists():
                                snap_path = alt
                                break
                            i += 1
                    dest.rename(snap_path)
                    backed_up.add(key)
                except Exception as e:
                    warnings.append(f"snapshot_failed:{dest}:{e}")

            def _safe_extract_tail(member: str) -> str:
                _, _, tail = member.partition('/')
                tail = tail.strip().lstrip('/')
                parts = Path(tail).parts
                if not tail:
                    raise ValueError('empty member path')
                if any(part in ('', '.', '..') for part in parts):
                    raise ValueError('unsafe member path')
                return tail

            def _extract(member: str, dest_root: Path, kind_name: str):
                if member.endswith('/'):
                    return
                tail = _safe_extract_tail(member)
                dest_root.mkdir(parents=True, exist_ok=True)
                dest = dest_root / tail
                root_resolved = dest_root.resolve()
                dest_resolved = dest.resolve() if dest.exists() else dest.parent.resolve() / dest.name
                if not str(dest_resolved).startswith(str(root_resolved)):
                    raise ValueError(f'unsafe restore path: {member}')
                _backup_existing(dest, kind_name=kind_name, rel_tail=tail)
                dest.parent.mkdir(parents=True, exist_ok=True)
                with z.open(member) as src, open(dest, 'wb') as out:
                    out.write(src.read())
                try:
                    if dest.suffix == '.conf':
                        os.chmod(dest, 0o600)
                except Exception:
                    pass

            if kind in ("db", "full"):
                for n in names:
                    if n.startswith("db/") and not n.endswith("/"):
                        _extract(n, db_dir, kind_name="db")

                db_files = list(db_dir.glob("*.db"))
                if db_files:
                    src = db_files[0]
                    try:
                        db_path = Path(DB_PATH)
                        db_path.parent.mkdir(parents=True, exist_ok=True)
                        _backup_existing(db_path, kind_name="db", rel_tail=db_path.name)
                        src.replace(db_path)
                        restored["db"] = True
                    except Exception as e:
                        return jsonify(
                            ok=False,
                            error="db_restore_failed",
                            message=str(e)
                        ), 500
                else:
                    warnings.append("db_requested_but_no_db_file_found")

            if kind in ("settings", "full"):
                if has_inst:
                    server_local_files = {
                        "runtime.json",
                        "panel_settings.json",
                        "backup_schedule.json",
                        "backup_settings.json",
                        "backup_last.json",
                        "auto_backup.json",
                    }
                    skipped_server_files = []
                    restored_server_files = []

                    for n in names:
                        if not n.startswith("instance/") or n.endswith("/"):
                            continue
                        fname = os.path.basename(n)
                        if fname in server_local_files:
                            if server_settings_mode == "saved":
                                _extract(n, inst_dir, kind_name="instance")
                                restored_server_files.append(fname)
                            else:
                                skipped_server_files.append(fname)
                            continue
                        _extract(n, inst_dir, kind_name="instance")

                    restored["settings"] = True
                    if skipped_server_files:
                        warnings.append(
                            "server_local_settings_protected: " +
                            ", ".join(sorted(set(skipped_server_files)))
                        )
                    if restored_server_files:
                        warnings.append(
                            "server_local_settings_restored: " +
                            ", ".join(sorted(set(restored_server_files)))
                        )

                    if server_settings_mode == "custom":
                        runtime_path = Path(current_app.instance_path) / "runtime.json"
                        panel_path = Path(current_app.instance_path) / "panel_settings.json"
                        port = custom_port or custom_http_port or custom_https_port
                        bind_host = custom_bind or "0.0.0.0"
                        if ":" in bind_host:
                            host_part, _, port_part = bind_host.rpartition(":")
                            bind_host = host_part or "0.0.0.0"
                            try:
                                port = int(port_part)
                            except Exception:
                                pass
                        if not port:
                            port = 443 if custom_scheme == "https" else 8000

                        runtime_payload = {
                            "bind": f"{bind_host}:{int(port)}",
                            "port": int(port),
                            "workers": 0,
                            "threads": 4,
                            "timeout": 60,
                            "graceful_timeout": 30,
                            "loglevel": "info",
                        }
                        panel_payload = {
                            "tls_enabled": custom_scheme == "https",
                            "domain": custom_domain,
                            "force_https_redirect": False,
                            "hsts": False,
                            "http_port": custom_http_port or (int(port) if custom_scheme == "http" else None),
                            "https_port": custom_https_port or (int(port) if custom_scheme == "https" else 443),
                            "tls_cert_path": "",
                            "tls_key_path": "",
                        }
                        runtime_path.write_text(json.dumps(runtime_payload, indent=2), encoding="utf-8")
                        panel_path.write_text(json.dumps(panel_payload, indent=2), encoding="utf-8")
                        warnings.append("custom_server_settings_written: runtime.json, panel_settings.json")
                else:
                    warnings.append("settings_requested_but_no_instance_files_found")

            if restore_wg and has_wg and kind in ("settings", "full"):
                for n in names:
                    if n.startswith("wg/") and n.endswith(".conf"):
                        _extract(n, wg_dir, kind_name="wg")
                restored["wg"] = True
            elif has_wg and not restore_wg:
                warnings.append("wg_present_but_not_restored")

            if restore_wg and has_node_wg and kind in ("settings", "full"):
                try:
                    node_restore_results = _restore_node_wg_zip(z, names)
                    restored["node_wg"] = any(bool(x.get("ok")) for x in node_restore_results)
                    if not restored["node_wg"]:
                        warnings.append("node_wg_present_but_no_node_restore_success")
                except Exception as e:
                    warnings.append(f"node_wg_restore_failed:{e}")
            elif has_node_wg and not restore_wg:
                warnings.append("node_wg_present_but_not_restored")

            try:
                _norm_adminlog({
                    "action": "backup_restore",
                    "details": (
                        f"kind={kind}; restore_wg={int(restore_wg)}; "
                        f"db={int(restored['db'])}; settings={int(restored['settings'])}; "
                        f"wg={int(restored['wg'])}; node_wg={int(restored['node_wg'])}"
                    ),
                    "channel": "api" if request.headers.get('Authorization') or request.headers.get('X-API-KEY') else "web",
                })
            except Exception:
                pass

            return jsonify(
                ok=True,
                kind=kind,
                server_settings_mode=server_settings_mode,
                detected={
                    "db": bool(has_db),
                    "settings": bool(has_inst),
                    "wg": bool(has_wg),
                    "node_wg": bool(has_node_wg),
                },
                restored=restored,
                warnings=warnings,
                node_restore_results=node_restore_results,
                message="Restore completed. Restart may be required."
            )

        finally:
            try:
                z.close()
            except Exception:
                pass

    finally:
        try:
            Path(tmp.name).unlink(missing_ok=True)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@backup_bp.get('/backup')
@login_required
def backup_page():
    return render_template('backup.html')


@backup_bp.post('/api/backup/restore')
@login_required
def backup_restore():
    return _backup_restore_impl()


@backup_bp.post('/api/backup/restore_api')
@require_api_key
def backup_restore_api():
    return _backup_restore_impl()


@backup_bp.post('/api/backup/inspect')
@login_required
def backup_inspect():
    f = request.files.get('file')
    if not f or not (f.filename or '').lower().endswith('.zip'):
        return jsonify(
            ok=False,
            error='no_file',
            message='Please upload a .zip backup file.'
        ), 400

    tmp = tempfile.NamedTemporaryFile(delete=False)
    try:
        f.save(tmp)
        tmp.flush()
        tmp.close()

        try:
            z = zipfile.ZipFile(tmp.name, 'r')
        except Exception:
            return jsonify(
                ok=False,
                error='invalid_zip',
                message='File is not a valid ZIP backup.'
            ), 400

        try:
            names = z.namelist()
            has_db = any(n.startswith('db/') and not n.endswith('/') for n in names)
            has_inst = any(n.startswith('instance/') and not n.endswith('/') for n in names)
            has_wg = any(n.startswith('wg/') and n.endswith('.conf') for n in names)
            has_node_wg = any(n.startswith('nodes/') and '/wg/' in n and n.endswith('.conf') for n in names)
            has_env = any(n == 'env/.env' for n in names)
            has_node_env = any(n.startswith('nodes/') and n.endswith('/env/.env') for n in names)

            local_wg_files = sorted([
                os.path.basename(n)
                for n in names
                if n.startswith('wg/') and n.endswith('.conf')
            ])

            node_wg_files = []
            node_wg_nodes = {}
            node_env_files = []
            node_env_nodes = {}

            for n in names:
                m = re.match(r'^nodes/(\d+)/wg/([^/]+\.conf)$', n)
                if m:
                    node_id = int(m.group(1))
                    filename = os.path.basename(m.group(2))
                    node_wg_files.append({'node_id': node_id, 'file': filename, 'path': n})
                    node_wg_nodes.setdefault(str(node_id), 0)
                    node_wg_nodes[str(node_id)] += 1
                    continue

                m_env = re.match(r'^nodes/(\d+)/env/\.env$', n)
                if m_env:
                    node_id = int(m_env.group(1))
                    node_env_files.append({'node_id': node_id, 'file': '.env', 'path': n})
                    node_env_nodes.setdefault(str(node_id), 0)
                    node_env_nodes[str(node_id)] += 1
                    continue

            def _read_text(member):
                try:
                    with z.open(member) as fh:
                        return fh.read().decode('utf-8', 'replace').strip()
                except Exception:
                    return None

            def _read_json(member):
                txt = _read_text(member)
                if not txt:
                    return None
                try:
                    return json.loads(txt)
                except Exception:
                    return None

            created = _read_text('meta/created.txt')
            host = _read_text('meta/host.txt')
            manifest = _read_json('meta/manifest.json')
            node_wg_backup = _read_json('meta/node_wg_backup.json')
            runtime_settings = _read_json('instance/runtime.json') or {}
            panel_settings = _read_json('instance/panel_settings.json') or {}
            app_meta = _read_json('meta/app.json') or {}

            kind = 'unknown'
            if has_db and has_inst:
                kind = 'full'
            elif has_db:
                kind = 'db'
            elif has_inst:
                kind = 'settings'

            contains = {
                'database': bool(has_db),
                'settings': bool(has_inst),
                'local_wireguard_conf': bool(has_wg),
                'remote_node_wireguard_conf': bool(has_node_wg),
                'env_file': bool(has_env),
                'remote_node_env': bool(has_node_env),
                'short_links': any(n == 'instance/short_links.json' for n in names),
                'manifest': bool(manifest),
            }

            counts = {
                'local_wg_files': len(local_wg_files),
                'node_wg_files': len(node_wg_files),
                'node_wg_nodes': len(node_wg_nodes),
                'node_env_files': len(node_env_files),
                'node_env_nodes': len(node_env_nodes),
                'instance_files': len([n for n in names if n.startswith('instance/') and not n.endswith('/')]),
                'db_files': len([n for n in names if n.startswith('db/') and not n.endswith('/')]),
            }

            return jsonify(
                ok=True,
                kind=kind,
                has_db=has_db,
                has_settings=has_inst,
                has_wg=has_wg,
                has_node_wg=has_node_wg,
                has_env=has_env,
                has_node_env=has_node_env,
                contains=contains,
                counts=counts,
                local_wg_files=local_wg_files,
                node_wg_files=node_wg_files,
                node_wg_nodes=node_wg_nodes,
                node_env_files=node_env_files,
                node_env_nodes=node_env_nodes,
                created=created,
                host=host,
                manifest=manifest,
                node_wg_backup=node_wg_backup,
                runtime=runtime_settings,
                panel_settings=panel_settings,
                app_meta=app_meta,
            )

        finally:
            try:
                z.close()
            except Exception:
                pass

    finally:
        try:
            Path(tmp.name).unlink(missing_ok=True)
        except Exception:
            pass


@backup_bp.get('/api/backup/node-agent/install-command')
@login_required
@admin_required
def backup_node_agent_install_command():
    node_id = request.args.get('node_id', type=int)
    node = db.session.get(Node, node_id) if node_id else None
    api_key = ''
    base_url = ''
    if node:
        try:
            api_key = _read_api_key(node)
        except Exception:
            api_key = ''
        base_url = getattr(node, 'base_url', '') or ''

    command = """sudo bash -c 'command -v curl >/dev/null 2>&1 || (apt-get update -y && apt-get install -y curl ca-certificates); bash -c "$(curl -fsSL https://raw.githubusercontent.com/MasterALiReza/OxWG-Panel/refs/heads/main/agent/node.sh)"'"""
    return jsonify(
        ok=True,
        node_id=node_id,
        node_name=getattr(node, 'name', None) if node else None,
        base_url=base_url,
        has_api_key=bool(api_key),
        command=command,
        next_command="node",
        notes=[
            "Run the install command on the node server as root.",
            "After installation, open the node menu by running: node",
            "Use the same API key and port as the node record in this panel.",
            "Return to the panel, test the node, then restore node WireGuard configs."
        ],
    )


@backup_bp.get('/api/backups/auto')
@login_required
def backups_autolist():
    root = Path(BACKUP_AUTO_DIR)
    root.mkdir(parents=True, exist_ok=True)
    files = []
    for p in root.glob('*.zip'):
        try:
            st = p.stat()
        except OSError:
            continue
        files.append({
            "name": p.name,
            "size": st.st_size,
            "ts": int(st.st_mtime),
        })
    files.sort(key=lambda x: x["ts"], reverse=True)
    return jsonify(files=files)


@backup_bp.route('/api/backups/file/<path:fname>', methods=['GET', 'DELETE'])
@require_api_key_or_login
def backups_auto(fname):
    safe_name = os.path.basename(str(fname or ''))
    if not safe_name or not safe_name.lower().endswith('.zip'):
        return jsonify(ok=False, error='invalid_filename', message='Invalid backup filename.'), 400

    backup_root = Path(BACKUP_AUTO_DIR).resolve()
    backup_path = (backup_root / safe_name).resolve()
    try:
        backup_path.relative_to(backup_root)
    except ValueError:
        return jsonify(ok=False, error='invalid_path', message='Invalid backup path.'), 400

    if not backup_path.is_file():
        return jsonify(ok=False, error='not_found', message='The saved backup was not found.'), 404

    if request.method == 'DELETE':
        try:
            file_size = backup_path.stat().st_size
            backup_path.unlink()
            current_app.logger.info('Automatic backup deleted: file=%s size=%s', safe_name, file_size)
            try:
                _norm_adminlog({
                    'action': 'auto_backup_delete',
                    'details': f'file={safe_name}; size={file_size}',
                    'channel': 'api' if request.headers.get('Authorization') or request.headers.get('X-API-KEY') else 'web',
                })
            except Exception:
                pass
            return jsonify(ok=True, deleted=safe_name, size=file_size, message='Automatic backup deleted.')
        except PermissionError:
            return jsonify(ok=False, error='permission_denied', message='The panel does not have permission to delete this backup.'), 403
        except Exception as exc:
            current_app.logger.exception('Could not delete automatic backup %s: %s', safe_name, exc)
            return jsonify(ok=False, error='delete_failed', message=str(exc)), 500

    download = (request.args.get('download') == '1')
    return send_file(
        str(backup_path),
        mimetype='application/zip',
        as_attachment=download,
        download_name=backup_path.name,
        conditional=True,
    )


@backup_bp.get('/api/backups/inspect/<path:fname>')
@require_api_key_or_login
def inspect_saved_auto_backup(fname):
    safe_name = os.path.basename(str(fname or ''))
    if not safe_name or not safe_name.lower().endswith('.zip'):
        return jsonify(ok=False, error='invalid_filename', message='Invalid backup filename.'), 400

    backup_root = Path(BACKUP_AUTO_DIR).resolve()
    backup_path = (backup_root / safe_name).resolve()
    try:
        backup_path.relative_to(backup_root)
    except ValueError:
        return jsonify(ok=False, error='invalid_path', message='Invalid backup path.'), 400

    if not backup_path.is_file():
        return jsonify(ok=False, error='not_found', message='The saved backup file was not found.'), 404

    try:
        with zipfile.ZipFile(backup_path, 'r') as archive:
            names = archive.namelist()

            def existing_files(prefix):
                return [name for name in names if name.startswith(prefix) and not name.endswith('/')]

            def read_text(member):
                if member not in names:
                    return None
                try:
                    return archive.read(member).decode('utf-8', 'replace').strip()
                except Exception:
                    return None

            def read_json(member):
                text = read_text(member)
                if not text:
                    return None
                try:
                    return json.loads(text)
                except Exception:
                    return None

            db_files = existing_files('db/')
            instance_files = existing_files('instance/')
            local_wg_files = sorted([
                os.path.basename(name)
                for name in names
                if name.startswith('wg/') and name.endswith('.conf')
            ])

            node_wg_files = []
            node_wg_nodes = {}
            node_env_files = []
            node_env_nodes = {}

            for member in names:
                match = re.match(r'^nodes/(\d+)/wg/([^/]+\.conf)$', member)
                if match:
                    node_id = int(match.group(1))
                    filename = os.path.basename(match.group(2))
                    node_wg_files.append({'node_id': node_id, 'file': filename, 'path': member})
                    node_key = str(node_id)
                    node_wg_nodes[node_key] = node_wg_nodes.get(node_key, 0) + 1
                    continue

                match_env = re.match(r'^nodes/(\d+)/env/\.env$', member)
                if match_env:
                    node_id = int(match_env.group(1))
                    node_env_files.append({'node_id': node_id, 'file': '.env', 'path': member})
                    node_key = str(node_id)
                    node_env_nodes[node_key] = node_env_nodes.get(node_key, 0) + 1

            has_db = bool(db_files)
            has_settings = bool(instance_files)
            has_wg = bool(local_wg_files)
            has_node_wg = bool(node_wg_files)
            has_env = ('env/.env' in names)
            has_node_env = bool(node_env_files)

            if has_db and has_settings:
                kind = 'full'
            elif has_db:
                kind = 'db'
            elif has_settings:
                kind = 'settings'
            else:
                kind = 'unknown'

            manifest = read_json('meta/manifest.json') or {}
            node_backup_results = read_json('meta/node_wg_backup.json') or []
            runtime_settings = read_json('instance/runtime.json') or {}
            panel_settings = read_json('instance/panel_settings.json') or {}
            app_meta = read_json('meta/app.json') or {}
            created = read_text('meta/created.txt')
            host = read_text('meta/host.txt')

            contains = {
                'database': has_db,
                'settings': has_settings,
                'local_wireguard_conf': has_wg,
                'remote_node_wireguard_conf': has_node_wg,
                'env_file': has_env,
                'remote_node_env': has_node_env,
                'short_links': any(n == 'instance/short_links.json' for n in names),
                'manifest': bool(manifest),
            }

            counts = {
                'local_wg_files': len(local_wg_files),
                'node_wg_files': len(node_wg_files),
                'node_wg_nodes': len(node_wg_nodes),
                'node_env_files': len(node_env_files),
                'node_env_nodes': len(node_env_nodes),
                'instance_files': len(instance_files),
                'db_files': len(db_files),
            }

            return jsonify(
                ok=True,
                filename=safe_name,
                size=backup_path.stat().st_size,
                kind=kind,
                has_db=has_db,
                has_settings=has_settings,
                has_wg=has_wg,
                has_node_wg=has_node_wg,
                has_env=has_env,
                has_node_env=has_node_env,
                contains=contains,
                counts=counts,
                local_wg_files=local_wg_files,
                node_wg_files=node_wg_files,
                node_wg_nodes=node_wg_nodes,
                node_env_files=node_env_files,
                node_env_nodes=node_env_nodes,
                created=created,
                host=host,
                manifest=manifest,
                node_wg_backup=node_backup_results,
                runtime=runtime_settings,
                panel_settings=panel_settings,
                app_meta=app_meta,
            )
    except Exception as exc:
        current_app.logger.exception('Could not inspect saved backup %s: %s', safe_name, exc)
        return jsonify(ok=False, error='inspection_failed', message=str(exc)), 500


@backup_bp.get('/api/backup/prefs')
@require_api_key_or_login
def backup_get():
    return jsonify(_backup_prefs_load())


@backup_bp.post('/api/backup/prefs')
@require_api_key_or_login
def backup_post():
    data = request.get_json(silent=True) or {}
    saved = _backup_prefs_save(data)
    return jsonify(ok=True, prefs=saved)


@backup_bp.get('/api/backup/db')
@require_api_key_or_login
def backup_db():
    dbp = _db_path()
    if not dbp or not os.path.isfile(dbp):
        return jsonify(error='db_not_found_or_not_sqlite'), 404

    mem = BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        z.write(dbp, arcname=f'db/{os.path.basename(dbp)}')
        z.writestr('meta/created.txt', datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'))
    mem.seek(0)

    ts = _panel_filename_stamp()
    fname = f'wgpanel_db_{ts}.zip'

    try:
        _norm_adminlog({
            "action": "backup_db",
            "details": f"file={fname} size={mem.getbuffer().nbytes}B",
            "channel": "api" if request.headers.get('Authorization') or request.headers.get('X-API-KEY') else "web"
        })
    except Exception:
        pass

    try:
        _record_backup('db')
    except Exception as e:
        current_app.logger.debug("record_backup(db) failed: %s", e)

    resp = send_file(mem, mimetype='application/zip', as_attachment=True, download_name=fname)
    resp.headers['X-Backup-Kind'] = 'db'
    resp.headers['X-Backup-Timestamp'] = ts
    return resp


@backup_bp.get('/api/backup/last')
@require_api_key_or_login
def backup_last_get():
    last = _load_backup_last() or {}

    def to_epoch(iso):
        try:
            return int(datetime.fromisoformat(iso.replace('Z', '+00:00')).timestamp())
        except Exception:
            return 0

    candidates = [to_epoch(last.get(k, '')) for k in ('db_last', 'settings_last', 'full_last')]
    best = max(candidates) if any(candidates) else 0
    return jsonify(last_backup_ts=(best if best > 0 else None))


@backup_bp.post('/api/backup/last')
@require_api_key_or_login
def backup_last_post():
    data = request.get_json(silent=True) or {}
    kind = (data.get('kind') or 'full').lower()
    try:
        ts = int(data.get('last_backup_ts')) if data.get('last_backup_ts') is not None else None
    except Exception:
        ts = None
    try:
        _record_backup(kind, ts)
    except Exception as e:
        current_app.logger.debug("record_backup(%s) failed: %s", kind, e)
    return jsonify(ok=True)


@backup_bp.get('/api/backup/settings')
@require_api_key_or_login
def backup_settings():
    mem = BytesIO()
    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        _jsonl_bundle(z)
        z.writestr('meta/created.txt', datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'))
    mem.seek(0)

    ts = _panel_filename_stamp()
    fname = f'wgpanel_settings_{ts}.zip'

    try:
        _norm_adminlog({
            "action": "backup_settings",
            "details": f"file={fname} size={mem.getbuffer().nbytes}B",
            "channel": "api" if request.headers.get('Authorization') or request.headers.get('X-API-KEY') else "web"
        })
    except Exception:
        pass

    try:
        _record_backup('settings')
    except Exception as e:
        current_app.logger.debug("record_backup(settings) failed: %s", e)

    resp = send_file(mem, mimetype='application/zip', as_attachment=True, download_name=fname)
    resp.headers['X-Backup-Kind'] = 'settings'
    resp.headers['X-Backup-Timestamp'] = ts
    return resp


@backup_bp.get('/api/backup/full')
@require_api_key_or_login
def backup_full():
    prefs = _backup_prefs_load()
    include_wg = (request.args.get('wg') or ('1' if prefs.get('include_wg') else '0')) == '1'
    send_tg = (request.args.get('tg') or ('1' if prefs.get('send_to_telegram') else '0')) == '1'
    auto_flag = (request.args.get('auto') or '0') == '1'
    selected_chat_id = (request.args.get("chat_id") or "").strip()

    node_wg_results = []
    saved_auto_backup = None
    mem = BytesIO()

    with zipfile.ZipFile(mem, 'w', zipfile.ZIP_DEFLATED) as z:
        dbp = _db_path()
        if dbp and os.path.isfile(dbp):
            z.write(dbp, arcname=f'db/{os.path.basename(dbp)}')

        _jsonl_bundle(z)
        _env_bundle(z)

        if include_wg:
            wgdir = current_app.config.get('WG_CONF_PATH') or '/etc/wireguard/'
            try:
                for p in Path(wgdir).glob('*.conf'):
                    if p.is_file():
                        z.write(p, arcname=f'wg/{p.name}')
            except Exception as e:
                current_app.logger.debug("Local WG bundle skipped: %s", e)

            try:
                node_wg_results = _bundle_node_wg_backups(z)
            except Exception as e:
                current_app.logger.warning("Node backup bundle skipped: %s", e)
                node_wg_results = [{
                    'ok': False,
                    'files': [],
                    'env_file': False,
                    'error': str(e),
                }]

        created_at = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
        z.writestr('meta/created.txt', created_at)
        z.writestr('meta/host.txt', socket.gethostname())
        z.writestr(
            'meta/app.json',
            json.dumps({
                'db_uri': current_app.config.get('SQLALCHEMY_DATABASE_URI', ''),
                'wg_conf_path': current_app.config.get('WG_CONF_PATH') or '/etc/wireguard/',
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

        try:
            local_wg_count = 0
            if include_wg:
                wgdir = current_app.config.get('WG_CONF_PATH') or '/etc/wireguard/'
                local_wg_count = len([p for p in Path(wgdir).glob('*.conf') if p.is_file()])
        except Exception:
            local_wg_count = 0

        node_wg_count = 0
        node_env_count = 0
        try:
            for rec in node_wg_results or []:
                node_wg_count += len(rec.get('files') or [])
                if rec.get('env_file'):
                    node_env_count += 1
        except Exception:
            node_wg_count = 0
            node_env_count = 0

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

    mem.seek(0)
    ts = _panel_filename_stamp()
    fname = f'wgpanel_full_backup_{ts}.zip'
    data = mem.getvalue()

    if auto_flag:
        try:
            schedule = _load_backup_schedule()
            keep = int(schedule.get("keep", 7))
        except Exception:
            keep = 7
        try:
            saved_auto_backup = _save_autobackup(data, keep=keep)
        except Exception as exc:
            saved_auto_backup = None
            current_app.logger.exception("Automatic backup storage failed: %s", exc)

    telegram_ok = None
    telegram_message = ""
    if send_tg:
        telegram_ok, telegram_message = _send_zip_telegram(data, fname, chat_id=selected_chat_id or None)
        if telegram_ok is False:
            current_app.logger.warning("Backup Telegram send failed: %s", telegram_message)

    try:
        node_wg_count = 0
        node_env_count = 0
        for rec in node_wg_results or []:
            node_wg_count += len(rec.get('files') or [])
            if rec.get('env_file'):
                node_env_count += 1

        _norm_adminlog({
            "action": "backup_full",
            "details": (
                f"file={fname} size={len(data)}B "
                f"wg={int(include_wg)} tg={int(send_tg)} auto={int(auto_flag)} "
                f"node_wg_nodes={len(node_wg_results or [])} "
                f"node_wg_files={node_wg_count} "
                f"node_env_files={node_env_count}"
            ),
            "channel": "api" if request.headers.get('Authorization') or request.headers.get('X-API-KEY') else "web",
        })
    except Exception:
        pass

    try:
        _record_backup('full')
    except Exception as e:
        current_app.logger.debug("record_backup(full) failed: %s", e)

    out = BytesIO(data)
    out.seek(0)
    resp = send_file(
        out,
        mimetype='application/zip',
        as_attachment=True,
        download_name=fname,
    )
    resp.headers['X-Backup-Kind'] = 'full'
    resp.headers['X-Backup-Timestamp'] = ts
    return resp


@backup_bp.get('/api/backup/status')
@require_api_key_or_login
def backup_status():
    return jsonify(_load_backup_last())


@backup_bp.get('/api/backup/schedule')
@require_api_key_or_login
def backup_schedule_get():
    s = _load_backup_schedule()
    s["next_run"] = _next_run(s)
    return jsonify(s)


@backup_bp.post('/api/backup/schedule')
@require_api_key_or_login
def backup_schedule_post():
    data = request.get_json(silent=True) or {}
    s = _save_backup_schedule(data)
    if not isinstance(s, dict):
        s = _load_backup_schedule()
    s["next_run"] = _next_run(s)
    return jsonify(ok=True, **s)
