#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
installer_web.py — GUI web installer for OxWG Panel
====================================================
Run via:  sudo bash install-gui.sh
Direct:   sudo python3 installer/installer_web.py

Security note
-------------
This server is meant to be accessed LOCALLY or through an SSH tunnel.
Default bind is 127.0.0.1 (localhost only).  Set INSTALLER_BIND=0.0.0.0
only if you understand the security implications (no auth on this UI).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import platform
import secrets
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Flask — only stdlib + flask required (install-gui.sh installs flask)
# ---------------------------------------------------------------------------
try:
    from flask import (
        Flask, render_template, redirect, url_for,
        request, flash, jsonify, send_file, abort,
    )
except ImportError:
    sys.exit("Flask is not installed.  Run:  pip install flask")

try:
    from cryptography.fernet import Fernet  # type: ignore
    _HAS_FERNET = True
except ImportError:
    _HAS_FERNET = False

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
HERE         = Path(__file__).resolve().parent
TEMPLATES_DIR = HERE / "templates"
STATIC_DIR    = HERE / "static"
PROJECT_ROOT  = HERE.parent          # parent of installer/ = project root

_STATE_BASE = Path(os.environ.get("WG_PANEL_STATE_DIR", "/etc/wg-panel"))
STATE_FILE  = _STATE_BASE / "installer.json"
LOG_FILE    = _STATE_BASE / "installer.log"

BIND = os.environ.get("INSTALLER_BIND", "127.0.0.1")
PORT = int(os.environ.get("INSTALLER_PORT", "8888"))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_log = logging.getLogger("installer_web")

# ---------------------------------------------------------------------------
# State helpers
# ---------------------------------------------------------------------------

def _load_state() -> dict:
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_state(data: dict) -> None:
    try:
        _STATE_BASE.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    except Exception as exc:
        _log.error("Cannot save state: %s", exc)


def _state() -> dict:
    """Return saved state merged with safe defaults."""
    defaults: dict = {
        "install_dir":       str(PROJECT_ROOT),
        "venv_dir":          "venv",
        "instance_dir":      "instance",
        "env_file":          ".env",
        "bind":              "0.0.0.0",
        "port":              8000,
        "workers":           2,
        "threads":           4,
        "timeout":           60,
        "graceful_timeout":  30,
        "loglevel":          "info",
        "panel_service":     "wg-panel",
        "bot_service":       "wg-panel-bot",
        "tls_enabled":       False,
        "tls_certfile":      "",
        "tls_keyfile":       "",
        "wg_conf_path":      "/etc/wireguard",
        "wg_default_iface":  "",
    }
    defaults.update(_load_state())
    return defaults


# ---------------------------------------------------------------------------
# .env helpers
# ---------------------------------------------------------------------------

def _parse_env(text: str) -> dict:
    out: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _env_dict() -> dict:
    st = _state()
    p = Path(st["install_dir"]) / st["env_file"]
    if p.exists():
        return _parse_env(p.read_text(encoding="utf-8"))
    return {}


def _write_env(vals: dict) -> None:
    st = _state()
    p = Path(st["install_dir"]) / st["env_file"]
    existing = _parse_env(p.read_text(encoding="utf-8")) if p.exists() else {}
    existing.update(vals)
    p.write_text(
        "\n".join(f"{k}={v}" for k, v in existing.items()) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# JSON config helpers
# ---------------------------------------------------------------------------

def _json_cfg(filename: str) -> dict:
    st = _state()
    p = Path(st["install_dir"]) / st["instance_dir"] / filename
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _write_json_cfg(filename: str, data: object) -> None:
    st = _state()
    inst = Path(st["install_dir"]) / st["instance_dir"]
    inst.mkdir(parents=True, exist_ok=True)
    (inst / filename).write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Installer log helpers
# ---------------------------------------------------------------------------
_log_lock = threading.Lock()


def _append_log(text: str) -> None:
    try:
        _STATE_BASE.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with _log_lock, open(LOG_FILE, "a", encoding="utf-8") as fh:
            for line in text.splitlines() or [""]:
                fh.write(f"[{ts}] {line}\n")
    except Exception:
        pass


def _tail_log(n: int = 220) -> list:
    try:
        if LOG_FILE.exists():
            return LOG_FILE.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()[-n:]
    except Exception:
        pass
    return []


# ---------------------------------------------------------------------------
# Secret generators
# ---------------------------------------------------------------------------

def _gen_flask_secret() -> str:
    return secrets.token_hex(32)


def _gen_fernet() -> str:
    if _HAS_FERNET:
        return Fernet.generate_key().decode()
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def _gen_api_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


def _gen_setup_token() -> str:
    return secrets.token_urlsafe(24)


# ---------------------------------------------------------------------------
# System helpers
# ---------------------------------------------------------------------------

def _detect_wg_interfaces() -> list:
    st = _state()
    wg_dir = Path(st.get("wg_conf_path", "/etc/wireguard"))
    if not wg_dir.is_dir():
        return []
    return sorted(p.stem for p in wg_dir.glob("*.conf"))


def _service_active(name: str) -> bool:
    try:
        r = subprocess.run(
            ["systemctl", "is-active", "--quiet", name],
            timeout=5, check=False,
        )
        return r.returncode == 0
    except Exception:
        return False


def _project_ok(install_dir: str) -> bool:
    p = Path(install_dir)
    return (p / "app.py").exists() and (p / "requirements.txt").exists()


def _sys_info() -> dict:
    st = _state()
    return {
        "project_ok": _project_ok(st["install_dir"]),
        "panel_up":   _service_active(st["panel_service"]),
        "bot_up":     _service_active(st["bot_service"]),
        "wg_ok":      shutil.which("wg") is not None,
        "python":     sys.version.split()[0],
        "platform":   platform.system(),
        "hostname":   socket.gethostname(),
    }


# ---------------------------------------------------------------------------
# Async install action runner
# ---------------------------------------------------------------------------

APT_PKGS = [
    "sudo", "ca-certificates", "curl", "wget", "git", "jq", "rsync",
    "unzip", "openssl", "python3", "python3-venv", "python3-pip",
    "python3-dev", "build-essential", "pkg-config", "libffi-dev",
    "libssl-dev", "wireguard", "wireguard-tools", "iproute2",
    "iptables", "procps",
]


def _run_action(action: str, install_dir: str) -> None:
    root = Path(install_dir)
    st   = _state()
    venv = root / st.get("venv_dir", "venv")
    py   = venv / "bin" / "python"
    pip  = venv / "bin" / "pip"

    _append_log(f"=== Action: {action} ===")

    def _run(cmd: list, cwd=None, env=None) -> int:
        _append_log("$ " + " ".join(str(c) for c in cmd))
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=cwd or root,
                env=env,
            )
            for line in proc.stdout or []:
                _append_log(line.rstrip())
            proc.wait()
            _append_log(f"[exit {proc.returncode}]")
            return proc.returncode
        except FileNotFoundError as exc:
            _append_log(f"[error] {exc}")
            return 1

    apt_env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}

    try:
        if action == "deps":
            _run(["apt-get", "update", "-o", "Dpkg::Use-Pty=0"], env=apt_env)
            _run(
                ["apt-get", "install", "-y", "--no-install-recommends",
                 "-o", "Dpkg::Use-Pty=0"] + APT_PKGS,
                env=apt_env,
            )

        elif action == "venv":
            if not py.exists():
                _run(["python3", "-m", "venv", str(venv)])
            _run([str(pip), "install", "-U", "pip", "setuptools", "wheel"])
            req = root / "requirements.txt"
            if req.exists():
                _run([str(pip), "install", "-r", str(req)])

        elif action == "env":
            env_path = root / st.get("env_file", ".env")
            vals = _parse_env(env_path.read_text(encoding="utf-8")) if env_path.exists() else {}
            vals.setdefault("FLASK_SECRET_KEY", _gen_flask_secret())
            vals.setdefault("FERNET_KEY", _gen_fernet())
            vals.setdefault("API_KEY", _gen_api_key())
            vals.setdefault("DATABASE_URL", "sqlite:///instance/wg_panel.db")
            vals.setdefault("LOG_LEVEL", "INFO")
            vals.setdefault("SECURE_COOKIES", "1")
            vals.setdefault("WIREGUARD_CONF_PATH", st.get("wg_conf_path", "/etc/wireguard"))
            env_path.write_text(
                "\n".join(f"{k}={v}" for k, v in vals.items()) + "\n",
                encoding="utf-8",
            )
            _append_log(f"[ok] .env written → {env_path}")

        elif action == "botenv":
            _append_log("[info] Bot env sync — .env is shared with bot service.")

        elif action == "json":
            _write_json_cfg("panel_settings.json", _json_cfg("panel_settings.json") or {
                "tls_enabled": False, "domain": "",
                "force_https_redirect": False, "hsts": False,
                "https_port": 443, "tls_cert_path": "", "tls_key_path": "",
            })
            _write_json_cfg("backup_schedule.json", _json_cfg("backup_schedule.json") or {
                "enabled": False, "freq": "daily", "time": "03:00",
                "timezone": "UTC", "keep": 7,
                "include_wg": True, "send_to_telegram": False,
            })
            _write_json_cfg("telegram_settings.json", _json_cfg("telegram_settings.json") or {
                "enabled": False, "bot_token": "",
                "notify": {"app_down": True, "iface_down": True},
            })
            if not _json_cfg("telegram_admins.json"):
                _write_json_cfg("telegram_admins.json", [])
            _append_log("[ok] JSON configs ensured.")

        elif action == "db":
            if py.exists():
                _run(
                    [str(py), "-m", "flask", "db", "upgrade"],
                    env={**os.environ, "FLASK_APP": "app.py"},
                )
            else:
                _append_log("[warn] venv not ready — run venv step first.")

        elif action == "systemd":
            svc = st.get("panel_service", "wg-panel")
            svc_path = Path(f"/etc/systemd/system/{svc}.service")
            if svc_path.exists():
                _run(["systemctl", "daemon-reload"])
                _run(["systemctl", "enable", svc])
                _append_log(f"[ok] Enabled {svc}")
            else:
                _append_log(f"[warn] {svc_path} not found — generate it via wg.py first.")

        elif action == "cli":
            wgpanel = root / "wg.py"
            dest = Path("/usr/local/bin/wgpanel")
            if wgpanel.exists():
                try:
                    if dest.exists() or dest.is_symlink():
                        dest.unlink()
                    dest.symlink_to(wgpanel)
                    wgpanel.chmod(0o755)
                    _append_log(f"[ok] wgpanel → {dest}")
                except Exception as exc:
                    _append_log(f"[error] {exc}")
            else:
                _append_log("[warn] wg.py not found in install_dir.")

        elif action == "start":
            _run(["systemctl", "start", st.get("panel_service", "wg-panel")])

        elif action == "stop":
            _run(["systemctl", "stop", st.get("panel_service", "wg-panel")])

        elif action == "restart":
            _run(["systemctl", "restart", st.get("panel_service", "wg-panel")])
            bot = st.get("bot_service", "wg-panel-bot")
            if _service_active(bot):
                _run(["systemctl", "restart", bot])

        elif action == "status":
            _run(["systemctl", "status",
                  st.get("panel_service", "wg-panel"), "--no-pager", "-l"])

        elif action == "clearlog":
            try:
                if LOG_FILE.exists():
                    LOG_FILE.unlink()
                _append_log("[ok] Log cleared.")
            except Exception as exc:
                _append_log(f"[error] {exc}")

        elif action == "all":
            for sub in ["deps", "venv", "env", "json", "db"]:
                _run_action(sub, install_dir)
            _append_log("[ok] Install Everything complete.")

        else:
            _append_log(f"[warn] Unknown action: {action}")

    except Exception as exc:
        _append_log(f"[error] Unhandled exception: {exc}")

    _append_log(f"=== Done: {action} ===")


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder=str(TEMPLATES_DIR),
    static_folder=str(STATIC_DIR),
)
app.secret_key = os.environ.get("INSTALLER_SECRET", secrets.token_hex(16))


# ── helpers ──────────────────────────────────────────────────────────────────

def _render(template: str, active: str, title: str, subtitle: str = "", **ctx):
    return render_template(
        template,
        active=active,
        title=title,
        subtitle=subtitle,
        st=_state(),
        info=_sys_info(),
        **ctx,
    )


# ── pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("overview"))


@app.route("/overview")
def overview():
    return _render("overview.html", "overview", "Overview", "Current system status")


@app.route("/install")
def install():
    st = _state()
    admins_raw = _json_cfg("telegram_admins.json")
    admins_txt = ", ".join(
        str(a) for a in (admins_raw if isinstance(admins_raw, list) else [])
    )
    return render_template(
        "install.html",
        active="install",
        title="Install",
        subtitle="Guided setup wizard",
        st=st,
        envd=_env_dict(),
        ps=_json_cfg("panel_settings.json"),
        bs=_json_cfg("backup_schedule.json"),
        ts=_json_cfg("telegram_settings.json"),
        admins_txt=admins_txt,
        info=_sys_info(),
    )


@app.route("/settings")
def settings():
    return _render("settings.html", "settings", "Settings", "Installer configuration")


@app.route("/files")
def files():
    st = _state()
    root = Path(st["install_dir"])
    entries = []
    if root.is_dir():
        for p in sorted(root.iterdir()):
            if p.name.startswith(".git"):
                continue
            entries.append({
                "name":   p.name,
                "is_dir": p.is_dir(),
                "size":   p.stat().st_size if p.is_file() else 0,
            })
    return render_template(
        "files.html",
        active="files", title="Files", subtitle="Project directory",
        st=st, entries=entries, info=_sys_info(),
    )


@app.route("/services")
def services():
    st = _state()
    svc_names = [st["panel_service"], st["bot_service"], "wg-node-agent"]
    rows = [{"name": s, "active": _service_active(s)} for s in svc_names]
    return render_template(
        "services.html",
        active="services", title="Services", subtitle="systemd service status",
        st=st, rows=rows, info=_sys_info(),
    )


@app.route("/cli")
def cli():
    return _render("cli.html", "cli", "CLI", "wgpanel command-line reference")


@app.route("/logs")
def logs():
    return render_template(
        "logs.html",
        active="logs", title="Logs", subtitle="Installer activity log",
        st=_state(), lines=_tail_log(300), info=_sys_info(),
    )


# ── form handlers ─────────────────────────────────────────────────────────────

@app.route("/params", methods=["POST"])
def install_params_apply():
    st = _load_state()
    int_keys = {"port", "workers", "threads", "timeout", "graceful_timeout"}
    for key in [
        "install_dir", "venv_dir", "instance_dir", "env_file",
        "bind", "port", "workers", "threads", "timeout",
        "graceful_timeout", "loglevel", "panel_service", "bot_service",
        "tls_certfile", "tls_keyfile",
    ]:
        if key in request.form:
            val = request.form[key]
            st[key] = int(val) if key in int_keys and val.isdigit() else val
    st["tls_enabled"] = request.form.get("tls_enabled", "0") == "1"
    _save_state(st)
    flash("System parameters saved.", "success")
    return redirect(url_for("install"))


@app.route("/env", methods=["POST"])
def install_env_apply():
    keys = [
        "FLASK_SECRET_KEY", "FERNET_KEY", "API_KEY", "DATABASE_URL",
        "LOG_LEVEL", "SECURE_COOKIES", "WIREGUARD_CONF_PATH",
        "SETUP_TOKEN", "TG_HEARTBEAT_SEC",
    ]
    vals = {k: request.form[k] for k in keys if k in request.form}
    try:
        _write_env(vals)
        flash(".env updated.", "success")
    except Exception as exc:
        flash(f"Error writing .env: {exc}", "error")
    return redirect(url_for("install"))


@app.route("/wg", methods=["POST"])
def install_wg_apply():
    st = _load_state()
    wg_path = request.form.get("wg_conf_path", "/etc/wireguard").strip()
    iface   = request.form.get("wg_default_iface", "").strip()
    st["wg_conf_path"]    = wg_path
    st["wg_default_iface"] = iface
    _save_state(st)
    try:
        _write_env({"WIREGUARD_CONF_PATH": wg_path})
    except Exception:
        pass
    flash("WireGuard settings saved.", "success")
    return redirect(url_for("install"))


@app.route("/json", methods=["POST"])
def install_json_apply():
    f = request.form
    try:
        _write_json_cfg("panel_settings.json", {
            "tls_enabled":          f.get("ps_tls_enabled", "0") == "1",
            "domain":               f.get("ps_domain", ""),
            "force_https_redirect": f.get("ps_force_https", "0") == "1",
            "hsts":                 f.get("ps_hsts", "0") == "1",
            "https_port":           int(f.get("ps_https_port") or 443),
            "tls_cert_path":        f.get("ps_cert", ""),
            "tls_key_path":         f.get("ps_key", ""),
        })
        _write_json_cfg("backup_schedule.json", {
            "enabled":          f.get("bs_enabled", "0") == "1",
            "freq":             f.get("bs_freq", "daily"),
            "time":             f.get("bs_time", "03:00"),
            "timezone":         f.get("bs_tz", "UTC"),
            "keep":             int(f.get("bs_keep") or 7),
            "include_wg":       f.get("bs_include_wg", "1") == "1",
            "send_to_telegram": f.get("bs_send_tg", "0") == "1",
        })
        _write_json_cfg("telegram_settings.json", {
            "enabled":   f.get("tg_enabled", "0") == "1",
            "bot_token": f.get("tg_token", ""),
            "notify": {
                "app_down":   f.get("tg_app_down", "1") == "1",
                "iface_down": f.get("tg_iface_down", "1") == "1",
            },
        })
        raw = f.get("tg_admins", "")
        ids = [
            int(x.strip())
            for x in raw.replace("\n", ",").split(",")
            if x.strip().lstrip("-").isdigit()
        ]
        _write_json_cfg("telegram_admins.json", ids)
        flash("JSON configs saved.", "success")
    except Exception as exc:
        flash(f"Error saving JSON: {exc}", "error")
    return redirect(url_for("install"))


@app.route("/do/<action>", methods=["POST"])
def do(action: str):
    allowed = {
        "all", "deps", "venv", "env", "botenv", "json", "db",
        "systemd", "cli", "start", "stop", "restart", "status", "clearlog",
    }
    if action not in allowed:
        abort(400)
    st = _state()
    t = threading.Thread(
        target=_run_action, args=(action, st["install_dir"]), daemon=True
    )
    t.start()
    flash(f"Action '{action}' started — watch the Activity tab.", "success")
    return redirect(url_for("install"))


# ── API endpoints ──────────────────────────────────────────────────────────────

@app.route("/api/gen", methods=["POST"])
def api_gen():
    data = request.get_json(silent=True) or {}
    kind = data.get("kind", "")
    generators = {
        "flask_secret": _gen_flask_secret,
        "fernet":       _gen_fernet,
        "api_key":      _gen_api_key,
        "setup_token":  _gen_setup_token,
    }
    fn = generators.get(kind)
    if not fn:
        return jsonify(error=f"Unknown kind: {kind}"), 400
    return jsonify(value=fn())


@app.route("/api/log-tail")
def api_log_tail():
    n = min(int(request.args.get("n", 220)), 1000)
    return jsonify(lines=_tail_log(n))


@app.route("/api/log-stream")
def api_log_stream():
    """Alias used by install.html Activity tab."""
    n = min(int(request.args.get("n", 220)), 1000)
    return jsonify(lines=_tail_log(n))


@app.route("/api/log-download")
def api_log_download():
    if not LOG_FILE.exists():
        abort(404)
    return send_file(str(LOG_FILE), as_attachment=True, download_name="installer.log")


@app.route("/api/status")
def api_status():
    st   = _state()
    info = _sys_info()
    return jsonify(
        project_ok=info["project_ok"],
        panel_up=info["panel_up"],
        bot_up=info["bot_up"],
        wg_ok=info["wg_ok"],
        install_dir=st["install_dir"],
        bind=st["bind"],
        port=st["port"],
        panel_service=st["panel_service"],
        bot_service=st["bot_service"],
        wg_conf_path=st["wg_conf_path"],
    )


@app.route("/api/wg-interfaces")
def api_wg_interfaces():
    return jsonify(interfaces=_detect_wg_interfaces())


# ---------------------------------------------------------------------------
# Stub templates for pages not covered by install.html
# ---------------------------------------------------------------------------

def _make_missing_templates() -> None:
    stubs = {
        "overview.html": textwrap.dedent("""\
            {% extends "layout.html" %}
            {% block body %}
            <div style="padding:24px">
              <h2 style="color:#e7eaf1;margin-bottom:16px">System Overview</h2>
              <ul style="color:#a9b1c7;line-height:2.2;list-style:none;padding:0">
                <li>📁 Project OK: <b style="color:{{ '#6ee7b7' if info.project_ok else '#ff5c7c' }}">{{ info.project_ok }}</b></li>
                <li>⚙️  Panel service: <b style="color:{{ '#6ee7b7' if info.panel_up else '#ff5c7c' }}">{{ 'active' if info.panel_up else 'inactive' }}</b></li>
                <li>🤖 Bot service: <b style="color:{{ '#6ee7b7' if info.bot_up else '#ffd166' }}">{{ 'active' if info.bot_up else 'inactive' }}</b></li>
                <li>🔒 WireGuard: <b style="color:{{ '#6ee7b7' if info.wg_ok else '#ff5c7c' }}">{{ 'installed' if info.wg_ok else 'not found' }}</b></li>
                <li>🐍 Python: <b>{{ info.python }}</b></li>
                <li>🖥️  Hostname: <b>{{ info.hostname }}</b></li>
                <li>📂 Install dir: <code>{{ st.install_dir }}</code></li>
              </ul>
              <p style="margin-top:20px">→ Go to <a href="/install" style="color:#56ccff">Install</a> to configure and set up the panel.</p>
            </div>
            {% endblock %}
            """),

        "settings.html": textwrap.dedent("""\
            {% extends "layout.html" %}
            {% block body %}
            <div style="padding:24px;color:#a9b1c7">
              <h2 style="color:#e7eaf1;margin-bottom:16px">Settings</h2>
              <p>All system parameters are configured in the <a href="/install" style="color:#56ccff">Install → System</a> tab.</p>
              <p style="font-size:12px;margin-top:24px;color:#6e7a9a">Current state:</p>
              <pre style="background:rgba(0,0,0,.3);padding:16px;border-radius:14px;font-size:12px;color:#e7eaf1;overflow:auto">{{ st | tojson(indent=2) }}</pre>
            </div>
            {% endblock %}
            """),

        "files.html": textwrap.dedent("""\
            {% extends "layout.html" %}
            {% block body %}
            <div style="padding:24px;color:#a9b1c7">
              <h2 style="color:#e7eaf1;margin-bottom:4px">Files</h2>
              <p style="font-size:12px;margin:0 0 16px"><code>{{ st.install_dir }}</code></p>
              <table style="width:100%;border-collapse:collapse;font-size:13px">
                <thead><tr style="color:#56ccff;border-bottom:1px solid rgba(255,255,255,.1)">
                  <th align="left" style="padding:6px 8px">Name</th>
                  <th align="right" style="padding:6px 8px">Size</th>
                </tr></thead>
                <tbody>{% for e in entries %}
                <tr style="border-bottom:1px solid rgba(255,255,255,.04)">
                  <td style="padding:7px 8px">{% if e.is_dir %}📁{% else %}📄{% endif %} {{ e.name }}</td>
                  <td align="right" style="padding:7px 8px;font-size:11px;color:#6e7a9a">{{ '' if e.is_dir else (e.size | string + ' B') }}</td>
                </tr>{% endfor %}
                </tbody>
              </table>
            </div>
            {% endblock %}
            """),

        "services.html": textwrap.dedent("""\
            {% extends "layout.html" %}
            {% block body %}
            <div style="padding:24px;color:#a9b1c7">
              <h2 style="color:#e7eaf1;margin-bottom:16px">Services</h2>
              {% for row in rows %}
              <div style="display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid rgba(255,255,255,.06)">
                <span style="width:9px;height:9px;border-radius:50%;background:{{ '#6ee7b7' if row.active else '#ff5c7c' }};flex-shrink:0"></span>
                <code style="flex:1">{{ row.name }}</code>
                <span style="font-size:12px;color:{{ '#6ee7b7' if row.active else '#ff5c7c' }}">{{ 'active' if row.active else 'inactive' }}</span>
              </div>
              {% endfor %}
              <div style="margin-top:20px;display:flex;gap:10px;flex-wrap:wrap">
                <form method="post" action="/do/restart">
                  <button type="submit" style="padding:9px 16px;background:rgba(56,248,182,.1);border:1px solid rgba(56,248,182,.3);color:#e7eaf1;border-radius:10px;cursor:pointer">Restart Panel</button>
                </form>
                <form method="post" action="/do/status">
                  <button type="submit" style="padding:9px 16px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);color:#e7eaf1;border-radius:10px;cursor:pointer">Refresh Status</button>
                </form>
              </div>
            </div>
            {% endblock %}
            """),

        "cli.html": textwrap.dedent("""\
            {% extends "layout.html" %}
            {% block body %}
            <div style="padding:24px;color:#a9b1c7">
              <h2 style="color:#e7eaf1;margin-bottom:16px">CLI — wgpanel</h2>
              <p>Install the CLI tool from <b>Install → Steps → 8) Install wgpanel CLI</b>.</p>
              <pre style="background:rgba(0,0,0,.3);padding:16px;border-radius:14px;font-size:13px;color:#6ee7b7">sudo wgpanel          # interactive menu
sudo wgpanel --help   # options</pre>
              <p style="margin-top:16px">The CLI provides the same functionality as this installer through a terminal TUI (wg.py).</p>
            </div>
            {% endblock %}
            """),

        "logs.html": textwrap.dedent("""\
            {% extends "layout.html" %}
            {% block body %}
            <div style="padding:24px">
              <h2 style="color:#e7eaf1;margin-bottom:16px">Installer Log</h2>
              <div id="liveLog" style="background:rgba(0,0,0,.35);border-radius:14px;padding:16px;font-family:monospace;font-size:12px;color:#e7eaf1;max-height:560px;overflow:auto;white-space:pre-wrap;line-height:1.45">{% for l in lines %}{{ l }}
            {% else %}(no log entries yet){% endfor %}</div>
              <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap">
                <a href="/api/log-download" style="padding:8px 14px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);color:#e7eaf1;border-radius:10px;text-decoration:none">⬇ Download log</a>
                <form method="post" action="/do/clearlog">
                  <button type="submit" style="padding:8px 14px;background:rgba(255,92,122,.1);border:1px solid rgba(255,92,122,.3);color:#e7eaf1;border-radius:10px;cursor:pointer">🗑 Clear log</button>
                </form>
              </div>
              <script>
                async function loadLog(){
                  try{
                    const r=await fetch("/api/log-tail?n=300",{cache:"no-store"});
                    const j=await r.json();
                    const b=document.getElementById("liveLog");
                    if(b&&j.lines){b.textContent=j.lines.join("\\n");b.scrollTop=b.scrollHeight;}
                  }catch(e){}
                }
                setInterval(loadLog,2000);
              </script>
            </div>
            {% endblock %}
            """),
    }
    for name, content in stubs.items():
        p = TEMPLATES_DIR / name
        if not p.exists():
            p.write_text(content, encoding="utf-8")
            _log.info("Created stub template: %s", p.name)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not PROJECT_ROOT.joinpath("app.py").exists():
        _log.warning(
            "app.py not found in %s — install_dir may be wrong. "
            "Run install-gui.sh from the project root.", PROJECT_ROOT,
        )

    _make_missing_templates()

    if BIND not in ("127.0.0.1", "localhost", "::1"):
        _log.warning(
            "INSTALLER_BIND=%s — this UI has NO authentication. "
            "Restrict access via firewall or SSH tunnel.", BIND,
        )

    _log.info("OxWG Panel GUI Installer starting")
    _log.info("  Open : http://%s:%s", BIND if BIND != "0.0.0.0" else "<SERVER-IP>", PORT)
    _log.info("  State: %s", STATE_FILE)
    _log.info("  Log  : %s", LOG_FILE)

    app.run(host=BIND, port=PORT, debug=False, threaded=True)
