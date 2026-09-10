"""
OxWg Panel - Panel & Node Updates Blueprint (update_bp)
======================================================
GitHub version checks, self-update coordination, update targets, and remote node updater.
"""
import os
import json
import logging
from pathlib import Path
from flask import Blueprint, request, jsonify, abort, current_app
import requests

from core.extensions import db
from core.paths import BASE_DIR, UPDATE_STATUS_FILE
from auth import require_api_key_or_login
from models import Node
from services.update_checker import (
    PANEL_VERSION,
    PANEL_REPO,
    _github_latest_panel_version,
    _version_tuple,
    check_panel_update,
)
from services.panel_update import (
    _norm_update_status,
    _queue_safe_update,
)
from services.node_client import node_get, node_post

logger = logging.getLogger(__name__)

update_bp = Blueprint('update_bp', __name__)


@update_bp.get("/api/panel/version")
@require_api_key_or_login
def api_panel_version():
    fresh = (
        str(request.args.get("fresh") or request.args.get("force") or "")
        .strip()
        .lower()
        in {"1", "true", "yes", "on"}
    )
    data = check_panel_update(fresh=fresh)
    return jsonify(data)


@update_bp.get("/api/panel/update/status")
@require_api_key_or_login
def api_panel_update_status():
    return jsonify(_norm_update_status(BASE_DIR, UPDATE_STATUS_FILE))


@update_bp.post("/api/panel/update")
@require_api_key_or_login
def api_panel_update_start():
    data = request.get_json(silent=True) or {}
    target = str(data.get("target") or "main").strip() or "main"

    try:
        status = _queue_safe_update(
            root=BASE_DIR,
            service="auto",
            status_file=UPDATE_STATUS_FILE,
            scope="panel",
            target=target,
        )
        return jsonify(
            ok=True,
            message="Local panel update queued.",
            status=status,
        ), 202
    except RuntimeError as exc:
        return jsonify(ok=False, error="update_not_started", detail=str(exc)), 409
    except Exception as exc:
        current_app.logger.exception("Could not queue local update")
        return jsonify(ok=False, error="update_queue_failed", detail=str(exc)), 500


@update_bp.get("/api/panel/update/targets")
@require_api_key_or_login
def api_panel_update_targets():
    remote = _github_latest_panel_version() or {}
    latest_version = remote.get("version") or PANEL_VERSION
    latest_revision = str(remote.get("revision") or "").strip()

    rows = []
    for node in Node.query.order_by(Node.id.asc()).all():
        row = {
            "id": node.id,
            "name": node.name,
            "base_url": node.base_url,
            "online": False,
            "version": {
                "current": None,
                "latest": latest_version,
                "target": "main",
                "source": "main",
                "latest_revision": latest_revision,
                "latest_revision_short": latest_revision[:8],
                "update_available": False,
            },
            "update": {
                "status": "idle",
            },
        }

        if not node.enabled:
            row["update"] = {"status": "disabled"}
            rows.append(row)
            continue

        try:
            version = node_get(node, "/api/system/version", timeout=8) or {}
            status = node_get(node, "/api/system/update/status", timeout=6) or {}

            row["online"] = True
            row["version"] = {
                "current": str(version.get("current") or "").strip() or None,
                "latest": str(version.get("latest") or latest_version or "").strip() or None,
                "target": "main",
                "source": "main",
                "current_revision": str(version.get("current_revision") or ""),
                "current_revision_short": str(version.get("current_revision_short") or ""),
                "latest_revision": str(version.get("latest_revision") or latest_revision or ""),
                "latest_revision_short": str(version.get("latest_revision_short") or latest_revision[:8] or ""),
                "revision_tracked": bool(version.get("revision_tracked")),
                "update_available": bool(version.get("update_available")),
            }
            row["update"] = status if isinstance(status, dict) else {"status": "idle"}
        except Exception as exc:
            row["update"] = {
                "status": "offline",
                "message": str(exc),
            }

        rows.append(row)

    return jsonify(
        ok=True,
        latest=latest_version,
        target="main",
        update_source="main",
        latest_revision=latest_revision,
        latest_revision_short=latest_revision[:8],
        nodes=rows,
    )


@update_bp.post("/api/nodes/<int:nid>/update")
@require_api_key_or_login
def api_node_update_start(nid):
    node = db.session.get(Node, nid) or abort(404)
    data = request.get_json(silent=True) or {}
    target = str(data.get("target") or "main").strip() or "main"

    try:
        response = node_post(
            node,
            "/api/system/update",
            {"target": target},
            timeout=12,
        )
        return jsonify(response if isinstance(response, dict) else {
            "ok": True,
            "message": str(response),
        }), 202
    except requests.HTTPError as exc:
        body = getattr(getattr(exc, "response", None), "text", "") or ""
        return jsonify(
            ok=False,
            error="node_update_rejected",
            detail=body[:1000] or str(exc),
        ), 502
    except Exception as exc:
        return jsonify(
            ok=False,
            error="node_update_failed",
            detail=str(exc),
        ), 502


@update_bp.get("/api/nodes/<int:nid>/update/status")
@require_api_key_or_login
def api_node_update_status(nid):
    node = db.session.get(Node, nid) or abort(404)
    try:
        data = node_get(node, "/api/system/update/status", timeout=8) or {}
        return jsonify(data if isinstance(data, dict) else {
            "status": "unknown",
            "message": str(data),
        })
    except Exception as exc:
        return jsonify(
            status="offline",
            message=str(exc),
            percent=0,
            log=[],
        ), 200
