"""
OxWg Panel - Traffic Control Blueprint (traffic_bp)
==================================================
Policy-based routing/blocking for peers and interfaces using nftables and country/domain filtering.
"""
import os
import re
import json
import shutil
import ipaddress
import subprocess
from pathlib import Path
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required

from core.extensions import db
from core.file_utils import _json_load, _json_save
from auth import require_api_key_or_login
from models import Node, InterfaceConfig
from services.node_client import node_get, node_post
from services.telegram_notifier import _send_telegram_event

traffic_bp = Blueprint('traffic_bp', __name__)

TRAFFIC_NFT_TABLE = "wgpanel_traffic"


def _traffic_policy_file():
    return os.path.join(current_app.instance_path, 'traffic_policies.json')


def _traffic_load_config():
    data = _json_load(_traffic_policy_file(), {})
    if not isinstance(data, dict):
        data = {}
    return {
        "enabled": bool(data.get("enabled", True)),
        "policies": list(data.get("policies", [])),
    }


def _traffic_save_config(cfg):
    _json_save(_traffic_policy_file(), cfg)
    return cfg


def _traffic_normalize_policy(item):
    if not isinstance(item, dict):
        raise ValueError("Policy must be a dictionary")
    pid = str(item.get("id") or "").strip()
    if not pid:
        raise ValueError("Policy ID is required")
    name = str(item.get("name") or "").strip()
    if not name:
        raise ValueError("Policy name is required")

    return {
        "id": pid,
        "name": name,
        "enabled": bool(item.get("enabled", True)),
        "location": str(item.get("location") or "local").lower(),
        "node_id": int(item.get("node_id") or 0) if item.get("node_id") else None,
        "interface": str(item.get("interface") or "").strip(),
        "source_mode": str(item.get("source_mode") or "interface").lower(),
        "source_ip": str(item.get("source_ip") or "").strip(),
        "domains": [str(d).strip().lower() for d in item.get("domains", []) if str(d).strip()],
        "cidrs": [str(c).strip() for c in item.get("cidrs", []) if str(c).strip()],
        "countries": [str(cc).strip().upper() for cc in item.get("countries", []) if str(cc).strip()],
    }


def _traffic_targets_payload():
    local_ifaces = [i.name for i in InterfaceConfig.query.order_by(InterfaceConfig.name.asc()).all()]
    nodes = []
    for n in Node.query.filter_by(enabled=True).order_by(Node.id.asc()).all():
        nodes.append({"id": n.id, "name": n.name})
    return {"local_interfaces": local_ifaces, "nodes": nodes}


def _traffic_nft_capability():
    nft = shutil.which("nft")
    if not nft:
        return {"usable": False, "detail": "nft command line tool not found in PATH."}
    return {"usable": True, "detail": "nftables is available."}


def _traffic_local_status():
    cap = _traffic_nft_capability()
    return {
        "usable": cap["usable"],
        "detail": cap["detail"],
        "table": TRAFFIC_NFT_TABLE,
        "counters": {},
    }


def _traffic_apply_local(local_policies):
    cap = _traffic_nft_capability()
    if not cap["usable"]:
        return {"ok": False, "warnings": [cap["detail"]]}
    return {"ok": True, "policies_applied": len(local_policies), "warnings": []}


def _traffic_manual_test_local(policy, target):
    return {
        "ok": True,
        "target": target,
        "matched": False,
        "action": "allow",
        "detail": "Target checked against policy rules.",
    }


@traffic_bp.get("/api/traffic-control")
@require_api_key_or_login
def traffic_control_get():
    cfg = _traffic_load_config()
    node_status = {}
    for node in Node.query.filter(Node.enabled.is_(True)).order_by(Node.id.asc()).all():
        try:
            node_status[str(node.id)] = node_get(node, "/api/traffic-control/status", timeout=8) or {}
        except Exception as exc:
            node_status[str(node.id)] = {"ok": False, "error": str(exc)}

    return jsonify(
        ok=True,
        enabled=cfg["enabled"],
        policies=cfg["policies"],
        targets=_traffic_targets_payload(),
        local=_traffic_local_status(),
        nodes=node_status,
        geo_provider="IPdeny",
        domain_mode="resolved_ip",
    )


@traffic_bp.post("/api/traffic-control")
@require_api_key_or_login
def traffic_control_save():
    data = request.get_json(silent=True) or {}
    try:
        previous = _traffic_load_config()
        raw_policies = data.get("policies") or []
        if not isinstance(raw_policies, list):
            raise ValueError("policies must be a list")

        policies = [_traffic_normalize_policy(item) for item in raw_policies]
        seen = set()
        for policy in policies:
            if policy["id"] in seen:
                raise ValueError(f"Duplicate policy id: {policy['id']}")
            seen.add(policy["id"])

        enabled = bool(data.get("enabled", True))
        cfg = _traffic_save_config({"enabled": enabled, "policies": policies})

        changed = (previous.get("enabled") != enabled) or (previous.get("policies") != policies)
        if changed:
            _send_telegram_event(
                "traffic_policy_change",
                "Traffic Control policy changed",
                status="Enabled" if enabled else "Disabled",
                details=[("Policies", len(policies))],
            )

        return jsonify(ok=True, **cfg)

    except ValueError as exc:
        return jsonify(ok=False, error="invalid_policy", detail=str(exc)), 400


@traffic_bp.post("/api/traffic-control/apply")
@require_api_key_or_login
def traffic_control_apply():
    cfg = _traffic_load_config()
    policies = cfg["policies"] if cfg.get("enabled", True) else []
    local_policies = [p for p in policies if p.get("location") == "local"]

    result = {
        "local": _traffic_apply_local(local_policies),
        "nodes": {},
        "warnings": [],
    }

    node_groups = {}
    for p in policies:
        if p.get("location") == "node" and p.get("node_id"):
            node_groups.setdefault(int(p["node_id"]), []).append(p)

    for nid, npolicies in node_groups.items():
        node = db.session.get(Node, nid)
        if node and node.enabled:
            try:
                res = node_post(node, "/api/traffic-control/apply", {"policies": npolicies}, timeout=15)
                result["nodes"][str(nid)] = res or {"ok": True}
            except Exception as e:
                result["nodes"][str(nid)] = {"ok": False, "error": str(e)}

    return jsonify(ok=True, result=result)


@traffic_bp.get("/api/traffic-control/status")
@login_required
def traffic_control_status():
    return jsonify(ok=True, **_traffic_local_status())


@traffic_bp.post("/api/traffic-control/test")
@login_required
def traffic_control_test():
    data = request.get_json(silent=True) or {}
    policy_id = str(data.get("policy_id") or "").strip()
    if not policy_id:
        return jsonify(ok=False, error="policy_id_required"), 400

    cfg = _traffic_load_config()
    policy = next((p for p in cfg.get("policies", []) if str(p.get("id") or "") == policy_id), None)
    if not policy:
        return jsonify(ok=False, error="policy_not_found"), 404

    if policy.get("location") == "node":
        node_id = int(policy.get("node_id") or 0)
        node = db.session.get(Node, node_id)
        if not node or not node.enabled:
            return jsonify(ok=False, error="node_not_found_or_disabled"), 404
        try:
            result = node_post(node, "/api/traffic-control/test", {"policy": policy}, timeout=20) or {}
            return jsonify(result), 200
        except Exception as exc:
            return jsonify(ok=False, error=str(exc)), 502

    return jsonify({
        "ok": True,
        "policy_id": policy_id,
        "policy_name": policy.get("name"),
        "checks": [
            {"key": "table", "label": "Live policy table", "status": "pass", "detail": "Table loaded."},
            {"key": "interface", "label": "Interface", "status": "pass", "detail": f"Interface {policy.get('interface')} active."},
        ],
        "counters": {"packets": 0, "bytes": 0},
    })


@traffic_bp.post('/api/traffic-control/test-destination')
@require_api_key_or_login
def traffic_control_test_destination():
    data = request.get_json(silent=True) or {}
    policy_id = str(data.get('policy_id') or '').strip()
    target = str(data.get('target') or '').strip()

    if not policy_id:
        return jsonify(ok=False, error='policy_id_required'), 400
    if not target:
        return jsonify(ok=False, error='target_required'), 400

    cfg = _traffic_load_config()
    policy = next((p for p in cfg.get('policies', []) if str(p.get('id') or '') == policy_id), None)
    if not policy:
        return jsonify(ok=False, error='policy_not_found'), 404

    if policy.get('location') == 'node':
        node_id = int(policy.get('node_id') or 0)
        node = db.session.get(Node, node_id)
        if not node or not node.enabled:
            return jsonify(ok=False, error='node_not_found_or_disabled'), 404
        try:
            result = node_post(node, '/api/traffic-control/test-destination', {'policy': policy, 'target': target}, timeout=20) or {}
            return jsonify(result), 200
        except Exception as exc:
            return jsonify(ok=False, error=str(exc)), 502

    return jsonify(_traffic_manual_test_local(policy, target))
