"""
OxWg Panel - Panel Version and Update Checker
=============================================
Version metadata parsing, semantic version comparison, and remote GitHub release tracking.
"""
import os
import re
import time
import json
import logging
from pathlib import Path
from typing import Any
import requests

from core.paths import BASE_DIR, INSTANCE_DIR
from core.constants import PANEL_UPDATE_TTL

logger = logging.getLogger(__name__)


def _project_version() -> str:
    """Read panel version string from the root VERSION file."""
    version_file = Path(BASE_DIR) / "VERSION"
    try:
        value = (
            version_file
            .read_text(encoding="utf-8")
            .strip()
            .lstrip("vV")
        )
        if value and re.fullmatch(r"\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?", value):
            return value
        logger.warning("Invalid VERSION file value: %r", value)
    except FileNotFoundError:
        logger.warning("VERSION file was not found: %s", version_file)
    except Exception:
        logger.exception("Could not read VERSION file")
    return "0.0.0"


PANEL_VERSION = _project_version()
PANEL_REPO = os.environ.get("PANEL_REPO", "MasterALiReza/WG_Panel")
_PANEL_UPDATE_CACHE: dict[str, Any] = {
    "ts": 0,
    "data": None,
}


def _version_tuple(v: Any) -> tuple[int, ...]:
    """
    Convert version string like '1.2.3' or 'v2.0' into a comparable tuple of integers (e.g. (1, 2, 3)).
    """
    s = str(v or "").strip().lstrip("vV")
    nums = re.findall(r"\d+", s)
    if not nums:
        return (0, 0, 0)
    parts = [int(x) for x in nums[:3]]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _update_source_marker(scope: str = "panel") -> Path:
    """Return path to the update source metadata file."""
    safe_scope = "node" if str(scope).strip().lower() == "node" else "panel"
    return Path(INSTANCE_DIR) / f"update_source_{safe_scope}.json"


def _read_update_source(scope: str = "panel") -> dict[str, Any]:
    """Read stored update source metadata."""
    try:
        marker = _update_source_marker(scope)
        if marker.is_file():
            payload = json.loads(marker.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
    except Exception:
        pass
    return {}


def _github_latest_panel_version() -> dict[str, Any] | None:
    """Query GitHub API for latest commit and VERSION file content on the main branch."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "WG-Panel",
        "Cache-Control": "no-cache",
    }

    commit_sha = ""
    commit_url = ""
    commit_date = ""
    remote_version = None

    try:
        url = f"https://api.github.com/repos/{PANEL_REPO}/commits/main"
        response = requests.get(url, headers=headers, timeout=8)
        if response.ok:
            payload = response.json() or {}
            commit_sha = str(payload.get("sha") or "").strip()
            commit_url = str(payload.get("html_url") or f"https://github.com/{PANEL_REPO}").strip()
            commit = payload.get("commit") or {}
            author = commit.get("author") or {}
            commit_date = str(author.get("date") or "").strip()
    except Exception as exc:
        logger.warning("Could not fetch GitHub main commit: %s", exc)

    try:
        raw_url = f"https://raw.githubusercontent.com/{PANEL_REPO}/main/VERSION"
        response = requests.get(raw_url, headers=headers, timeout=6)
        if response.ok:
            candidate = response.text.strip().lstrip("vV")
            if re.fullmatch(r"\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?", candidate):
                remote_version = candidate
    except Exception:
        pass

    if not commit_sha and not remote_version:
        return None

    return {
        "version": remote_version,
        "target": "main",
        "url": commit_url or f"https://github.com/{PANEL_REPO}",
        "source": "main",
        "revision": commit_sha,
        "revision_short": commit_sha[:8],
        "commit_date": commit_date,
    }


def check_panel_update(fresh: bool = False) -> dict[str, Any]:
    """
    Check if a newer panel version or commit is available on GitHub.
    Uses TTL caching unless fresh=True.
    """
    now = int(time.time())
    if not fresh and _PANEL_UPDATE_CACHE.get("data") and (now - int(_PANEL_UPDATE_CACHE.get("ts") or 0) < PANEL_UPDATE_TTL):
        return _PANEL_UPDATE_CACHE["data"]

    remote = _github_latest_panel_version() or {}
    installed = _read_update_source("panel")

    current_version = str(PANEL_VERSION or "0.0.0").strip().lstrip("vV")
    latest_version = str(remote.get("version") or current_version or "0.0.0").strip().lstrip("vV")

    remote_revision = str(remote.get("revision") or "").strip()
    installed_revision = str(installed.get("revision") or "").strip()

    version_update_available = _version_tuple(latest_version) > _version_tuple(current_version)
    revision_update_available = bool(
        remote_revision and installed_revision and remote_revision != installed_revision
    )

    update_available = version_update_available or revision_update_available
    update_reason = ""
    if version_update_available and revision_update_available:
        update_reason = "Newer version and commit available"
    elif version_update_available:
        update_reason = "Newer version available"
    elif revision_update_available:
        update_reason = "Newer commit available"

    result = {
        "ok": True,
        "current": current_version,
        "current_version": current_version,
        "version_source": "VERSION",
        "latest": latest_version,
        "latest_version": latest_version,
        "latest_url": remote.get("url") or f"https://github.com/{PANEL_REPO}",
        "source": "main",
        "target": "main",
        "update_source": "main",
        "current_revision": installed_revision,
        "current_revision_short": installed_revision[:8],
        "latest_revision": remote_revision,
        "latest_revision_short": remote_revision[:8],
        "commit_date": remote.get("commit_date"),
        "revision_tracked": bool(installed_revision),
        "version_update_available": version_update_available,
        "revision_update_available": revision_update_available,
        "update_available": update_available,
        "update_reason": update_reason,
        "remote": remote,
        "installed": installed,
        "repo": PANEL_REPO,
        "checked_at": now,
    }

    _PANEL_UPDATE_CACHE.update(ts=now, data=result)
    return result
