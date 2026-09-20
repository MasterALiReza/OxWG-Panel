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
PANEL_REPO = os.environ.get("PANEL_REPO", "MasterALiReza/OxWG-Panel")
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


def _local_git_revision(root: str | Path = BASE_DIR) -> str:
    """
    Attempt to read the current git commit SHA from the local repository.
    First tries direct file reading (.git/HEAD and refs), then falls back to git rev-parse.
    """
    try:
        head_file = Path(root) / ".git" / "HEAD"
        if head_file.is_file():
            content = head_file.read_text(encoding="utf-8").strip()
            if content.startswith("ref:"):
                rel_ref = content[4:].strip()
                ref_path = Path(root) / ".git" / rel_ref
                if ref_path.is_file():
                    sha = ref_path.read_text(encoding="utf-8").strip()
                    if re.fullmatch(r"[0-9a-fA-F]{40}", sha):
                        return sha.lower()
                packed = Path(root) / ".git" / "packed-refs"
                if packed.is_file():
                    for line in packed.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if not line or line.startswith(("#", "^")):
                            continue
                        parts = line.split(maxsplit=1)
                        if len(parts) == 2 and parts[1] == rel_ref:
                            if re.fullmatch(r"[0-9a-fA-F]{40}", parts[0]):
                                return parts[0].lower()
            elif re.fullmatch(r"[0-9a-fA-F]{40}", content):
                return content.lower()
    except Exception:
        pass

    try:
        import subprocess
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=3,
        )
        if res.returncode == 0:
            val = res.stdout.strip().lower()
            if re.fullmatch(r"[0-9a-fA-F]{40}", val):
                return val
    except Exception:
        pass

    return ""


def _update_source_marker(scope: str = "panel") -> Path:
    """Return path to the update source metadata file."""
    safe_scope = "node" if str(scope).strip().lower() == "node" else "panel"
    return Path(INSTANCE_DIR) / f"update_source_{safe_scope}.json"


def _read_update_source(scope: str = "panel") -> dict[str, Any]:
    """Read stored update source metadata, enhanced with live git revision if available."""
    payload: dict[str, Any] = {}
    marker = _update_source_marker(scope)
    marker_mtime = 0.0
    try:
        if marker.is_file():
            marker_mtime = marker.stat().st_mtime
            loaded = json.loads(marker.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                payload = loaded
    except Exception:
        pass

    if scope == "panel":
        git_sha = _local_git_revision(BASE_DIR)
        if git_sha:
            git_head = Path(BASE_DIR) / ".git" / "HEAD"
            git_mtime = git_head.stat().st_mtime if git_head.is_file() else 0.0
            recorded_sha = str(payload.get("revision") or "").strip().lower()

            # If no recorded revision exists from an update installer, git is the source of truth.
            # If git was modified AFTER the update marker file was created, someone ran git commands manually.
            # Otherwise, the updater installed files more recently than git, so keep the recorded revision!
            if not recorded_sha:
                payload["revision"] = git_sha
                payload["revision_short"] = git_sha[:8]
            elif git_mtime > marker_mtime and marker_mtime > 0:
                payload["revision"] = git_sha
                payload["revision_short"] = git_sha[:8]
            else:
                payload.setdefault("revision_short", recorded_sha[:8])

    return payload


def _github_latest_panel_version() -> dict[str, Any] | None:
    """
    Query GitHub for the latest commit and VERSION file on the main branch.
    Uses multi-tier fallback to remain 100% functional even when GitHub REST API
    hits its 60 req/hour unauthenticated rate limit:
      1. Git Smart HTTP (`git ls-remote`) - zero rate limit
      2. GitHub Atom feed (`commits/main.atom`) - public feed, no REST rate limit
      3. GitHub REST API (`api.github.com`) - with optional GITHUB_TOKEN
    """
    commit_sha = ""
    commit_url = ""
    commit_date = ""
    remote_version = None

    # Tier 1: git ls-remote (fast, immune to REST API rate limit)
    try:
        import subprocess
        res = subprocess.run(
            ["git", "ls-remote", f"https://github.com/{PANEL_REPO}.git", "refs/heads/main"],
            capture_output=True,
            text=True,
            timeout=6,
        )
        if res.returncode == 0 and res.stdout.strip():
            match = re.search(r"([0-9a-fA-F]{40})\s+refs/heads/main", res.stdout)
            if match:
                commit_sha = match.group(1).lower()
                commit_url = f"https://github.com/{PANEL_REPO}/commit/{commit_sha}"
    except Exception as exc:
        logger.debug("git ls-remote check skipped/failed: %s", exc)

    # Tier 2: GitHub Commits Atom Feed (public web feed, no REST rate limit)
    if not commit_sha:
        try:
            feed_url = f"https://github.com/{PANEL_REPO}/commits/main.atom"
            resp = requests.get(
                feed_url,
                headers={"User-Agent": "WG-Panel", "Cache-Control": "no-cache"},
                timeout=6,
            )
            if resp.ok:
                sha_match = re.search(r"Commit/([0-9a-fA-F]{40})", resp.text)
                if sha_match:
                    commit_sha = sha_match.group(1).lower()
                    commit_url = f"https://github.com/{PANEL_REPO}/commit/{commit_sha}"
                date_match = re.search(r"<updated>([^<]+)</updated>", resp.text)
                if date_match:
                    commit_date = date_match.group(1).strip()
        except Exception as exc:
            logger.debug("GitHub Atom feed check failed: %s", exc)

    # Tier 3: GitHub REST API (if commit_sha still empty or to get author date)
    if not commit_sha or not commit_date:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "WG-Panel",
            "Cache-Control": "no-cache",
        }
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token.strip()}"

        try:
            url = f"https://api.github.com/repos/{PANEL_REPO}/commits/main"
            response = requests.get(url, headers=headers, timeout=6)
            if response.ok:
                payload = response.json() or {}
                if not commit_sha:
                    commit_sha = str(payload.get("sha") or "").strip().lower()
                    commit_url = str(payload.get("html_url") or f"https://github.com/{PANEL_REPO}").strip()
                commit = payload.get("commit") or {}
                author = commit.get("author") or {}
                if not commit_date:
                    commit_date = str(author.get("date") or "").strip()
        except Exception as exc:
            logger.debug("GitHub REST API check failed: %s", exc)

    # Remote VERSION file check from raw.githubusercontent.com
    try:
        raw_url = f"https://raw.githubusercontent.com/{PANEL_REPO}/main/VERSION"
        response = requests.get(
            raw_url,
            headers={"User-Agent": "WG-Panel", "Cache-Control": "no-cache"},
            timeout=6,
        )
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
        "revision_short": commit_sha[:8] if commit_sha else "",
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
