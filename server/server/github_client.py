"""Helpers for interacting with the GitHub credential log repository."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from urllib import error as urllib_error
from urllib import request as urllib_request

__all__ = [
    "github_get_json",
    "github_upload_json",
    "github_upload_file",
    "github_list_directory",
    "git_blob_sha",
    "ensure_cleanup_workflow",
    "is_logging_enabled",
]

_API_BASE = "https://api.github.com"
_REPO_OWNER = "rainzhang05"
_REPO_NAME = "webauthn-credential-logs"
_CLEANUP_WORKFLOW_PATH = ".github/workflows/cleanup.yml"
_CLEANUP_WORKFLOW_CONTENT = """name: Maintain WebAuthn log retention

on:
  schedule:
    - cron: "0 0 * * *"  # Run daily at midnight UTC
  workflow_dispatch:

permissions:
  contents: write

jobs:
  cleanup:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Apply hybrid retention policy
        shell: bash
        run: |
          set -euo pipefail

          THRESHOLD_DAYS=14
          CUTOFF=$(date -u -d "${THRESHOLD_DAYS} days ago" +%s)

          if command -v jq >/dev/null 2>&1; then
            JQ_AVAILABLE=1
          else
            JQ_AVAILABLE=0
            echo "Warning: jq not found; attestation-based protection will be skipped."
          fi

          shopt -s nullglob
          echo "Starting retention sweep (threshold: ${THRESHOLD_DAYS} days)."

          for dir in logs/*; do
            if [ ! -d "$dir" ]; then
              continue
            fi

            echo "Processing directory: $dir"
            mapfile -t entries < <(find "$dir" -maxdepth 1 -type f -name '*.json' -printf '%s\t%p\n' | sort -t $'\t' -k1,1nr -k2,2)

            if [ ${#entries[@]} -eq 0 ]; then
              echo "  No JSON files found, skipping."
              continue
            fi

            declare -A protected=()
            declare -A seen_attfmt=()

            for entry in "${entries[@]:0:3}"; do
              file=${entry#*$'\t'}
              protected["$file"]=1
              echo "  Protecting (size-ranked): $file"
            done

            for entry in "${entries[@]}"; do
              file=${entry#*$'\t'}
              attfmt=""
              if [ "$JQ_AVAILABLE" -eq 1 ]; then
                attfmt=$(jq -r 'try .attfmt // empty' "$file" 2>/dev/null || true)
              fi

              if [ -n "$attfmt" ] && [ -z "${seen_attfmt[$attfmt]+x}" ]; then
                protected["$file"]=1
                seen_attfmt["$attfmt"]=1
                echo "  Protecting (attfmt=$attfmt): $file"
              fi
            done

            for entry in "${entries[@]}"; do
              file=${entry#*$'\t'}
              if [ -n "${protected[$file]+x}" ]; then
                continue
              fi

              mtime=$(stat -c %Y "$file")
              if [ "$mtime" -le "$CUTOFF" ]; then
                echo "  Deleting stale file: $file"
                rm "$file"
              else
                echo "  Skipping recent file: $file"
              fi
            done
          done

          echo "Retention sweep complete."

      - name: Commit and push if changes
        run: |
          if [ -n "$(git status --porcelain logs)" ]; then
            git config user.name "github-actions[bot]"
            git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
            git add logs
            git commit -m "Apply WebAuthn log retention policy"
            git push
          else
            echo "No changes detected; nothing to commit."
          fi
"""


_TRUTHY_VALUES = {"1", "true", "yes", "on"}


def _is_truthy(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.strip().lower() in _TRUTHY_VALUES


def is_logging_enabled() -> bool:
    """Return ``True`` when GitHub logging should be active."""

    explicit = os.environ.get("ENABLE_GITHUB_LOGGING")
    if explicit is not None:
        return _is_truthy(explicit)

    # Auto-enable on common hosted environments where local testing is unlikely.
    if os.environ.get("RENDER") or os.environ.get("RENDER_SERVICE_ID"):
        return True
    if os.environ.get("K_SERVICE") or os.environ.get("GAE_SERVICE"):
        return True

    return False


def _token() -> str:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN environment variable is required for credential logging")
    return token


def _api_url(path: str) -> str:
    path = path.lstrip("/")
    return f"{_API_BASE}/repos/{_REPO_OWNER}/{_REPO_NAME}/{path}"


def _request(method: str, url: str, body: Optional[Dict[str, Any]] = None) -> Tuple[int, bytes]:
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    req = urllib_request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"Bearer {_token()}")
    req.add_header("User-Agent", "postquantum-webauthn-logger")
    if body is not None:
        req.add_header("Content-Type", "application/json")

    for attempt in range(2):
        try:
            with urllib_request.urlopen(req) as resp:
                return resp.getcode(), resp.read()
        except urllib_error.HTTPError as exc:
            if 500 <= exc.code < 600 and attempt == 0:
                time.sleep(1)
                continue
            raise
        except urllib_error.URLError:
            if attempt == 0:
                time.sleep(1)
                continue
            raise
    raise RuntimeError("GitHub request failed after retries")


def _encode_content(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def git_blob_sha(data: bytes) -> str:
    """Return the git blob SHA1 for ``data``."""

    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def github_get_json(path: str) -> Tuple[Dict[str, Any], str]:
    """Return the JSON payload and SHA for ``path`` in the log repository."""

    url = _api_url(f"contents/{path}")
    try:
        _, body = _request("GET", url)
    except urllib_error.HTTPError as exc:
        if exc.code == 404:
            raise FileNotFoundError(path) from exc
        raise

    response: Dict[str, Any] = json.loads(body.decode("utf-8"))
    encoding = response.get("encoding")
    content_encoded = response.get("content")
    if encoding != "base64" or not isinstance(content_encoded, str):
        raise RuntimeError(f"Unexpected response fetching {path}")

    decoded_bytes = base64.b64decode(content_encoded)
    payload = json.loads(decoded_bytes.decode("utf-8"))
    sha = response.get("sha")
    if not isinstance(sha, str):
        raise RuntimeError(f"Missing SHA when fetching {path}")

    return payload, sha


def github_upload_json(path: str, obj: Dict[str, Any], sha: Optional[str] = None) -> None:
    """Create or replace a JSON file at ``path`` in the credential log repository."""

    serialised = json.dumps(obj, ensure_ascii=False, indent=2)
    content = _encode_content(serialised.encode("utf-8"))

    filename = os.path.basename(path)
    folder = os.path.basename(os.path.dirname(path)) or "unknown"

    action = "update" if sha else "add"
    body: Dict[str, Any] = {
        "message": f"{action}: {filename} (AAGUID={folder})",
        "content": content,
    }
    if sha:
        body["sha"] = sha

    url = _api_url(f"contents/{path}")
    _request("PUT", url, body)


def github_upload_file(path: str, data: bytes, message: str, sha: Optional[str] = None) -> None:
    """Create or replace a file at ``path`` with ``data`` in the log repository."""

    body: Dict[str, Any] = {
        "message": message,
        "content": _encode_content(data),
    }
    if sha:
        body["sha"] = sha

    url = _api_url(f"contents/{path}")
    _request("PUT", url, body)


def github_list_directory(path: str) -> List[Dict[str, Any]]:
    """Return the metadata for files within ``path`` in the log repository."""

    url = _api_url(f"contents/{path}")
    try:
        _, body = _request("GET", url)
    except urllib_error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise

    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, list):
        raise RuntimeError(f"Unexpected response listing directory {path}")
    return payload


def ensure_cleanup_workflow() -> None:
    """Ensure the cleanup workflow exists in the credential log repository."""

    url = _api_url(f"contents/{_CLEANUP_WORKFLOW_PATH}")
    try:
        _request("GET", url)
        return
    except urllib_error.HTTPError as exc:
        if exc.code != 404:
            raise

    body = {
        "message": "chore: add cleanup workflow",
        "content": _encode_content(_CLEANUP_WORKFLOW_CONTENT.encode("utf-8")),
    }
    _request("PUT", url, body)
