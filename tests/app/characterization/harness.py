"""Record what the ceremony routes answer, byte for byte, in a pinned environment.

Every source of variation is pinned or scrubbed so the same request gives the
same record on every run:

- ``time.time`` is fixed (it feeds the challenge stamps, the signed session
  cookie, registration times and storage ids);
- ``os.urandom``, ``secrets.token_*`` and ``uuid.uuid4`` draw from a stream that
  is reseeded before each request, keyed by scenario and request index, so a
  change that draws one more random value cannot shift the values after it;
- values derived from ``datetime.now`` (a cookie's ``Expires``, a device-log
  timestamp) are scrubbed rather than frozen: swapping the ``datetime`` class
  would break ``isinstance`` checks in the code under test;
- the credential store, the artifact store and the session-metadata directory
  live in a temporary directory; the MDS verifier is stubbed out, and an audit
  hook fails the scenario if anything opens a file under ``frontend/static``
  (where the real MDS snapshot lives).

A record holds the status, every header but ``Set-Cookie``, each cookie's
attributes without its value and expiry but with its decoded contents, the body
(parsed for a readable diff, plus the SHA-256 of the raw bytes), every JSON file
the request created or changed in either store, and the device-log events.
"""
from __future__ import annotations

import base64
import dataclasses
import datetime
import difflib
import hashlib
import json
import os
import secrets
import sys
import time
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

FIXED_TIME = 1_790_000_000.0
TEST_SECRET_KEY = "characterization-secret-0123456789abcdef"
GOLDEN_DIR = Path(__file__).parent / "golden"
WRITE_ENV = "CHARACTERIZATION_WRITE"
METADATA_COOKIE_SALT = "fido.mds.session-cookie.v1"

_SNAPSHOT_GUARD: dict[str, Any] = {"root": None, "hits": [], "installed": False}


def _audit(event: str, args: tuple) -> None:
    root = _SNAPSHOT_GUARD["root"]
    if root is None or event != "open" or not args:
        return
    try:
        path = os.fspath(args[0])
    except TypeError:
        return
    if isinstance(path, str) and path.startswith(root):
        _SNAPSHOT_GUARD["hits"].append(path)


class RandomStream:
    """Deterministic bytes, reseeded per request."""

    def __init__(self) -> None:
        self.label = "unseeded"
        self.counter = 0

    def reseed(self, label: str) -> None:
        self.label = label
        self.counter = 0

    def take(self, size: int) -> bytes:
        out = b""
        while len(out) < size:
            out += hashlib.sha256(f"{self.label}:{self.counter}".encode()).digest()
            self.counter += 1
        return out[:size]


def json_safe(value: Any) -> Any:
    """A JSON-ready copy that keeps the distinctions JSON would lose."""

    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"$bytes": bytes(value).hex()}
    if isinstance(value, datetime.datetime):
        return "<datetime scrubbed>"
    if isinstance(value, Mapping):
        if all(isinstance(key, str) for key in value):
            return {key: json_safe(item) for key, item in value.items()}
        return {"$map": [[json_safe(key), json_safe(item)] for key, item in value.items()]}
    if isinstance(value, tuple):
        return {"$tuple": [json_safe(item) for item in value]}
    if isinstance(value, (list, set, frozenset)):
        items = [json_safe(item) for item in value]
        return items if isinstance(value, list) else {"$set": sorted(items, key=repr)}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: json_safe(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return {"$repr": repr(value)}


class StoreWatcher:
    """Reports the JSON files each request created, changed or removed."""

    def __init__(self, roots: dict[str, Path]) -> None:
        self.roots = roots
        self.seen: dict[str, str] = {}

    def _scan(self) -> dict[str, tuple[str, bytes]]:
        found: dict[str, tuple[str, bytes]] = {}
        for label, root in self.roots.items():
            if not root.exists():
                continue
            for path in sorted(root.rglob("*.json")):
                data = path.read_bytes()
                found[f"{label}/{path.relative_to(root).as_posix()}"] = (hashlib.sha256(data).hexdigest(), data)
        return found

    def changes(self) -> list[dict[str, Any]]:
        current = self._scan()
        changes: list[dict[str, Any]] = []
        for name, (digest, data) in current.items():
            if self.seen.get(name) != digest:
                try:
                    content: Any = json.loads(data)
                except ValueError:
                    content = {"$text": data.decode("utf-8", "replace")}
                changes.append({"file": name, "sha256": digest, "content": content})
        for name in self.seen:
            if name not in current:
                changes.append({"file": name, "removed": True})
        self.seen = {name: digest for name, (digest, _data) in current.items()}
        return changes


class Environment:
    """One pinned app per scenario, and the recorder for its requests."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self.monkeypatch = monkeypatch
        self.tmp_path = tmp_path
        self.stream = RandomStream()
        self.events: list[Any] = []
        self._pin()
        self.watcher = StoreWatcher(
            {
                "credentials": tmp_path / "credentials",
                "artifacts": tmp_path / "artifacts",
                "session-metadata": tmp_path / "session-metadata",
            }
        )

    def _pin(self) -> None:
        mp = self.monkeypatch
        for name in list(os.environ):
            if name.startswith(("FIDO_SERVER_", "GITHUB_")):
                mp.delenv(name)

        stream = self.stream
        mp.setattr(time, "time", lambda: FIXED_TIME)
        mp.setattr(os, "urandom", stream.take)
        mp.setattr(secrets, "token_bytes", lambda nbytes=32: stream.take(nbytes))
        mp.setattr(secrets, "token_hex", lambda nbytes=32: stream.take(nbytes).hex())
        mp.setattr(
            secrets,
            "token_urlsafe",
            lambda nbytes=32: base64.urlsafe_b64encode(stream.take(nbytes)).rstrip(b"=").decode("ascii"),
        )
        mp.setattr(uuid, "uuid4", lambda: uuid.UUID(bytes=stream.take(16), version=4))

        from server.app import credential_artifacts, device_logs
        from server.app.config import paths
        from server.app.storage import credentials, session_metadata
        from server.app.webauthn import metadata
        from server.app.webauthn.metadata import sessions

        mp.setattr(credentials, "_LOCAL_CREDENTIAL_BASE", str(self.tmp_path / "credentials"))
        mp.setattr(credentials, "_LEGACY_LOCAL_CREDENTIAL_BASE", str(self.tmp_path / "legacy-credentials"))
        mp.setattr(credential_artifacts, "_ARTIFACT_DIR", str(self.tmp_path / "artifacts"))
        mp.setattr(session_metadata, "SESSION_METADATA_DIR", str(self.tmp_path / "session-metadata"))
        mp.setattr(sessions, "_schedule_inactive_session_cleanup", lambda: None)
        mp.setattr(metadata, "get_mds_verifier", lambda: None)
        mp.setattr(device_logs, "record_registration_event", self.events.append)

        if not _SNAPSHOT_GUARD["installed"]:
            sys.addaudithook(_audit)
            _SNAPSHOT_GUARD["installed"] = True
        _SNAPSHOT_GUARD["root"] = str(paths._FRONTEND_STATIC_ROOT)
        _SNAPSHOT_GUARD["hits"] = []

    def close(self) -> None:
        _SNAPSHOT_GUARD["root"] = None

    def app(self):
        from server.app.factory import create_app

        return create_app(
            {
                "TESTING": True,
                "SECRET_KEY": TEST_SECRET_KEY,
                "FIDO_SERVER_RP_ID": "localhost",
                "FIDO_SERVER_ALLOWED_ORIGINS": "http://localhost",
            }
        )


class Recorder:
    """Sends a scenario's requests and records each one."""

    def __init__(self, name: str, env: Environment) -> None:
        self.name = name
        self.env = env
        self.app = env.app()
        self.records: list[dict[str, Any]] = []

    def client(self):
        return self.app.test_client()

    def post(self, client, path: str, *, json: Any = None, headers: Mapping[str, str] | None = None):
        index = len(self.records)
        self.env.stream.reseed(f"{self.name}#{index}")
        record: dict[str, Any] = {"request": f"POST {path}"}
        response = None
        try:
            response = client.post(path, json=json, headers=dict(headers or {}))
        except Exception as exc:  # TESTING re-raises what would be a 500
            record["exception"] = f"{type(exc).__name__}: {exc}"
        else:
            record.update(self._describe(response))
        stored = self.env.watcher.changes()
        if stored:
            record["stored"] = stored
        if self.env.events:
            record["deviceLogEvents"] = [json_safe(event) for event in self.env.events]
            self.env.events.clear()
        self.records.append(record)
        return response

    def _describe(self, response) -> dict[str, Any]:
        data = response.get_data()
        try:
            body: Any = json.loads(data)
        except ValueError:
            body = {"$text": data.decode("utf-8", "replace")}
        return {
            "status": response.status_code,
            "headers": [[key, value] for key, value in response.headers if key.lower() != "set-cookie"],
            "cookies": [self._cookie(header) for header in response.headers.getlist("Set-Cookie")],
            "bodySha256": hashlib.sha256(data).hexdigest(),
            "body": body,
        }

    def _cookie(self, header: str) -> dict[str, Any]:
        from itsdangerous import URLSafeTimedSerializer

        first, *attributes = header.split("; ")
        name, _, value = first.partition("=")
        kept = [attribute for attribute in attributes if not attribute.lower().startswith("expires=")]
        cookie: dict[str, Any] = {"name": name, "attributes": kept}
        if not value:
            cookie["contents"] = None
        elif name == self.app.config.get("SESSION_COOKIE_NAME", "session"):
            serializer = self.app.session_interface.get_signing_serializer(self.app)
            cookie["contents"] = json_safe(serializer.loads(value))
        elif name == "fido.mds.session":
            cookie["contents"] = URLSafeTimedSerializer(self.app.secret_key, salt=METADATA_COOKIE_SALT).loads(value)
        else:
            cookie["contents"] = {"$raw": value}
        return cookie

    def result(self) -> dict[str, Any]:
        hits = list(_SNAPSHOT_GUARD["hits"])
        assert not hits, f"{self.name} opened files under frontend/static: {hits}"
        return {"scenario": self.name, "requests": self.records}


def render(record: Any) -> str:
    return json.dumps(record, indent=1, sort_keys=False, ensure_ascii=True) + "\n"


def check_golden(relative: str, record: Any) -> None:
    """Compare ``record`` with ``golden/<relative>``; ``CHARACTERIZATION_WRITE=1`` rewrites it."""

    path = GOLDEN_DIR / relative
    actual = render(record)
    if os.environ.get(WRITE_ENV) == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(actual)
        return
    assert path.exists(), f"no golden file {path}; run with {WRITE_ENV}=1 to record it"
    expected = path.read_text()
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                expected.splitlines(keepends=True), actual.splitlines(keepends=True), "golden", "actual", n=4
            )
        )
        pytest.fail(f"{relative} differs from its golden record:\n{diff[:20000]}", pytrace=False)


def run(name: str, env: Environment, scenario: Callable[[Recorder], None]) -> dict[str, Any]:
    recorder = Recorder(name, env)
    scenario(recorder)
    return recorder.result()
