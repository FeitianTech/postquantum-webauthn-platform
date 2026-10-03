"""The session cookie's interface: a file's answer never sets the cookie again,
so it cannot put back a session a ceremony has moved on from."""
from __future__ import annotations

import io
import json

import pytest

from server.app.config import session_cookie
from server.app.config.web_export import WEB_EXPORT_ROOT_KEY
from tests.app.metadata.upload_entries import minimal_entry


def _sets_session_cookie(response) -> bool:
    return any(value.startswith("session=") for value in response.headers.getlist("Set-Cookie"))


@pytest.fixture
def visitor(make_app, export_root, mds_fixture_snapshot):
    """A client whose session is permanent: an upload gave it a namespace."""

    app = make_app({WEB_EXPORT_ROOT_KEY: str(export_root)})
    client = app.test_client()
    first = client.post(
        "/api/mds/metadata/upload",
        data={"files": (io.BytesIO(json.dumps(minimal_entry("uploaded")).encode()), "entry.json")},
        content_type="multipart/form-data",
    )
    assert first.status_code == 200
    assert _sets_session_cookie(first)
    return client, client.get("/api/mds/metadata/info").get_json()["snapshotUrl"]


def test_the_app_uses_the_interface_that_leaves_files_alone(app):
    assert isinstance(app.session_interface, session_cookie.FileQuietSessionInterface)


@pytest.mark.parametrize("path", ["/", "/_next/static/chunks/main-abc123.js", "/health", "/no-such-page"])
def test_the_exports_answers_leave_a_permanent_session_cookie_alone(visitor, path):
    client, _snapshot_url = visitor

    response = client.get(path)

    assert not _sets_session_cookie(response)


def test_the_mds_files_answers_leave_a_permanent_session_cookie_alone(visitor):
    client, snapshot_url = visitor

    response = client.get(snapshot_url)

    assert response.status_code == 200
    assert not _sets_session_cookie(response)


def test_an_api_answer_still_refreshes_a_permanent_session_cookie(visitor):
    client, _snapshot_url = visitor

    assert _sets_session_cookie(client.get("/api/mds/metadata/info"))
