from __future__ import annotations

import secrets

import itsdangerous
import pytest
from flask import ctx, g, session

from server.app import visitor_session
from server.app.storage import github_mirror
from tests.app.entry_app import entry_app


@pytest.fixture
def metadata_module(monkeypatch, metadata_state):
    """A fresh MDS cache and sweep state."""

    """A fresh MDS cache and sweep state."""


def _minimal_entry_payload(*, aaguid: str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa") -> dict:
    return {
        "aaguid": aaguid,
        "statusReports": [],
        "timeOfLastStatusChange": "2026-01-01",
        "metadataStatement": {
            "description": "Demo",
            "authenticatorVersion": 1,
            "schema": 3,
            "upv": [],
            "attestationTypes": [],
            "userVerificationDetails": [],
            "keyProtection": [],
            "matcherProtection": [],
            "attachmentHint": [],
            "tcDisplay": [],
            "attestationRootCertificates": [],
        },
    }


def test_session_cookie_scheduler_branches_and_after_request_cookie(metadata_module, monkeypatch, sessions, app_config):
    touched = []
    monkeypatch.setattr(
        visitor_session,
        "note_activity",
        lambda session_id, **_kwargs: touched.append(session_id),
    )

    visitor_session._schedule_cookie("outside-context")

    with entry_app().test_request_context("/", base_url="https://localhost"):
        visitor_session._schedule_cookie("   ")
        request_ctx = ctx._cv_request.get()
        assert request_ctx._after_request_functions == []

        visitor_session._schedule_cookie("session-cookie")
        assert g._session_metadata_cookie == "session-cookie"
        assert len(request_ctx._after_request_functions) == 1

        visitor_session._schedule_cookie("session-cookie")
        assert len(request_ctx._after_request_functions) == 1

        response = request_ctx._after_request_functions[0](entry_app().response_class("ok"))
        set_cookie = response.headers["Set-Cookie"]
        assert set_cookie.startswith(f"{visitor_session.COOKIE_NAME}=")
        assert "Secure" in set_cookie
        assert "SameSite=Lax" in set_cookie
        assert "SameSite=None" not in set_cookie

        # The namespace name is signed with the application secret rather than
        # emitted verbatim, so a caller cannot rewrite it to somebody else's.
        cookie_value = set_cookie.split(";", 1)[0].split("=", 1)[1]
        assert cookie_value != "session-cookie"
        assert itsdangerous.URLSafeTimedSerializer(
            entry_app().secret_key, salt="fido.mds.session-cookie.v1"
        ).loads(cookie_value) == "session-cookie"

    assert touched == ["session-cookie", "session-cookie"]


def test_get_session_id_and_ensure_paths_cover_invalid_existing_and_error_branch(metadata_module, monkeypatch, sessions, app_config):
    assert visitor_session.current_id(create=True) is None

    scheduled = []
    monkeypatch.setattr(
        visitor_session,
        "_schedule_cookie",
        lambda identifier: scheduled.append(identifier),
    )
    monkeypatch.setattr(secrets, "token_urlsafe", lambda _n: "generated-session")

    # An unsigned cookie naming a namespace is ignored: trusting it verbatim was
    # an IDOR, since any caller could name another visitor's namespace.
    with entry_app().test_request_context(
        "/",
        headers={"Cookie": f"{visitor_session.COOKIE_NAME}=cookie-session"},
    ):
        session[visitor_session.SESSION_KEY] = ".invalid"
        assert visitor_session.current_id(create=False) is None

    # A cookie this server signed still restores the namespace it names.
    sealed = itsdangerous.URLSafeTimedSerializer(
        entry_app().secret_key, salt="fido.mds.session-cookie.v1"
    ).dumps("cookie-session")
    with entry_app().test_request_context(
        "/",
        headers={"Cookie": f"{visitor_session.COOKIE_NAME}={sealed}"},
    ):
        session[visitor_session.SESSION_KEY] = ".invalid"
        assert visitor_session.current_id(create=False) == "cookie-session"
        assert session[visitor_session.SESSION_KEY] == "cookie-session"

    with entry_app().test_request_context("/"):
        session[visitor_session.SESSION_KEY] = ".invalid"
        assert visitor_session.current_id(create=False) is None
        assert visitor_session.current_id(create=True) == "generated-session"

    with entry_app().test_request_context("/"):
        monkeypatch.setattr(visitor_session, "current_id", lambda **_kwargs: None)
        with pytest.raises(RuntimeError, match="Unable to establish"):
            visitor_session.ensure_id()

    with entry_app().test_request_context("/"):
        monkeypatch.setattr(
            visitor_session,
            "current_id",
            lambda **_kwargs: "ensured-session",
        )
        assert visitor_session.ensure_id() == "ensured-session"
        assert session.permanent is True

    assert scheduled == ["cookie-session", "generated-session"]


def test_session_directory_touch_and_resolve_error_paths(metadata_module, monkeypatch, session_store):
    monkeypatch.setattr(
        session_store,
        "touch_last_access",
        lambda _sid: (_ for _ in ()).throw(RuntimeError("touch failed")),
    )
    visitor_session._touch_last_access("session-a")

    monkeypatch.setattr(
        session_store,
        "resolve_last_access",
        lambda _sid: (_ for _ in ()).throw(RuntimeError("resolve failed")),
    )
    assert visitor_session._resolve_last_access("session-a") is None



def test_upload_and_normalisation_error_edges(metadata_module, monkeypatch, uploads, sessions):
    recorded = []
    monkeypatch.setattr(uploads, "is_logging_enabled", lambda: True)
    monkeypatch.setattr(uploads, "git_blob_sha", lambda _content: "new-sha")
    monkeypatch.setattr(
        uploads,
        "github_list_directory",
        lambda _folder: [
            123,
            {"type": "dir", "name": "not-a-file"},
            {"type": "file", "name": "target.json", "sha": "old-sha", "path": 99},
        ],
    )
    monkeypatch.setattr(
        uploads,
        "github_upload_file",
        lambda *args, **kwargs: recorded.append((args, kwargs)),
    )

    assert github_mirror.maybe_store_uploaded_metadata_file("target.json", b"{}") is True
    assert recorded[0][0][0] == "metadata/target.json"
    assert recorded[0][1] == {"sha": "old-sha"}


def test_the_never_raised_metadata_download_error_is_gone():
    # Nothing raised or caught it; it was exported for nobody.
    import importlib
    import pkgutil

    import server.app.mds as package

    for info in pkgutil.iter_modules(package.__path__, f"{package.__name__}."):
        assert not hasattr(importlib.import_module(info.name), "MetadataDownloadError")
