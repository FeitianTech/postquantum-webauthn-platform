import json

import pytest

from server.app import visitor_session
from server.app.storage import credential_artifacts
from tests.app.entry_app import entry_app

from ..storage import fake_gcs


def test_bulk_credential_artifact_route_requires_array(monkeypatch):
    monkeypatch.setattr(visitor_session, "current_id", lambda **_kwargs: "session-id")

    with entry_app().test_client() as client:
        response = client.post(
            "/api/advanced/credential-artifacts/bulk",
            json={"storageIds": "cred-1"},
        )

    assert response.status_code == 400
    assert response.get_json()["error"] == "storageIds must be an array."


def test_put_credential_artifact_route_requires_object_payload(monkeypatch):
    with entry_app().test_client() as client:
        response = client.put(
            "/api/advanced/credential-artifacts/cred-1",
            json={"artifact": "not-an-object"},
        )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Artifact payload must be an object."}


def test_put_credential_artifact_route_returns_400_when_store_fails(monkeypatch):
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "session-id")
    monkeypatch.setattr(
        credential_artifacts,
        "store_credential_artifact",
        lambda *_args, **_kwargs: False
    )

    with entry_app().test_client() as client:
        response = client.put(
            "/api/advanced/credential-artifacts/cred-3",
            json={"artifact": {"x": 1}},
        )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Unable to store artifact."}


def test_put_snapshot_route_rejects_non_object_snapshot(monkeypatch):
    with entry_app().test_client() as client:
        response = client.put(
            "/api/advanced/credential-artifacts/cred-4/snapshot",
            json={"snapshot": "not-an-object"},
        )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Snapshot must be an object."}


def test_put_snapshot_route_returns_400_when_store_fails(monkeypatch):
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "session-id")
    monkeypatch.setattr(
        credential_artifacts,
        "store_credential_artifact",
        lambda *_args, **_kwargs: False
    )

    with entry_app().test_client() as client:
        response = client.put(
            "/api/advanced/credential-artifacts/cred-4/snapshot",
            json={"snapshot": {"html": "<p>snapshot</p>"}},
        )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Unable to store artifact snapshot."}


def test_a_snapshot_the_store_cannot_be_made_for_is_not_stored(monkeypatch, advanced_stores, tmp_path):
    # The artifact store's folder is a file: nothing can be made under it.
    blocked = tmp_path / "artifacts-blocked"
    blocked.write_text("not a folder")
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR", str(blocked))

    with entry_app().test_client() as client:
        response = client.put("/api/advanced/credential-artifacts/cred-4/snapshot", json={"snapshot": {"view": 1}})

    assert response.status_code == 400
    assert response.get_json() == {"error": "Unable to store artifact snapshot."}


def test_a_blank_artifact_id_is_refused():
    with entry_app().test_client() as client:
        response = client.delete("/api/advanced/credential-artifacts/%20")

    assert response.status_code == 400
    assert response.get_json() == {"status": "failed", "error": "Invalid storage identifier."}


@pytest.mark.parametrize(
    "delete_status,expected_http_status,expected_payload",
    [
        ("deleted", 200, {"status": "deleted"}),
        ("absent", 200, {"status": "absent"}),
        (
            "failed",
            500,
            {
                "status": "failed",
                "error": "Unable to delete credential artifact.",
            },
        ),
    ],
)
def test_delete_credential_artifact_route_reports_status(monkeypatch, delete_status, expected_http_status, expected_payload):
    monkeypatch.setattr(visitor_session, "current_id", lambda **_kwargs: "session-id")
    monkeypatch.setattr(
        credential_artifacts,
        "delete_credential_artifact_with_status",
        lambda storage_id, *, session_id=None: delete_status
    )

    with entry_app().test_client() as client:
        response = client.delete("/api/advanced/credential-artifacts/cred-6")

    assert response.status_code == expected_http_status
    assert response.get_json() == expected_payload


@pytest.mark.parametrize("route", ["get", "bulk", "merging-put", "snapshot"])
def test_an_artifact_the_store_cannot_read_answers_503_not_missing_or_unstored(
    monkeypatch, client, route
):
    # A failed download used to read as "no artifact" (404, or left out of the
    # bulk answer), and a merge that could not read answered 400.
    bucket = fake_gcs.install(monkeypatch, credential_artifacts)
    monkeypatch.setattr(visitor_session, "ensure_id", lambda: "session-id")
    monkeypatch.setattr(visitor_session, "current_id", lambda **_kwargs: "session-id")
    blob_name = credential_artifacts._artifact_blob("cred-1", "session-id")
    bucket.put(blob_name, json.dumps({"storageId": "cred-1", "payload": {"kept": True}}).encode())
    bucket.failing[blob_name] = fake_gcs.ServiceUnavailable("503 at /secret/path")

    base = "/api/advanced/credential-artifacts"
    if route == "get":
        response = client.get(f"{base}/cred-1")
    elif route == "bulk":
        response = client.post(f"{base}/bulk", json={"storageIds": ["cred-1"]})
    elif route == "merging-put":
        response = client.put(f"{base}/cred-1", json={"artifact": {"late": True}})
    else:
        response = client.put(f"{base}/cred-1/snapshot", json={"snapshot": {"html": "<p>x</p>"}})

    assert response.status_code == 503, response.get_json()
    assert list(response.get_json()) == ["error"]
    assert "/secret/path" not in response.get_data(as_text=True)
    bucket.failing.clear()
    assert json.loads(bucket.objects[blob_name][0])["payload"] == {"kept": True}


@pytest.mark.parametrize(
    ("method", "path", "body", "status", "answer"),
    [
        ("GET", "/api/advanced/credential-artifacts/cred-1", None, 404, {"error": "Credential artifact not found."}),
        ("POST", "/api/advanced/credential-artifacts/bulk", {"storageIds": ["cred-1"]}, 200, {"artifacts": {}}),
        ("DELETE", "/api/advanced/credential-artifacts/cred-1", None, 200, {"status": "absent"}),
    ],
)
def test_a_visitor_without_a_namespace_reads_and_deletes_without_being_given_one(method, path, body, status, answer):
    with entry_app().test_client() as client:
        response = client.open(path, method=method, json=body)

    assert (response.status_code, response.get_json()) == (status, answer)
    assert response.headers.getlist("Set-Cookie") == []


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "/api/advanced/credential-artifacts/cred-1", None),
        ("POST", "/api/advanced/credential-artifacts/bulk", {"storageIds": ["cred-1"]}),
        ("PUT", "/api/advanced/credential-artifacts/cred-1", {"artifact": {"kept": True}}),
    ],
)
def test_the_visitors_artifacts_are_never_cached_and_keyed_on_the_cookie(advanced_stores, method, path, body):
    with entry_app().test_client() as client:
        response = client.open(path, method=method, json=body)

    assert response.headers["Cache-Control"] == "no-store"
    assert "Cookie" in response.headers["Vary"]


def test_an_artifact_is_stored_merged_snapshotted_read_and_deleted_in_the_visitors_store(advanced_stores):
    base = "/api/advanced/credential-artifacts"
    client = entry_app().test_client()

    assert client.put(f"{base}/cred-1", json={"artifact": {"storedCredential": {"id": "cred-1"}}}).get_json() == {"status": "OK"}
    # Merged by default, under either name.
    assert client.put(f"{base}/cred-1", json={"payload": {"note": 1}}).status_code == 200
    assert client.put(f"{base}/cred-1/snapshot", json={"snapshot": {"view": 1}}).status_code == 200
    stored = {"note": 1, "registrationDetailSnapshot": {"view": 1}, "storedCredential": {"id": "cred-1"}}
    assert client.get(f"{base}/cred-1").get_json() == {"storageId": "cred-1", "artifact": stored}
    # Bulk: each id once, trimmed; what is missing or no id is left out.
    bulk = client.post(f"{base}/bulk", json={"storageIds": [" cred-1 ", "missing", "cred-1", 5]})
    assert bulk.get_json() == {"artifacts": {"cred-1": stored}}
    # Another visitor's client sees none of it.
    assert entry_app().test_client().post(f"{base}/bulk", json={"storageIds": ["cred-1"]}).get_json() == {"artifacts": {}}

    assert client.put(f"{base}/cred-1", json={"artifact": {"only": True}, "merge": False}).status_code == 200
    assert client.get(f"{base}/cred-1").get_json()["artifact"] == {"only": True}

    assert client.delete(f"{base}/cred-1").get_json() == {"status": "deleted"}
    assert client.delete(f"{base}/cred-1").get_json() == {"status": "absent"}
    assert client.get(f"{base}/cred-1").status_code == 404
