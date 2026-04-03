import pickle

import pytest


def test_deletepub_and_downloadcred_contracts(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    deleted = []
    stored_credentials = [{"credential_id": "abc", "sign_count": 7}]

    monkeypatch.setattr(
        general_module,
        "ensure_metadata_session_id",
        lambda: "session-123",
        raising=False,
    )
    monkeypatch.setattr(
        general_module,
        "delkey",
        lambda email, session_id=None: deleted.append((email, session_id)),
        raising=False,
    )
    monkeypatch.setattr(
        general_module,
        "readkey",
        lambda email, session_id=None: (
            stored_credentials if email == "user@example.com" and session_id == "session-123" else None
        ),
        raising=False,
    )

    with config_module.app.test_client() as client:
        delete_missing_email = client.post("/api/deletepub", json={})
        assert delete_missing_email.status_code == 400

        delete_ok = client.post("/api/deletepub", json={"email": "user@example.com"})
        assert delete_ok.status_code == 200
        assert delete_ok.get_json() == {"status": "OK"}
        assert deleted == [("user@example.com", "session-123")]

        download_missing_email = client.get("/api/downloadcred")
        assert download_missing_email.status_code == 400

        download_missing_user = client.get("/api/downloadcred?email=missing@example.com")
        assert download_missing_user.status_code == 404

        download_ok = client.get("/api/downloadcred?email=user@example.com")
        assert download_ok.status_code == 200
        assert download_ok.mimetype == "application/octet-stream"
        assert "attachment;" in download_ok.headers.get("Content-Disposition", "")
        assert "user@example.com_credential_data.pkl" in download_ok.headers.get("Content-Disposition", "")
        assert pickle.loads(download_ok.data) == stored_credentials