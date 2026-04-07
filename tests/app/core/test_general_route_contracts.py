import base64
import pickle
from types import SimpleNamespace

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


def test_decode_and_certificate_routes_cover_error_and_success_paths(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    def _fake_decode(payload_text):
        if payload_text == "bad":
            raise ValueError("bad payload")
        if payload_text == "boom":
            raise RuntimeError("decoder crashed")
        return {"success": True, "decoded": payload_text}

    def _fake_serialize(certificate_bytes):
        if certificate_bytes == b"bad-cert":
            raise ValueError("certificate parse failed")
        return {"length": len(certificate_bytes), "hex": certificate_bytes.hex()}

    monkeypatch.setattr(general_module, "decode_payload_text", _fake_decode, raising=False)
    monkeypatch.setattr(general_module, "serialize_attestation_certificate", _fake_serialize, raising=False)

    bad_cert_b64 = base64.b64encode(b"bad-cert").decode("ascii")
    good_cert_unpadded = base64.b64encode(b"good-cert").decode("ascii").rstrip("=")

    with config_module.app.test_client() as client:
        decode_non_json = client.post("/api/decode", data="payload", content_type="text/plain")
        assert decode_non_json.status_code == 400
        assert decode_non_json.get_json() == {"error": "Expected JSON payload."}

        decode_missing_payload = client.post("/api/decode", json={"payload": "   "})
        assert decode_missing_payload.status_code == 400
        assert decode_missing_payload.get_json() == {
            "error": "Decoder payload must be a non-empty string."
        }

        decode_value_error = client.post("/api/decode", json={"payload": "bad"})
        assert decode_value_error.status_code == 422
        assert decode_value_error.get_json() == {"error": "bad payload"}

        decode_runtime_error = client.post("/api/decode", json={"payload": "boom"})
        assert decode_runtime_error.status_code == 500
        assert decode_runtime_error.get_json() == {"error": "Unable to decode payload."}

        decode_success = client.post("/api/decode", json={"payload": "AQID"})
        assert decode_success.status_code == 200
        assert decode_success.get_json() == {"success": True, "decoded": "AQID"}

        cert_non_json = client.post(
            "/api/mds/decode-certificate",
            data="payload",
            content_type="text/plain",
        )
        assert cert_non_json.status_code == 400
        assert cert_non_json.get_json() == {"error": "Expected JSON payload."}

        cert_missing = client.post("/api/mds/decode-certificate", json={})
        assert cert_missing.status_code == 400
        assert cert_missing.get_json() == {"error": "Certificate is required."}

        cert_invalid_encoding = client.post(
            "/api/mds/decode-certificate",
            json={"certificate": "💥"},
        )
        assert cert_invalid_encoding.status_code == 400
        assert cert_invalid_encoding.get_json() == {"error": "Invalid certificate encoding."}

        cert_parse_error = client.post(
            "/api/mds/decode-certificate",
            json={"certificate": bad_cert_b64},
        )
        assert cert_parse_error.status_code == 422
        assert cert_parse_error.get_json() == {
            "error": "Unable to decode certificate: certificate parse failed"
        }

        cert_success = client.post(
            "/api/mds/decode-certificate",
            json={"certificate": f"  {good_cert_unpadded}  \n"},
        )
        assert cert_success.status_code == 200
        assert cert_success.get_json() == {
            "details": {
                "length": len(b"good-cert"),
                "hex": b"good-cert".hex(),
            }
        }


def test_metadata_routes_cover_verified_snapshot_and_custom_error_branches(monkeypatch, tmp_path):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    with config_module.app.test_client() as client:
        missing_path = tmp_path / "missing.json"
        monkeypatch.setattr(general_module, "MDS_METADATA_VERIFIED_PATH", str(missing_path), raising=False)

        missing_response = client.get("/api/mds/metadata/base")
        assert missing_response.status_code == 404
        assert missing_response.get_json() == {
            "error": "Verified metadata snapshot is not available."
        }

        corrupted_path = tmp_path / "corrupted.json"
        corrupted_path.write_text("{bad", encoding="utf-8")
        monkeypatch.setattr(general_module, "MDS_METADATA_VERIFIED_PATH", str(corrupted_path), raising=False)

        corrupted_response = client.get("/api/mds/metadata/base")
        assert corrupted_response.status_code == 500
        assert corrupted_response.get_json() == {
            "error": "Verified metadata snapshot is corrupted."
        }

        valid_path = tmp_path / "valid.json"
        valid_payload = {"entries": [{"entryId": "test-entry"}]}
        valid_path.write_text('{"entries":[{"entryId":"test-entry"}]}', encoding="utf-8")
        monkeypatch.setattr(general_module, "MDS_METADATA_VERIFIED_PATH", str(valid_path), raising=False)

        valid_response = client.get("/api/mds/metadata/base")
        assert valid_response.status_code == 200
        assert valid_response.get_json() == valid_payload

        session_calls = []
        monkeypatch.setattr(
            general_module,
            "ensure_metadata_session_id",
            lambda: session_calls.append("called") or "session-abc",
            raising=False,
        )
        monkeypatch.setattr(
            general_module,
            "list_session_metadata_items",
            lambda: [{"storedFilename": "one.json"}],
            raising=False,
        )
        monkeypatch.setattr(
            general_module,
            "serialize_session_metadata_item",
            lambda item: {"storedFilename": item["storedFilename"], "label": "demo"},
            raising=False,
        )

        list_response = client.get("/api/mds/metadata/custom")
        assert list_response.status_code == 200
        assert list_response.get_json() == {
            "items": [{"storedFilename": "one.json", "label": "demo"}]
        }
        assert session_calls

    def _unpack(result):
        if isinstance(result, tuple):
            response, status = result
            return response, status
        return result, result.status_code

    class _Files:
        def __init__(self, entries):
            self._entries = list(entries)

        def getlist(self, name):
            assert name == "files"
            return list(self._entries)

    class _Storage:
        def __init__(self, filename, data=None, exc=None):
            self.filename = filename
            self._data = data
            self._exc = exc

        def read(self):
            if self._exc is not None:
                raise self._exc
            return self._data

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-abc", raising=False)

    with config_module.app.app_context():
        monkeypatch.setattr(general_module, "request", SimpleNamespace(files=None), raising=False)
        response, status = _unpack(general_module.api_upload_custom_metadata())
        assert status == 400
        assert response.get_json() == {
            "items": [],
            "errors": ["No JSON files were provided."],
        }

        monkeypatch.setattr(
            general_module,
            "request",
            SimpleNamespace(files=_Files([_Storage("note.txt", b"{}")])) ,
            raising=False,
        )
        response, status = _unpack(general_module.api_upload_custom_metadata())
        assert status == 400
        assert response.get_json() == {
            "items": [],
            "errors": ["note.txt is not a JSON file."],
        }

        monkeypatch.setattr(
            general_module,
            "request",
            SimpleNamespace(files=_Files([_Storage("bad.json", exc=RuntimeError("disk read failed"))])),
            raising=False,
        )
        response, status = _unpack(general_module.api_upload_custom_metadata())
        assert status == 400
        assert response.get_json() == {
            "items": [],
            "errors": ["Failed to read bad.json: disk read failed"],
        }

        monkeypatch.setattr(
            general_module,
            "request",
            SimpleNamespace(files=_Files([_Storage("utf8.json", b"\xff")])) ,
            raising=False,
        )
        response, status = _unpack(general_module.api_upload_custom_metadata())
        assert status == 400
        assert response.get_json() == {
            "items": [],
            "errors": ["utf8.json is not valid UTF-8 JSON."],
        }

        monkeypatch.setattr(
            general_module,
            "request",
            SimpleNamespace(files=_Files([_Storage("syntax.json", b"{not-json")])) ,
            raising=False,
        )
        response, status = _unpack(general_module.api_upload_custom_metadata())
        assert status == 400
        assert response.get_json()["items"] == []
        assert "syntax.json:" in response.get_json()["errors"][0]

        monkeypatch.setattr(
            general_module,
            "request",
            SimpleNamespace(files=_Files([_Storage("array.json", b"[]")])) ,
            raising=False,
        )
        response, status = _unpack(general_module.api_upload_custom_metadata())
        assert status == 400
        assert response.get_json() == {
            "items": [],
            "errors": ["array.json must contain a JSON object."],
        }

        monkeypatch.setattr(
            general_module,
            "expand_metadata_entry_payloads",
            lambda _payload: (_ for _ in ()).throw(ValueError("bad metadata object")),
            raising=False,
        )
        monkeypatch.setattr(
            general_module,
            "request",
            SimpleNamespace(files=_Files([_Storage("expand.json", b"{}")])) ,
            raising=False,
        )
        response, status = _unpack(general_module.api_upload_custom_metadata())
        assert status == 400
        assert response.get_json() == {
            "items": [],
            "errors": ["expand.json: bad metadata object"],
        }

        monkeypatch.setattr(
            general_module,
            "expand_metadata_entry_payloads",
            lambda _payload: [{"entry": 1}, {"entry": 2}],
            raising=False,
        )
        monkeypatch.setattr(
            general_module,
            "maybe_store_uploaded_metadata_file",
            lambda *_args, **_kwargs: None,
            raising=False,
        )

        def _save_item(entry_payload, original_filename=None):
            if entry_payload.get("entry") == 1:
                raise ValueError("duplicate entry")
            return {"storedFilename": "stored-2.json", "originalFilename": original_filename}

        monkeypatch.setattr(general_module, "save_session_metadata_item", _save_item, raising=False)
        monkeypatch.setattr(
            general_module,
            "serialize_session_metadata_item",
            lambda item: item,
            raising=False,
        )
        monkeypatch.setattr(
            general_module,
            "load_effective_full_snapshot",
            lambda: {"meta": {"entryCount": 1}},
            raising=False,
        )
        monkeypatch.setattr(
            general_module,
            "request",
            SimpleNamespace(files=_Files([_Storage("mixed.json", b"{}")])) ,
            raising=False,
        )
        response, status = _unpack(general_module.api_upload_custom_metadata())
        payload = response.get_json()
        assert status == 200
        assert payload["items"] == [
            {
                "storedFilename": "stored-2.json",
                "originalFilename": "mixed.json (entry 2)",
            }
        ]
        assert payload["errors"] == ["mixed.json (entry 1): duplicate entry"]
        assert payload["snapshot"] == {"meta": {"entryCount": 1}}

        monkeypatch.setattr(
            general_module,
            "save_session_metadata_item",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("persistence down")),
            raising=False,
        )
        monkeypatch.setattr(
            general_module,
            "request",
            SimpleNamespace(files=_Files([_Storage("fatal.json", b"{}")])) ,
            raising=False,
        )
        response, status = _unpack(general_module.api_upload_custom_metadata())
        assert status == 500
        assert response.get_json() == {"error": "persistence down"}

    with config_module.app.test_client() as client:
        monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-abc", raising=False)

        monkeypatch.setattr(
            general_module,
            "delete_session_metadata_item",
            lambda _name: (_ for _ in ()).throw(ValueError("invalid filename")),
            raising=False,
        )
        delete_value_error = client.delete("/api/mds/metadata/custom/invalid")
        assert delete_value_error.status_code == 400
        assert delete_value_error.get_json() == {"error": "invalid filename"}

        monkeypatch.setattr(
            general_module,
            "delete_session_metadata_item",
            lambda _name: (_ for _ in ()).throw(RuntimeError("storage unavailable")),
            raising=False,
        )
        delete_runtime_error = client.delete("/api/mds/metadata/custom/invalid")
        assert delete_runtime_error.status_code == 500
        assert delete_runtime_error.get_json() == {"error": "storage unavailable"}

        monkeypatch.setattr(
            general_module,
            "delete_session_metadata_item",
            lambda _name: False,
            raising=False,
        )
        delete_not_found = client.delete("/api/mds/metadata/custom/missing.json")
        assert delete_not_found.status_code == 404
        assert delete_not_found.get_json() == {
            "deleted": False,
            "message": "Metadata entry not found.",
        }


def test_general_helper_bootstrap_and_empty_snapshot_branches(monkeypatch):
    general_module = pytest.importorskip("server.app.routes.general")
    config_module = pytest.importorskip("server.app.config")
    pytest.importorskip("server.app.app")

    flag_name = "TEST_GENERAL_ENV_FLAG"
    monkeypatch.delenv(flag_name, raising=False)
    assert general_module._env_flag(flag_name) is None

    monkeypatch.setenv(flag_name, " off ")
    assert general_module._env_flag(flag_name) is False

    monkeypatch.setenv(flag_name, "yes")
    assert general_module._env_flag(flag_name) is True

    monkeypatch.setattr(general_module, "startup_fail_fast_enabled", lambda: True, raising=False)
    monkeypatch.setenv(general_module._INDEX_EAGER_METADATA_ENV_FLAG, "0")
    assert general_module._should_bootstrap_metadata_on_index() is False
    monkeypatch.setenv(general_module._INDEX_EAGER_METADATA_ENV_FLAG, "1")
    assert general_module._should_bootstrap_metadata_on_index() is True

    state = {
        "started": False,
        "completed": False,
        "marker": None,
        "cache_loaded": False,
    }
    monkeypatch.setattr(general_module, "_metadata_bootstrap_state", state, raising=False)

    monkeypatch.setattr(general_module, "load_cached_metadata_snapshot", lambda: {}, raising=False)
    general_module._load_cached_metadata_snapshot_if_available()
    assert state["cache_loaded"] is False

    monkeypatch.setattr(general_module, "load_cached_metadata_snapshot", lambda: {"meta": {}}, raising=False)
    general_module._load_cached_metadata_snapshot_if_available()
    assert state["cache_loaded"] is True
    general_module._load_cached_metadata_snapshot_if_available()
    assert state["cache_loaded"] is True

    load_calls = []
    monkeypatch.setattr(general_module, "_load_cached_metadata_snapshot_if_available", lambda: load_calls.append("load"), raising=False)
    monkeypatch.setattr(general_module.app, "debug", True, raising=False)
    monkeypatch.delenv("WERKZEUG_RUN_MAIN", raising=False)
    general_module.ensure_metadata_bootstrapped(skip_if_reloader_parent=True)
    assert load_calls == []

    today = general_module._bootstrap_marker_for_today()
    monkeypatch.setattr(
        general_module,
        "_metadata_bootstrap_state",
        {
            "started": False,
            "completed": True,
            "marker": today,
            "cache_loaded": False,
        },
        raising=False,
    )
    monkeypatch.setattr(general_module.app, "debug", False, raising=False)
    load_calls.clear()
    monkeypatch.setattr(general_module, "_load_cached_metadata_snapshot_if_available", lambda: load_calls.append("load"), raising=False)
    monkeypatch.setattr(
        general_module,
        "_load_base_metadata",
        lambda: (_ for _ in ()).throw(AssertionError("_load_base_metadata should not be called")),
        raising=False,
    )
    general_module.ensure_metadata_bootstrapped(skip_if_reloader_parent=False)
    assert load_calls == ["load"]

    marked = []
    monkeypatch.setattr(
        general_module,
        "_metadata_bootstrap_state",
        {
            "started": False,
            "completed": False,
            "marker": None,
            "cache_loaded": False,
        },
        raising=False,
    )
    monkeypatch.setattr(general_module, "_load_cached_metadata_snapshot_if_available", lambda: None, raising=False)
    monkeypatch.setattr(general_module, "_load_base_metadata", lambda: (None, None), raising=False)
    monkeypatch.setattr(general_module, "_mark_bootstrap_completed_for_today", lambda: marked.append(True), raising=False)
    general_module.ensure_metadata_bootstrapped(skip_if_reloader_parent=False)
    assert marked == [True]

    with config_module.app.test_client() as client:
        monkeypatch.setattr(general_module, "_should_bootstrap_metadata_on_index", lambda: False, raising=False)
        monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
        monkeypatch.setattr(general_module, "load_packaged_explorer_summary", lambda: {}, raising=False)
        monkeypatch.setattr(general_module, "render_template", lambda *_args, **_kwargs: "index-body", raising=False)
        index_response = client.get("/")
        assert index_response.status_code == 200
        assert index_response.get_data(as_text=True) == "index-body"

        monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
        monkeypatch.setattr(general_module, "load_effective_explorer_snapshot", lambda: {}, raising=False)
        monkeypatch.setattr(general_module, "load_effective_full_snapshot", lambda: {}, raising=False)

        explorer_missing = client.get("/api/mds/metadata/explorer")
        assert explorer_missing.status_code == 404
        assert explorer_missing.get_json() == {
            "error": "Verified metadata snapshot is not available."
        }

        full_explorer_missing = client.get("/api/mds/metadata/explorer/full")
        assert full_explorer_missing.status_code == 404
        assert full_explorer_missing.get_json() == {
            "error": "Verified metadata snapshot is not available."
        }

    class _Files:
        def __init__(self, entries):
            self._entries = list(entries)

        def getlist(self, name):
            assert name == "files"
            return list(self._entries)

    class _Storage:
        def __init__(self, filename, data):
            self.filename = filename
            self._data = data

        def read(self):
            return self._data

    def _unpack(result):
        if isinstance(result, tuple):
            response, status = result
            return response, status
        return result, result.status_code

    monkeypatch.setattr(general_module, "ensure_metadata_session_id", lambda: "session-id", raising=False)
    monkeypatch.setattr(general_module, "expand_metadata_entry_payloads", lambda payload: [payload], raising=False)
    monkeypatch.setattr(general_module, "maybe_store_uploaded_metadata_file", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(
        general_module,
        "save_session_metadata_item",
        lambda _payload, original_filename=None: {"originalFilename": original_filename},
        raising=False,
    )
    monkeypatch.setattr(general_module, "serialize_session_metadata_item", lambda item: item, raising=False)
    monkeypatch.setattr(general_module, "load_effective_full_snapshot", lambda: {"meta": {"entryCount": 1}}, raising=False)

    with config_module.app.app_context():
        monkeypatch.setattr(
            general_module,
            "request",
            SimpleNamespace(files=_Files([_Storage("   ", b"{}")])) ,
            raising=False,
        )
        response, status = _unpack(general_module.api_upload_custom_metadata())
        assert status == 200
        assert response.get_json()["items"] == [{"originalFilename": "metadata.json"}]