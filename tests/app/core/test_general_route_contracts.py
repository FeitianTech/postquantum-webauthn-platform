import base64
from types import SimpleNamespace

from server.app.decoder.decode import pipeline as decode_pipeline
from server.app.routes import mds as mds_routes
from server.app.webauthn.attestation import certificates as attestation_certificates
from server.app.webauthn.metadata import effective as metadata_effective
from server.app.webauthn.metadata import entries as metadata_entries
from server.app.webauthn.metadata import sessions as metadata_sessions
from server.app.webauthn.metadata import uploads as metadata_uploads
from tests.app.entry_app import entry_app


def test_decode_and_certificate_routes_cover_error_and_success_paths(monkeypatch):
    def _fake_decode(payload_text, **_options):
        if payload_text == "bad":
            raise ValueError("bad payload")
        if payload_text == "boom":
            raise RuntimeError("decoder crashed")
        return {"success": True, "decoded": payload_text}

    def _fake_serialize(certificate_bytes):
        if certificate_bytes == b"bad-cert":
            raise ValueError("certificate parse failed")
        return {"length": len(certificate_bytes), "hex": certificate_bytes.hex()}

    monkeypatch.setattr(decode_pipeline, "decode_payload_text", _fake_decode)
    monkeypatch.setattr(attestation_certificates, "serialize_attestation_certificate", _fake_serialize)

    bad_cert_b64 = base64.b64encode(b"bad-cert").decode("ascii")
    good_cert_unpadded = base64.b64encode(b"good-cert").decode("ascii").rstrip("=")

    with entry_app().test_client() as client:
        decode_non_json = client.post("/api/codec", data="payload", content_type="text/plain")
        assert decode_non_json.status_code == 400
        assert decode_non_json.get_json() == {"error": "Expected JSON payload."}

        decode_missing_payload = client.post("/api/codec", json={"payload": "   "})
        assert decode_missing_payload.status_code == 400
        assert decode_missing_payload.get_json() == {
            "error": "Codec payload must be a non-empty string."
        }

        decode_value_error = client.post("/api/codec", json={"payload": "bad"})
        assert decode_value_error.status_code == 422
        assert decode_value_error.get_json() == {"error": "bad payload"}

        decode_runtime_error = client.post("/api/codec", json={"payload": "boom"})
        assert decode_runtime_error.status_code == 500
        assert decode_runtime_error.get_json() == {"error": "Unable to decode payload."}

        decode_success = client.post("/api/codec", json={"payload": "AQID"})
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


def test_metadata_routes_cover_custom_error_branches(monkeypatch, tmp_path):
    with entry_app().test_client() as client:
        session_calls = []
        monkeypatch.setattr(
            metadata_sessions,
            "ensure_metadata_session_id",
            lambda: session_calls.append("called") or "session-abc",
        )
        monkeypatch.setattr(
            metadata_sessions,
            "list_session_metadata_items",
            lambda: [{"storedFilename": "one.json"}],
        )
        monkeypatch.setattr(
            metadata_sessions,
            "serialize_session_metadata_item",
            lambda item: {"storedFilename": item["storedFilename"], "label": "demo"},
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

    monkeypatch.setattr(metadata_sessions, "ensure_metadata_session_id", lambda: "session-abc")

    with entry_app().app_context():
        monkeypatch.setattr(mds_routes, "request", SimpleNamespace(files=None))
        response, status = _unpack(mds_routes.api_upload_custom_metadata())
        assert status == 400
        assert response.get_json() == {
            "items": [],
            "errors": ["No JSON files were provided."],
        }

        monkeypatch.setattr(
            mds_routes,
            "request",
            SimpleNamespace(files=_Files([_Storage("note.txt", b"{}")])),
        )
        response, status = _unpack(mds_routes.api_upload_custom_metadata())
        assert status == 400
        assert response.get_json() == {
            "items": [],
            "errors": ["note.txt is not a JSON file."],
        }

        monkeypatch.setattr(
            mds_routes,
            "request",
            SimpleNamespace(files=_Files([_Storage("bad.json", exc=RuntimeError("disk read failed"))])),
        )
        response, status = _unpack(mds_routes.api_upload_custom_metadata())
        assert status == 400
        assert response.get_json() == {
            "items": [],
            "errors": ["Failed to read bad.json: disk read failed"],
        }

        monkeypatch.setattr(
            mds_routes,
            "request",
            SimpleNamespace(files=_Files([_Storage("utf8.json", b"\xff")])),
        )
        response, status = _unpack(mds_routes.api_upload_custom_metadata())
        assert status == 400
        assert response.get_json() == {
            "items": [],
            "errors": ["utf8.json is not valid UTF-8 JSON."],
        }

        monkeypatch.setattr(
            mds_routes,
            "request",
            SimpleNamespace(files=_Files([_Storage("syntax.json", b"{not-json")])),
        )
        response, status = _unpack(mds_routes.api_upload_custom_metadata())
        assert status == 400
        assert response.get_json()["items"] == []
        assert "syntax.json:" in response.get_json()["errors"][0]

        monkeypatch.setattr(
            mds_routes,
            "request",
            SimpleNamespace(files=_Files([_Storage("array.json", b"[]")])),
        )
        response, status = _unpack(mds_routes.api_upload_custom_metadata())
        assert status == 400
        assert response.get_json() == {
            "items": [],
            "errors": ["array.json must contain a JSON object."],
        }

        monkeypatch.setattr(
            metadata_entries,
            "expand_metadata_entry_payloads",
            lambda _payload: (_ for _ in ()).throw(ValueError("bad metadata object")),
        )
        monkeypatch.setattr(
            mds_routes,
            "request",
            SimpleNamespace(files=_Files([_Storage("expand.json", b"{}")])),
        )
        response, status = _unpack(mds_routes.api_upload_custom_metadata())
        assert status == 400
        assert response.get_json() == {
            "items": [],
            "errors": ["expand.json: bad metadata object"],
        }

        monkeypatch.setattr(
            metadata_entries,
            "expand_metadata_entry_payloads",
            lambda _payload: [{"entry": 1}, {"entry": 2}],
        )
        monkeypatch.setattr(
            metadata_uploads,
            "maybe_store_uploaded_metadata_file",
            lambda *_args, **_kwargs: None,
        )

        def _save_item(entry_payload, original_filename=None):
            if entry_payload.get("entry") == 1:
                raise ValueError("duplicate entry")
            return {"storedFilename": "stored-2.json", "originalFilename": original_filename}

        monkeypatch.setattr(metadata_sessions, "save_session_metadata_item", _save_item)
        monkeypatch.setattr(
            metadata_sessions,
            "serialize_session_metadata_item",
            lambda item: item,
        )
        monkeypatch.setattr(
            metadata_effective,
            "load_effective_full_snapshot",
            lambda: {"meta": {"entryCount": 1}},
        )
        monkeypatch.setattr(
            mds_routes,
            "request",
            SimpleNamespace(files=_Files([_Storage("mixed.json", b"{}")])),
        )
        response, status = _unpack(mds_routes.api_upload_custom_metadata())
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
            metadata_sessions,
            "save_session_metadata_item",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("persistence down")),
        )
        monkeypatch.setattr(
            mds_routes,
            "request",
            SimpleNamespace(files=_Files([_Storage("fatal.json", b"{}")])),
        )
        response, status = _unpack(mds_routes.api_upload_custom_metadata())
        assert status == 500
        assert response.get_json() == {"error": "persistence down"}

    with entry_app().test_client() as client:
        monkeypatch.setattr(metadata_sessions, "ensure_metadata_session_id", lambda: "session-abc")

        monkeypatch.setattr(
            metadata_sessions,
            "delete_session_metadata_item",
            lambda _name: (_ for _ in ()).throw(ValueError("invalid filename")),
        )
        delete_value_error = client.delete("/api/mds/metadata/custom/invalid")
        assert delete_value_error.status_code == 400
        assert delete_value_error.get_json() == {"error": "invalid filename"}

        monkeypatch.setattr(
            metadata_sessions,
            "delete_session_metadata_item",
            lambda _name: (_ for _ in ()).throw(RuntimeError("storage unavailable")),
        )
        delete_runtime_error = client.delete("/api/mds/metadata/custom/invalid")
        assert delete_runtime_error.status_code == 500
        assert delete_runtime_error.get_json() == {"error": "storage unavailable"}

        monkeypatch.setattr(
            metadata_sessions,
            "delete_session_metadata_item",
            lambda _name: False,
        )
        delete_not_found = client.delete("/api/mds/metadata/custom/missing.json")
        assert delete_not_found.status_code == 404
        assert delete_not_found.get_json() == {
            "deleted": False,
            "message": "Metadata entry not found.",
        }


def test_general_empty_snapshot_and_upload_branches(monkeypatch):
    with entry_app().test_client() as client:
        monkeypatch.setattr(metadata_sessions, "ensure_metadata_session_id", lambda: "session-id")
        monkeypatch.setattr(metadata_effective, "load_effective_full_snapshot", lambda: {})

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

    monkeypatch.setattr(metadata_sessions, "ensure_metadata_session_id", lambda: "session-id")
    monkeypatch.setattr(metadata_entries, "expand_metadata_entry_payloads", lambda payload: [payload])
    monkeypatch.setattr(metadata_uploads, "maybe_store_uploaded_metadata_file", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        metadata_sessions,
        "save_session_metadata_item",
        lambda _payload, original_filename=None: {"originalFilename": original_filename},
    )
    monkeypatch.setattr(metadata_sessions, "serialize_session_metadata_item", lambda item: item)
    monkeypatch.setattr(metadata_effective, "load_effective_full_snapshot", lambda: {"meta": {"entryCount": 1}})

    with entry_app().app_context():
        monkeypatch.setattr(
            mds_routes,
            "request",
            SimpleNamespace(files=_Files([_Storage("   ", b"{}")])),
        )
        response, status = _unpack(mds_routes.api_upload_custom_metadata())
        assert status == 200
        assert response.get_json()["items"] == [{"originalFilename": "metadata.json"}]