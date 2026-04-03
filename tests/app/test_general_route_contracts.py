import base64
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