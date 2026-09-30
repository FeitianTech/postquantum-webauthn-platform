from __future__ import annotations

import gzip

from flask import Flask

from server.app.config import (
    application,
    attestation_trust,
    compression,
    paths,
    relying_party,
)
from tests.app.entry_app import entry_app


def test_the_project_root_is_two_levels_above_the_package():
    assert paths._PACKAGE_ROOT.parts[-2:] == ("server", "app")
    assert paths._PROJECT_ROOT == paths._PACKAGE_ROOT.parents[1]
    assert (paths._PROJECT_ROOT / "server" / "app" / "config" / "paths.py").is_file()


def test_response_compression_paths_and_accepts_gzip_guard(monkeypatch):
    app = entry_app()

    assert compression._accepts_gzip() is False

    with app.test_request_context("/", headers={"Accept-Encoding": "gzip"}):
        app.config["RESPONSE_COMPRESSION_MIN_SIZE"] = 1

        payload = b"A" * 1024
        response = app.response_class(payload, status=200, mimetype="text/plain")
        response.direct_passthrough = True
        response.headers["ETag"] = "etag"
        response.headers["Content-MD5"] = "digest"

        compressed = compression.maybe_compress_response(response)
        assert compressed.headers["Content-Encoding"] == "gzip"
        assert "Accept-Encoding" in compressed.headers["Vary"]
        assert compressed.direct_passthrough is False
        assert "ETag" not in compressed.headers
        assert "Content-MD5" not in compressed.headers
        assert gzip.decompress(compressed.get_data()) == payload

        monkeypatch.setattr(
            compression.gzip,
            "compress",
            lambda data, compresslevel=6: data + b"not-smaller",
        )
        unchanged = app.response_class(payload, status=200, mimetype="text/plain")
        assert compression.maybe_compress_response(unchanged).headers.get("Content-Encoding") is None

        already_encoded = app.response_class(payload, status=200, mimetype="text/plain")
        already_encoded.headers["Content-Encoding"] = "br"
        assert compression.maybe_compress_response(already_encoded) is already_encoded

        non_2xx = app.response_class(payload, status=304, mimetype="text/plain")
        assert compression.maybe_compress_response(non_2xx) is non_2xx

        non_text = app.response_class(payload, status=200, mimetype="application/octet-stream")
        assert compression.maybe_compress_response(non_text) is non_text


def test_add_after_request_once_guard_paths(monkeypatch):
    flask_app = Flask("config-branch-guards")
    marker = compression._RESPONSE_COMPRESSION_MARKER

    calls = []
    monkeypatch.setattr(flask_app, "after_request", lambda handler: calls.append(handler))

    def existing(response):
        return response

    setattr(existing, marker, True)
    flask_app.after_request_funcs.setdefault(None, []).append(existing)

    application.add_after_request_once(flask_app, lambda response: response, marker)
    assert calls == []

    flask_app.after_request_funcs[None] = []
    monkeypatch.setattr(flask_app, "_got_first_request", True)
    application.add_after_request_once(flask_app, lambda response: response, marker)
    assert calls == []

    monkeypatch.setattr(flask_app, "_got_first_request", False)
    def handler(response):
        return response

    application.add_after_request_once(flask_app, handler, marker)
    assert calls == [handler]


def test_parse_fingerprints_and_host_normalization_branches(monkeypatch):
    assert attestation_trust._parse_trusted_ca_fingerprints(None) is None
    assert attestation_trust._parse_trusted_ca_fingerprints("ab:cd") is None

    long_fp = ":".join(["aa"] * 20)
    parsed = attestation_trust._parse_trusted_ca_fingerprints(f"{long_fp}, short")
    assert parsed == {"AA" * 20}

    monkeypatch.setitem(entry_app().config, "FIDO_SERVER_RP_ID", "  configured.example  ")
    with entry_app().app_context():
        assert relying_party.determine_rp_id() == "configured.example"

    assert relying_party._normalise_request_host(None) is None
    assert relying_party._normalise_request_host("   ") is None
    assert relying_party._normalise_request_host("[2001:db8::1]:8443") == "2001:db8::1"
    assert relying_party._normalise_request_host("2001:db8::1") == "2001:db8::1"
    assert relying_party._normalise_request_host("Example.COM:8443") == "example.com"
    assert relying_party._normalise_request_host("bad host") == "bad host"

    assert relying_party._resolve_request_host() is None

    with entry_app().test_request_context(
        "/",
        headers={"Host": ""},
        environ_overrides={"HTTP_HOST": "api.example", "SERVER_NAME": "fallback.example"},
    ):
        assert relying_party._resolve_request_host() == "api.example"

    with entry_app().test_request_context(
        "/",
        headers={"Host": ""},
        environ_overrides={"HTTP_HOST": "", "SERVER_NAME": ""},
    ):
        assert relying_party._resolve_request_host() is None
