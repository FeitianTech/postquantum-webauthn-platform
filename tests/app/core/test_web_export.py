"""``/beta`` serves the new UI's static export (``routes/web_export.py``).

Every test builds its own export in ``tmp_path``: pytest never needs Node, and
never reads a ``web/out`` a local build (or Cloud Build's web step, running
beside the Python tests) may be writing.
"""
from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from server.app.config import paths, web_export

INDEX = b"<!DOCTYPE html><html><head><title>New UI</title></head><body>index page " + b"x" * 600 + b"</body></html>"
DESIGN = b"<!DOCTYPE html><html><body>design page</body></html>"
NOT_FOUND = b"<!DOCTYPE html><html><body>export 404 page</body></html>"
CHUNK = b"console.log('chunk');\n" * 200
SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Content-Security-Policy-Report-Only",
    "Reporting-Endpoints",
    "Permissions-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
)
IMMUTABLE = "public, max-age=31536000, immutable"


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


@pytest.fixture
def export_root(tmp_path) -> Path:
    root = tmp_path / "out"
    _write(root / "index.html", INDEX)
    _write(root / "design.html", DESIGN)
    _write(root / "404.html", NOT_FOUND)
    _write(root / "500.html", b"<!DOCTYPE html><html><body>500</body></html>")
    _write(root / "_next" / "static" / "chunks" / "main-abc123.js", CHUNK)
    _write(root / "_next" / "static" / "chunks" / "main-abc123.js.gz", gzip.compress(CHUNK))
    _write(root / "_next" / "static" / "media" / "geist.woff2", b"wOF2font")
    _write(tmp_path / "secret.txt", b"outside the export")
    return root


@pytest.fixture
def beta(make_app, export_root):
    return make_app({web_export.WEB_EXPORT_ROOT_KEY: str(export_root)}).test_client()


def test_the_export_is_web_out_in_the_checkout_unless_the_environment_says(monkeypatch):
    monkeypatch.delenv("FIDO_SERVER_WEB_EXPORT_ROOT", raising=False)
    assert web_export.config_from_env() == {"WEB_EXPORT_ROOT": str(paths._PROJECT_ROOT / "web" / "out")}

    monkeypatch.setenv("FIDO_SERVER_WEB_EXPORT_ROOT", "  ")
    assert web_export.config_from_env()["WEB_EXPORT_ROOT"] == str(web_export.DEFAULT_WEB_EXPORT_ROOT)

    monkeypatch.setenv("FIDO_SERVER_WEB_EXPORT_ROOT", "/srv/export")
    assert web_export.config_from_env()["WEB_EXPORT_ROOT"] == "/srv/export"


def test_the_environment_reaches_the_app(monkeypatch, make_app, export_root):
    monkeypatch.setenv("FIDO_SERVER_WEB_EXPORT_ROOT", str(export_root))
    response = make_app().test_client().get("/beta")

    assert response.status_code == 200
    assert b"index page" in response.data


@pytest.mark.parametrize("url", ["/beta", "/beta/"])
def test_beta_answers_the_index_page_at_both_spellings(beta, url):
    response = beta.get(url)

    assert response.status_code == 200
    assert response.mimetype == "text/html"
    assert response.data == INDEX
    assert response.headers["Cache-Control"] == "no-cache"


@pytest.mark.parametrize("url", ["/beta/design", "/beta/design.html"])
def test_a_page_is_served_by_its_name(beta, url):
    response = beta.get(url)

    assert response.status_code == 200
    assert response.data == DESIGN
    assert response.headers["Cache-Control"] == "no-cache"


def test_html_is_revalidated_with_its_etag(beta):
    first = beta.get("/beta/design")
    again = beta.get("/beta/design", headers={"If-None-Match": first.headers["ETag"]})

    assert first.headers["ETag"]
    assert again.status_code == 304
    assert again.headers["Cache-Control"] == "no-cache"


def test_html_is_gzipped_for_a_client_that_takes_it(beta):
    response = beta.get("/beta", headers={"Accept-Encoding": "gzip"})

    assert response.headers["Content-Encoding"] == "gzip"
    assert gzip.decompress(response.data) == INDEX


def test_hashed_assets_are_immutable_for_a_year_and_precompressed(beta):
    url = "/beta/_next/static/chunks/main-abc123.js"
    zipped = beta.get(url, headers={"Accept-Encoding": "gzip, br"})
    plain = beta.get(url)
    again = beta.get(url, headers={"If-None-Match": plain.headers["ETag"]})

    assert zipped.status_code == 200
    assert zipped.headers["Cache-Control"] == IMMUTABLE
    assert zipped.headers["Content-Encoding"] == "gzip"
    assert "Accept-Encoding" in zipped.headers["Vary"]
    assert gzip.decompress(zipped.data) == CHUNK
    assert plain.headers["Cache-Control"] == IMMUTABLE
    assert "Content-Encoding" not in plain.headers
    assert plain.data == CHUNK
    assert plain.mimetype in {"application/javascript", "text/javascript"}
    assert again.status_code == 304


def test_a_font_under_next_static_is_immutable_too(beta):
    response = beta.get("/beta/_next/static/media/geist.woff2")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == IMMUTABLE
    assert response.data == b"wOF2font"


@pytest.mark.parametrize(
    "url",
    ["/beta/nothing-here", "/beta/_next/static/chunks/missing.js", "/beta/design/", "/beta/404", "/beta/404.html", "/beta/500.html"],
)
def test_an_unknown_path_answers_the_export_404_page(beta, url):
    response = beta.get(url)

    assert response.status_code == 404
    assert response.data == NOT_FOUND
    assert response.headers["Cache-Control"] == "no-cache"


def test_a_404_is_never_a_304_or_a_range(beta):
    for headers in ({"If-None-Match": "*"}, {"Range": "bytes=0-3"}, {"If-Modified-Since": "Wed, 01 Jan 2031 00:00:00 GMT"}):
        response = beta.get("/beta/nothing-here", headers=headers)
        assert response.status_code == 404, headers
        assert response.data == NOT_FOUND


@pytest.mark.parametrize(
    "url",
    ["/beta/../secret.txt", "/beta/%2e%2e/secret.txt", "/beta/_next/static/../../../secret.txt", "/beta/..%2fsecret.txt"],
)
def test_nothing_outside_the_export_is_served(beta, url):
    response = beta.get(url)

    assert response.status_code == 404
    assert b"outside the export" not in response.data


def test_without_an_export_beta_is_a_plain_404(make_app, tmp_path):
    client = make_app({web_export.WEB_EXPORT_ROOT_KEY: str(tmp_path / "no-build")}).test_client()

    for url in ("/beta", "/beta/", "/beta/design", "/beta/_next/static/chunks/main.js"):
        response = client.get(url)
        assert response.status_code == 404, url
        assert b"<title>404 Not Found</title>" in response.data


def test_an_export_without_a_404_page_answers_a_plain_404(make_app, tmp_path):
    root = tmp_path / "out"
    _write(root / "index.html", INDEX)
    client = make_app({web_export.WEB_EXPORT_ROOT_KEY: str(root)}).test_client()

    assert client.get("/beta").status_code == 200
    response = client.get("/beta/missing")
    assert response.status_code == 404
    assert b"<title>404 Not Found</title>" in response.data


def test_beta_answers_carry_the_same_security_headers_as_the_current_ui(beta):
    legacy = beta.get("/")
    assert legacy.status_code == 200

    for url in ("/beta", "/beta/design", "/beta/_next/static/chunks/main-abc123.js", "/beta/nothing-here"):
        response = beta.get(url)
        for header in SECURITY_HEADERS:
            assert response.headers.get(header) == legacy.headers.get(header), (url, header)
    assert "'unsafe-inline'" not in legacy.headers["Content-Security-Policy"]


def test_the_current_ui_and_its_root_files_are_unchanged(beta):
    assert beta.get("/").status_code == 200
    assert beta.get("/favicon.ico").status_code == 200


def test_head_answers_without_a_body(beta):
    response = beta.head("/beta")

    assert response.status_code == 200
    assert response.data == b""
