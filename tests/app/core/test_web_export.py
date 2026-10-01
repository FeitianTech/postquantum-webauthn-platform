"""The site's pages are the UI's static export, served at ``/``
(``routes/web_export.py``); ``/beta``, which old links still name,
redirects there.

Every test builds its own export in ``tmp_path`` (the ``export_root`` fixture):
pytest never needs Node, and never reads a ``web/out`` a local build (or Cloud
Build's web step, running beside the Python tests) may be writing.
"""
from __future__ import annotations

import gzip

import pytest

from server.app.config import paths, web_export
from tests.app.web_export_files import CHUNK, INDEX, NOT_FOUND, write

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


@pytest.fixture
def site(make_app, export_root):
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
    response = make_app().test_client().get("/")

    assert response.status_code == 200
    assert b"index page" in response.data


@pytest.mark.parametrize("url", ["/", "/index.html"])
def test_the_site_answers_the_index_page(site, url):
    response = site.get(url)

    assert response.status_code == 200
    assert response.mimetype == "text/html"
    assert response.data == INDEX
    assert response.headers["Cache-Control"] == "no-cache"


def test_html_is_revalidated_with_its_etag(site):
    first = site.get("/")
    again = site.get("/", headers={"If-None-Match": first.headers["ETag"]})

    assert first.headers["ETag"]
    assert again.status_code == 304
    assert again.headers["Cache-Control"] == "no-cache"


def test_html_is_gzipped_for_a_client_that_takes_it(site):
    response = site.get("/", headers={"Accept-Encoding": "gzip"})

    assert response.headers["Content-Encoding"] == "gzip"
    assert gzip.decompress(response.data) == INDEX


def test_hashed_assets_are_immutable_for_a_year_and_precompressed(site):
    url = "/_next/static/chunks/main-abc123.js"
    zipped = site.get(url, headers={"Accept-Encoding": "gzip, br"})
    plain = site.get(url)
    again = site.get(url, headers={"If-None-Match": plain.headers["ETag"]})

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


def test_a_font_under_next_static_is_immutable_too(site):
    response = site.get("/_next/static/media/geist.woff2")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == IMMUTABLE
    assert response.data == b"wOF2font"


def test_a_file_at_the_export_root_is_served_and_revalidated(site, export_root):
    write(export_root / "favicon.ico", b"\x00\x01ico")
    response = site.get("/favicon.ico")

    assert response.status_code == 200
    assert response.data == b"\x00\x01ico"
    assert response.headers["Cache-Control"] == "no-cache"


@pytest.mark.parametrize(
    "url",
    ["/nothing-here", "/_next/static/chunks/missing.js", "/index", "/404", "/404.html", "/500.html", "/scripts/main.js"],
)
def test_an_unknown_path_answers_the_export_404_page(site, url):
    response = site.get(url)

    assert response.status_code == 404
    assert response.data == NOT_FOUND
    assert response.headers["Cache-Control"] == "no-cache"


@pytest.mark.parametrize("url", ["/api", "/api/", "/api/nothing-here", "/api/mds/nothing-here"])
def test_an_unknown_api_path_answers_a_plain_404(site, url):
    response = site.get(url)

    assert response.status_code == 404
    assert response.data != NOT_FOUND
    assert b"<title>404 Not Found</title>" in response.data


def test_a_404_is_never_a_304_or_a_range(site):
    for headers in ({"If-None-Match": "*"}, {"Range": "bytes=0-3"}, {"If-Modified-Since": "Wed, 01 Jan 2031 00:00:00 GMT"}):
        response = site.get("/nothing-here", headers=headers)
        assert response.status_code == 404, headers
        assert response.data == NOT_FOUND


@pytest.mark.parametrize(
    "url",
    ["/../secret.txt", "/%2e%2e/secret.txt", "/_next/static/../../../secret.txt", "/..%2fsecret.txt"],
)
def test_nothing_outside_the_export_is_served(site, url):
    response = site.get(url)

    assert response.status_code == 404
    assert b"outside the export" not in response.data


def test_without_an_export_every_page_is_a_plain_404(make_app, tmp_path):
    client = make_app({web_export.WEB_EXPORT_ROOT_KEY: str(tmp_path / "no-build")}).test_client()

    for url in ("/", "/index.html", "/_next/static/chunks/main.js"):
        response = client.get(url)
        assert response.status_code == 404, url
        assert b"<title>404 Not Found</title>" in response.data
    assert client.get("/health").status_code == 200


def test_an_export_without_a_404_page_answers_a_plain_404(make_app, tmp_path):
    root = tmp_path / "out"
    write(root / "index.html", INDEX)
    client = make_app({web_export.WEB_EXPORT_ROOT_KEY: str(root)}).test_client()

    assert client.get("/").status_code == 200
    response = client.get("/missing")
    assert response.status_code == 404
    assert b"<title>404 Not Found</title>" in response.data


def test_the_pages_carry_the_security_headers_of_every_answer(site):
    api = site.get("/health")

    for url in ("/", "/index.html", "/_next/static/chunks/main-abc123.js", "/nothing-here", "/beta"):
        response = site.get(url)
        for header in SECURITY_HEADERS:
            assert response.headers.get(header) == api.headers.get(header), (url, header)
    assert "'unsafe-inline'" not in api.headers["Content-Security-Policy"]


def test_head_answers_without_a_body(site):
    response = site.head("/")

    assert response.status_code == 200
    assert response.data == b""


def test_a_method_the_site_does_not_take_is_refused_as_before(site):
    assert site.post("/").status_code == 405
    assert site.post("/index.html").status_code == 405
    assert site.post("/api/nothing-here").status_code == 405


def test_every_other_rule_still_answers_for_itself(site):
    """The page rule is the catch-all: no rule with a path of its own falls to it."""

    adapter = site.application.url_map.bind("localhost")
    for rule in site.application.url_map.iter_rules():
        if rule.endpoint == "web_export.page" or "GET" not in rule.methods:
            continue
        path = rule.rule.replace("<build_id>", "abc").replace("<path:filename>", "x.js").replace("<path:subpath>", "x")
        path = path.replace("<", "").replace(">", "")
        endpoint, _ = adapter.match(path, method="GET")
        assert endpoint == rule.endpoint, rule.rule


# -- /beta, which old links still name ------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "location"),
    [
        ("/beta", "/"),
        ("/beta/", "/"),
        ("/beta/favicon.ico", "/favicon.ico"),
        ("/beta/index.html", "/index.html"),
        ("/beta/_next/static/chunks/main-abc123.js", "/_next/static/chunks/main-abc123.js"),
        ("/beta/no-such-page", "/no-such-page"),
        ("/beta?x=1&y=%20z", "/?x=1&y=%20z"),
        ("/beta/favicon.ico?q=%E2%9C%93", "/favicon.ico?q=%E2%9C%93"),
        ("/beta/a%20b", "/a%20b"),
    ],
)
def test_beta_redirects_permanently_to_the_same_path_at_the_root(site, url, location):
    response = site.get(url)

    assert response.status_code == 308
    assert response.headers["Location"] == location
    # Revalidated, so a browser does not hold the redirect past a rollback.
    assert response.headers["Cache-Control"] == "no-cache"


@pytest.mark.parametrize(
    "url",
    ["/beta/%09/evil.example", "/beta/%5Cevil.example", "/beta/%5C%5Cevil.example", "/beta//evil.example", "/beta/%2F%2Fevil.example"],
)
def test_beta_never_redirects_to_another_origin(site, url):
    response = site.get(url)

    location = response.headers.get("Location", "/")
    assert location.startswith("/"), location
    assert not location.startswith("//"), location
    assert "\\" not in location and "\t" not in location, location


def test_beta_redirects_a_head_and_a_post_alike(site):
    assert site.head("/beta/favicon.ico").headers["Location"] == "/favicon.ico"
    assert site.post("/beta/favicon.ico").status_code == 405
