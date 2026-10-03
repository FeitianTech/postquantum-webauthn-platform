"""A write to the API from another site, as the browser names it in ``Sec-Fetch-Site``, is refused."""
from __future__ import annotations

import io

import pytest

from server.app.config import fetch_metadata

WRITES = [
    ("POST", "/api/codec", lambda: {"json": {"mode": "decode", "payload": "a0"}}),
    ("POST", "/api/register/begin?email=user@example.com", lambda: {"json": {}}),
    ("PUT", "/api/advanced/credential-artifacts/cred-1", lambda: {"json": {"artifact": {"kept": True}}}),
    ("DELETE", "/api/mds/metadata/custom/0123456789abcdef.json", dict),
    ("POST", "/api/mds/metadata/upload", lambda: {"data": {"files": (io.BytesIO(b"{}"), "entry.json")}}),
]


@pytest.mark.parametrize("site", ["cross-site", "same-site", "Cross-Site"])
@pytest.mark.parametrize(("method", "path", "body"), WRITES)
def test_a_write_from_another_site_is_refused(client, method, path, body, site):
    response = client.open(path, method=method, headers={"Sec-Fetch-Site": site}, **body())

    assert response.status_code == 403
    assert response.get_json() == {"error": fetch_metadata.REFUSED}
    assert response.headers.getlist("Set-Cookie") == []


@pytest.mark.parametrize("site", ["same-origin", "none", None])
@pytest.mark.parametrize(("method", "path", "body"), WRITES)
def test_a_write_from_this_origin_from_no_page_or_from_no_browser_goes_through(client, method, path, body, site):
    headers = {"Sec-Fetch-Site": site} if site else {}

    response = client.open(path, method=method, headers=headers, **body())

    assert response.status_code != 403


@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", "/api/mds/metadata/info"), ("HEAD", "/api/mds/metadata/info"), ("POST", "/api/csp-report"), ("POST", "/")],
)
def test_reads_the_csp_reports_and_the_pages_are_not_checked(client, method, path):
    response = client.open(path, method=method, headers={"Sec-Fetch-Site": "cross-site"}, json={})

    assert response.status_code != 403
