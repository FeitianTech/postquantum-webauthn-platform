"""Versioned static asset serving and the build-time asset preparation tool."""

from __future__ import annotations

import gzip
import importlib.util
import os
from pathlib import Path

import pytest

from server.app.mds import cache as mds_cache
from server.app.routes import assets
from tests.app.entry_app import entry_app

_REPO_ROOT = Path(__file__).resolve().parents[3]


_EXPLORER_FULL = "fido-mds3.explorer.full.json"
# What the explorer's meta names (the version) and what the file holds.
_META = {"no": 7, "etag": '"fixture-7"', "generatedAt": "2026-09-27T07:00:00+00:00"}
_BODY = b'{"entries": [], "meta": {"no": 7}}' * 64


@pytest.fixture
def assets_env(monkeypatch, tmp_path):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / _EXPLORER_FULL).write_bytes(_BODY)
    (snapshot / f"{_EXPLORER_FULL}.gz").write_bytes(gzip.compress(_BODY))
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(snapshot))
    monkeypatch.setattr(mds_cache, "load_packaged_snapshot_meta", lambda: dict(_META))
    version = assets.snapshot_version(_META)
    return entry_app().test_client(), version


def test_the_current_snapshot_is_immutable_and_precompressed(assets_env):
    client, version = assets_env

    with client.get(f"/assets/mds/{_EXPLORER_FULL}?v={version}", headers={"Accept-Encoding": "gzip, br"}) as response:
        assert response.status_code == 200
        assert response.headers["Content-Encoding"] == "gzip"
        assert response.headers["Cache-Control"] == "public, max-age=31536000, immutable"
        assert "Accept-Encoding" in response.headers["Vary"]
        assert response.mimetype == "application/json"
        assert response.headers.get("ETag")
        assert gzip.decompress(response.data) == _BODY

    with client.get(
        f"/assets/mds/{_EXPLORER_FULL}?v={version}",
        headers={"Accept-Encoding": "gzip", "If-None-Match": response.headers["ETag"]},
    ) as revalidated:
        assert revalidated.status_code == 304


def test_identity_encoding_when_gzip_not_accepted(assets_env):
    client, version = assets_env

    with client.get(f"/assets/mds/{_EXPLORER_FULL}?v={version}", headers={"Accept-Encoding": "identity"}) as response:
        assert response.status_code == 200
        assert response.headers.get("Content-Encoding") is None
        assert response.data == _BODY


@pytest.mark.parametrize("query", ["", "?v=6.000000000000", "?v="])
def test_another_version_or_none_must_revalidate(assets_env, query):
    client, _version = assets_env

    with client.get(f"/assets/mds/{_EXPLORER_FULL}{query}") as response:
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-cache"


@pytest.mark.parametrize("segment", ["0ldbu1ld", "dev"])
def test_no_other_segment_serves_the_snapshot(assets_env, segment):
    client, version = assets_env

    assert client.get(f"/assets/{segment}/{_EXPLORER_FULL}?v={version}").status_code == 404


def test_without_a_snapshot_meta_nothing_is_immutable(assets_env, monkeypatch):
    client, version = assets_env
    monkeypatch.setattr(mds_cache, "load_packaged_snapshot_meta", lambda: None)

    with client.get(f"/assets/mds/{_EXPLORER_FULL}?v={version}") as response:
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-cache"


@pytest.mark.parametrize(
    "name",
    [
        "blob.jwt",
        "fido-mds3.verified.json",
        "fido-mds3.verified.json.meta.json",
        "fido-mds3.explorer.json",
        "fido-mds3.explorer.json.meta.json",
        "fido-mds3.explorer.full.json.meta.json",
        "fido-mds3.explorer.full.json.gz",
        "scripts/main.js",
        "favicon.ico",
        "../config.py",
        "sub/fido-mds3.explorer.full.json",
        "fido-mds3.explorer.full.json/",
    ],
)
def test_the_route_refuses_every_other_name(assets_env, name):
    client, _version = assets_env
    snapshot = Path(os.environ["FIDO_SERVER_MDS_SNAPSHOT_DIR"])
    for other in ("blob.jwt", "fido-mds3.verified.json", "scripts/main.js", "favicon.ico"):
        (snapshot / other).parent.mkdir(parents=True, exist_ok=True)
        (snapshot / other).write_text("{}", encoding="utf-8")

    assert client.get(f"/assets/mds/{name}").status_code == 404


def test_a_missing_snapshot_is_not_found(assets_env, monkeypatch, tmp_path):
    client, version = assets_env
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(tmp_path / "empty"))

    assert client.get(f"/assets/mds/{_EXPLORER_FULL}?v={version}").status_code == 404


def test_no_snapshot_file_is_served_at_the_site_root(assets_env, monkeypatch, tmp_path, make_app, export_root):
    from server.app.config.web_export import WEB_EXPORT_ROOT_KEY
    from server.app.mds import files as mds_files

    # The site's root is the UI's export: a snapshot file there is never served.
    names = [*mds_files.SNAPSHOT_FILENAMES, f"{_EXPLORER_FULL}.gz"]
    for name in names:
        (export_root / name).write_text("{}", encoding="utf-8")
    (export_root / "favicon.ico").write_bytes(b"\x00\x01ico")
    client = make_app({WEB_EXPORT_ROOT_KEY: str(export_root)}).test_client()

    with client.get("/favicon.ico") as other:
        assert other.status_code == 200
    for name in names:
        with client.get(f"/{name}") as root:
            assert root.status_code == 404, name


def test_asset_url_has_a_fixed_segment_and_the_version_names_the_snapshot(assets_env):
    _client, version = assets_env

    assert assets.asset_url("/fido-mds3.explorer.full.json") == "/assets/mds/fido-mds3.explorer.full.json"
    assert assets.snapshot_version(None) is None
    assert version.startswith("7.")
    assert len(version.split(".")[1]) == 12
    assert assets.snapshot_version({**_META, "etag": '"fixture-8"'}) != version


def _load_build_tool():
    spec = importlib.util.spec_from_file_location(
        "build_static_assets", _REPO_ROOT / "tools" / "build_static_assets.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_tool_precompresses_the_web_export(tmp_path, capsys):
    tool = _load_build_tool()
    export = tmp_path / "web" / "out"
    (export / "_next" / "static" / "chunks").mkdir(parents=True)
    (export / "_next" / "static" / "chunks" / "main-abc.js").write_text("console.log('x');\n" * 200, encoding="utf-8")
    (export / "index.html").write_text("<p>page</p>" * 200, encoding="utf-8")
    (export / "tiny.css").write_text("a{}", encoding="utf-8")
    (export / "noise.json").write_bytes(os.urandom(4096))
    (export / "font.woff2").write_bytes(b"wOF2" * 500)

    assert tool.main(["build_static_assets.py", str(export)]) == 0

    assert gzip.decompress((export / "index.html.gz").read_bytes()) == (export / "index.html").read_bytes()
    assert (export / "_next" / "static" / "chunks" / "main-abc.js.gz").exists()
    assert not (export / "tiny.css.gz").exists()
    assert not (export / "noise.json.gz").exists()
    assert not (export / "font.woff2.gz").exists()
    assert "Precompressed 2 files under" in capsys.readouterr().out

    # A second run reads the .gz copies as nothing new.
    assert tool.main(["build_static_assets.py", str(export)]) == 0
    assert not (export / "index.html.gz.gz").exists()


def test_build_tool_names_its_one_argument(capsys):
    tool = _load_build_tool()

    assert tool.main(["build_static_assets.py"]) == 2
    assert "usage: build_static_assets.py DIR" in capsys.readouterr().err
