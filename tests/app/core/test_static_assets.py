"""Versioned static asset serving and the build-time asset preparation tool."""

from __future__ import annotations

import gzip
import importlib.util
import json
import os
from pathlib import Path

import pytest

from server.app.config.web_export import WEB_EXPORT_ROOT_KEY
from server.app.mds import cache as mds_cache
from server.app.mds import files as mds_files
from tests.app.entry_app import entry_app

_REPO_ROOT = Path(__file__).resolve().parents[3]


_EXPLORER_FULL = "fido-mds3.explorer.full.json"


@pytest.fixture
def assets_env(monkeypatch, tmp_path):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    for name in (_EXPLORER_FULL, f"{_EXPLORER_FULL}.gz", "blob.jwt", "fido-mds3.verified.json", "scripts/main.js", "favicon.ico"):
        (snapshot / name).parent.mkdir(parents=True, exist_ok=True)
        (snapshot / name).write_text("{}", encoding="utf-8")
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(snapshot))
    return entry_app().test_client()


@pytest.mark.parametrize(
    "name",
    [
        "blob.jwt",
        "fido-mds3.verified.json",
        "fido-mds3.verified.json.meta.json",
        "fido-mds3.explorer.json",
        "fido-mds3.explorer.json.meta.json",
        "fido-mds3.explorer.full.json",
        "fido-mds3.explorer.full.json.meta.json",
        "fido-mds3.explorer.full.json.gz",
        "scripts/main.js",
        "favicon.ico",
        "../config.py",
        "sub/fido-mds3.explorer.full.json",
        "fido-mds3.explorer.full.json/",
    ],
)
def test_no_file_of_the_snapshot_directory_is_served(assets_env, name):
    # Browsers load only what the explorer's files derive from it.
    assert assets_env.get(f"/assets/mds/{name}").status_code == 404


@pytest.mark.parametrize("segment", ["0ldbu1ld", "dev"])
def test_no_other_segment_serves_the_list(assets_env, segment):
    assert assets_env.get(f"/assets/{segment}/fido-mds3.explorer.list.json").status_code == 404


def test_no_snapshot_file_is_served_at_the_site_root(make_app, export_root):
    # The site's root is the UI's export: a snapshot file there (or the .gz copy
    # earlier releases wrote beside the full one) is never served.
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


# The explorer's files derived from the snapshot (mds/explorer_files.py).


def _derived(client):
    with client.application.app_context():
        return mds_cache.load_explorer_files()


def test_the_explorer_list_is_one_url_revalidated_by_its_etag(mds_fixture_snapshot, client):
    files = _derived(client)

    with client.get("/assets/mds/fido-mds3.explorer.list.json", headers={"Accept-Encoding": "gzip"}) as listed:
        assert listed.status_code == 200
        assert listed.headers["Content-Encoding"] == "gzip"
        assert listed.headers["Cache-Control"] == "no-cache"
        assert "Accept-Encoding" in listed.headers["Vary"]
        assert listed.mimetype == "application/json"
        assert gzip.decompress(listed.data) == files.list_json
    with client.get(
        "/assets/mds/fido-mds3.explorer.list.json",
        headers={"Accept-Encoding": "gzip", "If-None-Match": listed.headers["ETag"]},
    ) as again:
        assert again.status_code == 304


def test_the_explorer_list_is_sent_whole_to_a_client_that_takes_no_gzip(mds_fixture_snapshot, client):
    with client.get("/assets/mds/fido-mds3.explorer.list.json", headers={"Accept-Encoding": "identity"}) as listed:
        assert listed.status_code == 200
        assert "Content-Encoding" not in listed.headers
        assert json.loads(listed.data)["meta"]["no"] == 7
        assert listed.headers["ETag"] != f'"{_derived(client).version}.gz"'


def test_an_icon_is_its_image_for_good_and_runs_nothing_when_opened(mds_fixture_snapshot, client):
    files = _derived(client)
    name, icon = next(iter(files.icons.items()))

    with client.get(f"/assets/mds/icons/{name}") as served:
        assert served.status_code == 200
        assert served.mimetype == "image/png"
        assert served.data == icon.data
        assert served.headers["Cache-Control"] == "public, max-age=31536000, immutable"
        assert served.headers["Content-Security-Policy"] == "default-src 'none'; style-src 'unsafe-inline'; sandbox"
    assert client.get("/assets/mds/icons/0000.png").status_code == 404


def test_an_entrys_detail_is_immutable_at_the_version_its_url_names(mds_fixture_snapshot, client):
    files = _derived(client)
    rows = {row["entryId"]: row for row in json.loads(files.list_json)["entries"]}
    url = rows["aaid:F1D0#0012"]["detailUrl"]

    with client.get(url) as detail:
        assert detail.status_code == 200
        assert detail.headers["Cache-Control"] == "public, max-age=31536000, immutable"
        assert json.loads(detail.data)["entryId"] == "aaid:F1D0#0012"
    with client.get(url.split("?")[0] + "?v=6.earlier") as earlier:
        assert earlier.status_code == 200
        assert earlier.headers["Cache-Control"] == "no-cache"
    assert client.get("/assets/mds/entries/aaguid%3A00000000-0000-0000-0000-000000000000").status_code == 404


def test_without_a_snapshot_there_is_no_explorer_file(metadata_state, monkeypatch, tmp_path, client):
    monkeypatch.setenv("FIDO_SERVER_MDS_SNAPSHOT_DIR", str(tmp_path))

    assert client.get("/assets/mds/fido-mds3.explorer.list.json").status_code == 404
