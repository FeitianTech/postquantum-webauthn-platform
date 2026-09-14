"""Versioned static asset serving and the build-time asset preparation tool."""

from __future__ import annotations

import gzip
import importlib.util
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def assets_env(monkeypatch, tmp_path):
    pytest.importorskip("server.app.app")
    static_assets = pytest.importorskip("server.app.static_assets")
    config = pytest.importorskip("server.app.config")

    static_root = tmp_path / "static"
    (static_root / "scripts").mkdir(parents=True)
    source = b"export const answer = 42;\n" * 200
    (static_root / "scripts" / "main.js").write_bytes(source)
    (static_root / "scripts" / "main.js.gz").write_bytes(gzip.compress(source))
    (static_root / "favicon.ico").write_bytes(b"\x00\x01ico")

    monkeypatch.setattr(static_assets, "_STATIC_ROOT", str(static_root))
    monkeypatch.setattr(static_assets, "BUILD_ID", "abc123def456")
    return static_assets, config.app.test_client(), source


def test_current_build_assets_are_immutable_and_precompressed(assets_env):
    _static_assets, client, source = assets_env

    response = client.get(
        "/assets/abc123def456/scripts/main.js", headers={"Accept-Encoding": "gzip, br"}
    )

    assert response.status_code == 200
    assert response.headers["Content-Encoding"] == "gzip"
    assert response.headers["Cache-Control"] == "public, max-age=31536000, immutable"
    assert "Accept-Encoding" in response.headers["Vary"]
    assert response.mimetype in {"text/javascript", "application/javascript"}
    assert response.headers.get("ETag")
    assert gzip.decompress(response.data) == source

    revalidated = client.get(
        "/assets/abc123def456/scripts/main.js",
        headers={"Accept-Encoding": "gzip", "If-None-Match": response.headers["ETag"]},
    )
    assert revalidated.status_code == 304


def test_identity_encoding_when_gzip_not_accepted(assets_env):
    _static_assets, client, source = assets_env

    response = client.get("/assets/abc123def456/scripts/main.js", headers={"Accept-Encoding": "identity"})

    assert response.status_code == 200
    assert response.headers.get("Content-Encoding") is None
    assert response.data == source


def test_other_build_ids_must_revalidate(assets_env):
    _static_assets, client, _source = assets_env

    response = client.get("/assets/0ldbu1ld/favicon.ico")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-cache"


def test_asset_route_rejects_traversal_and_missing_files(assets_env):
    _static_assets, client, _source = assets_env

    assert client.get("/assets/abc123def456/../config.py").status_code == 404
    assert client.get("/assets/abc123def456/scripts/missing.js").status_code == 404


def test_private_mds_source_files_are_not_served(assets_env):
    _static_assets, client, _source = assets_env

    for name in ("blob.jwt", "fido-mds3.verified.json", "fido-mds3.explorer.json"):
        assert client.get(f"/{name}").status_code == 404
        assert client.get(f"/assets/abc123def456/{name}").status_code == 404


def test_asset_url_uses_build_id(assets_env):
    static_assets, _client, _source = assets_env

    assert static_assets.asset_url("/scripts/main.js") == "/assets/abc123def456/scripts/main.js"


def _load_build_tool():
    spec = importlib.util.spec_from_file_location(
        "build_static_assets", _REPO_ROOT / "tools" / "build_static_assets.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_tool_writes_build_id_and_gzip_variants(tmp_path):
    tool = _load_build_tool()
    static_root = tmp_path / "frontend" / "static"
    static_root.mkdir(parents=True)
    (static_root / "app.js").write_text("console.log('x');\n" * 200, encoding="utf-8")
    (static_root / "tiny.css").write_text("a{}", encoding="utf-8")
    (static_root / "blob.jwt").write_text("x" * 5000, encoding="utf-8")

    first_id = tool.compute_build_id(static_root)
    assert tool.main(["build_static_assets.py", str(static_root)]) == 0

    assert (tmp_path / "frontend" / "BUILD_ID").read_text(encoding="utf-8").strip() == first_id
    assert (static_root / "app.js.gz").exists()
    assert not (static_root / "tiny.css.gz").exists()
    assert not (static_root / "blob.jwt.gz").exists()
    # Generated .gz files do not change the build id.
    assert tool.compute_build_id(static_root) == first_id

    (static_root / "app.js").write_text("console.log('changed');\n", encoding="utf-8")
    assert tool.compute_build_id(static_root) != first_id
