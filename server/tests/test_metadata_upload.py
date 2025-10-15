import io
import json
import pathlib
import sys
from typing import List

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
SERVER_SRC = PROJECT_ROOT / "server"
if str(SERVER_SRC) not in sys.path:
    sys.path.insert(0, str(SERVER_SRC))

from server import config, metadata  # type: ignore  # noqa: E402
from server.app import app  # type: ignore  # noqa: E402

_MDS_SAMPLE_PATH = SERVER_SRC / "server" / "static" / "fido-mds3.verified.json"


@pytest.fixture
def session_client(tmp_path, monkeypatch):
    session_dir = tmp_path / "session-metadata"
    monkeypatch.setattr(metadata, "SESSION_METADATA_DIR", str(session_dir))
    monkeypatch.setattr(config, "SESSION_METADATA_DIR", str(session_dir))
    app.config.update(TESTING=True)

    with app.test_client() as test_client:
        yield test_client


def test_expand_metadata_entry_payloads_propagates_legal_header():
    payload = {
        "legalHeader": "Example legal header",
        "entries": [
            {"aaguid": "123", "statusReports": []},
            {"aaguid": "456", "statusReports": []},
        ],
    }

    expanded = metadata.expand_metadata_entry_payloads(payload)
    assert len(expanded) == 2
    assert all(entry["legalHeader"] == "Example legal header" for entry in expanded)


def test_uploading_multi_entry_json_creates_individual_metadata(session_client):
    with _MDS_SAMPLE_PATH.open("r", encoding="utf-8") as sample_file:
        sample_blob = json.load(sample_file)

    payload = {
        "legalHeader": sample_blob.get("legalHeader", ""),
        "entries": sample_blob["entries"][:2],
    }

    body = json.dumps(payload).encode("utf-8")
    response = session_client.post(
        "/api/mds/metadata/upload",
        data={"files": (io.BytesIO(body), "multi.json")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    result = response.get_json()
    assert result is not None
    items: List[dict] = result["items"]
    assert len(items) == 2
    assert result.get("errors") is None

    filenames = [item["source"]["originalFilename"] for item in items]
    assert filenames == ["multi.json (entry 1)", "multi.json (entry 2)"]

    with session_client.session_transaction() as flask_session:
        session_id = flask_session[metadata._SESSION_METADATA_SESSION_KEY]  # pylint: disable=protected-access

    stored = list(metadata.list_session_metadata_items(session_id=session_id))
    assert len(stored) == 2
