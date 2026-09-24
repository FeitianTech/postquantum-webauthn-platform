"""A credential listing reads the session's folder and the flat legacy copies, nothing else.

The flat legacy copies (``user-data/<name>_credential_data.json``) sit directly
under the user folder, beside every session's folder. The legacy pass used to
list everything under ``user-data/`` -- every session's credentials, artifacts
and metadata -- and throw away the nested names; it now lists only that level.
"""
from __future__ import annotations

import pytest

from server.app.storage import record_format

from . import fake_gcs

SESSIONS = ("s1", "s2", "s3")


@pytest.fixture
def bucket(monkeypatch, storage_module):
    monkeypatch.delenv("FIDO_SERVER_GCS_ENABLED", raising=False)
    bucket = fake_gcs.install(monkeypatch, storage_module)
    for session in SESSIONS:
        bucket.put(storage_module._credential_blob(f"user-{session}", session), record_format.encode_records([session]))
        bucket.put(f"user-data/{session}/credential-artifacts/0123abcd.json", b"{}")
        bucket.put(f"user-data/{session}/metadata/metadata.json", b"{}")
        bucket.put(f"user-data/{session}/.last-access", b"")
    # A flat legacy copy, one shadowed by s1's current copy, and a stray nested one.
    bucket.put(storage_module._legacy_credential_blob("legacy-user"), record_format.encode_records(["flat"]))
    bucket.put(storage_module._legacy_credential_blob("user-s1"), record_format.encode_records(["stale"]))
    return bucket


def test_the_legacy_pass_lists_only_the_objects_directly_under_the_user_folder(bucket, storage_module):
    listed = []
    real_list_blobs = bucket.list_blobs

    def _recording(prefix="", max_results=None, delimiter=None):
        listing = real_list_blobs(prefix, max_results, delimiter)
        listed.extend(blob.name for blob in listing._blobs)
        return listing

    bucket.list_blobs = _recording

    users = dict(storage_module.iter_credentials(session_id="s1"))

    assert bucket.list_calls == [("user-data/s1/credentials/", None), ("user-data/", "/")]
    # Nothing of s2's or s3's, and none of s1's artifacts or metadata, was handed back.
    assert all(name.count("/") == 1 or name.startswith("user-data/s1/credentials/") for name in listed), listed
    assert sorted(listed) == [
        "user-data/legacy-user_credential_data.json",
        "user-data/s1/credentials/user-s1_credential_data.json",
        "user-data/user-s1_credential_data.json",
    ]
    # The first copy that exists is the user's: s1's current copy, not the flat one.
    assert users == {"user-s1": ["s1"], "legacy-user": ["flat"]}
