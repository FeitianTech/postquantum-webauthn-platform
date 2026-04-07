from __future__ import annotations

import types
import zlib

import pytest

from fido2 import cbor
import fido2.ctap2.blob as blob


class _FakeCtap:
    def __init__(self, *, options=None, max_msg_size=80):
        self.info = types.SimpleNamespace(
            options=options if options is not None else {"largeBlobs": True},
            max_msg_size=max_msg_size,
        )
        self.get_fragments = {}
        self.set_calls = []

    def large_blobs(
        self,
        offset,
        get=None,
        set=None,
        length=None,
        pin_uv_protocol=None,
        pin_uv_param=None,
    ):
        if get is not None:
            return {1: self.get_fragments[offset]}

        self.set_calls.append(
            {
                "offset": offset,
                "set": set,
                "length": length,
                "pin_uv_protocol": pin_uv_protocol,
                "pin_uv_param": pin_uv_param,
            }
        )
        return {}


class _FakeProtocol:
    VERSION = 2

    def __init__(self):
        self.calls = []

    def authenticate(self, token, message):
        self.calls.append((token, message))
        return b"auth-mac"


def _prepare_fragments(ctap, entries):
    payload = cbor.encode(entries)
    full = payload + blob.sha256(payload)[:16]
    frag_size = ctap.info.max_msg_size - 64
    ctap.get_fragments = {
        offset: full[offset : offset + frag_size]
        for offset in range(0, len(full), frag_size)
    }


def test_blob_helper_roundtrip_and_error_paths():
    data = b"hello large blob"
    compressed = blob._compress(data)
    assert blob._decompress(compressed) == data

    assert blob._lb_ad(7) == b"blob\x07\x00\x00\x00\x00\x00\x00\x00"

    key = b"K" * 16
    entry = blob._lb_pack(key, data)
    unpacked_compressed, orig_size = blob._lb_unpack(key, entry)
    assert blob._decompress(unpacked_compressed) == data
    assert orig_size == len(data)

    with pytest.raises(ValueError, match="Invalid entry"):
        blob._lb_unpack(key, {1: b"only-ciphertext"})

    with pytest.raises(ValueError, match="Wrong key"):
        blob._lb_unpack(b"Z" * 16, entry)


def test_large_blobs_init_support_checks_and_pin_configuration():
    unsupported = _FakeCtap(options={"largeBlobs": False})
    with pytest.raises(ValueError, match="does not support LargeBlobs"):
        blob.LargeBlobs(unsupported)

    supported = _FakeCtap()
    manager = blob.LargeBlobs(supported)
    assert manager.max_fragment_length == supported.info.max_msg_size - 64
    assert manager.pin_uv is None

    protocol = _FakeProtocol()
    manager_with_pin = blob.LargeBlobs(supported, protocol, b"token")
    assert manager_with_pin.pin_uv is not None
    assert manager_with_pin.pin_uv.protocol is protocol
    assert manager_with_pin.pin_uv.token == b"token"


def test_read_blob_array_handles_fragmented_data_and_checksum_mismatch():
    ctap = _FakeCtap(max_msg_size=70)  # fragment length = 6
    manager = blob.LargeBlobs(ctap)

    entries = [{1: b"abc"}, {2: b"def"}]
    _prepare_fragments(ctap, entries)

    decoded = manager.read_blob_array()
    assert decoded == entries

    # Corrupt checksum by replacing tail fragment bytes.
    all_offsets = sorted(ctap.get_fragments)
    last_offset = all_offsets[-1]
    ctap.get_fragments[last_offset] = b"X" * len(ctap.get_fragments[last_offset])
    assert manager.read_blob_array() == []


def test_write_blob_array_validates_type_and_writes_fragments_with_and_without_pin():
    ctap = _FakeCtap(max_msg_size=72)  # fragment length = 8
    manager = blob.LargeBlobs(ctap)

    with pytest.raises(TypeError, match="must be a list"):
        manager.write_blob_array(tuple())

    payload = [{1: b"v1"}, {2: b"v2"}]
    manager.write_blob_array(payload)

    assert ctap.set_calls
    assert ctap.set_calls[0]["offset"] == 0
    assert ctap.set_calls[0]["length"] is not None
    assert all(call["pin_uv_protocol"] is None for call in ctap.set_calls)
    assert all(call["pin_uv_param"] is None for call in ctap.set_calls)

    ctap_with_pin = _FakeCtap(max_msg_size=72)
    protocol = _FakeProtocol()
    manager_with_pin = blob.LargeBlobs(ctap_with_pin, protocol, b"pin-token")
    manager_with_pin.write_blob_array(payload)

    assert protocol.calls
    assert all(call["pin_uv_protocol"] == protocol.VERSION for call in ctap_with_pin.set_calls)
    assert all(call["pin_uv_param"] == b"auth-mac" for call in ctap_with_pin.set_calls)


def test_get_blob_returns_first_valid_entry_and_handles_decode_errors(monkeypatch):
    key = b"K" * 16
    good = blob._lb_pack(key, b"payload")

    manager = blob.LargeBlobs(_FakeCtap())
    monkeypatch.setattr(manager, "read_blob_array", lambda: [{1: b"bad"}, good])

    assert manager.get_blob(key) == b"payload"

    bad_size = dict(good)
    bad_size[3] = good[3] + 10
    monkeypatch.setattr(manager, "read_blob_array", lambda: [bad_size, good])
    assert manager.get_blob(key) == b"payload"

    monkeypatch.setattr(manager, "read_blob_array", lambda: [bad_size])
    assert manager.get_blob(key) is None

    monkeypatch.setattr(blob, "_decompress", lambda _value: (_ for _ in ()).throw(zlib.error("bad zlib")))
    monkeypatch.setattr(manager, "read_blob_array", lambda: [good])
    assert manager.get_blob(key) is None


def test_get_blob_continues_when_size_does_not_match(monkeypatch):
    key = b"K" * 16
    entries = [{"first": True}, {"second": True}]
    manager = blob.LargeBlobs(_FakeCtap())

    monkeypatch.setattr(manager, "read_blob_array", lambda: entries)

    def _fake_unpack(_key, entry):
        if entry is entries[0]:
            return (b"a", 2)  # decompressed len 1, orig_size 2 -> mismatch branch
        return (b"bb", 2)

    monkeypatch.setattr(blob, "_lb_unpack", _fake_unpack)
    monkeypatch.setattr(blob, "_decompress", lambda value: value)

    assert manager.get_blob(key) == b"bb"


def test_put_blob_replaces_or_deletes_entries_and_delete_blob_delegates(monkeypatch):
    key = b"A" * 16
    other_key = b"B" * 16

    existing_for_key = blob._lb_pack(key, b"old")
    existing_other = blob._lb_pack(other_key, b"other")

    manager = blob.LargeBlobs(_FakeCtap())
    writes = []

    monkeypatch.setattr(manager, "read_blob_array", lambda: [existing_for_key, existing_other])
    monkeypatch.setattr(manager, "write_blob_array", lambda entries: writes.append(entries))

    manager.put_blob(key, b"new")
    assert len(writes) == 1
    written_entries = writes[0]
    assert len(written_entries) == 2

    def _can_unpack_with(target_key, entry):
        try:
            blob._lb_unpack(target_key, entry)
            return True
        except ValueError:
            return False

    def _unpacked_payload_equals(target_key, entry, expected):
        try:
            compressed, _size = blob._lb_unpack(target_key, entry)
        except ValueError:
            return False
        return blob._decompress(compressed) == expected

    assert any(_can_unpack_with(other_key, entry) for entry in written_entries)
    assert any(
        _unpacked_payload_equals(key, entry, b"new") for entry in written_entries
    )

    writes.clear()
    manager.put_blob(key, None)
    assert len(writes) == 1
    remaining_entries = writes[0]
    assert len(remaining_entries) == 1
    assert blob._decompress(blob._lb_unpack(other_key, remaining_entries[0])[0]) == b"other"

    writes.clear()
    monkeypatch.setattr(manager, "read_blob_array", lambda: [existing_other])
    manager.put_blob(key, None)
    assert writes == []

    delegated = []
    monkeypatch.setattr(manager, "put_blob", lambda k, data: delegated.append((k, data)))
    manager.delete_blob(key)
    assert delegated == [(key, None)]
