from __future__ import annotations

import importlib.util
import struct
import sys
import types
from pathlib import Path
from threading import Event

import pytest

from fido2.ctap import CtapError
from fido2.hid.base import HidDescriptor


hid = pytest.importorskip("fido2.hid")


class _Conn:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.writes = []
        self.closed = False

    def write_packet(self, data):
        self.writes.append(data)

    def read_packet(self):
        if not self.responses:
            raise AssertionError("No response packets available")
        return self.responses.pop(0)

    def close(self):
        self.closed = True


def _init_response(nonce: bytes, channel=0x01020304, proto=2, v1=1, v2=2, v3=3, caps=0):
    return nonce + struct.pack(">IBBBBB", channel, proto, v1, v2, v3, caps)


def _packet(channel: int, cmd: int, payload: bytes, packet_size: int):
    return (struct.pack(">IBH", channel, hid.TYPE_INIT | cmd, len(payload)) + payload).ljust(
        packet_size, b"\x00"
    )


def _load_hid_module_for_platform(monkeypatch, platform: str, backend_name: str):
    init_path = Path(__file__).resolve().parents[2] / "fido2" / "hid" / "__init__.py"
    module_name = f"fido2.hid._platform_branch_{platform}"
    backend_mod_name = f"fido2.hid.{backend_name}"

    backend = types.ModuleType(backend_mod_name)
    backend.list_descriptors = lambda: []
    backend.get_descriptor = lambda path: path
    backend.open_connection = lambda descriptor: descriptor

    monkeypatch.setitem(sys.modules, backend_mod_name, backend)
    monkeypatch.setattr(sys, "platform", platform)

    spec = importlib.util.spec_from_file_location(module_name, init_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "fido2.hid"
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module


def test_ctaphid_init_success_and_properties(monkeypatch):
    descriptor = HidDescriptor("/dev/fake", 1, 2, 64, 64, "Prod", "Serial")
    conn = _Conn()
    nonce = b"12345678"

    monkeypatch.setattr(hid.os, "urandom", lambda n: nonce)
    monkeypatch.setattr(
        hid.CtapHidDevice,
        "call",
        lambda self, cmd, data=b"", event=None, on_keepalive=None: _init_response(
            nonce, caps=int(hid.CAPABILITY.CBOR | hid.CAPABILITY.WINK)
        ),
    )

    device = hid.CtapHidDevice(descriptor, conn)

    assert repr(device) == "CtapHidDevice('/dev/fake')"
    assert device.version == 2
    assert device.device_version == (1, 2, 3)
    assert device.capabilities == int(hid.CAPABILITY.CBOR | hid.CAPABILITY.WINK)
    assert device.product_name == "Prod"
    assert device.serial_number == "Serial"


def test_ctaphid_init_rejects_wrong_nonce(monkeypatch):
    descriptor = HidDescriptor("/dev/fake", 1, 2, 64, 64, "Prod", "Serial")
    conn = _Conn()
    nonce = b"abcdefgh"

    monkeypatch.setattr(hid.os, "urandom", lambda n: nonce)
    monkeypatch.setattr(
        hid.CtapHidDevice,
        "call",
        lambda self, cmd, data=b"", event=None, on_keepalive=None: _init_response(b"wrong!!!"),
    )

    with pytest.raises(hid.ConnectionFailure, match="Wrong nonce"):
        hid.CtapHidDevice(descriptor, conn)


def test_call_propagates_non_busy_ctap_errors(monkeypatch):
    device = object.__new__(hid.CtapHidDevice)
    monkeypatch.setattr(
        device,
        "_do_call",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(CtapError(CtapError.ERR.INVALID_PARAMETER)),
    )

    with pytest.raises(CtapError) as exc_info:
        device.call(hid.CTAPHID.PING, b"x")

    assert exc_info.value.code == CtapError.ERR.INVALID_PARAMETER


def test_do_call_invalid_response_command_maps_to_invalid_command_error():
    channel = 0xAABBCCDD
    conn = _Conn(responses=[_packet(channel, hid.CTAPHID.WINK, b"", 16)])
    device = object.__new__(hid.CtapHidDevice)
    device._channel_id = channel
    device._packet_size = 16
    device._connection = conn

    with pytest.raises(CtapError) as exc_info:
        device._do_call(hid.CTAPHID.PING, b"", Event(), None)

    assert exc_info.value.code == CtapError.ERR.INVALID_COMMAND


def test_wink_ping_lock_and_close_delegate_to_connection(monkeypatch):
    conn = _Conn()
    device = object.__new__(hid.CtapHidDevice)
    device._connection = conn

    calls = []
    monkeypatch.setattr(device, "call", lambda cmd, data=b"", event=None, on_keepalive=None: calls.append((cmd, data)) or b"pong")

    assert device.wink() is None
    assert device.ping(b"hello") == b"pong"
    assert device.lock(7) is None
    device.close()

    assert calls[0] == (hid.CTAPHID.WINK, b"")
    assert calls[1] == (hid.CTAPHID.PING, b"hello")
    assert calls[2] == (hid.CTAPHID.LOCK, struct.pack(">B", 7))
    assert conn.closed is True


def test_module_level_list_devices_delegates_to_class(monkeypatch):
    monkeypatch.setattr(hid.CtapHidDevice, "list_devices", classmethod(lambda cls: iter(["d1", "d2"])))
    assert list(hid.list_devices()) == ["d1", "d2"]


def test_platform_branch_selects_expected_backend_modules(monkeypatch):
    mapping = {
        "linux": "linux",
        "win32": "windows",
        "freebsd": "freebsd",
        "netbsd": "netbsd",
        "openbsd": "openbsd",
    }

    for platform, backend_name in mapping.items():
        module = _load_hid_module_for_platform(monkeypatch, platform, backend_name)
        assert module.backend.__name__ == f"fido2.hid.{backend_name}"


def test_platform_branch_raises_for_unsupported_platform(monkeypatch):
    init_path = Path(__file__).resolve().parents[2] / "fido2" / "hid" / "__init__.py"
    module_name = "fido2.hid._platform_branch_unsupported"

    monkeypatch.setattr(sys, "platform", "plan9")

    spec = importlib.util.spec_from_file_location(module_name, init_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "fido2.hid"
    monkeypatch.setitem(sys.modules, module_name, module)

    with pytest.raises(Exception, match="Unsupported platform"):
        spec.loader.exec_module(module)
