from __future__ import annotations

import ctypes
import importlib.util
import sys
from pathlib import Path

import pytest


def _load_hid_windows_module(monkeypatch):
    module_path = Path(__file__).resolve().parents[2] / "fido2" / "hid" / "windows.py"
    module_name = f"fido2.hid._windows_contracts_{id(monkeypatch)}"

    class _FakeFunction:
        def __init__(self, return_value=0):
            self.return_value = return_value
            self.argtypes = None
            self.restype = None
            self.calls = []

        def __call__(self, *args):
            self.calls.append(args)
            return self.return_value

    class _FakeLib:
        def __init__(self):
            self._functions = {}

        def __getattr__(self, name):
            if name not in self._functions:
                self._functions[name] = _FakeFunction(0)
            return self._functions[name]

    class _FakeLoader:
        def __init__(self, _dll_factory):
            self._libs = {}

        def __getattr__(self, name):
            if name not in self._libs:
                self._libs[name] = _FakeLib()
            return self._libs[name]

    monkeypatch.setattr(sys, "platform", "win32", raising=False)
    monkeypatch.setattr(ctypes, "WinDLL", lambda _name: None, raising=False)
    monkeypatch.setattr(ctypes, "LibraryLoader", _FakeLoader, raising=False)
    monkeypatch.setattr(ctypes, "WinError", lambda *_args, **_kwargs: OSError("win error"), raising=False)

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "fido2.hid"
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module


def test_hid_windows_vid_pid_product_and_serial_helpers(monkeypatch):
    module = _load_hid_windows_module(monkeypatch)

    def _attrs(_device, attrs_ptr):
        attrs_ptr._obj.VendorID = 0x1234
        attrs_ptr._obj.ProductID = 0x5678
        return True

    def _product(_device, buf, _size):
        buf.value = "Demo Key"
        return True

    def _serial(_device, buf, _size):
        buf.value = "SER123"
        return True

    monkeypatch.setattr(module.hid, "HidD_GetAttributes", _attrs, raising=False)
    monkeypatch.setattr(module.hid, "HidD_GetProductString", _product, raising=False)
    monkeypatch.setattr(module.hid, "HidD_GetSerialNumberString", _serial, raising=False)

    assert module.get_vid_pid(1) == (0x1234, 0x5678)
    assert module.get_product_name(1) == "Demo Key"
    assert module.get_serial(1) == "SER123"


def test_hid_windows_get_descriptor_success_and_non_ctap_failure(monkeypatch):
    module = _load_hid_windows_module(monkeypatch)

    monkeypatch.setattr(module.kernel32, "CreateFileA", lambda *_args, **_kwargs: 1, raising=False)
    monkeypatch.setattr(module.kernel32, "CloseHandle", lambda _handle: True, raising=False)

    def _preparsed(_device, ptr):
        ptr._obj.value = 99
        return True

    monkeypatch.setattr(module.hid, "HidD_GetPreparsedData", _preparsed, raising=False)
    monkeypatch.setattr(module.hid, "HidD_FreePreparsedData", lambda _ppd: True, raising=False)
    monkeypatch.setattr(module, "get_vid_pid", lambda _device: (0x1111, 0x2222), raising=False)
    monkeypatch.setattr(module, "get_product_name", lambda _device: "Security Key", raising=False)
    monkeypatch.setattr(module, "get_serial", lambda _device: "SERIAL", raising=False)

    def _caps_ctap(_preparsed, caps_ptr):
        caps_ptr._obj.UsagePage = module.FIDO_USAGE_PAGE
        caps_ptr._obj.Usage = module.FIDO_USAGE
        caps_ptr._obj.InputReportByteLength = 65
        caps_ptr._obj.OutputReportByteLength = 65
        return module.HIDP_STATUS_SUCCESS

    monkeypatch.setattr(module.hid, "HidP_GetCaps", _caps_ctap, raising=False)

    descriptor = module.get_descriptor(b"device-path")
    assert descriptor.path == b"device-path"
    assert descriptor.vid == 0x1111
    assert descriptor.pid == 0x2222
    assert descriptor.report_size_in == 64
    assert descriptor.report_size_out == 64

    def _caps_non_ctap(_preparsed, caps_ptr):
        caps_ptr._obj.UsagePage = 0x0001
        caps_ptr._obj.Usage = 0x0001
        caps_ptr._obj.InputReportByteLength = 64
        caps_ptr._obj.OutputReportByteLength = 64
        return module.HIDP_STATUS_SUCCESS

    monkeypatch.setattr(module.hid, "HidP_GetCaps", _caps_non_ctap, raising=False)

    with pytest.raises(ValueError, match="Not a CTAP device"):
        module.get_descriptor(b"device-path")


def test_hid_windows_connection_write_and_read_packet_contracts(monkeypatch):
    module = _load_hid_windows_module(monkeypatch)

    descriptor = module.HidDescriptor(
        path=b"device-path",
        vid=0x1111,
        pid=0x2222,
        report_size_in=64,
        report_size_out=64,
        product_name="Demo",
        serial_number="SERIAL",
    )

    monkeypatch.setattr(module.kernel32, "CreateFileA", lambda *_args, **_kwargs: 99, raising=False)
    monkeypatch.setattr(module.kernel32, "CloseHandle", lambda _handle: True, raising=False)

    def _write_file(_handle, out_buf, out_len, num_written_ptr, _overlapped):
        num_written_ptr._obj.value = out_len
        return True

    def _read_file(_handle, buf, buf_len, num_read_ptr, _overlapped):
        payload = b"\x00" + (b"A" * (buf_len - 1))
        ctypes.memmove(buf, payload, len(payload))
        num_read_ptr._obj.value = buf_len
        return True

    monkeypatch.setattr(module.kernel32, "WriteFile", _write_file, raising=False)
    monkeypatch.setattr(module.kernel32, "ReadFile", _read_file, raising=False)

    connection = module.WinCtapHidConnection(descriptor)
    connection.write_packet(b"B" * 64)
    packet = connection.read_packet()

    assert packet == b"A" * 64


def test_hid_windows_write_packet_raises_when_partial_write_occurs(monkeypatch):
    module = _load_hid_windows_module(monkeypatch)

    descriptor = module.HidDescriptor(
        path=b"device-path",
        vid=0x1111,
        pid=0x2222,
        report_size_in=64,
        report_size_out=64,
        product_name="Demo",
        serial_number="SERIAL",
    )

    monkeypatch.setattr(module.kernel32, "CreateFileA", lambda *_args, **_kwargs: 99, raising=False)
    monkeypatch.setattr(module.kernel32, "CloseHandle", lambda _handle: True, raising=False)

    def _short_write(_handle, _out_buf, out_len, num_written_ptr, _overlapped):
        num_written_ptr._obj.value = out_len - 1
        return True

    monkeypatch.setattr(module.kernel32, "WriteFile", _short_write, raising=False)

    connection = module.WinCtapHidConnection(descriptor)
    with pytest.raises(OSError, match="Failed to write complete packet"):
        connection.write_packet(b"C" * 64)
