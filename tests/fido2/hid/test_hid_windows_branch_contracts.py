from __future__ import annotations

import ctypes
import importlib.util
import platform
import sys
from pathlib import Path

import pytest


def _repo_root() -> Path:
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "fido2" / "hid" / "windows.py").is_file():
            return candidate
    raise FileNotFoundError("Unable to locate repository root containing fido2/hid/windows.py")


def _load_hid_windows_module(monkeypatch, *, arch="64bit"):
    module_path = _repo_root() / "fido2" / "hid" / "windows.py"
    module_name = f"fido2.hid._windows_branch_contracts_{arch}_{id(monkeypatch)}"

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
    monkeypatch.setattr(platform, "architecture", lambda: (arch, ""), raising=False)
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


def _descriptor(module):
    return module.HidDescriptor(
        path=b"device-path",
        vid=0x1111,
        pid=0x2222,
        report_size_in=64,
        report_size_out=64,
        product_name="Demo",
        serial_number="SERIAL",
    )


def test_import_architecture_branches(monkeypatch):
    module_32bit = _load_hid_windows_module(monkeypatch, arch="32bit")
    assert module_32bit.SETUPAPI_PACK == 1

    with pytest.raises(OSError, match="Unknown architecture"):
        _load_hid_windows_module(monkeypatch, arch="mystery")


def test_connection_and_descriptor_error_paths(monkeypatch):
    module = _load_hid_windows_module(monkeypatch)

    monkeypatch.setattr(
        module.kernel32,
        "CreateFileA",
        lambda *_args, **_kwargs: module.INVALID_HANDLE_VALUE,
        raising=False,
    )
    with pytest.raises(OSError):
        module.WinCtapHidConnection(_descriptor(module))

    closed = []
    monkeypatch.setattr(module.kernel32, "CreateFileA", lambda *_args, **_kwargs: 99, raising=False)
    monkeypatch.setattr(module.kernel32, "CloseHandle", lambda handle: closed.append(handle) or True, raising=False)
    conn = module.WinCtapHidConnection(_descriptor(module))
    conn.close()
    assert closed == [99]

    monkeypatch.setattr(module.kernel32, "WriteFile", lambda *_args, **_kwargs: False, raising=False)
    with pytest.raises(OSError):
        conn.write_packet(b"A" * 64)

    monkeypatch.setattr(module.kernel32, "ReadFile", lambda *_args, **_kwargs: False, raising=False)
    with pytest.raises(OSError):
        conn.read_packet()

    def _short_read(_handle, _buf, buf_len, num_read_ptr, _overlapped):
        num_read_ptr._obj.value = buf_len - 1
        return True

    monkeypatch.setattr(module.kernel32, "ReadFile", _short_read, raising=False)
    with pytest.raises(OSError, match="full length report"):
        conn.read_packet()

    monkeypatch.setattr(module.hid, "HidD_GetAttributes", lambda *_args, **_kwargs: False, raising=False)
    with pytest.raises(OSError):
        module.get_vid_pid(1)

    monkeypatch.setattr(module.hid, "HidD_GetProductString", lambda *_args, **_kwargs: False, raising=False)
    monkeypatch.setattr(module.hid, "HidD_GetSerialNumberString", lambda *_args, **_kwargs: False, raising=False)
    assert module.get_product_name(1) is None
    assert module.get_serial(1) is None

    monkeypatch.setattr(
        module.kernel32,
        "CreateFileA",
        lambda *_args, **_kwargs: module.INVALID_HANDLE_VALUE,
        raising=False,
    )
    with pytest.raises(OSError):
        module.get_descriptor(b"device-path")

    monkeypatch.setattr(module.kernel32, "CreateFileA", lambda *_args, **_kwargs: 7, raising=False)
    monkeypatch.setattr(module.kernel32, "CloseHandle", lambda _handle: True, raising=False)
    monkeypatch.setattr(module.hid, "HidD_GetPreparsedData", lambda *_args, **_kwargs: False, raising=False)
    with pytest.raises(OSError):
        module.get_descriptor(b"device-path")

    def _preparsed(_device, ptr):
        ptr._obj.value = 123
        return True

    monkeypatch.setattr(module.hid, "HidD_GetPreparsedData", _preparsed, raising=False)
    monkeypatch.setattr(module.hid, "HidD_FreePreparsedData", lambda _value: True, raising=False)
    monkeypatch.setattr(module.hid, "HidP_GetCaps", lambda *_args, **_kwargs: 0, raising=False)
    with pytest.raises(OSError):
        module.get_descriptor(b"device-path")

    marker = object()
    monkeypatch.setattr(module, "WinCtapHidConnection", lambda descriptor: (marker, descriptor), raising=False)
    descriptor = _descriptor(module)
    assert module.open_connection(descriptor) == (marker, descriptor)


def test_list_descriptors_cache_hits_and_stale_cleanup(monkeypatch):
    module = _load_hid_windows_module(monkeypatch)

    cached = _descriptor(module)
    module._descriptor_cache.clear()
    module._descriptor_cache[b"cached-ok"] = cached
    module._descriptor_cache[b"cached-skip"] = module._SKIP
    module._descriptor_cache[b"stale-device"] = _descriptor(module)

    monkeypatch.setattr(module.hid, "HidD_GetHidGuid", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(module.setupapi, "SetupDiGetClassDevsA", lambda *_args, **_kwargs: 123, raising=False)

    destroyed = []
    monkeypatch.setattr(
        module.setupapi,
        "SetupDiDestroyDeviceInfoList",
        lambda collection: destroyed.append(collection) or True,
        raising=False,
    )

    monkeypatch.setattr(
        module.setupapi,
        "SetupDiEnumDeviceInterfaces",
        lambda _collection, _dev_info, _guid, index, _interface: index < 2,
        raising=False,
    )

    def _detail(_collection, _interface_data, detail_ptr, _detail_len, required_len_ptr, _dev_info):
        if detail_ptr is None:
            required_len_ptr._obj.value = 16
            return False
        return True

    monkeypatch.setattr(module.setupapi, "SetupDiGetDeviceInterfaceDetailA", _detail, raising=False)

    paths = [b"cached-ok", b"cached-skip"]
    monkeypatch.setattr(module.ctypes, "string_at", lambda _ptr: paths.pop(0), raising=False)
    monkeypatch.setattr(module, "get_descriptor", lambda _path: (_ for _ in ()).throw(AssertionError("unexpected")), raising=False)

    descriptors = module.list_descriptors()
    assert descriptors == [cached]
    assert b"stale-device" not in module._descriptor_cache
    assert destroyed == [123]


def test_list_descriptors_zero_length_and_descriptor_failures(monkeypatch):
    module = _load_hid_windows_module(monkeypatch)
    module._descriptor_cache.clear()

    monkeypatch.setattr(module.hid, "HidD_GetHidGuid", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(module.setupapi, "SetupDiGetClassDevsA", lambda *_args, **_kwargs: 321, raising=False)
    monkeypatch.setattr(module.setupapi, "SetupDiDestroyDeviceInfoList", lambda *_args, **_kwargs: True, raising=False)

    state = {"index": 0}

    def _enum(_collection, _dev_info, _guid, index, _interface):
        state["index"] = index
        return index < 3

    monkeypatch.setattr(module.setupapi, "SetupDiEnumDeviceInterfaces", _enum, raising=False)

    def _detail(_collection, _interface_data, detail_ptr, _detail_len, required_len_ptr, _dev_info):
        if detail_ptr is None:
            required_len_ptr._obj.value = 0 if state["index"] == 0 else 16
            return False
        return True

    monkeypatch.setattr(module.setupapi, "SetupDiGetDeviceInterfaceDetailA", _detail, raising=False)

    paths = [b"value-error-path", b"exception-path"]
    monkeypatch.setattr(module.ctypes, "string_at", lambda _ptr: paths.pop(0), raising=False)

    debug_messages = []
    monkeypatch.setattr(module.logger, "debug", lambda *args, **kwargs: debug_messages.append(args), raising=False)

    def _get_descriptor(path):
        if path == b"value-error-path":
            raise ValueError("not ctap")
        raise RuntimeError("boom")

    monkeypatch.setattr(module, "get_descriptor", _get_descriptor, raising=False)

    assert module.list_descriptors() == []
    assert module._descriptor_cache[b"value-error-path"] is module._SKIP
    assert module._descriptor_cache[b"exception-path"] is module._SKIP
    assert debug_messages


def test_list_descriptors_raises_on_detail_api_failures(monkeypatch):
    module = _load_hid_windows_module(monkeypatch)

    monkeypatch.setattr(module.hid, "HidD_GetHidGuid", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(module.setupapi, "SetupDiGetClassDevsA", lambda *_args, **_kwargs: 1, raising=False)
    monkeypatch.setattr(module.setupapi, "SetupDiDestroyDeviceInfoList", lambda *_args, **_kwargs: True, raising=False)
    monkeypatch.setattr(
        module.setupapi,
        "SetupDiEnumDeviceInterfaces",
        lambda _collection, _dev_info, _guid, index, _interface: index < 1,
        raising=False,
    )

    # Initial detail query unexpectedly succeeds -> WinError branch.
    monkeypatch.setattr(
        module.setupapi,
        "SetupDiGetDeviceInterfaceDetailA",
        lambda _collection, _interface_data, detail_ptr, _detail_len, _required_len_ptr, _dev_info: detail_ptr is None,
        raising=False,
    )
    with pytest.raises(OSError):
        module.list_descriptors()

    module_fail_second = _load_hid_windows_module(monkeypatch)
    monkeypatch.setattr(module_fail_second.hid, "HidD_GetHidGuid", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(module_fail_second.setupapi, "SetupDiGetClassDevsA", lambda *_args, **_kwargs: 2, raising=False)
    monkeypatch.setattr(module_fail_second.setupapi, "SetupDiDestroyDeviceInfoList", lambda *_args, **_kwargs: True, raising=False)
    monkeypatch.setattr(
        module_fail_second.setupapi,
        "SetupDiEnumDeviceInterfaces",
        lambda _collection, _dev_info, _guid, index, _interface: index < 1,
        raising=False,
    )

    def _detail_fail_second(_collection, _interface_data, detail_ptr, _detail_len, required_len_ptr, _dev_info):
        if detail_ptr is None:
            required_len_ptr._obj.value = 16
            return False
        return False

    monkeypatch.setattr(module_fail_second.setupapi, "SetupDiGetDeviceInterfaceDetailA", _detail_fail_second, raising=False)

    with pytest.raises(OSError):
        module_fail_second.list_descriptors()
