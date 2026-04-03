from __future__ import annotations

import builtins
import ctypes
import struct

import pytest


freebsd = pytest.importorskip("fido2.hid.freebsd")
base = pytest.importorskip("fido2.hid.base")


@pytest.fixture(autouse=True)
def _restore_failed_cache():
    snapshot = set(freebsd._failed_cache)
    freebsd._failed_cache.clear()
    yield
    freebsd._failed_cache.clear()
    freebsd._failed_cache.update(snapshot)


class _FakeFile:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_hidraw_connection_write_packet_prepends_report_id(monkeypatch):
    captured = {}

    def _fake_parent_write(self, data):
        captured["data"] = data

    monkeypatch.setattr(base.FileCtapHidConnection, "write_packet", _fake_parent_write)

    conn = object.__new__(freebsd.HidrawCtapHidConnection)
    conn.write_packet(b"\x01\x02")

    assert captured["data"] == b"\x00\x01\x02"


def test_open_connection_selects_hidraw_or_file_backend(monkeypatch):
    class _FakeHidraw:
        def __init__(self, descriptor):
            self.descriptor = descriptor

    class _FakeFileConn:
        def __init__(self, descriptor):
            self.descriptor = descriptor

    monkeypatch.setattr(freebsd, "HidrawCtapHidConnection", _FakeHidraw)
    monkeypatch.setattr(freebsd, "FileCtapHidConnection", _FakeFileConn)

    hidraw_desc = base.HidDescriptor("/dev/hidraw0", 1, 2, 64, 64, "name", None)
    uhid_desc = base.HidDescriptor("/dev/uhid0", 1, 2, 64, 64, "name", None)

    hidraw_conn = freebsd.open_connection(hidraw_desc)
    uhid_conn = freebsd.open_connection(uhid_desc)

    assert isinstance(hidraw_conn, _FakeHidraw)
    assert isinstance(uhid_conn, _FakeFileConn)


def test_get_report_data_returns_bytes_and_raises_on_ioctl_failure(monkeypatch):
    def _ioctl_success(_fd, _req, desc_ptr):
        desc = ctypes.cast(desc_ptr, ctypes.POINTER(freebsd.usb_gen_descriptor)).contents
        payload = b"\x01\x02\x03\x04"
        ctypes.memmove(desc.ugd_data, payload, len(payload))
        desc.ugd_actlen = len(payload)
        return 0

    monkeypatch.setattr(freebsd.libc, "ioctl", _ioctl_success)
    assert freebsd._get_report_data(12, 3) == b"\x01\x02\x03\x04"

    monkeypatch.setattr(freebsd.libc, "ioctl", lambda *_args: 1)
    with pytest.raises(ValueError, match="ioctl failed"):
        freebsd._get_report_data(12, 3)


def test_read_descriptor_opens_reads_parses_and_closes(monkeypatch):
    monkeypatch.setattr(freebsd.os, "open", lambda _path, _flags: 77)

    closed = []
    monkeypatch.setattr(freebsd.os, "close", lambda fd: closed.append(fd))
    monkeypatch.setattr(freebsd, "_get_report_data", lambda _fd, _rtype: b"\xAA\xBB\xCC")
    monkeypatch.setattr(freebsd, "parse_report_descriptor", lambda data: (len(data), len(data) + 1))

    descriptor = freebsd._read_descriptor(11, 22, "uhid0", "SER", "/dev/uhid0")

    assert descriptor == base.HidDescriptor("/dev/uhid0", 11, 22, 3, 4, "uhid0", "SER")
    assert closed == [77]


def test_enumerate_parses_pnpinfo_and_description(monkeypatch):
    monkeypatch.setattr(freebsd.glob, "glob", lambda _pattern: ["/dev/uhid0", "/dev/uhidX"])

    def _sysctlbyname(key, ovalue, olen_ptr, _newp, _newlen):
        name = ctypes.cast(key, ctypes.c_char_p).value.decode()
        olen = ctypes.cast(olen_ptr, ctypes.POINTER(ctypes.c_size_t))

        if name.endswith(".0.%pnpinfo"):
            payload = b'vendor=0x1200 product=0x3400 sernum="SERIAL-1"'
        elif name.endswith(".0.%desc"):
            payload = b"Demo USB Token"
        else:
            return -1

        ctypes.memmove(ovalue, payload, len(payload))
        olen.contents.value = len(payload)
        return 0

    monkeypatch.setattr(freebsd.libc, "sysctlbyname", _sysctlbyname, raising=False)

    devices = list(freebsd._enumerate())

    assert len(devices) == 1
    dev = devices[0]
    assert dev.path == "/dev/uhid0"
    assert dev.vendor_id == 0x1200
    assert dev.product_id == 0x3400
    assert dev.serial_number == "SERIAL-1"
    assert dev.product_desc == "Demo USB Token"


def test_enumerate_skips_failed_pnpinfo_and_sets_none_for_missing_desc(monkeypatch):
    monkeypatch.setattr(freebsd.glob, "glob", lambda _pattern: ["/dev/uhid0", "/dev/uhid1"])

    def _sysctlbyname(key, ovalue, olen_ptr, _newp, _newlen):
        name = ctypes.cast(key, ctypes.c_char_p).value.decode()
        olen = ctypes.cast(olen_ptr, ctypes.POINTER(ctypes.c_size_t))

        if name.endswith(".0.%pnpinfo"):
            return -1
        if name.endswith(".1.%pnpinfo"):
            payload = b"vendor=0x0100 product=0x0200"
            ctypes.memmove(ovalue, payload, len(payload))
            olen.contents.value = len(payload)
            return 0
        if name.endswith(".1.%desc"):
            return -1
        return -1

    monkeypatch.setattr(freebsd.libc, "sysctlbyname", _sysctlbyname, raising=False)

    devices = list(freebsd._enumerate())

    assert len(devices) == 1
    dev = devices[0]
    assert dev.path == "/dev/uhid1"
    assert dev.vendor_id == 0x0100
    assert dev.product_id == 0x0200
    assert dev.product_desc is None


def test_get_hidraw_descriptor_reads_all_hidraw_fields(monkeypatch):
    monkeypatch.setattr(builtins, "open", lambda _path, _mode: _FakeFile())

    def _fake_ioctl(_file_obj, request, buf, _mutate):
        if request == freebsd.HIDIOCGRAWINFO:
            for idx, value in enumerate(struct.pack("<IHH", 0, 0x1234, 0x5678)):
                buf[idx] = value
            return 0
        if request == freebsd.HIDIOCGRAWNAME_128:
            payload = b"FreeBSD Key\x00"
            for idx, value in enumerate(payload):
                buf[idx] = value
            return 0
        if request == freebsd.HIDIOCGRAWUNIQ_64:
            payload = b"SER-FREEBSD\x00"
            for idx, value in enumerate(payload):
                buf[idx] = value
            return 0
        if request == freebsd.HIDIOCGRDESCSIZE:
            for idx, value in enumerate(struct.pack("<I", 2)):
                buf[idx] = value
            return 0
        if request == freebsd.HIDIOCGRDESC:
            buf[4] = 0xAB
            buf[5] = 0xCD
            return 0
        raise AssertionError(f"Unexpected request: {request}")

    monkeypatch.setattr(freebsd.fcntl, "ioctl", _fake_ioctl)
    monkeypatch.setattr(freebsd, "parse_report_descriptor", lambda data: (len(data), len(data) + 2))

    descriptor = freebsd.get_hidraw_descriptor("/dev/hidraw0")

    assert descriptor.path == "/dev/hidraw0"
    assert descriptor.vid == 0x1234
    assert descriptor.pid == 0x5678
    assert descriptor.product_name == "FreeBSD Key"
    assert descriptor.serial_number == "SER-FREEBSD"
    assert descriptor.report_size_in == 2
    assert descriptor.report_size_out == 4


def test_get_hidraw_descriptor_handles_missing_unique_serial(monkeypatch):
    monkeypatch.setattr(builtins, "open", lambda _path, _mode: _FakeFile())

    def _fake_ioctl(_file_obj, request, buf, _mutate):
        if request == freebsd.HIDIOCGRAWINFO:
            for idx, value in enumerate(struct.pack("<IHH", 0, 1, 2)):
                buf[idx] = value
            return 0
        if request == freebsd.HIDIOCGRAWNAME_128:
            # Empty string => None
            buf[0] = 0
            return 0
        if request == freebsd.HIDIOCGRAWUNIQ_64:
            raise OSError("missing serial")
        if request == freebsd.HIDIOCGRDESCSIZE:
            for idx, value in enumerate(struct.pack("<I", 1)):
                buf[idx] = value
            return 0
        if request == freebsd.HIDIOCGRDESC:
            buf[4] = 0x01
            return 0
        raise AssertionError(f"Unexpected request: {request}")

    monkeypatch.setattr(freebsd.fcntl, "ioctl", _fake_ioctl)
    monkeypatch.setattr(freebsd, "parse_report_descriptor", lambda _data: (64, 64))

    descriptor = freebsd.get_hidraw_descriptor("/dev/hidraw9")

    assert descriptor.product_name is None
    assert descriptor.serial_number is None


def test_get_descriptor_chooses_hidraw_and_enumerated_paths(monkeypatch):
    monkeypatch.setattr(freebsd, "get_hidraw_descriptor", lambda path: ("hidraw", path))
    assert freebsd.get_descriptor("/dev/hidraw1") == ("hidraw", "/dev/hidraw1")

    devices = [
        freebsd._UhidDevice("uhid0", "/dev/uhid0", 1, 2, "SER", "desc"),
    ]
    monkeypatch.setattr(freebsd, "_enumerate", lambda: iter(devices))
    monkeypatch.setattr(
        freebsd,
        "_read_descriptor",
        lambda vid, pid, name, serial, path: base.HidDescriptor(path, vid, pid, 64, 64, name, serial),
    )

    descriptor = freebsd.get_descriptor("/dev/uhid0")
    assert descriptor.path == "/dev/uhid0"
    assert descriptor.vid == 1
    assert descriptor.pid == 2

    monkeypatch.setattr(freebsd, "_enumerate", lambda: iter(()))
    with pytest.raises(ValueError, match="Device not found"):
        freebsd.get_descriptor("/dev/uhid-missing")


def test_get_descriptor_scans_enumeration_until_path_matches(monkeypatch):
    devices = [
        freebsd._UhidDevice("uhid0", "/dev/uhid0", 1, 2, "A", "desc0"),
        freebsd._UhidDevice("uhid1", "/dev/uhid1", 3, 4, "B", "desc1"),
    ]
    monkeypatch.setattr(freebsd, "_enumerate", lambda: iter(devices))
    monkeypatch.setattr(
        freebsd,
        "_read_descriptor",
        lambda vid, pid, name, serial, path: base.HidDescriptor(path, vid, pid, 64, 64, name, serial),
    )

    descriptor = freebsd.get_descriptor("/dev/uhid1")

    assert descriptor.path == "/dev/uhid1"
    assert descriptor.vid == 3
    assert descriptor.pid == 4


def test_list_descriptors_uses_hidraw_and_cache_behavior(monkeypatch):
    descriptor_ok = base.HidDescriptor("/dev/hidraw0", 1, 2, 64, 64, "ok", "s")
    monkeypatch.setattr(
        freebsd.glob,
        "glob",
        lambda _pattern: ["/dev/hidraw0", "/dev/hidraw1", "/dev/hidraw2"],
    )

    def _fake_get_descriptor(path):
        if path.endswith("0"):
            return descriptor_ok
        if path.endswith("1"):
            raise ValueError("not ctap")
        raise RuntimeError("io failure")

    monkeypatch.setattr(freebsd, "get_descriptor", _fake_get_descriptor)
    monkeypatch.setattr(freebsd, "_enumerate", lambda: iter(()))

    debug_calls = []
    monkeypatch.setattr(freebsd.logger, "debug", lambda *args, **kwargs: debug_calls.append((args, kwargs)))

    freebsd._failed_cache.add("/dev/hidraw-stale")

    first = freebsd.list_descriptors()
    second = freebsd.list_descriptors()

    assert first == [descriptor_ok]
    assert second == [descriptor_ok]
    assert "/dev/hidraw-stale" not in freebsd._failed_cache
    assert "/dev/hidraw2" in freebsd._failed_cache
    assert "/dev/hidraw1" not in freebsd._failed_cache
    assert len(debug_calls) == 1


def test_list_descriptors_falls_back_to_uhid_enumeration_when_hidraw_empty(monkeypatch):
    monkeypatch.setattr(freebsd.glob, "glob", lambda _pattern: ["/dev/hidraw0"])
    monkeypatch.setattr(freebsd, "get_descriptor", lambda _path: (_ for _ in ()).throw(ValueError("no ctap")))

    enumerated = [
        freebsd._UhidDevice("uhid0", "/dev/uhid0", 10, 20, "SER0", "desc0"),
        freebsd._UhidDevice("uhid1", "/dev/uhid1", 11, 21, "SER1", "desc1"),
    ]
    monkeypatch.setattr(freebsd, "_enumerate", lambda: iter(enumerated))

    def _fake_read_descriptor(vid, pid, name, serial, path):
        if path.endswith("1"):
            raise RuntimeError("broken uhid")
        return base.HidDescriptor(path, vid, pid, 32, 64, name, serial)

    monkeypatch.setattr(freebsd, "_read_descriptor", _fake_read_descriptor)

    debug_calls = []
    monkeypatch.setattr(freebsd.logger, "debug", lambda *args, **kwargs: debug_calls.append((args, kwargs)))

    descriptors = freebsd.list_descriptors()

    assert len(descriptors) == 1
    assert descriptors[0].path == "/dev/uhid0"
    assert "/dev/uhid1" in freebsd._failed_cache
    assert len(debug_calls) == 1


def test_list_descriptors_fallback_ignores_value_error_and_skips_cached_exception(monkeypatch):
    monkeypatch.setattr(freebsd.glob, "glob", lambda _pattern: ["/dev/hidraw0"])
    monkeypatch.setattr(freebsd, "get_descriptor", lambda _path: (_ for _ in ()).throw(ValueError("not ctap")))

    enumerated = [
        freebsd._UhidDevice("uhid0", "/dev/uhid0", 1, 2, "S0", "desc0"),
        freebsd._UhidDevice("uhid1", "/dev/uhid1", 3, 4, "S1", "desc1"),
    ]
    monkeypatch.setattr(freebsd, "_enumerate", lambda: iter(enumerated))

    def _fake_read_descriptor(_vid, _pid, _name, _serial, path):
        if path.endswith("0"):
            raise ValueError("ignored")
        raise RuntimeError("cached failure")

    monkeypatch.setattr(freebsd, "_read_descriptor", _fake_read_descriptor)

    debug_calls = []
    monkeypatch.setattr(freebsd.logger, "debug", lambda *args, **kwargs: debug_calls.append((args, kwargs)))

    freebsd._failed_cache.add("/dev/uhid1")

    descriptors = freebsd.list_descriptors()

    assert descriptors == []
    assert len(debug_calls) == 0
