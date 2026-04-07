from __future__ import annotations

import builtins
import struct

import pytest


linux = pytest.importorskip("fido2.hid.linux")
base = pytest.importorskip("fido2.hid.base")


@pytest.fixture(autouse=True)
def _restore_failed_cache():
    snapshot = set(linux._failed_cache)
    linux._failed_cache.clear()
    yield
    linux._failed_cache.clear()
    linux._failed_cache.update(snapshot)


class _FakeFile:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_linux_connection_write_packet_prepends_report_id(monkeypatch):
    captured = {}

    def _fake_parent_write(self, data):
        captured["data"] = data

    monkeypatch.setattr(base.FileCtapHidConnection, "write_packet", _fake_parent_write)

    conn = object.__new__(linux.LinuxCtapHidConnection)
    conn.write_packet(b"\x01\x02")

    assert captured["data"] == b"\x00\x01\x02"


def test_open_connection_returns_linux_connection_wrapper(monkeypatch):
    class _FakeConnection:
        def __init__(self, descriptor):
            self.descriptor = descriptor

    monkeypatch.setattr(linux, "LinuxCtapHidConnection", _FakeConnection)

    descriptor = object()
    connection = linux.open_connection(descriptor)

    assert isinstance(connection, _FakeConnection)
    assert connection.descriptor is descriptor


def test_get_descriptor_reads_vid_pid_name_serial_and_report_sizes(monkeypatch):
    monkeypatch.setattr(builtins, "open", lambda _path, _mode: _FakeFile())

    def _fake_ioctl(_file_obj, request, buf, _mutate):
        if request == linux.HIDIOCGRAWINFO:
            for idx, value in enumerate(struct.pack("<IHH", 0, 0x1200, 0x3400)):
                buf[idx] = value
            return 0
        if request == linux.HIDIOCGRAWNAME:
            payload = b"Demo Key\x00"
            for idx, value in enumerate(payload):
                buf[idx] = value
            return len(payload)
        if request == linux.HIDIOCGRAWUNIQ:
            payload = b"SER123\x00"
            for idx, value in enumerate(payload):
                buf[idx] = value
            return len(payload)
        if request == linux.HIDIOCGRDESCSIZE:
            for idx, value in enumerate(struct.pack("<I", 3)):
                buf[idx] = value
            return 0
        if request == linux.HIDIOCGRDESC:
            buf[4] = 0xAA
            buf[5] = 0xBB
            buf[6] = 0xCC
            return 0
        raise AssertionError(f"Unexpected ioctl request: {request}")

    monkeypatch.setattr(linux.fcntl, "ioctl", _fake_ioctl)
    monkeypatch.setattr(linux, "parse_report_descriptor", lambda data: (len(data), len(data) + 1))

    descriptor = linux.get_descriptor("/dev/hidraw0")

    assert descriptor.path == "/dev/hidraw0"
    assert descriptor.vid == 0x1200
    assert descriptor.pid == 0x3400
    assert descriptor.product_name == "Demo Key"
    assert descriptor.serial_number == "SER123"
    assert descriptor.report_size_in == 3
    assert descriptor.report_size_out == 4


def test_get_descriptor_handles_missing_serial_and_empty_product_name(monkeypatch):
    monkeypatch.setattr(builtins, "open", lambda _path, _mode: _FakeFile())

    def _fake_ioctl(_file_obj, request, buf, _mutate):
        if request == linux.HIDIOCGRAWINFO:
            for idx, value in enumerate(struct.pack("<IHH", 0, 0x1000, 0x2000)):
                buf[idx] = value
            return 0
        if request == linux.HIDIOCGRAWNAME:
            # length <= 1 should map to None
            return 1
        if request == linux.HIDIOCGRAWUNIQ:
            raise OSError("No serial")
        if request == linux.HIDIOCGRDESCSIZE:
            for idx, value in enumerate(struct.pack("<I", 1)):
                buf[idx] = value
            return 0
        if request == linux.HIDIOCGRDESC:
            buf[4] = 0x01
            return 0
        raise AssertionError(f"Unexpected ioctl request: {request}")

    monkeypatch.setattr(linux.fcntl, "ioctl", _fake_ioctl)
    monkeypatch.setattr(linux, "parse_report_descriptor", lambda _data: (64, 64))

    descriptor = linux.get_descriptor("/dev/hidraw9")

    assert descriptor.path == "/dev/hidraw9"
    assert descriptor.product_name is None
    assert descriptor.serial_number is None
    assert descriptor.report_size_in == 64
    assert descriptor.report_size_out == 64


def test_list_descriptors_filters_value_errors_and_caches_repeated_failures(monkeypatch):
    descriptor_ok = base.HidDescriptor("/dev/hidraw0", 1, 2, 64, 64, "demo", "serial")

    monkeypatch.setattr(
        linux.glob,
        "glob",
        lambda _pattern: ["/dev/hidraw0", "/dev/hidraw1", "/dev/hidraw2"],
    )

    def _fake_get_descriptor(path):
        if path.endswith("0"):
            return descriptor_ok
        if path.endswith("1"):
            raise ValueError("Not CTAP")
        raise RuntimeError("Unexpected low-level failure")

    monkeypatch.setattr(linux, "get_descriptor", _fake_get_descriptor)

    debug_calls = []
    monkeypatch.setattr(linux.logger, "debug", lambda *args, **kwargs: debug_calls.append((args, kwargs)))

    linux._failed_cache.add("/dev/hidraw-stale")

    first = linux.list_descriptors()
    second = linux.list_descriptors()

    assert first == [descriptor_ok]
    assert second == [descriptor_ok]
    assert "/dev/hidraw-stale" not in linux._failed_cache
    assert "/dev/hidraw1" not in linux._failed_cache
    assert "/dev/hidraw2" in linux._failed_cache
    # Repeated failures on the same path should only log once while cached.
    assert len(debug_calls) == 1


def test_list_descriptors_removes_cache_entries_for_disappeared_devices(monkeypatch):
    monkeypatch.setattr(linux.glob, "glob", lambda _pattern: ["/dev/hidraw5"])
    monkeypatch.setattr(
        linux,
        "get_descriptor",
        lambda _path: base.HidDescriptor("/dev/hidraw5", 10, 11, 64, 64, "new", None),
    )

    linux._failed_cache.update({"/dev/hidraw5", "/dev/hidraw-old"})

    descriptors = linux.list_descriptors()

    assert len(descriptors) == 1
    assert descriptors[0].path == "/dev/hidraw5"
    assert linux._failed_cache == {"/dev/hidraw5"}
