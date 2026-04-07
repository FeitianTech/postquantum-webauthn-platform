from __future__ import annotations

import errno

import pytest


netbsd = pytest.importorskip("fido2.hid.netbsd")
openbsd = pytest.importorskip("fido2.hid.openbsd")
base = pytest.importorskip("fido2.hid.base")


@pytest.fixture(autouse=True)
def _restore_failed_caches():
    netbsd_snapshot = set(netbsd._failed_cache)
    openbsd_snapshot = set(openbsd._failed_cache)
    netbsd._failed_cache.clear()
    openbsd._failed_cache.clear()
    yield
    netbsd._failed_cache.clear()
    openbsd._failed_cache.clear()
    netbsd._failed_cache.update(netbsd_snapshot)
    openbsd._failed_cache.update(openbsd_snapshot)


def test_netbsd_get_descriptor_reads_struct_fields_and_report_sizes(monkeypatch):
    monkeypatch.setattr(netbsd.os, "open", lambda _path, _flags: 42)

    closed = []
    monkeypatch.setattr(netbsd.os, "close", lambda fd: closed.append(fd))

    def _fake_ioctl(fd, request, target):
        assert fd == 42
        if request == netbsd.USB_GET_DEVICE_INFO:
            target.udi_vendorNo = 0x1200
            target.udi_productNo = 0x3400
            target.udi_product = b"NetBSD Token"
            target.udi_serial = b"SN-42"
        elif request == netbsd.USB_GET_REPORT_DESC:
            target.ucrd_size = 3
            target.ucrd_data[0] = 0xAA
            target.ucrd_data[1] = 0xBB
            target.ucrd_data[2] = 0xCC
        else:
            raise AssertionError(f"Unexpected ioctl request: {request}")

    monkeypatch.setattr(netbsd, "ioctl", _fake_ioctl)
    monkeypatch.setattr(netbsd.base, "parse_report_descriptor", lambda report: (len(report), len(report) + 1))

    descriptor = netbsd.get_descriptor("/dev/uhid0")

    assert descriptor.path == "/dev/uhid0"
    assert descriptor.vid == 0x1200
    assert descriptor.pid == 0x3400
    assert descriptor.report_size_in == 3
    assert descriptor.report_size_out == 4
    assert descriptor.product_name.startswith("NetBSD Token")
    assert descriptor.serial_number.startswith("SN-42")
    assert closed == [42]


def test_netbsd_get_descriptor_handles_unicode_decode_failures(monkeypatch):
    monkeypatch.setattr(netbsd.os, "open", lambda _path, _flags: 7)
    monkeypatch.setattr(netbsd.os, "close", lambda _fd: None)

    def _fake_ioctl(_fd, request, target):
        if request == netbsd.USB_GET_DEVICE_INFO:
            target.udi_vendorNo = 1
            target.udi_productNo = 2
            target.udi_product = b"\xff"
            target.udi_serial = b"\xff"
        elif request == netbsd.USB_GET_REPORT_DESC:
            target.ucrd_size = 1
            target.ucrd_data[0] = 0x01
        else:
            raise AssertionError(f"Unexpected ioctl request: {request}")

    monkeypatch.setattr(netbsd, "ioctl", _fake_ioctl)
    monkeypatch.setattr(netbsd.base, "parse_report_descriptor", lambda _report: (64, 64))

    descriptor = netbsd.get_descriptor("/dev/uhid1")

    assert descriptor.product_name is None
    assert descriptor.serial_number is None


def test_netbsd_list_descriptors_breaks_on_enoent_and_cleans_stale_cache(monkeypatch):
    descriptor_ok = base.HidDescriptor("/dev/uhid0", 1, 2, 64, 64, "ok", None)

    def _fake_get_descriptor(path):
        if path.endswith("0"):
            return descriptor_ok
        raise OSError(errno.ENOENT, "no such device")

    monkeypatch.setattr(netbsd, "get_descriptor", _fake_get_descriptor)

    netbsd._failed_cache.add("/dev/uhid-stale")
    descriptors = netbsd.list_descriptors()

    assert descriptors == [descriptor_ok]
    assert netbsd._failed_cache == set()


def test_netbsd_list_descriptors_caches_non_enoent_failures_once(monkeypatch):
    def _fake_get_descriptor(path):
        if path.endswith("0"):
            raise RuntimeError("boom")
        raise OSError(errno.ENOENT, "stop")

    monkeypatch.setattr(netbsd, "get_descriptor", _fake_get_descriptor)

    debug_calls = []
    monkeypatch.setattr(netbsd.logger, "debug", lambda *args, **kwargs: debug_calls.append((args, kwargs)))

    first = netbsd.list_descriptors()
    second = netbsd.list_descriptors()

    assert first == []
    assert second == []
    assert "/dev/uhid0" in netbsd._failed_cache
    assert len(debug_calls) == 1


def test_netbsd_list_descriptors_caches_non_enoent_oserror_paths(monkeypatch):
    def _fake_get_descriptor(path):
        if path.endswith("0"):
            raise OSError(errno.EIO, "io error")
        raise OSError(errno.ENOENT, "stop")

    monkeypatch.setattr(netbsd, "get_descriptor", _fake_get_descriptor)

    debug_calls = []
    monkeypatch.setattr(netbsd.logger, "debug", lambda *args, **kwargs: debug_calls.append((args, kwargs)))

    descriptors = netbsd.list_descriptors()

    assert descriptors == []
    assert "/dev/uhid0" in netbsd._failed_cache
    assert len(debug_calls) == 1


def test_netbsd_connection_init_raises_and_closes_on_ping_timeout(monkeypatch):
    def _fake_parent_init(self, descriptor):
        self.handle = 99
        self.descriptor = descriptor

    monkeypatch.setattr(base.FileCtapHidConnection, "__init__", _fake_parent_init)
    monkeypatch.setattr(netbsd, "ioctl", lambda *_args, **_kwargs: None)

    monkeypatch.setattr(netbsd.NetBSDCtapHidConnection, "write_packet", lambda self, _data: None)
    monkeypatch.setattr(netbsd.NetBSDCtapHidConnection, "read_packet", lambda self: b"\x00" * 64)

    class _Poll:
        def register(self, _handle, _events):
            return None

        def poll(self, _timeout):
            return []

    monkeypatch.setattr(netbsd.select, "poll", lambda: _Poll())

    closed = []
    monkeypatch.setattr(netbsd.NetBSDCtapHidConnection, "close", lambda self: closed.append(True))

    descriptor = base.HidDescriptor("/dev/uhid0", 1, 2, 64, 64, "name", None)
    with pytest.raises(Exception, match="u2f ping timeout"):
        netbsd.NetBSDCtapHidConnection(descriptor)

    assert closed == [True]


def test_netbsd_connection_init_reads_ping_response_on_poll_event(monkeypatch):
    def _fake_parent_init(self, descriptor):
        self.handle = 101
        self.descriptor = descriptor

    monkeypatch.setattr(base.FileCtapHidConnection, "__init__", _fake_parent_init)
    monkeypatch.setattr(netbsd, "ioctl", lambda *_args, **_kwargs: None)

    writes = []
    reads = []
    monkeypatch.setattr(netbsd.NetBSDCtapHidConnection, "write_packet", lambda self, data: writes.append(data))
    monkeypatch.setattr(netbsd.NetBSDCtapHidConnection, "read_packet", lambda self: reads.append(True) or (b"\x00" * 64))

    class _Poll:
        def register(self, _handle, _events):
            return None

        def poll(self, _timeout):
            return [(101, netbsd.select.POLLIN)]

    monkeypatch.setattr(netbsd.select, "poll", lambda: _Poll())

    descriptor = base.HidDescriptor("/dev/uhid0", 1, 2, 64, 64, "name", None)
    connection = netbsd.NetBSDCtapHidConnection(descriptor)

    assert isinstance(connection, netbsd.NetBSDCtapHidConnection)
    assert len(writes) == 1
    assert reads == [True]


def test_netbsd_open_connection_returns_wrapper(monkeypatch):
    class _FakeConnection:
        def __init__(self, descriptor):
            self.descriptor = descriptor

    monkeypatch.setattr(netbsd, "NetBSDCtapHidConnection", _FakeConnection)

    descriptor = object()
    connection = netbsd.open_connection(descriptor)

    assert isinstance(connection, _FakeConnection)
    assert connection.descriptor is descriptor


def test_netbsd_list_descriptors_exhausts_scan_and_skips_cached_oserror_debug(monkeypatch):
    def _fake_get_descriptor(path):
        if path.endswith("0"):
            raise OSError(errno.EIO, "cached io error")
        raise RuntimeError("generic failure")

    monkeypatch.setattr(netbsd, "get_descriptor", _fake_get_descriptor)

    debug_calls = []
    monkeypatch.setattr(netbsd.logger, "debug", lambda *args, **kwargs: debug_calls.append((args, kwargs)))

    netbsd._failed_cache.add("/dev/uhid0")

    descriptors = netbsd.list_descriptors()

    assert descriptors == []
    # Cached OSError path should not emit a duplicate debug call.
    assert all(not (args and args[1] == "/dev/uhid0") for args, _ in debug_calls)
    # Full scan path should still record failures for other enumerated descriptors.
    assert "/dev/uhid99" in netbsd._failed_cache


def test_openbsd_get_descriptor_reads_usb_device_info(monkeypatch):
    monkeypatch.setattr(openbsd.os, "open", lambda _path, _flags: 55)

    closed = []
    monkeypatch.setattr(openbsd.os, "close", lambda fd: closed.append(fd))

    def _fake_ioctl(fd, request, target):
        assert fd == 55
        assert request == openbsd.USB_GET_DEVICEINFO
        target.udi_vendorNo = 0x1111
        target.udi_productNo = 0x2222
        target.udi_product = b"OpenBSD Key"
        target.udi_serial = b"SER-OPENBSD"

    monkeypatch.setattr(openbsd.fcntl, "ioctl", _fake_ioctl)

    descriptor = openbsd.get_descriptor("/dev/fido/fido0")

    assert descriptor.path == "/dev/fido/fido0"
    assert descriptor.vid == 0x1111
    assert descriptor.pid == 0x2222
    assert descriptor.report_size_in == openbsd.MAX_U2F_HIDLEN
    assert descriptor.report_size_out == openbsd.MAX_U2F_HIDLEN
    assert descriptor.product_name.startswith("OpenBSD Key")
    assert descriptor.serial_number.startswith("SER-OPENBSD")
    assert closed == [55]


def test_openbsd_ping_kludge_writes_four_ping_reports(monkeypatch):
    conn = object.__new__(openbsd.OpenBsdCtapHidConnection)
    conn.handle = 123
    conn.descriptor = base.HidDescriptor("/dev/fido/fido0", 1, 2, 64, 64, "name", None)

    writes = []
    monkeypatch.setattr(openbsd.OpenBsdCtapHidConnection, "write_packet", lambda self, data: writes.append(data))
    monkeypatch.setattr(openbsd.OpenBsdCtapHidConnection, "read_packet", lambda self: b"\x00" * 64)

    class _Poll:
        def register(self, _handle, _events):
            return None

        def poll(self, _timeout):
            return [(conn.handle, openbsd.select.POLLIN)]

    monkeypatch.setattr(openbsd.select, "poll", lambda: _Poll())

    conn._terrible_ping_kludge()

    assert len(writes) == 4
    assert all(packet.startswith(b"\xff\xff\xff\xff\x81\x00\x01") for packet in writes)
    assert all(len(packet) == conn.descriptor.report_size_out for packet in writes)


def test_openbsd_init_closes_on_ping_failure(monkeypatch):
    def _fake_parent_init(self, descriptor):
        self.handle = 303
        self.descriptor = descriptor

    monkeypatch.setattr(base.FileCtapHidConnection, "__init__", _fake_parent_init)
    monkeypatch.setattr(
        openbsd.OpenBsdCtapHidConnection,
        "_terrible_ping_kludge",
        lambda self: (_ for _ in ()).throw(RuntimeError("ping failed")),
    )

    closed = []
    monkeypatch.setattr(openbsd.OpenBsdCtapHidConnection, "close", lambda self: closed.append(True))

    descriptor = base.HidDescriptor("/dev/fido/fido0", 1, 2, 64, 64, "name", None)
    with pytest.raises(RuntimeError, match="ping failed"):
        openbsd.OpenBsdCtapHidConnection(descriptor)

    assert closed == [True]


def test_openbsd_open_connection_returns_wrapper(monkeypatch):
    class _FakeConnection:
        def __init__(self, descriptor):
            self.descriptor = descriptor

    monkeypatch.setattr(openbsd, "OpenBsdCtapHidConnection", _FakeConnection)

    descriptor = object()
    connection = openbsd.open_connection(descriptor)

    assert isinstance(connection, _FakeConnection)
    assert connection.descriptor is descriptor


def test_openbsd_list_descriptors_caches_failures(monkeypatch):
    descriptor_ok = base.HidDescriptor("/dev/fido/fido0", 1, 2, 64, 64, "ok", None)
    monkeypatch.setattr(openbsd.os, "listdir", lambda _path: ["fido0", "fido1"])

    def _fake_get_descriptor(path):
        if path.endswith("fido0"):
            return descriptor_ok
        raise RuntimeError("broken")

    monkeypatch.setattr(openbsd, "get_descriptor", _fake_get_descriptor)

    debug_calls = []
    monkeypatch.setattr(openbsd.logger, "debug", lambda *args, **kwargs: debug_calls.append((args, kwargs)))

    first = openbsd.list_descriptors()
    second = openbsd.list_descriptors()

    assert first == [descriptor_ok]
    assert second == [descriptor_ok]
    assert "/dev/fido/fido1" in openbsd._failed_cache
    assert len(debug_calls) == 1
