import pytest

from fido2.hid.base import (
    FileCtapHidConnection,
    HidDescriptor,
    parse_report_descriptor,
)


def test_file_ctap_connection_io_and_report_descriptor_duplicate_output_branch(monkeypatch):
    descriptor = HidDescriptor(
        path="/dev/fake-hid",
        vid=0x1234,
        pid=0x5678,
        report_size_in=64,
        report_size_out=64,
        product_name="Fake HID",
        serial_number="SER123",
    )

    opened = []
    closed = []
    written = []

    monkeypatch.setattr("fido2.hid.base.os.open", lambda path, flags: opened.append((path, flags)) or 42)
    monkeypatch.setattr("fido2.hid.base.os.close", lambda handle: closed.append(handle))

    def _write(handle, data):
        written.append((handle, data))
        return len(data) if data != b"fail" else len(data) - 1

    monkeypatch.setattr("fido2.hid.base.os.write", _write)
    monkeypatch.setattr("fido2.hid.base.os.read", lambda handle, size: b"R" * size)

    connection = FileCtapHidConnection(descriptor)
    assert connection.handle == 42
    assert connection.descriptor is descriptor
    assert opened

    connection.write_packet(b"ok")
    assert written[-1] == (42, b"ok")

    with pytest.raises(OSError, match="failed to write entire packet"):
        connection.write_packet(b"fail")

    assert connection.read_packet() == b"R" * 64

    connection.close()
    assert closed == [42]

    # Build a descriptor where OUTPUT is seen twice after report count/size is set.
    # The first OUTPUT initializes max_output_size, the second OUTPUT should hit the
    # "already set" path and leave max_output_size unchanged.
    report_descriptor = bytes(
        [
            0x95,
            0x40,  # REPORT_COUNT = 64
            0x75,
            0x08,  # REPORT_SIZE = 8
            0x91,
            0x00,  # OUTPUT -> max_output_size = 64
            0x95,
            0x20,  # REPORT_COUNT = 32
            0x75,
            0x08,  # REPORT_SIZE = 8
            0x91,
            0x00,  # OUTPUT again, ignored for max_output_size update
            0x06,
            0xD0,
            0xF1,  # USAGE_PAGE = 0xF1D0 (FIDO)
            0x09,
            0x01,  # USAGE = 1 (FIDO)
            0x95,
            0x10,  # REPORT_COUNT = 16
            0x75,
            0x08,  # REPORT_SIZE = 8
            0x81,
            0x00,  # INPUT -> max_input_size = 16
        ]
    )

    assert parse_report_descriptor(report_descriptor) == (32, 64)