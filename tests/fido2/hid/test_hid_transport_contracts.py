from __future__ import annotations

import struct
from threading import Event

import pytest

from fido2.ctap import CtapError, STATUS
from fido2.hid.base import HidDescriptor


hid = pytest.importorskip("fido2.hid")


class _FakeConnection:
    def __init__(self, responses):
        self.responses = list(responses)
        self.writes = []
        self.closed = False

    def write_packet(self, data):
        self.writes.append(data)

    def read_packet(self):
        if not self.responses:
            raise AssertionError("No response packet queued")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    def close(self):
        self.closed = True


def _make_device(*, packet_size=16, channel=0xA1B2C3D4, responses=()):
    device = object.__new__(hid.CtapHidDevice)
    device.descriptor = HidDescriptor("/dev/fake", 1, 2, packet_size, packet_size, "Fake", "123")
    device._packet_size = packet_size
    device._channel_id = channel
    device._connection = _FakeConnection(responses)
    return device


def _init_packet(channel, cmd, payload, packet_size, total_len=None):
    if total_len is None:
        total_len = len(payload)
    return (struct.pack(">IBH", channel, hid.TYPE_INIT | cmd, total_len) + payload).ljust(packet_size, b"\x00")


def _cont_packet(channel, seq, payload, packet_size):
    return (struct.pack(">IB", channel, seq) + payload).ljust(packet_size, b"\x00")


def test_capability_supported_uses_bitmask():
    flags = hid.CAPABILITY.WINK | hid.CAPABILITY.CBOR

    assert hid.CAPABILITY.WINK.supported(flags) is True
    assert hid.CAPABILITY.CBOR.supported(flags) is True
    assert hid.CAPABILITY.NMSG.supported(flags) is False


def test_send_cancel_writes_cancel_packet():
    device = _make_device(packet_size=12, channel=0x01020304)

    device._send_cancel()

    assert len(device._connection.writes) == 1
    expected = struct.pack(">IB", 0x01020304, hid.TYPE_INIT | hid.CTAPHID.CANCEL).ljust(12, b"\x00")
    assert device._connection.writes[0] == expected


def test_do_call_sends_request_and_reassembles_fragmented_response():
    payload = b"R" * 20
    packet_size = 16
    device = _make_device(
        packet_size=packet_size,
        responses=[
            _init_packet(
                device_channel := 0xA1B2C3D4,
                hid.CTAPHID.PING,
                payload[:9],
                packet_size,
                total_len=len(payload),
            ),
            _cont_packet(device_channel, 0, payload[9:], packet_size),
        ],
    )
    device._channel_id = device_channel

    response = device._do_call(hid.CTAPHID.PING, b"abc", Event(), None)

    assert response == payload
    assert len(device._connection.writes) == 1
    sent = device._connection.writes[0]
    assert sent.startswith(struct.pack(">IBH", device_channel, hid.TYPE_INIT | hid.CTAPHID.PING, 3))


def test_do_call_processes_keepalive_and_deduplicates_callback_statuses():
    packet_size = 16
    channel = 0x10203040
    final_payload = b"ok"
    keepalive_processing = _init_packet(channel, hid.CTAPHID.KEEPALIVE, bytes([STATUS.PROCESSING]), packet_size)
    keepalive_upneeded = _init_packet(channel, hid.CTAPHID.KEEPALIVE, bytes([STATUS.UPNEEDED]), packet_size)
    final_packet = _init_packet(channel, hid.CTAPHID.PING, final_payload, packet_size)

    device = _make_device(
        packet_size=packet_size,
        channel=channel,
        responses=[keepalive_processing, keepalive_processing, keepalive_upneeded, final_packet],
    )

    observed = []
    response = device._do_call(hid.CTAPHID.PING, b"", Event(), observed.append)

    assert response == final_payload
    assert observed == [STATUS.PROCESSING, STATUS.UPNEEDED]


def test_do_call_raises_connection_failure_for_invalid_keepalive_status():
    packet_size = 16
    channel = 0x99887766
    invalid_keepalive = _init_packet(channel, hid.CTAPHID.KEEPALIVE, b"\x09", packet_size)

    device = _make_device(packet_size=packet_size, channel=channel, responses=[invalid_keepalive])

    with pytest.raises(hid.ConnectionFailure, match="Invalid keepalive status"):
        device._do_call(hid.CTAPHID.PING, b"", Event(), None)


def test_do_call_raises_connection_failure_for_wrong_channel():
    packet_size = 16
    device = _make_device(
        packet_size=packet_size,
        channel=0x11111111,
        responses=[_init_packet(0x22222222, hid.CTAPHID.PING, b"ok", packet_size)],
    )

    with pytest.raises(hid.ConnectionFailure, match="Wrong channel"):
        device._do_call(hid.CTAPHID.PING, b"", Event(), None)


def test_do_call_raises_connection_failure_for_wrong_sequence_number():
    packet_size = 16
    channel = 0xABCDEF01
    first = _init_packet(channel, hid.CTAPHID.PING, b"123456789", packet_size, total_len=20)
    wrong_seq = _cont_packet(channel, 1, b"01234567890", packet_size)

    device = _make_device(packet_size=packet_size, channel=channel, responses=[first, wrong_seq])

    with pytest.raises(hid.ConnectionFailure, match="Wrong sequence number"):
        device._do_call(hid.CTAPHID.PING, b"", Event(), None)


def test_do_call_raises_ctap_error_when_error_packet_received():
    packet_size = 16
    channel = 0xA0A0A0A0
    error_packet = _init_packet(
        channel,
        hid.CTAPHID.ERROR,
        bytes([CtapError.ERR.INVALID_COMMAND]),
        packet_size,
    )
    device = _make_device(packet_size=packet_size, channel=channel, responses=[error_packet])

    with pytest.raises(CtapError) as exc_info:
        device._do_call(hid.CTAPHID.PING, b"", Event(), None)

    assert exc_info.value.code == CtapError.ERR.INVALID_COMMAND


def test_do_call_sends_cancel_when_event_is_set(monkeypatch):
    packet_size = 16
    channel = 0x12344321
    device = _make_device(
        packet_size=packet_size,
        channel=channel,
        responses=[_init_packet(channel, hid.CTAPHID.PING, b"", packet_size)],
    )

    sent_cancel = []
    monkeypatch.setattr(device, "_send_cancel", lambda: sent_cancel.append(True))

    event = Event()
    event.set()

    response = device._do_call(hid.CTAPHID.PING, b"", event, None)

    assert response == b""
    assert sent_cancel == [True]


def test_do_call_keyboard_interrupt_triggers_cancel(monkeypatch):
    device = _make_device(packet_size=16, responses=[KeyboardInterrupt()])

    sent_cancel = []
    monkeypatch.setattr(device, "_send_cancel", lambda: sent_cancel.append(True))

    with pytest.raises(KeyboardInterrupt):
        device._do_call(hid.CTAPHID.PING, b"", Event(), None)

    assert sent_cancel == [True]


def test_call_retries_channel_busy_until_success(monkeypatch):
    device = _make_device()

    calls = {"count": 0}

    def _fake_do_call(_cmd, _data, _event, _on_keepalive):
        calls["count"] += 1
        if calls["count"] == 1:
            raise CtapError(CtapError.ERR.CHANNEL_BUSY)
        return b"ok"

    monkeypatch.setattr(device, "_do_call", _fake_do_call)

    result = device.call(hid.CTAPHID.PING, b"data")

    assert result == b"ok"
    assert calls["count"] == 2


def test_call_raises_channel_busy_when_cancel_event_is_set(monkeypatch):
    device = _make_device()
    monkeypatch.setattr(
        device,
        "_do_call",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(CtapError(CtapError.ERR.CHANNEL_BUSY)),
    )

    event = Event()
    event.set()

    with pytest.raises(CtapError) as exc_info:
        device.call(hid.CTAPHID.PING, b"data", event=event)

    assert exc_info.value.code == CtapError.ERR.CHANNEL_BUSY


def test_list_devices_and_open_device_use_descriptor_and_connection_backends(monkeypatch):
    descriptors = [
        HidDescriptor("/dev/fake0", 1, 2, 64, 64, "A", "S0"),
        HidDescriptor("/dev/fake1", 3, 4, 64, 64, "B", "S1"),
    ]

    monkeypatch.setattr(hid, "list_descriptors", lambda: descriptors)
    monkeypatch.setattr(hid, "get_descriptor", lambda path: next(d for d in descriptors if d.path == path))
    monkeypatch.setattr(hid, "open_connection", lambda descriptor: f"conn:{descriptor.path}")

    def _fake_init(self, descriptor, connection):
        self.descriptor = descriptor
        self._connection = connection

    monkeypatch.setattr(hid.CtapHidDevice, "__init__", _fake_init)

    discovered = list(hid.CtapHidDevice.list_devices())
    opened = hid.open_device("/dev/fake1")

    assert [d.descriptor.path for d in discovered] == ["/dev/fake0", "/dev/fake1"]
    assert [d._connection for d in discovered] == ["conn:/dev/fake0", "conn:/dev/fake1"]
    assert opened.descriptor.path == "/dev/fake1"
    assert opened._connection == "conn:/dev/fake1"
