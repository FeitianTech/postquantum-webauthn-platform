from __future__ import annotations

import importlib
import sys
import types

import pytest

from fido2.ctap import CtapError, STATUS
from fido2.hid import CAPABILITY, CTAPHID


def _ensure_smartcard_stubs():
    if "smartcard" in sys.modules:
        return

    smartcard = types.ModuleType("smartcard")

    class _System:
        @staticmethod
        def readers():
            return []

    smartcard.System = _System

    card_connection_module = types.ModuleType("smartcard.CardConnection")

    class CardConnection:
        pass

    card_connection_module.CardConnection = CardConnection

    pcsc_package = types.ModuleType("smartcard.pcsc")
    pcsc_exceptions_module = types.ModuleType("smartcard.pcsc.PCSCExceptions")

    class ListReadersException(Exception):
        pass

    pcsc_exceptions_module.ListReadersException = ListReadersException

    sys.modules["smartcard"] = smartcard
    sys.modules["smartcard.CardConnection"] = card_connection_module
    sys.modules["smartcard.pcsc"] = pcsc_package
    sys.modules["smartcard.pcsc.PCSCExceptions"] = pcsc_exceptions_module


_ensure_smartcard_stubs()
pcsc = importlib.import_module("fido2.pcsc")


class _FakeConn:
    def __init__(self):
        self.connected = False
        self.disconnected = False
        self._atr = [0x3B, 0x00]
        self.transmit_result = ([0xAA], 0x90, 0x00)
        self.control_result = [0xBB]

    def connect(self):
        self.connected = True

    def disconnect(self):
        self.disconnected = True

    def getATR(self):
        return self._atr

    def transmit(self, apdu, protocol=None):
        self.last_transmit = (apdu, protocol)
        return self.transmit_result

    def control(self, control_code, control_data):
        self.last_control = (control_code, control_data)
        return self.control_result


def _new_device():
    device = object.__new__(pcsc.CtapPcscDevice)
    device._name = "Reader"
    device._capabilities = CAPABILITY(0)
    device.use_ext_apdu = False
    device.use_nfcctap_getresponse = True
    device._conn = _FakeConn()
    return device


def test_init_connects_and_probes_capabilities(monkeypatch):
    connected = []
    monkeypatch.setattr(pcsc.CtapPcscDevice, "connect", lambda self: connected.append(True))
    monkeypatch.setattr(pcsc.CtapPcscDevice, "call", lambda self, cmd, data=b"": b"ok")

    device = pcsc.CtapPcscDevice(_FakeConn(), "Reader A")

    assert connected == [True]
    assert CAPABILITY.CBOR in device.capabilities
    assert device.version == 2

    monkeypatch.setattr(pcsc.CtapPcscDevice, "connect", lambda self: None)
    monkeypatch.setattr(
        pcsc.CtapPcscDevice,
        "call",
        lambda self, cmd, data=b"": (_ for _ in ()).throw(CtapError(CtapError.ERR.INVALID_COMMAND)),
    )
    with pytest.raises(ValueError, match="Unsupported device"):
        pcsc.CtapPcscDevice(_FakeConn(), "Reader B")


def test_init_keeps_device_when_call_fails_but_capability_already_present(monkeypatch):
    def _fake_connect(self):
        self._capabilities |= CAPABILITY.NMSG

    monkeypatch.setattr(pcsc.CtapPcscDevice, "connect", _fake_connect)
    monkeypatch.setattr(
        pcsc.CtapPcscDevice,
        "call",
        lambda self, cmd, data=b"": (_ for _ in ()).throw(CtapError(CtapError.ERR.INVALID_COMMAND)),
    )

    device = pcsc.CtapPcscDevice(_FakeConn(), "Reader C")
    assert CAPABILITY.NMSG in device.capabilities


def test_basic_properties_and_connection_helpers():
    device = _new_device()

    assert repr(device) == "CtapPcscDevice(Reader)"
    assert device.product_name is None
    assert device.serial_number is None
    assert device.version == 1

    device._capabilities |= CAPABILITY.CBOR
    assert device.version == 2

    device.connect()
    assert device._conn.connected is True

    assert device.get_atr() == b"\x3b\x00"

    device.close()
    assert device._conn.disconnected is True


def test_apdu_and_control_exchange_forward_to_connection():
    device = _new_device()

    apdu_response = device.apdu_exchange(b"\x00\xa4\x04\x00")
    control_response = device.control_exchange(0x1234, b"\x99")

    assert apdu_response == (b"\xaa", 0x90, 0x00)
    assert device._conn.last_transmit == ([0x00, 0xA4, 0x04, 0x00], None)

    assert control_response == b"\xbb"
    assert device._conn.last_control == (0x1234, [0x99])


def test_select_sets_nmsg_and_rejects_failed_selection(monkeypatch):
    device = _new_device()

    monkeypatch.setattr(device, "_chained_apdu_exchange", lambda apdu: (b"U2F_V2", 0x90, 0x00))
    device._select()
    assert CAPABILITY.NMSG in device._capabilities

    monkeypatch.setattr(device, "_chained_apdu_exchange", lambda apdu: (b"", 0x6A, 0x82))
    with pytest.raises(ValueError, match="selection failure"):
        device._select()


def test_chain_apdus_handles_extended_and_short_chaining(monkeypatch):
    device = _new_device()

    device.use_ext_apdu = True
    monkeypatch.setattr(device, "apdu_exchange", lambda apdu: (b"EXT", 0x90, 0x00))
    resp, sw1, sw2 = device._chain_apdus(0x80, 0x10, 0x00, 0x00, b"X" * 300)
    assert (resp, sw1, sw2) == (b"EXT", 0x90, 0x00)

    device.use_ext_apdu = False
    responses = [
        (b"", 0x90, 0x00),
        (b"A", pcsc.SW1_MORE_DATA, 0x02),
        (b"BC", 0x90, 0x00),
    ]

    monkeypatch.setattr(device, "apdu_exchange", lambda apdu: responses.pop(0))
    resp, sw1, sw2 = device._chain_apdus(0x80, 0x10, 0x00, 0x00, b"Y" * 260)

    assert (resp, sw1, sw2) == (b"ABC", 0x90, 0x00)


def test_chain_apdus_returns_early_on_chunk_failure_and_handles_empty_tail(monkeypatch):
    device = _new_device()
    device.use_ext_apdu = False

    # Early return path when intermediate chunking APDU fails.
    monkeypatch.setattr(device, "apdu_exchange", lambda _apdu: (b"ERR", 0x6A, 0x82))
    resp, sw1, sw2 = device._chain_apdus(0x80, 0x10, 0x00, 0x00, b"Z" * 251)
    assert (resp, sw1, sw2) == (b"ERR", 0x6A, 0x82)

    # Branch where `if data:` is false (line 160 false path).
    calls = []
    responses = [(b"FINAL", 0x90, 0x00)]

    def _exchange(apdu):
        calls.append(bytes(apdu))
        return responses.pop(0)

    monkeypatch.setattr(device, "apdu_exchange", _exchange)
    resp, sw1, sw2 = device._chain_apdus(0x80, 0x10, 0x00, 0x00, b"")
    assert (resp, sw1, sw2) == (b"FINAL", 0x90, 0x00)
    # Final APDU should be header + Le only (no Lc/data) when trailing data is empty.
    assert calls[-1] == b"\x80\x10\x00\x00\x00"


def test_chained_apdu_exchange_parses_extended_short_and_header_only(monkeypatch):
    device = _new_device()
    captured = []
    monkeypatch.setattr(
        device,
        "_chain_apdus",
        lambda cla, ins, p1, p2, data=b"": captured.append((cla, ins, p1, p2, data)) or (b"R", 0x90, 0x00),
    )

    ext_apdu = bytes([0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, 0x03, 0x11, 0x22, 0x33])
    short_apdu = bytes([0x00, 0xA4, 0x04, 0x00, 0x02, 0xAA, 0xBB])
    header_only = bytes([0x00, 0xA4, 0x04, 0x00])

    device._chained_apdu_exchange(ext_apdu)
    device._chained_apdu_exchange(short_apdu)
    device._chained_apdu_exchange(header_only)

    assert captured[0] == (0x00, 0xA4, 0x04, 0x00, b"\x11\x22\x33")
    assert captured[1] == (0x00, 0xA4, 0x04, 0x00, b"\xaa\xbb")
    assert captured[2] == (0x00, 0xA4, 0x04, 0x00, b"")


def test_call_apdu_and_call_dispatch_behaviors(monkeypatch):
    device = _new_device()
    monkeypatch.setattr(device, "_chained_apdu_exchange", lambda _apdu: (b"DATA", 0x90, 0x01))
    assert device._call_apdu(b"\x01") == b"DATA\x90\x01"

    monkeypatch.setattr(device, "_call_cbor", lambda *args, **kwargs: b"CBOR")
    monkeypatch.setattr(device, "_call_apdu", lambda _data: b"MSG")
    assert device.call(CTAPHID.CBOR, b"x") == b"CBOR"
    assert device.call(CTAPHID.MSG, b"y") == b"MSG"

    with pytest.raises(CtapError) as exc_info:
        device.call(CTAPHID.PING, b"z")
    assert exc_info.value.code == CtapError.ERR.INVALID_COMMAND


def test_call_cbor_keepalive_cancel_and_error_paths(monkeypatch):
    device = _new_device()

    class _Event:
        def __init__(self):
            self.calls = 0

        def wait(self, _timeout):
            self.calls += 1
            return self.calls >= 2

    calls = []
    responses = [
        (bytes([STATUS.PROCESSING]), 0x91, 0x00),
        (bytes([STATUS.PROCESSING]), 0x91, 0x00),
        (b"done", 0x90, 0x00),
    ]

    def _chain(cla, ins, p1, p2, data=b""):
        calls.append((cla, ins, p1, p2, data))
        return responses.pop(0)

    monkeypatch.setattr(device, "_chain_apdus", _chain)

    keepalives = []
    result = device._call_cbor(b"cmd", _Event(), keepalives.append)

    assert result == b"done"
    assert keepalives == [STATUS.PROCESSING]
    assert any(ins == 0x11 and p1 == 0x11 for (_cla, ins, p1, _p2, _data) in calls)

    # Non-success terminal status maps to CtapError.ERR.OTHER
    monkeypatch.setattr(device, "_chain_apdus", lambda *_args, **_kwargs: (b"", 0x6A, 0x82))
    with pytest.raises(CtapError) as exc_info:
        device._call_cbor(b"cmd")
    assert exc_info.value.code == CtapError.ERR.OTHER


def test_call_cbor_keyboard_interrupt_sends_cancel(monkeypatch):
    device = _new_device()

    calls = []

    def _chain(cla, ins, p1, p2, data=b""):
        calls.append((cla, ins, p1, p2, data))
        if len(calls) == 1:
            return (bytes([STATUS.PROCESSING]), 0x91, 0x00)
        if len(calls) == 2:
            raise KeyboardInterrupt()
        return (b"", 0x90, 0x00)

    monkeypatch.setattr(device, "_chain_apdus", _chain)

    with pytest.raises(KeyboardInterrupt):
        device._call_cbor(b"cmd")

    assert calls[-1] == (0x80, 0x11, 0x11, 0x00, b"")


def test_list_devices_filters_reader_name_and_logs_reader_errors(monkeypatch):
    class _Reader:
        def __init__(self, name):
            self.name = name

        def createConnection(self):
            return f"conn:{self.name}"

    monkeypatch.setattr(pcsc, "_list_readers", lambda: [_Reader("Reader-A"), _Reader("Reader-B")])

    original_init = pcsc.CtapPcscDevice.__init__

    def _fake_init(self, connection, name):
        if name == "Reader-B":
            raise RuntimeError("reader failed")
        self._name = name
        self._conn = connection
        self._capabilities = CAPABILITY(0)

    monkeypatch.setattr(pcsc.CtapPcscDevice, "__init__", _fake_init)

    debug_calls = []
    monkeypatch.setattr(pcsc.logger, "debug", lambda *args, **kwargs: debug_calls.append((args, kwargs)))

    devices = list(pcsc.CtapPcscDevice.list_devices("Reader"))
    assert len(devices) == 1
    assert devices[0]._name == "Reader-A"
    assert debug_calls

    monkeypatch.setattr(pcsc.CtapPcscDevice, "__init__", original_init)


def test_list_devices_skips_non_matching_reader_names(monkeypatch):
    class _Reader:
        def __init__(self, name):
            self.name = name

        def createConnection(self):
            return f"conn:{self.name}"

    monkeypatch.setattr(pcsc, "_list_readers", lambda: [_Reader("Alpha"), _Reader("Beta")])
    devices = list(pcsc.CtapPcscDevice.list_devices("Gamma"))
    assert devices == []


def test_list_readers_retries_after_pcsc_context_reset(monkeypatch):
    calls = {"count": 0}

    def _readers():
        calls["count"] += 1
        if calls["count"] == 1:
            raise pcsc.ListReadersException("stale context")
        return ["reader"]

    monkeypatch.setattr(pcsc.System, "readers", _readers)

    fake_context_module = types.ModuleType("smartcard.pcsc.PCSCContext")

    class _FakePCSCContext:
        instance = object()

    fake_context_module.PCSCContext = _FakePCSCContext
    monkeypatch.setitem(sys.modules, "smartcard.pcsc.PCSCContext", fake_context_module)

    readers = pcsc._list_readers()

    assert readers == ["reader"]
    assert _FakePCSCContext.instance is None


def test_list_readers_raises_original_exception_when_pcsccontext_missing(monkeypatch):
    error = pcsc.ListReadersException("no readers")
    monkeypatch.setattr(pcsc.System, "readers", lambda: (_ for _ in ()).throw(error))

    sys.modules.pop("smartcard.pcsc.PCSCContext", None)

    with pytest.raises(pcsc.ListReadersException) as exc_info:
        pcsc._list_readers()

    assert exc_info.value is error
