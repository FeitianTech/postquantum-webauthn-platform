from __future__ import annotations

import ctypes
from queue import Queue

import pytest

from fido2.hid.base import HidDescriptor


macos = pytest.importorskip("fido2.hid.macos")


def test_hid_read_callback_enqueues_report_bytes():
    read_queue = Queue()
    report = (ctypes.c_uint8 * 3)(1, 2, 3)

    macos._hid_read_callback(read_queue, 0, None, 0, 0, report, 3)

    assert read_queue.get_nowait() == b"\x01\x02\x03"


def test_hid_removal_callback_stops_run_loop(monkeypatch):
    class _Device:
        run_loop_ref = "runloop-ref"

    stopped = []
    monkeypatch.setattr(macos.cf, "CFRunLoopStop", lambda ref: stopped.append(ref))

    macos._hid_removal_callback(_Device(), 0, None)

    assert stopped == ["runloop-ref"]


def test_dev_read_thread_handles_missing_run_loop(monkeypatch):
    device = type("Device", (), {"read_queue": Queue(), "handle": 1})()
    monkeypatch.setattr(macos.cf, "CFRunLoopGetCurrent", lambda: None)

    errors = []
    monkeypatch.setattr(macos.logger, "error", lambda *args, **kwargs: errors.append((args, kwargs)))

    macos._dev_read_thread(device)

    assert len(errors) == 1


def test_dev_read_thread_retries_then_exits_after_data(monkeypatch):
    device = type("Device", (), {"read_queue": Queue(), "handle": 2, "run_loop_ref": None})()

    monkeypatch.setattr(macos.cf, "CFRunLoopGetCurrent", lambda: "runloop")
    monkeypatch.setattr(macos.iokit, "IOHIDDeviceScheduleWithRunLoop", lambda *_args: None)
    monkeypatch.setattr(macos.iokit, "IOHIDDeviceRegisterRemovalCallback", lambda *_args: None)
    monkeypatch.setattr(macos.iokit, "IOHIDDeviceUnscheduleFromRunLoop", lambda *_args: None)

    debug_calls = []
    monkeypatch.setattr(macos.logger, "debug", lambda *args, **kwargs: debug_calls.append((args, kwargs)))

    run_calls = {"count": 0}

    def _run_in_mode(*_args):
        run_calls["count"] += 1
        if run_calls["count"] == 2:
            device.read_queue.put(b"payload")
        return macos.K_CF_RUN_LOOP_RUN_HANDLED_SOURCE

    monkeypatch.setattr(macos.cf, "CFRunLoopRunInMode", _run_in_mode)

    macos._dev_read_thread(device)

    assert run_calls["count"] == 2
    assert len(debug_calls) == 1


def test_dev_read_thread_logs_unexpected_exit(monkeypatch):
    device = type("Device", (), {"read_queue": Queue(), "handle": 3, "run_loop_ref": None})()

    monkeypatch.setattr(macos.cf, "CFRunLoopGetCurrent", lambda: "runloop")
    monkeypatch.setattr(macos.iokit, "IOHIDDeviceScheduleWithRunLoop", lambda *_args: None)
    monkeypatch.setattr(macos.iokit, "IOHIDDeviceRegisterRemovalCallback", lambda *_args: None)
    monkeypatch.setattr(macos.iokit, "IOHIDDeviceUnscheduleFromRunLoop", lambda *_args: None)
    monkeypatch.setattr(macos.cf, "CFRunLoopRunInMode", lambda *_args: macos.K_CF_RUN_LOOP_RUN_TIMED_OUT)

    errors = []
    monkeypatch.setattr(macos.logger, "error", lambda *args, **kwargs: errors.append((args, kwargs)))

    macos._dev_read_thread(device)

    assert len(errors) == 1


def test_dev_read_thread_exits_after_max_retries_without_data(monkeypatch):
    device = type("Device", (), {"read_queue": Queue(), "handle": 4, "run_loop_ref": None})()

    monkeypatch.setattr(macos.cf, "CFRunLoopGetCurrent", lambda: "runloop")
    monkeypatch.setattr(macos.iokit, "IOHIDDeviceScheduleWithRunLoop", lambda *_args: None)
    monkeypatch.setattr(macos.iokit, "IOHIDDeviceRegisterRemovalCallback", lambda *_args: None)

    unscheduled = []
    monkeypatch.setattr(
        macos.iokit,
        "IOHIDDeviceUnscheduleFromRunLoop",
        lambda *args: unscheduled.append(args),
    )
    monkeypatch.setattr(macos.cf, "CFRunLoopRunInMode", lambda *_args: macos.K_CF_RUN_LOOP_RUN_HANDLED_SOURCE)

    debug_calls = []
    monkeypatch.setattr(macos.logger, "debug", lambda *args, **kwargs: debug_calls.append((args, kwargs)))

    macos._dev_read_thread(device)

    assert len(debug_calls) == 2
    assert len(unscheduled) == 1


def test_macos_connection_write_and_read_behaviors(monkeypatch):
    connection = object.__new__(macos.MacCtapHidConnection)
    connection.handle = "handle"
    connection.descriptor = HidDescriptor("1", 1, 2, 4, 4, "prod", "serial")
    connection.read_queue = Queue()
    connection.in_report_buffer = (ctypes.c_uint8 * 4)()

    monkeypatch.setattr(macos.iokit, "IOHIDDeviceSetReport", lambda *_args: macos.K_IO_RETURN_SUCCESS)
    connection.write_packet(b"\x00\x01")

    monkeypatch.setattr(macos.iokit, "IOHIDDeviceSetReport", lambda *_args: 99)
    with pytest.raises(OSError, match="Failed to write report"):
        connection.write_packet(b"\x00\x01")

    connection.read_queue.put(b"immediate")
    assert connection.read_packet() == b"immediate"

    # Empty queue -> spin read thread path
    monkeypatch.setattr(macos, "_dev_read_thread", lambda conn: conn.read_queue.put(b"threaded"))

    class _Thread:
        def __init__(self, target, args):
            self.target = target
            self.args = args

        def start(self):
            self.target(*self.args)

        def join(self):
            return None

    monkeypatch.setattr(macos.threading, "Thread", _Thread)
    assert connection.read_packet() == b"threaded"

    monkeypatch.setattr(macos, "_dev_read_thread", lambda _conn: None)
    with pytest.raises(OSError, match="Failed reading a response"):
        connection.read_packet()


def test_macos_connection_close_unregisters_input_callback(monkeypatch):
    connection = object.__new__(macos.MacCtapHidConnection)
    connection.handle = "handle"
    connection.descriptor = HidDescriptor("1", 1, 2, 5, 5, "prod", "serial")
    connection.in_report_buffer = (ctypes.c_uint8 * 5)()

    calls = []
    monkeypatch.setattr(macos.iokit, "IOHIDDeviceRegisterInputReportCallback", lambda *args: calls.append(args))

    connection.close()

    assert len(calls) == 1


def test_macos_connection_init_registers_callback_and_handles_open_failure(monkeypatch):
    descriptor = HidDescriptor("123", 1, 2, 6, 6, "prod", "serial")

    monkeypatch.setattr(macos, "_handle_from_path", lambda _path: "resolved-handle")
    monkeypatch.setattr(macos.iokit, "IOHIDDeviceOpen", lambda *_args: macos.K_IO_RETURN_SUCCESS)

    callback_calls = []
    monkeypatch.setattr(
        macos.iokit,
        "IOHIDDeviceRegisterInputReportCallback",
        lambda *args: callback_calls.append(args),
    )

    connection = macos.MacCtapHidConnection(descriptor)
    assert connection.handle == "resolved-handle"
    assert connection.descriptor is descriptor
    assert connection.read_queue.qsize() == 0
    assert connection.run_loop_ref is None
    assert len(callback_calls) == 1

    monkeypatch.setattr(macos.iokit, "IOHIDDeviceOpen", lambda *_args: 9)
    with pytest.raises(OSError, match="Failed to open device for communication"):
        macos.MacCtapHidConnection(descriptor)


def test_open_connection_returns_macos_connection_wrapper(monkeypatch):
    class _FakeConnection:
        def __init__(self, descriptor):
            self.descriptor = descriptor

    monkeypatch.setattr(macos, "MacCtapHidConnection", _FakeConnection)

    descriptor = HidDescriptor("123", 1, 2, 4, 4, "prod", None)
    connection = macos.open_connection(descriptor)

    assert isinstance(connection, _FakeConnection)
    assert connection.descriptor is descriptor


def test_get_int_property_success_and_error_paths(monkeypatch):
    monkeypatch.setattr(macos.cf, "CFStringCreateWithCString", lambda *_args: "cf-key")
    monkeypatch.setattr(macos.cf, "CFRelease", lambda *_args: None)

    monkeypatch.setattr(macos.iokit, "IOHIDDeviceGetProperty", lambda *_args: None)
    with pytest.raises(ValueError, match="not found"):
        macos.get_int_property("dev", b"k")

    monkeypatch.setattr(macos.iokit, "IOHIDDeviceGetProperty", lambda *_args: "type-ref")
    monkeypatch.setattr(macos.cf, "CFGetTypeID", lambda _ref: 10)
    monkeypatch.setattr(macos.cf, "CFNumberGetTypeID", lambda: 20)
    with pytest.raises(OSError, match="Expected number type"):
        macos.get_int_property("dev", b"k")

    monkeypatch.setattr(macos.cf, "CFGetTypeID", lambda _ref: 20)
    monkeypatch.setattr(macos.cf, "CFNumberGetValue", lambda *_args: 0)
    with pytest.raises(OSError, match="Failed to read property"):
        macos.get_int_property("dev", b"k")

    def _number_get_value(_type_ref, _num_type, out_ptr):
        ctypes.cast(out_ptr, ctypes.POINTER(ctypes.c_int32)).contents.value = 42
        return 1

    monkeypatch.setattr(macos.cf, "CFNumberGetValue", _number_get_value)
    assert macos.get_int_property("dev", b"k") == 42


def test_get_string_property_success_and_error_paths(monkeypatch):
    monkeypatch.setattr(macos.cf, "CFStringCreateWithCString", lambda *_args: "cf-key")
    monkeypatch.setattr(macos.cf, "CFRelease", lambda *_args: None)

    monkeypatch.setattr(macos.iokit, "IOHIDDeviceGetProperty", lambda *_args: None)
    assert macos.get_string_property("dev", b"k") is None

    monkeypatch.setattr(macos.iokit, "IOHIDDeviceGetProperty", lambda *_args: "type-ref")
    monkeypatch.setattr(macos.cf, "CFGetTypeID", lambda _ref: 10)
    monkeypatch.setattr(macos.cf, "CFStringGetTypeID", lambda: 20)
    with pytest.raises(OSError, match="Expected string type"):
        macos.get_string_property("dev", b"k")

    monkeypatch.setattr(macos.cf, "CFGetTypeID", lambda _ref: 20)
    monkeypatch.setattr(macos.cf, "CFStringGetCString", lambda *_args: False)
    assert macos.get_string_property("dev", b"k") is None

    def _string_get_cstring(_type_ref, out_buf, _size, _encoding):
        out_buf.raw = b"hello\x00" + b"\x00" * (len(out_buf.raw) - 6)
        return True

    monkeypatch.setattr(macos.cf, "CFStringGetCString", _string_get_cstring)
    assert macos.get_string_property("dev", b"k") == "hello"

    def _invalid_utf8(_type_ref, out_buf, _size, _encoding):
        out_buf.raw = b"\xff\x00" + b"\x00" * (len(out_buf.raw) - 2)
        return True

    monkeypatch.setattr(macos.cf, "CFStringGetCString", _invalid_utf8)
    assert macos.get_string_property("dev", b"k") is None


def test_get_device_id_and_handle_resolution_paths(monkeypatch):
    monkeypatch.setattr(macos.iokit, "IOHIDDeviceGetService", lambda _handle: "service")

    def _registry_entry_success(_service, out_ptr):
        ctypes.cast(out_ptr, ctypes.POINTER(ctypes.c_uint64)).contents.value = 1234
        return macos.K_IO_RETURN_SUCCESS

    monkeypatch.setattr(macos.iokit, "IORegistryEntryGetRegistryEntryID", _registry_entry_success)
    assert macos.get_device_id("handle") == 1234

    monkeypatch.setattr(macos.iokit, "IORegistryEntryGetRegistryEntryID", lambda *_args: 7)
    with pytest.raises(OSError, match="Failed to obtain IORegistry entry ID"):
        macos.get_device_id("handle")

    monkeypatch.setattr(macos.iokit, "IORegistryEntryIDMatching", lambda _entry_id: "matching")
    monkeypatch.setattr(macos.iokit, "IOServiceGetMatchingService", lambda *_args: 0)
    with pytest.raises(OSError, match="does not match"):
        macos._handle_from_path("99")

    monkeypatch.setattr(macos.iokit, "IOServiceGetMatchingService", lambda *_args: "service")
    monkeypatch.setattr(macos.iokit, "IOHIDDeviceCreate", lambda *_args: "device-handle")
    assert macos._handle_from_path("99") == "device-handle"


def test_descriptor_helpers_and_list_descriptors_contract(monkeypatch):
    # _get_descriptor_from_handle success path
    int_values = {
        macos.HID_DEVICE_PROPERTY_PRIMARY_USAGE_PAGE: macos.FIDO_USAGE_PAGE,
        macos.HID_DEVICE_PROPERTY_PRIMARY_USAGE: macos.FIDO_USAGE,
        macos.HID_DEVICE_PROPERTY_VENDOR_ID: 10,
        macos.HID_DEVICE_PROPERTY_PRODUCT_ID: 20,
        macos.HID_DEVICE_PROPERTY_MAX_INPUT_REPORT_SIZE: 64,
        macos.HID_DEVICE_PROPERTY_MAX_OUTPUT_REPORT_SIZE: 65,
    }
    monkeypatch.setattr(macos, "get_int_property", lambda _h, key: int_values[key])
    monkeypatch.setattr(
        macos,
        "get_string_property",
        lambda _h, key: "prod" if key == macos.HID_DEVICE_PROPERTY_PRODUCT else "serial",
    )
    monkeypatch.setattr(macos, "get_device_id", lambda _h: 777)

    descriptor = macos._get_descriptor_from_handle("handle")
    assert descriptor == HidDescriptor("777", 10, 20, 64, 65, "prod", "serial")

    int_values[macos.HID_DEVICE_PROPERTY_PRIMARY_USAGE] = 0
    with pytest.raises(ValueError, match="Not a CTAP device"):
        macos._get_descriptor_from_handle("handle")

    # get_descriptor delegates through path->handle resolution
    monkeypatch.setattr(macos, "_handle_from_path", lambda _p: "resolved")
    monkeypatch.setattr(macos, "_get_descriptor_from_handle", lambda _h: "desc")
    assert macos.get_descriptor("101") == "desc"

    # list_descriptors: manager acquisition failure
    monkeypatch.setattr(macos.iokit, "IOHIDManagerCreate", lambda *_args: None)
    with pytest.raises(OSError, match="Unable to obtain HID manager"):
        macos.list_descriptors()

    # list_descriptors: copy devices failure
    monkeypatch.setattr(macos.iokit, "IOHIDManagerCreate", lambda *_args: "mgr")
    monkeypatch.setattr(macos.iokit, "IOHIDManagerSetDeviceMatching", lambda *_args: None)
    monkeypatch.setattr(macos.iokit, "IOHIDManagerCopyDevices", lambda *_args: None)
    monkeypatch.setattr(macos.cf, "CFRelease", lambda *_args: None)
    with pytest.raises(OSError, match="Failed to obtain devices"):
        macos.list_descriptors()

    # list_descriptors: one CTAP descriptor and one non-CTAP handle
    handles = [ctypes.pointer(macos._IOHIDDevice()), ctypes.pointer(macos._IOHIDDevice())]
    monkeypatch.setattr(macos.iokit, "IOHIDManagerCopyDevices", lambda *_args: "set")
    monkeypatch.setattr(macos.iokit, "CFSetGetCount", lambda *_args: 2)

    def _set_values(_set_ref, out_array):
        out_array[0] = handles[0]
        out_array[1] = handles[1]

    monkeypatch.setattr(macos.iokit, "CFSetGetValues", _set_values)

    call_count = {"n": 0}

    def _descriptor_from_handle(_handle):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return HidDescriptor("1", 1, 2, 64, 64, "ok", None)
        raise ValueError("not ctap")

    monkeypatch.setattr(macos, "_get_descriptor_from_handle", _descriptor_from_handle)

    descriptors = macos.list_descriptors()
    assert len(descriptors) == 1
    assert descriptors[0].path == "1"
