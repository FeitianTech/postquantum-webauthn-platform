from pathlib import Path


def pytest_addoption(parser):
    parser.addoption("--reader", action="store")
    parser.addoption("--no-device", action="store_true")
    parser.addoption("--ep-rp-id", action="store")
    parser.addoption("--ccid", action="store_true")
    parser.addoption(
        "--run-device-tests",
        action="store_true",
        help="Include the hardware-in-the-loop tests under tests/device.",
    )


def pytest_ignore_collect(collection_path, config):
    """Skip destructive hardware tests unless explicitly requested."""

    if config.getoption("--run-device-tests"):
        return False

    try:
        path_obj = Path(str(collection_path))
    except TypeError:
        return False

    parts = path_obj.parts
    try:
        tests_index = parts.index("tests")
    except ValueError:
        return False

    return tests_index + 1 < len(parts) and parts[tests_index + 1] == "device"
