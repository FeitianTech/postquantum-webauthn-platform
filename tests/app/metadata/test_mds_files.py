"""``mds.files``: the snapshot's files, and the HTTP dates their metas hold."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from server.app.mds import files as mds_files

NOON_UTC = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "header",
    [
        "Wed, 01 Apr 2026 12:00:00 GMT",
        "Wed, 01 Apr 2026 14:00:00 +0200",
        # RFC 5322's -0000: a time with no zone given, read as UTC.
        "Wed, 01 Apr 2026 12:00:00 -0000",
    ],
)
def test_an_http_date_is_read_as_an_aware_utc_time(header):
    assert mds_files.parse_http_datetime(header) == NOON_UTC
    assert mds_files.format_last_modified(header) == "2026-04-01T12:00:00+00:00"


@pytest.mark.parametrize("header", [None, "", "bad"])
def test_a_header_that_is_no_date_is_no_time_and_kept_as_it_is(header):
    assert mds_files.parse_http_datetime(header) is None
    assert mds_files.format_last_modified(header) == header
