# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from fido2.hid.base import parse_report_descriptor
import pytest


def test_parse_report_descriptor_1():
    max_in_size, max_out_size = parse_report_descriptor(
        bytes.fromhex(
            "06d0f10901a1010920150026ff007508954081020921150026ff00750895409102c0"
        )
    )

    assert max_in_size == 64
    assert max_out_size == 64


def test_parse_report_descriptor_2():
    with pytest.raises(ValueError):
        parse_report_descriptor(
            bytes.fromhex(
                "05010902a1010901a10005091901290515002501950575018102950175038101"
                "05010930093109381581257f750895038106c0c0"
            )
        )


def test_file_descriptor_connection_init(monkeypatch):
    """Test FileCtapHidConnection initialization."""
    from fido2.hid.base import FileCtapHidConnection
    from unittest.mock import Mock, MagicMock
    import os
    
    # Mock os.open
    mock_fd = 12345
    mock_open = Mock(return_value=mock_fd)
    monkeypatch.setattr(os, "open", mock_open)
    
    # Create a mock descriptor
    descriptor = MagicMock()
    descriptor.path = "/dev/hidraw0"
    descriptor.report_size_in = 64
    
    # Create connection
    conn = FileCtapHidConnection(descriptor)
    
    # Verify os.open was called
    mock_open.assert_called_once_with("/dev/hidraw0", os.O_RDWR)
    assert conn.handle == mock_fd
    assert conn.descriptor == descriptor


def test_file_descriptor_connection_close(monkeypatch):
    """Test FileCtapHidConnection close."""
    from fido2.hid.base import FileCtapHidConnection
    from unittest.mock import Mock, MagicMock
    import os
    
    # Mock os.open and os.close
    mock_fd = 12345
    monkeypatch.setattr(os, "open", Mock(return_value=mock_fd))
    mock_close = Mock()
    monkeypatch.setattr(os, "close", mock_close)
    
    # Create a mock descriptor
    descriptor = MagicMock()
    descriptor.path = "/dev/hidraw0"
    
    # Create and close connection
    conn = FileCtapHidConnection(descriptor)
    conn.close()
    
    # Verify os.close was called with the handle
    mock_close.assert_called_once_with(mock_fd)


def test_file_descriptor_connection_write_packet(monkeypatch):
    """Test FileCtapHidConnection write_packet."""
    from fido2.hid.base import FileCtapHidConnection
    from unittest.mock import Mock, MagicMock
    import os
    
    # Mock os.open and os.write
    mock_fd = 12345
    monkeypatch.setattr(os, "open", Mock(return_value=mock_fd))
    
    data = b"\x01\x02\x03\x04"
    mock_write = Mock(return_value=len(data))
    monkeypatch.setattr(os, "write", mock_write)
    
    # Create a mock descriptor
    descriptor = MagicMock()
    descriptor.path = "/dev/hidraw0"
    
    # Create connection and write
    conn = FileCtapHidConnection(descriptor)
    conn.write_packet(data)
    
    # Verify os.write was called correctly
    mock_write.assert_called_once_with(mock_fd, data)


def test_file_descriptor_connection_write_packet_partial(monkeypatch):
    """Test FileCtapHidConnection write_packet with partial write."""
    from fido2.hid.base import FileCtapHidConnection
    from unittest.mock import Mock, MagicMock
    import os
    import pytest
    
    # Mock os.open and os.write (partial write)
    mock_fd = 12345
    monkeypatch.setattr(os, "open", Mock(return_value=mock_fd))
    
    data = b"\x01\x02\x03\x04"
    mock_write = Mock(return_value=2)  # Only wrote 2 bytes instead of 4
    monkeypatch.setattr(os, "write", mock_write)
    
    # Create a mock descriptor
    descriptor = MagicMock()
    descriptor.path = "/dev/hidraw0"
    
    # Create connection and try to write
    conn = FileCtapHidConnection(descriptor)
    
    with pytest.raises(OSError, match="failed to write entire packet"):
        conn.write_packet(data)


def test_file_descriptor_connection_read_packet(monkeypatch):
    """Test FileCtapHidConnection read_packet."""
    from fido2.hid.base import FileCtapHidConnection
    from unittest.mock import Mock, MagicMock
    import os
    
    # Mock os.open and os.read
    mock_fd = 12345
    monkeypatch.setattr(os, "open", Mock(return_value=mock_fd))
    
    read_data = b"\x01\x02\x03\x04" + b"\x00" * 60
    mock_read = Mock(return_value=read_data)
    monkeypatch.setattr(os, "read", mock_read)
    
    # Create a mock descriptor
    descriptor = MagicMock()
    descriptor.path = "/dev/hidraw0"
    descriptor.report_size_in = 64
    
    # Create connection and read
    conn = FileCtapHidConnection(descriptor)
    result = conn.read_packet()
    
    # Verify os.read was called correctly
    mock_read.assert_called_once_with(mock_fd, 64)
    assert result == read_data
