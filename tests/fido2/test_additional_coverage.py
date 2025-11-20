"""Additional tests to improve coverage for fido2 modules."""

from __future__ import annotations

import unittest
from unittest import mock

import pytest

from fido2.rpid import verify_rp_id
from fido2.ctap import STATUS, CtapError, CtapDevice
from fido2.ctap1 import ApduError, RegistrationData, SignatureData


class TestRpIdAdditional(unittest.TestCase):
    """Additional tests for rpid.py to achieve 100% coverage."""
    
    def test_empty_rp_id(self):
        """Test that empty RP ID is rejected (line 60-61)."""
        # This tests the missing line 61
        self.assertFalse(verify_rp_id("", "https://example.com"))


class TestCtapAdditional(unittest.TestCase):
    """Additional tests for ctap.py to achieve higher coverage."""
    
    def test_status_enum_values(self):
        """Test STATUS enum values (lines 40-41)."""
        assert STATUS.PROCESSING == 1
        assert STATUS.UPNEEDED == 2
    
    def test_status_str(self):
        """Test STATUS string representation."""
        # These lines weren't covered
        # STATUS is just an IntEnum, so str() returns the value
        assert str(STATUS.PROCESSING) == "1"
        assert str(STATUS.UPNEEDED) == "2"
    
    def test_ctap_error_unknown_err_value(self):
        """Test CtapError.UNKNOWN_ERR value property (lines 101-102)."""
        unknown_err = CtapError.UNKNOWN_ERR(0xFF)
        assert unknown_err.value == 0xFF
    
    def test_ctap_error_unknown_err_repr(self):
        """Test CtapError.UNKNOWN_ERR repr (lines 104-105)."""
        unknown_err = CtapError.UNKNOWN_ERR(0xAB)
        repr_str = repr(unknown_err)
        assert "UNKNOWN" in repr_str
        assert "171" in repr_str or "AB" in repr_str  # Decimal or hex
    
    def test_ctap_error_unknown_err_str(self):
        """Test CtapError.UNKNOWN_ERR str (lines 107-108)."""
        unknown_err = CtapError.UNKNOWN_ERR(0x42)
        str_repr = str(unknown_err)
        assert "0x42" in str_repr
        assert "UNKNOWN" in str_repr
    
    def test_ctap_error_with_unknown_code(self):
        """Test CtapError with unknown error code (lines 179-180)."""
        # Create error with unknown code
        error = CtapError(0xAB)
        assert isinstance(error.code, CtapError.UNKNOWN_ERR)
        assert error.code == 0xAB
        assert "CTAP error" in str(error)
    
    def test_ctap_device_context_manager(self):
        """Test CtapDevice context manager (lines 80-84)."""
        class TestDevice(CtapDevice):
            def __init__(self):
                self.closed = False
                
            @property
            def capabilities(self):
                return 0
            
            def call(self, cmd, data=b"", event=None, on_keepalive=None):
                return b""
            
            def close(self):
                self.closed = True
            
            @classmethod
            def list_devices(cls):
                yield TestDevice()
        
        device = TestDevice()
        assert not device.closed
        
        with device as d:
            assert d is device
            assert not device.closed
        
        assert device.closed


class TestCtap1Additional(unittest.TestCase):
    """Additional tests for ctap1.py to achieve higher coverage."""
    
    def test_apdu_error_repr(self):
        """Test ApduError repr (line 64)."""
        error = ApduError(0x6A80, b"test data")
        repr_str = repr(error)
        assert "0x6A80" in repr_str
        assert "9" in repr_str  # Length of "test data"
    
    def test_registration_data_invalid_reserved_byte(self):
        """Test RegistrationData with invalid reserved byte (line 89)."""
        # Create data with wrong reserved byte
        invalid_data = b"\x04" + b"\x00" * 100
        with pytest.raises(ValueError, match="Reserved byte"):
            RegistrationData(invalid_data)
    
    def test_registration_data_b64(self):
        """Test RegistrationData b64 property (lines 105-107)."""
        # Use valid test data from existing test
        test_data = bytes.fromhex(
            "0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c253082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804a6d3d3961ef871"
        )
        reg_data = RegistrationData(test_data)
        b64_str = reg_data.b64
        assert isinstance(b64_str, str)
        assert len(b64_str) > 0
    
    def test_registration_data_from_b64(self):
        """Test RegistrationData.from_b64 (lines 126-132)."""
        test_data = bytes.fromhex(
            "0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c253082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804a6d3d3961ef871"
        )
        reg_data = RegistrationData(test_data)
        b64_str = reg_data.b64
        
        # Now decode it back
        decoded = RegistrationData.from_b64(b64_str)
        assert decoded.public_key == reg_data.public_key
        assert decoded.key_handle == reg_data.key_handle
    
    def test_signature_data_b64(self):
        """Test SignatureData b64 property (lines 158-160)."""
        test_data = bytes.fromhex(
            "0100000001304402204b5f0cd17534cedd8c34ee09570ef542a353df4436030ce43d406de870b847780220267bb998fac9b7266eb60e7cb0b5eabdfd5ba9614f53c7b22272ec10047a923f"
        )
        sig_data = SignatureData(test_data)
        b64_str = sig_data.b64
        assert isinstance(b64_str, str)
        assert len(b64_str) > 0
    
    def test_signature_data_from_b64(self):
        """Test SignatureData.from_b64 (lines 174-180)."""
        test_data = bytes.fromhex(
            "0100000001304402204b5f0cd17534cedd8c34ee09570ef542a353df4436030ce43d406de870b847780220267bb998fac9b7266eb60e7cb0b5eabdfd5ba9614f53c7b22272ec10047a923f"
        )
        sig_data = SignatureData(test_data)
        b64_str = sig_data.b64
        
        # Now decode it back
        decoded = SignatureData.from_b64(b64_str)
        assert decoded.user_presence == sig_data.user_presence
        assert decoded.counter == sig_data.counter
        assert decoded.signature == sig_data.signature
