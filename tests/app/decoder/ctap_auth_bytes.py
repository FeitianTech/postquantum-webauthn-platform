"""Inputs shared by the decoder tests."""





def _auth_header(flags: int = 0x01, sign_count: int = 1) -> bytes:
    return bytes(range(32)) + bytes([flags]) + sign_count.to_bytes(4, "big")
