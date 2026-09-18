"""Signature-counter comparison (WebAuthn L3 §7.2 step 21), shared by both flows.

The simple flow rejects on :data:`SIGN_COUNT_REGRESSED`; the advanced request
editor only reports the status.
"""
from __future__ import annotations

__all__ = [
    "SIGN_COUNT_NOT_SUPPORTED",
    "SIGN_COUNT_OK",
    "SIGN_COUNT_REGRESSED",
    "sign_count_status",
]

#: The counter strictly increased.
SIGN_COUNT_OK = "ok"
#: The counter did not increase: a possible cloned authenticator.
SIGN_COUNT_REGRESSED = "regressed"
#: Stored and received are both 0: the authenticator has no counter (synced
#: passkeys always report 0), so there is nothing to compare.
SIGN_COUNT_NOT_SUPPORTED = "not-supported"


def sign_count_status(stored: int, received: int) -> str:
    if stored == 0 and received == 0:
        return SIGN_COUNT_NOT_SUPPORTED
    if received <= stored:
        return SIGN_COUNT_REGRESSED
    return SIGN_COUNT_OK
