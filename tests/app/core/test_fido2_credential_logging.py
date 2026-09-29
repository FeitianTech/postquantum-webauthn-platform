"""fido2's server logs no credential ID once the app is set up.

fido2's ``Fido2Server`` logs each registered and authenticated credential ID at
INFO; ``config.logs`` holds ``fido2.server`` at WARNING, so a root handler at
INFO (``logging.basicConfig``, a platform's log agent) still gets none of them.
"""
from __future__ import annotations

import hashlib
import logging

from fido2.server import Fido2Server
from fido2.webauthn import AttestedCredentialData, PublicKeyCredentialRpEntity

from tests.app.security.ceremony_helpers import (
    ORIGIN,
    RP_ID,
    Authenticator,
    assertion_payload,
)

CHALLENGE = b"\x4c" * 32


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.NOTSET)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def test_an_authentication_logs_no_credential_id_at_info(make_app):
    make_app()
    authenticator = Authenticator(credential_id=hashlib.sha256(b"logged?").digest())
    credential = AttestedCredentialData.create(b"\x00" * 16, authenticator.credential_id, authenticator.cose_key)
    server = Fido2Server(PublicKeyCredentialRpEntity(name="Logging", id=RP_ID), verify_origin=lambda origin: origin == ORIGIN)
    _options, state = server.authenticate_begin([credential], challenge=CHALLENGE)

    root = logging.getLogger()
    handler, level = _Records(), root.level
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    try:
        server.authenticate_complete(state, [credential], assertion_payload(authenticator, challenge=CHALLENGE))
    finally:
        root.removeHandler(handler)
        root.setLevel(level)

    assert logging.getLogger("fido2.server").getEffectiveLevel() == logging.WARNING
    logged = [record.getMessage() for record in handler.records if record.name.startswith("fido2")]
    assert not any(authenticator.credential_id.hex() in message for message in logged), logged
