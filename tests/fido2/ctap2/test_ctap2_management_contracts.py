from __future__ import annotations

import types

import pytest

from fido2.ctap import CtapError
import fido2.ctap2.bio as bio_module
import fido2.ctap2.config as config_module
import fido2.ctap2.credman as credman_module


class _Protocol:
    VERSION = 7

    def __init__(self):
        self.calls = []

    def authenticate(self, token, message):
        self.calls.append((token, message))
        return b"auth-param"


def _info(*, options=None, versions=None):
    return types.SimpleNamespace(options=options or {}, versions=versions or [])


def test_config_support_checks_and_command_wrappers():
    assert config_module.Config.is_supported(_info(options={"authnrCfg": True})) is True
    assert config_module.Config.is_supported(_info(options={"authnrCfg": False})) is False

    ctap = types.SimpleNamespace(info=_info(options={"authnrCfg": True}), calls=[])
    ctap.config = lambda sub_cmd, params, pin_uv_protocol, pin_uv_param: ctap.calls.append(
        (sub_cmd, params, pin_uv_protocol, pin_uv_param)
    ) or {"ok": True}

    cfg = config_module.Config(ctap)
    cfg.enable_enterprise_attestation()
    cfg.toggle_always_uv()
    cfg.set_min_pin_length(min_pin_length=6, rp_ids=["example.com"], force_change_pin=True)
    cfg.set_min_pin_length()

    assert ctap.calls[0][0] == config_module.Config.CMD.ENABLE_ENTERPRISE_ATT
    assert ctap.calls[1][0] == config_module.Config.CMD.TOGGLE_ALWAYS_UV
    assert ctap.calls[2][0] == config_module.Config.CMD.SET_MIN_PIN_LENGTH
    assert ctap.calls[2][1][config_module.Config.PARAM.NEW_MIN_PIN_LENGTH] == 6
    assert ctap.calls[2][1][config_module.Config.PARAM.MIN_PIN_LENGTH_RPIDS] == ["example.com"]
    assert ctap.calls[2][1][config_module.Config.PARAM.FORCE_CHANGE_PIN] is True
    assert ctap.calls[3][1] == {config_module.Config.PARAM.FORCE_CHANGE_PIN: False}

    with pytest.raises(ValueError, match="does not support Config"):
        config_module.Config(types.SimpleNamespace(info=_info(options={})))


def test_config_call_with_pin_uv_adds_authentication_message():
    protocol = _Protocol()
    ctap = types.SimpleNamespace(info=_info(options={"authnrCfg": True}), calls=[])
    ctap.config = lambda sub_cmd, params, pin_uv_protocol, pin_uv_param: ctap.calls.append(
        (sub_cmd, params, pin_uv_protocol, pin_uv_param)
    ) or {"ok": True}

    cfg = config_module.Config(ctap, protocol, b"token")
    cfg._call(config_module.Config.CMD.SET_MIN_PIN_LENGTH, {1: 8})
    cfg._call(config_module.Config.CMD.TOGGLE_ALWAYS_UV)

    assert ctap.calls[0][2] == protocol.VERSION
    assert ctap.calls[0][3] == b"auth-param"
    assert protocol.calls and protocol.calls[0][0] == b"token"
    assert len(protocol.calls) == 2


def test_bio_enrollment_support_and_constructor_behaviors(monkeypatch):
    assert bio_module.BioEnrollment.is_supported(_info(options={"bioEnroll": True})) is True
    assert (
        bio_module.BioEnrollment.is_supported(
            _info(options={"userVerificationMgmtPreview": True}, versions=["FIDO_2_1_PRE"])
        )
        is True
    )
    assert bio_module.BioEnrollment.is_supported(_info(options={}, versions=[])) is False

    ctap = types.SimpleNamespace(info=_info(options={"bioEnroll": True}))
    ctap.bio_enrollment = lambda **kwargs: {bio_module.BioEnrollment.RESULT.MODALITY: bio_module.BioEnrollment.MODALITY.FINGERPRINT}

    enrollment = bio_module.BioEnrollment(ctap, bio_module.BioEnrollment.MODALITY.FINGERPRINT)
    assert enrollment.modality == bio_module.BioEnrollment.MODALITY.FINGERPRINT

    with pytest.raises(ValueError, match="does not support BioEnroll"):
        bio_module.BioEnrollment(types.SimpleNamespace(info=_info(options={})), bio_module.BioEnrollment.MODALITY.FINGERPRINT)

    ctap_mismatch = types.SimpleNamespace(info=_info(options={"bioEnroll": True}))
    ctap_mismatch.bio_enrollment = lambda **kwargs: {bio_module.BioEnrollment.RESULT.MODALITY: 99}
    with pytest.raises(ValueError, match="Unknown format code"):
        bio_module.BioEnrollment(ctap_mismatch, bio_module.BioEnrollment.MODALITY.FINGERPRINT)

    err = bio_module.CaptureError(5)
    assert err.code == 5
    assert "Fingerprint capture error" in str(err)


def test_fp_enrollment_context_capture_flow_and_cancel():
    class _Bio:
        FEEDBACK = bio_module.FPBioEnrollment.FEEDBACK

        def __init__(self):
            self.calls = []

        def enroll_begin(self, timeout, event=None, on_keepalive=None):
            self.calls.append(("begin", timeout))
            return b"template", self.FEEDBACK.FP_GOOD, 1

        def enroll_capture_next(self, template_id, timeout, event=None, on_keepalive=None):
            self.calls.append(("next", template_id, timeout))
            return self.FEEDBACK.FP_GOOD, 0

        def enroll_cancel(self):
            self.calls.append(("cancel",))

    bio = _Bio()
    ctx = bio_module.FPEnrollmentContext(bio, timeout=500)

    assert ctx.capture() is None
    assert ctx.capture() == b"template"

    ctx.cancel()
    assert ctx.template_id is None

    class _BioBad(_Bio):
        def enroll_begin(self, timeout, event=None, on_keepalive=None):
            return b"template", self.FEEDBACK.FP_TOO_FAST, 2

    with pytest.raises(bio_module.CaptureError):
        bio_module.FPEnrollmentContext(_BioBad()).capture()


def test_fpbio_call_and_management_operations(monkeypatch):
    protocol = _Protocol()
    ctap = types.SimpleNamespace(info=_info(options={"bioEnroll": True}), calls=[])

    def _bio_enrollment(**kwargs):
        ctap.calls.append(kwargs)
        if kwargs.get("get_modality"):
            return {bio_module.BioEnrollment.RESULT.MODALITY: bio_module.BioEnrollment.MODALITY.FINGERPRINT}
        sub_cmd = kwargs.get("sub_cmd")
        if sub_cmd == bio_module.FPBioEnrollment.CMD.GET_SENSOR_INFO:
            return {bio_module.BioEnrollment.RESULT.FINGERPRINT_KIND: 1}
        if sub_cmd == bio_module.FPBioEnrollment.CMD.ENROLL_BEGIN:
            return {
                bio_module.BioEnrollment.RESULT.TEMPLATE_ID: b"id",
                bio_module.BioEnrollment.RESULT.LAST_SAMPLE_STATUS: bio_module.FPBioEnrollment.FEEDBACK.FP_GOOD,
                bio_module.BioEnrollment.RESULT.REMAINING_SAMPLES: 2,
            }
        if sub_cmd == bio_module.FPBioEnrollment.CMD.ENROLL_CAPTURE_NEXT:
            return {
                bio_module.BioEnrollment.RESULT.LAST_SAMPLE_STATUS: bio_module.FPBioEnrollment.FEEDBACK.FP_GOOD,
                bio_module.BioEnrollment.RESULT.REMAINING_SAMPLES: 1,
            }
        if sub_cmd == bio_module.FPBioEnrollment.CMD.ENUMERATE_ENROLLMENTS:
            return {
                bio_module.BioEnrollment.RESULT.TEMPLATE_INFOS: [
                    {
                        bio_module.BioEnrollment.TEMPLATE_INFO.ID: b"a",
                        bio_module.BioEnrollment.TEMPLATE_INFO.NAME: "A",
                    }
                ]
            }
        return {}

    ctap.bio_enrollment = _bio_enrollment

    fp = bio_module.FPBioEnrollment(ctap, protocol, b"token")

    assert str(bio_module.FPBioEnrollment.FEEDBACK.FP_TOO_FAST) == "0x05 - FP_TOO_FAST"

    assert fp.get_fingerprint_sensor_info()[bio_module.BioEnrollment.RESULT.FINGERPRINT_KIND] == 1

    template_id, status, remaining = fp.enroll_begin(timeout=1000)
    assert template_id == b"id"
    assert status == bio_module.FPBioEnrollment.FEEDBACK.FP_GOOD
    assert remaining == 2

    status2, remaining2 = fp.enroll_capture_next(b"id", timeout=500)
    assert status2 == bio_module.FPBioEnrollment.FEEDBACK.FP_GOOD
    assert remaining2 == 1

    status3, remaining3 = fp.enroll_capture_next(b"id")
    assert status3 == bio_module.FPBioEnrollment.FEEDBACK.FP_GOOD
    assert remaining3 == 1

    fp.enroll_cancel()
    ctx = fp.enroll(timeout=777)
    assert isinstance(ctx, bio_module.FPEnrollmentContext)
    assert ctx.timeout == 777

    assert fp.enumerate_enrollments() == {b"a": "A"}

    fp.set_name(b"id", "friendly")
    fp.remove_enrollment(b"id")

    # Authenticated calls should carry protocol version and auth param.
    auth_calls = [call for call in ctap.calls if call.get("pin_uv_protocol") is not None]
    assert auth_calls and all(call["pin_uv_protocol"] == protocol.VERSION for call in auth_calls)

    # INVALID_OPTION should map to empty enrollment list.
    ctap.bio_enrollment = lambda **kwargs: (_ for _ in ()).throw(CtapError(CtapError.ERR.INVALID_OPTION))
    assert fp.enumerate_enrollments() == {}

    ctap.bio_enrollment = lambda **kwargs: (_ for _ in ()).throw(CtapError(CtapError.ERR.INVALID_COMMAND))
    with pytest.raises(CtapError):
        fp.enumerate_enrollments()


def test_credential_management_support_flags_and_enumeration_paths(monkeypatch):
    info_preview = _info(options={"credentialMgmtPreview": True}, versions=["FIDO_2_1_PRE"])
    info_full = _info(options={"credMgmt": True, "perCredMgmtRO": True}, versions=[])

    assert credman_module.CredentialManagement.is_supported(info_preview) is True
    assert credman_module.CredentialManagement.is_supported(info_full) is True
    assert credman_module.CredentialManagement.is_supported(_info(options={}, versions=[])) is False

    assert credman_module.CredentialManagement.is_update_supported(info_full) is True
    assert credman_module.CredentialManagement.is_update_supported(info_preview) is False
    assert credman_module.CredentialManagement.is_readonly_supported(info_full) is True
    assert credman_module.CredentialManagement.is_readonly_supported(_info(options={}, versions=[])) is False

    protocol = _Protocol()
    ctap = types.SimpleNamespace(info=info_full, calls=[])

    def _cred_mgmt(**kwargs):
        ctap.calls.append(kwargs)
        sub_cmd = kwargs.get("sub_cmd")
        if sub_cmd == credman_module.CredentialManagement.CMD.GET_CREDS_METADATA:
            return {credman_module.CredentialManagement.RESULT.EXISTING_CRED_COUNT: 1}
        if sub_cmd == credman_module.CredentialManagement.CMD.ENUMERATE_RPS_BEGIN:
            return {
                credman_module.CredentialManagement.RESULT.TOTAL_RPS: 2,
                credman_module.CredentialManagement.RESULT.RP_ID_HASH: b"h",
            }
        if sub_cmd == credman_module.CredentialManagement.CMD.ENUMERATE_RPS_NEXT:
            return {credman_module.CredentialManagement.RESULT.RP_ID_HASH: b"h2"}
        if sub_cmd == credman_module.CredentialManagement.CMD.ENUMERATE_CREDS_BEGIN:
            return {credman_module.CredentialManagement.RESULT.TOTAL_CREDENTIALS: 2}
        if sub_cmd == credman_module.CredentialManagement.CMD.ENUMERATE_CREDS_NEXT:
            return {credman_module.CredentialManagement.RESULT.CREDENTIAL_ID: {"id": b"x"}}
        return {}

    ctap.credential_mgmt = _cred_mgmt

    mgr = credman_module.CredentialManagement(ctap, protocol, b"token")

    assert mgr.get_metadata()[credman_module.CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 1
    assert len(mgr.enumerate_rps()) == 2
    assert len(mgr.enumerate_creds(b"rp-hash")) == 2

    # No credentials shortcuts.
    monkeypatch.setattr(
        mgr,
        "enumerate_rps_begin",
        lambda: (_ for _ in ()).throw(CtapError(CtapError.ERR.NO_CREDENTIALS)),
    )
    assert mgr.enumerate_rps() == []

    monkeypatch.setattr(
        mgr,
        "enumerate_rps_begin",
        lambda: {credman_module.CredentialManagement.RESULT.TOTAL_RPS: 0},
    )
    assert mgr.enumerate_rps() == []

    monkeypatch.setattr(
        mgr,
        "enumerate_creds_begin",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(CtapError(CtapError.ERR.NO_CREDENTIALS)),
    )
    assert mgr.enumerate_creds(b"rp-hash") == []

    # Re-raise non-NO_CREDENTIALS errors.
    monkeypatch.setattr(
        mgr,
        "enumerate_rps_begin",
        lambda: (_ for _ in ()).throw(CtapError(CtapError.ERR.INVALID_COMMAND)),
    )
    with pytest.raises(CtapError):
        mgr.enumerate_rps()

    monkeypatch.setattr(
        mgr,
        "enumerate_creds_begin",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(CtapError(CtapError.ERR.INVALID_COMMAND)),
    )
    with pytest.raises(CtapError):
        mgr.enumerate_creds(b"rp-hash")


def test_credential_management_delete_and_update_operations(monkeypatch):
    info_full = _info(options={"credMgmt": True}, versions=[])
    protocol = _Protocol()
    ctap = types.SimpleNamespace(info=info_full)
    ctap.credential_mgmt = lambda **kwargs: kwargs

    mgr = credman_module.CredentialManagement(ctap, protocol, b"token")

    calls = []
    monkeypatch.setattr(mgr, "_call", lambda sub_cmd, params=None, auth=True: calls.append((sub_cmd, params, auth)) or {})
    monkeypatch.setattr(
        credman_module.PublicKeyCredentialDescriptor,
        "from_dict",
        classmethod(lambda cls, value: {"cred": value}),
    )
    monkeypatch.setattr(
        credman_module.PublicKeyCredentialUserEntity,
        "from_dict",
        classmethod(lambda cls, value: {"user": value}),
    )
    monkeypatch.setattr(credman_module, "_as_cbor", lambda value: {"cbor": value})

    mgr.delete_cred({"id": "abc", "type": "public-key"})
    assert calls[0][0] == credman_module.CredentialManagement.CMD.DELETE_CREDENTIAL

    mgr.update_user_info(
        {"id": "abc", "type": "public-key"},
        {"id": b"u", "name": "user", "displayName": "User"},
    )
    assert calls[1][0] == credman_module.CredentialManagement.CMD.UPDATE_USER_INFO

    mgr_no_update = credman_module.CredentialManagement(
        types.SimpleNamespace(info=_info(options={"credentialMgmtPreview": True}, versions=["FIDO_2_1_PRE"]), credential_mgmt=lambda **kwargs: kwargs),
        protocol,
        b"token",
    )
    with pytest.raises(ValueError, match="does not support update_user_info"):
        mgr_no_update.update_user_info(
            {"id": "abc", "type": "public-key"},
            {"id": b"u", "name": "user", "displayName": "User"},
        )

    with pytest.raises(ValueError, match="does not support Credential Management"):
        credman_module.CredentialManagement(types.SimpleNamespace(info=_info(options={}, versions=[])), protocol, b"token")
