from __future__ import annotations

from typing import Any, List, Mapping, Optional


def _resolve_uv_required(
    state: Optional[Mapping[str, Any]],
    public_key_options: Optional[Mapping[str, Any]],
) -> bool:
    uv_required = False
    if isinstance(state, Mapping):
        state_uv = state.get("user_verification")
        if getattr(state_uv, "value", None) == "required" or state_uv == "required":
            uv_required = True

    if not uv_required and isinstance(public_key_options, Mapping):
        uv_setting: Optional[str] = None
        authenticator_selection = public_key_options.get("authenticatorSelection")
        if isinstance(authenticator_selection, Mapping):
            uv_setting = authenticator_selection.get("userVerification")
        if not uv_setting:
            uv_setting = public_key_options.get("userVerification")
        if isinstance(uv_setting, str) and uv_setting.lower() == "required":
            uv_required = True

    return uv_required


def _collect_allowed_algorithms(
    public_key_options: Optional[Mapping[str, Any]],
) -> List[int]:
    allowed_algorithms: List[int] = []
    if isinstance(public_key_options, Mapping):
        params = public_key_options.get("pubKeyCredParams")
        if isinstance(params, list):
            for param in params:
                if isinstance(param, Mapping) and isinstance(param.get("alg"), int):
                    allowed_algorithms.append(param["alg"])
    return allowed_algorithms
