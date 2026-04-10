from __future__ import annotations

from typing import Any, Dict, List

from .credentials_builder_dict_impl import build_credential_info_from_dict_credential_data_impl
from .credentials_builder_object_impl import (
    build_credential_info_from_bare_credential_impl,
    build_credential_info_from_object_credential_data_impl,
)


def list_credentials_impl(simple_module: Any):
    metadata_session_id = simple_module.ensure_metadata_session_id()
    if simple_module.request.method == "DELETE":
        removed = 0
        try:
            for username in list(simple_module.storage_list_credentials(session_id=metadata_session_id).keys()):
                simple_module.delkey(username, session_id=metadata_session_id)
                removed += 1
        except Exception:
            pass

        return simple_module.jsonify({"status": "OK", "removed": removed})

    credentials: List[Dict[str, Any]] = []

    try:
        for email, user_creds in simple_module.iter_credentials(session_id=metadata_session_id):
            try:
                for cred in user_creds:
                    try:
                        if isinstance(cred, dict) and "credential_data" in cred:
                            if isinstance(cred["credential_data"], dict):
                                credential_info = build_credential_info_from_dict_credential_data_impl(
                                    simple_module,
                                    email,
                                    cred,
                                )
                            else:
                                credential_info = build_credential_info_from_object_credential_data_impl(
                                    simple_module,
                                    email,
                                    cred,
                                )
                        else:
                            credential_info = build_credential_info_from_bare_credential_impl(
                                simple_module,
                                email,
                                cred,
                            )

                        credentials.append(credential_info)
                    except Exception:
                        continue
            except Exception:
                continue

    except Exception:
        pass

    return simple_module.jsonify(credentials)
