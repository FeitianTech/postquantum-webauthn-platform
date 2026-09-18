from __future__ import annotations

from typing import Any

from flask import jsonify, request

from ... import metadata, storage
from . import credential_list, credentials_builder_object_impl


def list_credentials_impl():
    metadata_session_id = metadata.ensure_metadata_session_id()
    if request.method == "DELETE":
        removed = 0
        try:
            for username in list(storage.list_credentials(session_id=metadata_session_id).keys()):
                storage.delkey(username, session_id=metadata_session_id)
                removed += 1
        except Exception:
            pass

        return jsonify({"status": "OK", "removed": removed})

    credentials: list[dict[str, Any]] = []

    try:
        for email, user_creds in storage.iter_credentials(session_id=metadata_session_id):
            try:
                for cred in user_creds:
                    try:
                        if isinstance(cred, dict) and "credential_data" in cred:
                            if isinstance(cred["credential_data"], dict):
                                credential_info = credential_list.build_credential_info_from_dict_credential_data_impl(email,
                                    cred,
                                )
                            else:
                                credential_info = credentials_builder_object_impl.build_credential_info_from_object_credential_data_impl(email,
                                    cred,
                                )
                        else:
                            credential_info = credentials_builder_object_impl.build_credential_info_from_bare_credential_impl(email,
                                cred,
                            )

                        credentials.append(credential_info)
                    except Exception:
                        continue
            except Exception:
                continue

    except Exception:
        pass

    return jsonify(credentials)
