"""Tests import the app's own modules plainly: no ``pytest.importorskip`` of them.

``pytest.importorskip("server.app.x")`` turns a module that fails to import -- one
that moved, or an import cycle -- into a skipped test, so the run stays green while
testing less. The app's modules (``server``), the tools and the test helpers are
always importable in this repository; a test imports them like any other module.

A call whose argument is not a literal cannot be checked, so it counts too. The
files below still make such calls, each with its current count: an entry must
equal the file's count (lower it as calls go, remove it at zero), and a file not
listed may make none.
"""
from __future__ import annotations

import ast
from pathlib import Path

TESTS_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = TESTS_ROOT.parent
FIRST_PARTY = ("server", "tools", "tests")

ALLOWED: dict[str, int] = {
    "tests/app/advanced/test_advanced_auth_flows.py": 7,
    "tests/app/advanced/test_advanced_auth_session_edges.py": 9,
    "tests/app/advanced/test_advanced_authenticate_begin_contracts.py": 22,
    "tests/app/advanced/test_advanced_branch_focus_contracts.py": 13,
    "tests/app/advanced/test_advanced_branch_uplift_batch_five.py": 13,
    "tests/app/advanced/test_advanced_branch_uplift_batch_four.py": 6,
    "tests/app/advanced/test_advanced_credential_artifacts.py": 2,
    "tests/app/advanced/test_advanced_helper_contracts.py": 1,
    "tests/app/advanced/test_advanced_register_begin_contracts.py": 27,
    "tests/app/advanced/test_advanced_register_complete_contracts.py": 7,
    "tests/app/conftest.py": 5,
    "tests/app/core/test_app_entrypoint_contracts.py": 1,
    "tests/app/core/test_authentication_failure_payloads.py": 2,
    "tests/app/core/test_background_warmup.py": 2,
    "tests/app/core/test_codec_contracts.py": 26,
    "tests/app/core/test_encoding_module.py": 1,
    "tests/app/core/test_encoding_strictness_contracts.py": 14,
    "tests/app/core/test_general_route_contracts.py": 6,
    "tests/app/core/test_security_headers.py": 6,
    "tests/app/core/test_static_assets.py": 2,
    "tests/app/metadata/conftest.py": 9,
    "tests/app/metadata/test_mds_provisioning.py": 1,
    "tests/app/metadata/test_metadata_bootstrap.py": 7,
    "tests/app/metadata/test_metadata_branch_focus_contracts.py": 2,
    "tests/app/metadata/test_metadata_cleanup_scheduler_contracts.py": 2,
    "tests/app/metadata/test_metadata_internal_contracts.py": 4,
    "tests/app/metadata/test_metadata_internal_edges.py": 1,
    "tests/app/metadata/test_metadata_residual_branches.py": 1,
    "tests/app/metadata/test_metadata_session_store_edges.py": 2,
    "tests/app/metadata/test_metadata_sessions.py": 5,
    "tests/app/metadata/test_packaged_meta_freshness.py": 1,
    "tests/app/metadata/test_session_touch_throttle.py": 3,
    "tests/app/metadata/test_trust_anchor_concurrency.py": 1,
    "tests/app/security/conftest.py": 5,
    "tests/app/security/test_pqc_attestation_reporting.py": 1,
    "tests/app/security/test_sign_count_regression.py": 1,
    "tests/app/session/test_metadata_session_binding.py": 4,
    "tests/app/session/test_session_metadata_store_contracts.py": 1,
    "tests/app/session/test_session_metadata_store_local_edges.py": 1,
    "tests/app/session/test_session_metadata_store_security.py": 6,
    "tests/app/simple/test_simple_auth_flows.py": 6,
    "tests/app/simple/test_simple_binary_parsing_contracts.py": 9,
    "tests/app/simple/test_simple_branch_focus_contracts.py": 5,
    "tests/app/simple/test_simple_register_complete_failure_contracts.py": 2,
    "tests/app/simple/test_simple_residual_branches_batch_three.py": 4,
    "tests/app/simple/test_simple_session_state_and_cleanup.py": 3,
    "tests/app/storage/test_credential_artifacts_store_contracts.py": 4,
    "tests/app/storage/test_frontend_payload_contracts.py": 9,
    "tests/app/storage/test_register_storage_failure_contracts.py": 10,
    "tests/app/storage/test_storage_local_contracts.py": 2,
    "tests/app/storage/test_storage_security_contracts.py": 2,
}


def _first_party_skips(tree: ast.AST) -> int:
    found = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name != "importorskip":
            continue
        target = node.args[0]
        if isinstance(target, ast.Constant) and isinstance(target.value, str):
            if target.value.split(".")[0] not in FIRST_PARTY:
                continue
        found += 1
    return found


def _measure() -> dict[str, int]:
    measured = {}
    for source in sorted(TESTS_ROOT.rglob("*.py")):
        count = _first_party_skips(ast.parse(source.read_text(), filename=str(source)))
        if count:
            measured[source.relative_to(REPO_ROOT).as_posix()] = count
    return measured


def test_no_test_skips_on_importing_the_app():
    measured = _measure()
    problems = []
    for path, count in sorted(measured.items()):
        allowed = ALLOWED.get(path, 0)
        if count > allowed:
            problems.append(f"{path}: {count} importorskip of the app's own modules; import them plainly")
        elif count < allowed:
            problems.append(f"{path}: {count} left, listed at {allowed}: lower its entry")
    for path in sorted(set(ALLOWED) - set(measured)):
        problems.append(f"{path} makes no such call now: remove its entry")
    assert not problems, "\n".join(problems)


def test_the_check_counts_first_party_and_unreadable_targets_only():
    source = (
        "import pytest\n"
        "pytest.importorskip('server.app.app')\n"
        "pytest.importorskip('tests.app.helpers')\n"
        "pytest.importorskip(name)\n"
        "pytest.importorskip('hypothesis')\n"
        "pytest.importorskip('gunicorn')\n"
    )
    assert _first_party_skips(ast.parse(source)) == 3
