"""No test may patch an attribute that does not exist, unless it says why it must not.

``monkeypatch.setattr(target, name, value, raising=False)`` succeeds when
``target`` has no ``name``: it just adds one. When the code under test moves or
renames ``name``, such a patch attaches to nothing the code reads, and the test
goes on passing while it tests nothing. ``mock.patch(..., create=True)`` does the
same. Phase 18 removed 403 of them; this keeps them out.

The few patches that must create an attribute are listed below with the reason
the attribute cannot exist. An entry no call uses any more fails too.
"""
from __future__ import annotations

import ast
from pathlib import Path

TESTS_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = TESTS_ROOT.parent

_BUILTIN = "shadows the builtin {} in this module's globals only; a module never has one of its own"
_WINDOWS = "exists only on Windows; supplied so fido2's Windows backend imports on macOS and Linux"

ALLOWED: dict[tuple[str, str], str] = {
    ("tests/app/core/test_config_residual_branches_batch_three.py", "open"): _BUILTIN.format("open"),
    ("tests/app/metadata/test_metadata_residual_branches.py", "open"): _BUILTIN.format("open"),
    ("tests/app/storage/test_github_client.py", "range"): _BUILTIN.format("range"),
    ("tests/fido2/hid/test_hid_windows_branch_contracts.py", "WinDLL"): _WINDOWS,
    ("tests/fido2/hid/test_hid_windows_branch_contracts.py", "WinError"): _WINDOWS,
    ("tests/fido2/hid/test_hid_windows_contracts.py", "WinDLL"): _WINDOWS,
    ("tests/fido2/hid/test_hid_windows_contracts.py", "WinError"): _WINDOWS,
    ("tests/fido2/windows/test_win_api_struct_contracts.py", "WinDLL"): _WINDOWS,
    ("tests/fido2/windows/test_win_api_struct_contracts.py", "HRESULT"): _WINDOWS,
}

_PATCHERS = {"patch", "object", "multiple", "dict"}


def _is_true(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _name(call: ast.Call, index: int) -> str:
    if len(call.args) > index and isinstance(call.args[index], ast.Constant):
        return str(call.args[index].value)
    return "<computed>"


def _may_create(call: ast.Call) -> str | None:
    """The attribute a call may create, or ``None`` when it can only replace one."""

    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in {"setattr", "setitem"}:
        for keyword in call.keywords:
            if keyword.arg == "raising" and not _is_true(keyword.value):
                return _name(call, 1)
        dotted = bool(call.args) and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)
        position = 2 if dotted else 3
        if func.attr == "setattr" and len(call.args) > position and not _is_true(call.args[position]):
            return _name(call, 0 if dotted else 1)
        return None
    patcher = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
    if patcher in _PATCHERS:
        for keyword in call.keywords:
            if keyword.arg == "create" and not _is_false(keyword.value):
                return _name(call, 1 if patcher == "object" else 0)
    return None


def _creating_calls() -> list[tuple[str, int, str]]:
    found = []
    for path in sorted(TESTS_ROOT.rglob("*.py")):
        relative = path.relative_to(REPO_ROOT).as_posix()
        for node in ast.walk(ast.parse(path.read_text(), filename=relative)):
            if isinstance(node, ast.Call):
                name = _may_create(node)
                if name is not None:
                    found.append((relative, node.lineno, name))
    return found


def test_no_patch_can_silently_create_an_attribute():
    unexplained = [
        f"{path}:{line} may create {name!r}"
        for path, line, name in _creating_calls()
        if (path, name) not in ALLOWED
    ]
    assert not unexplained, (
        "These patches succeed even when the attribute does not exist, so they keep passing after "
        "the code they patch moves. Drop raising=False / create=True, or add the patch to ALLOWED "
        "with the reason the attribute cannot exist:\n" + "\n".join(unexplained)
    )


def test_every_allowed_patch_is_still_used():
    used = {(path, name) for path, _line, name in _creating_calls()}
    stale = sorted(set(ALLOWED) - used)
    assert not stale, f"ALLOWED lists patches no test makes any more; remove them: {stale}"


def test_the_detector_sees_every_spelling():
    samples = {
        'monkeypatch.setattr(m, "a", 1, raising=False)': "a",
        'monkeypatch.setattr(m, "b", 1, raising=platform == "win32")': "b",
        'monkeypatch.setattr(m, "c", 1, False)': "c",
        'monkeypatch.setattr("pkg.mod.d", 1, False)': "pkg.mod.d",
        'mp.setitem(d, "e", 1, raising=False)': "e",
        'mock.patch.object(m, "f", create=True)': "f",
        'patch("pkg.g", create=True)': "pkg.g",
        'mock.patch.multiple(target, create=True, h=1)': "<computed>",
        'monkeypatch.setattr(m, "ok", 1)': None,
        'monkeypatch.setattr(m, "ok", 1, raising=True)': None,
        'monkeypatch.delenv("X", raising=False)': None,
        'mock.patch.object(m, "ok", create=False)': None,
    }
    for source, expected in samples.items():
        call = ast.parse(source).body[0].value
        assert _may_create(call) == expected, source
