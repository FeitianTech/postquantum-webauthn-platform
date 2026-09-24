"""The server needs Python 3.12 (server/pyproject.toml): no backport of a stdlib module."""
from __future__ import annotations

import ast
from pathlib import Path

SERVER = Path(__file__).resolve().parents[3] / "server"


def test_no_server_module_imports_a_backport():
    imports = []
    for path in sorted(SERVER.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = [alias.name for alias in node.names] if isinstance(node, ast.Import) else []
            if isinstance(node, ast.ImportFrom) and node.module:
                names.append(node.module)
            if any(name.split(".")[0] == "backports" for name in names):
                imports.append(f"{path.relative_to(SERVER)}:{node.lineno}")

    assert imports == []
