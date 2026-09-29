"""The Codec's logic never touches innerHTML.

What it builds, much of it quoted from the input, is text; web/'s components
render it with React.
"""
from __future__ import annotations

from pathlib import Path

from tests.app.tooling.test_html_sinks import LOGIC_ROOT, logic_modules

_ROOT = Path(__file__).resolve().parents[3]
_DECODER_SCRIPTS = LOGIC_ROOT / "decoder"


def test_decoder_scripts_never_touch_inner_html():
    uses = [
        f"{path.relative_to(_ROOT)}:{number}: {line.strip()}"
        for path in logic_modules()
        if path.is_relative_to(_DECODER_SCRIPTS)
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if "innerHTML" in line
    ]

    assert uses == [], "give the text to a React component instead"
