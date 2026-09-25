"""The decoder tab builds its DOM from text, and the templates gain no inline handlers.

Two rules the decoder work keeps. Template lines with an inline event handler
(onclick=, onmouseenter=, ...) may fall in number but never rise: 96 lines carry
one today (125 handlers; 29 lines carry two). And the decoder's scripts never
touch innerHTML: they empty a container with replaceChildren(), and everything
they show, much of it quoted from the input, goes in through textContent.
"""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_TEMPLATES = _ROOT / "frontend" / "templates"
_DECODER_SCRIPTS = _ROOT / "frontend" / "static" / "scripts" / "decoder"
_INLINE_HANDLER = re.compile(r"\son[a-zA-Z]+\s*=")
_TEMPLATE_HANDLER_LINES = 96


def test_template_lines_with_an_inline_handler_do_not_grow():
    lines = [
        f"{path.relative_to(_ROOT)}:{number}"
        for path in sorted(_TEMPLATES.rglob("*.html"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if _INLINE_HANDLER.search(line)
    ]

    assert len(lines) <= _TEMPLATE_HANDLER_LINES, lines


def test_decoder_scripts_never_touch_inner_html():
    uses = [
        f"{path.relative_to(_ROOT)}:{number}: {line.strip()}"
        for path in sorted(_DECODER_SCRIPTS.rglob("*.js"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if "innerHTML" in line
    ]

    assert uses == [], "empty a container with replaceChildren() and write text with textContent"
