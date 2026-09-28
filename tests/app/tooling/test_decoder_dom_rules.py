"""The Codec's scripts never touch innerHTML.

What they build, much of it quoted from the input, is text; the new UI renders
it with React. (The rule that the current UI's templates gained no inline
handler went with the templates in Phase 30.)
"""
from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_DECODER_SCRIPTS = _ROOT / "frontend" / "static" / "scripts" / "decoder"


def test_decoder_scripts_never_touch_inner_html():
    uses = [
        f"{path.relative_to(_ROOT)}:{number}: {line.strip()}"
        for path in sorted(_DECODER_SCRIPTS.rglob("*.js"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if "innerHTML" in line
    ]

    assert uses == [], "empty a container with replaceChildren() and write text with textContent"
