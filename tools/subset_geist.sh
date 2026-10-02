#!/bin/sh
# Geist in two faces for web/src/fonts (docs/DESIGN.md): the Latin face the
# page preloads (the UI's text and the symbols it uses) and the rest of the
# font, which a browser fetches only for a character in its unicode-range.
# Both are cut from the geist package's own Geist-Variable.woff2 (the version
# web/package-lock.json pins), its variable weight axis kept, under its licence
# (SIL OFL 1.1, no Reserved Font Name), copied beside them.
#
# Run from anywhere, after `npm ci` in web/:  sh tools/subset_geist.sh
# then put the unicode-range it prints for the rest into web/src/pages/_app.tsx.
set -eu
cd "$(dirname "$0")/.."

FONTTOOLS="fonttools==4.66.1"
SOURCE=web/node_modules/geist/dist/fonts/geist-sans/Geist-Variable.woff2
OUT=web/src/fonts
# Google Fonts' "latin" range, with the arrows the UI draws.
LATIN="U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2190-2199,U+2212,U+2215,U+FEFF,U+FFFD"

subset() {
  uvx --quiet --with brotli --from "$FONTTOOLS" pyftsubset "$SOURCE" --unicodes="$1" \
    --layout-features='*' --flavor=woff2 --output-file="$2"
}

subset "$LATIN" "$OUT/Geist-Latin.woff2"
# Every other character Geist draws, as ranges.
REST=$(uvx --quiet --with brotli --from "$FONTTOOLS" python - "$SOURCE" "$OUT/Geist-Latin.woff2" <<'PY'
import sys
from fontTools.ttLib import TTFont

whole = set(TTFont(sys.argv[1]).getBestCmap())
rest = sorted(whole - set(TTFont(sys.argv[2]).getBestCmap()))
ranges, start = [], None
for index, code in enumerate(rest):
    if start is None:
        start = code
    if index + 1 == len(rest) or rest[index + 1] != code + 1:
        ranges.append(f"U+{start:04X}" if start == code else f"U+{start:04X}-{code:04X}")
        start = None
print(",".join(ranges))
PY
)
subset "$REST" "$OUT/Geist-Rest.woff2"
cp web/node_modules/geist/LICENSE.txt "$OUT/OFL.txt"

echo "Latin face: $(wc -c < "$OUT/Geist-Latin.woff2") bytes; the rest: $(wc -c < "$OUT/Geist-Rest.woff2") bytes."
echo "The rest's unicode-range, for web/src/pages/_app.tsx:"
echo "$REST" | sed 's/,/, /g'
