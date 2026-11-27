# The UI's design and serving rules

The site's UI is `web/`: Next.js 15 (Pages Router), TypeScript and Tailwind CSS v4,
exported as static files that Flask serves at `/`. These are the rules it keeps.
`AGENTS.md` maps the code; `web/e2e/smoke.spec.ts` checks the focus and fill rules on
the page in a real browser.

## Look

- **Light mode only**: no dark theme, no theme switch, no `prefers-color-scheme`
  rules (`color-scheme: light`).
- **White page, white components.** No grey component anywhere, the top bar
  included: no grey background, track, fill, tile, table header, text area, code or
  JSON block, read-only or disabled field, hover or panel. Grey is only ever a text
  colour (secondary text) or a hairline. A read-only or disabled field is white with
  muted text; a hover is a darker hairline or a faint accent tint; a selected chip or
  tab uses the accent, or white with a shadow on a white track. `web/e2e/design-rules.ts`
  finds grey fills in the browser tests.
- One accent (`#0071e3`); semantic tints (success, warning, danger, info) only for
  status. State is never carried by colour alone: a word or a mark goes with it.
- Hierarchy through type, space and hairlines, not fills. Shadows only on floating
  layers (menus, popovers, drawers, dialogs, toasts) and on the segmented control's
  highlight. No card inside a card; sections are separated by space and hairlines.
- Geist for text and Geist Mono for data (identifiers, AAGUIDs, hex, base64, PEM,
  JSON, EDN), both self-hosted from the `geist` package, so no font origin reaches the
  CSP. Geist is cut in two faces of one family (`tools/subset_geist.sh`, into
  `web/src/fonts` with its licence): the Latin face the page preloads, and the rest,
  fetched only for a character in its `unicode-range`. Geist Mono is fetched when mono
  text first shows. Mono never leaks into buttons or labels.
- The tokens are in `web/src/styles/globals.css` (`@theme`): Tailwind's palette, type
  scale, radii and shadows are cleared first, so only named tokens exist.
- One component per job, with the same height, radius, padding and label placement
  everywhere. Switches for single booleans, toggle chips for sets. Long values are
  never cut off silently: they are truncated with a way to see all and a copy button.

## Focus

- Text fields (`data-text-field`: inputs, text areas, the JSON editor, search and
  filter fields) show **no focus effect** at all: no ring, glow, outline, shadow or
  border change. The caret shows focus.
- Every other control (buttons, links, tabs, switches, chips) keeps a visible 2 px
  `:focus-visible` ring.

## Motion

- The top bar's four sections (Simple, Advanced, Codec, MDS) are a segmented control
  on a white track with a hairline. Its one white highlight **slides horizontally**
  to the chosen tab (`transform`, about 280 ms on `--ease-standard`), moved through the
  CSSOM from a ref, never a `style` prop. The same control switches Registration /
  Authentication and Decode / Encode.
- The highlight **jumps** instead of sliding (and the tabs' colours change at once)
  on its first placement, on a resize, when the URL hash changes it, and always under
  `prefers-reduced-motion`.
- Before hydration no tab is chosen: the export's HTML is the same for every hash, and
  the hash is read before the hydrated page's first frame.
- A section, a Codec mode or an MDS page plays its entrance (a short fade and rise,
  `section-in`) only for what the person brings up with a key, a pointer or the
  browser's history, never for what the URL opens (`web/src/lib/entrance.ts`), however
  late its data or its chunk arrives.

## Layout

- Pages use the width they are given and collapse to 375 px with no sideways page
  scroll. The reference widths are 1440, 1024 and 375 px.
- Below 900 px the sections move into the phone's menu sheet; from 900 to 1280 px the
  header takes two rows; from 1280 px one.
- From 1024 px the Simple tab's form sits beside the saved credentials; from 1280 px the
  Advanced form sits beside its JSON editor and the Codec's input beside its output.

## The MDS page

- The dataset's summary and status line, with **Manage Metadata** (a dialog listing
  the session's uploads with Delete).
- A **filter bar above the table**, each field labelled with what it reads (one search
  for the name and the ID; the eight filters with a list are ARIA comboboxes), one
  "Clear filters", and a Sort select with a button that turns the order round; folded
  behind "Show filters" on a phone.
- The **table**: every row fits the page's width in two lines, so nothing scrolls
  sideways: the name over the ID, the status over the protocol, the transports over the
  attachment, and a column only from the width at which it fits (`grid.ts`). A row
  expands to show every word, with a labelled line for each thing its two lines do not
  hold. All 14 columns stay in every row and in the header, in order, for a screen
  reader. The frame scrolls by itself, its header in view; sortable columns; Back to
  top. Every row stays in the page, rendered cheaply (`content-visibility: auto`).
- **An entry is a URL and a page** (`#mds/<entryId>`; a saved credential opens
  `#mds/aaguid:<aaguid>`): sections as headings and hairlines, identifiers whole in
  Geist Mono with copy, status reports that stack on a phone, a condensed bar once the
  title has scrolled away. A certificate is a page under its entry
  (`…/certificate/<n>`); the raw entry is a dialog, and so are a saved credential's details
  over it (`…/credential/<key>`). Back goes up one level, and the list
  keeps its filters, sort and scroll.

## Links between sections

- A control that opens another section (a saved credential's FIDO MDS, Decode in
  Codec, an MDS entry's Try in Advanced) is a secondary button. It pushes a history
  entry, so Back returns to the place it left, and the focus goes back to that control
  when the page still holds it. The credential details, which a dialog remounts, put
  their Decode in Codec button back themselves, where it was in the level's view. An
  MDS entry is not kept while its section is hidden: Back from Try in Advanced shows
  it again as it arrives, its heading focused. Details over an entry come back with
  it and find their place the same way; their × gives the focus to the credential's
  button under the entry's header, else to the entry's heading.
- What a control hands the section it opens (a payload for the Codec, an MDS
  statement's settings for the Advanced registration) goes through the section
  router, never the URL: the hash names the section alone.

## Browser security

- The policy Flask sends with every page: `script-src 'self'`, `style-src 'self'`,
  `font-src 'self'`, no `'unsafe-inline'`, no other origin
  (`server/app/config/security_headers.py`); Trusted Types are enforced
  (`require-trusted-types-for 'script'`), and only Next's two policies may be made
  (`trusted-types nextjs nextjs#bundler`). Violations reach `/api/csp-report`.
- Every answer is `Cross-Origin-Opener-Policy: same-origin` (a page shares no window
  group with another site's) and `Cross-Origin-Resource-Policy: same-origin` (no other
  site loads what this one answers). The page keeps no handle on a window it opens
  (the GitHub link is `noopener`) and loads nothing from another origin, so neither
  changes what it does.
- A request under `/api/` that may change something (any method but GET, HEAD and
  OPTIONS) is refused, 403, unless the browser's `Sec-Fetch-Site` says it comes from this
  origin (`same-origin`) or from no page (`none`); the CSP reports stay open, and a
  request without the header is let through (`server/app/config/fetch_metadata.py`).
- So in `web/src` (`tests/app/tooling/test_web_source_rules.py` holds it): no `style`
  prop (the export would render a style attribute; set `element.style` through a ref),
  no `<style>` or `<script>` element, no `next/script`, no `next/link` (links are plain
  `<a>`), no `dangerouslySetInnerHTML` or other markup sink, no `eval`, no `atob`,
  nothing written to `window`, and no `Suspense` on the server-rendered path (React
  would put an inline script in the export). `web/scripts/check-export-csp.mjs` scans
  the export for anything that would still slip through.
- Overlays stack (each layer's z-index is its depth; only the top one handles Escape
  and Tab; the ones under it are inert; focus returns layer by layer). A question
  before something that cannot be undone is `ConfirmDialog`, never the browser's
  `confirm`. A success is a toast; a failure stays in place until the next attempt.

## What serves what

- **The export** (`web/out`): three pages (`index`, `404`, `500`) and
  `/_next/static/`. The page's own chunk holds the shell and the Simple tab; the other
  sections, the credential details, the Analyze Browser panel and the attestation
  findings' list (with its sentences in English and 中文) are chunks of their own,
  fetched once the first view is interactive (the section the URL names, and the
  findings list when a result has findings, at once). Flask's `web_export` blueprint
  serves it at `/`: HTML `no-cache`; `/_next/static/` immutable for a year, gzipped from
  the build's `.gz` copies; the export's 404 page for an unknown path.
- **Flask** answers everything with a static segment first: `/health`, `/api/…`
  (errors in JSON: `server/app/routes/errors.py`) and `/assets/mds/…` (the MDS
  explorer's files: docs/MDS_SNAPSHOT.md). The export's files and `/assets/` never set
  the session's cookie, and the page fetches the MDS list without it: an answer
  landing after a ceremony's begin cannot put back the session from before it.
