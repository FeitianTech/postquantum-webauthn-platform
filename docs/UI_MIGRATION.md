# UI migration to Next.js + Tailwind CSS (Phases 25–30)

The owner asked on 2026-09-25 for the whole UI to move to Next.js + Tailwind CSS, following the design
direction in the untracked `new_design/` folder at the repository root, with every current function kept.
This file is the charter for that migration. Read it before changing anything under `frontend/` or `web/`.
It outlives `new_design/`, which is deleted in the last phase.

## The owner's direction

- Modern, professional, clean, with a tech feel, in the style of Apple and OpenAI. **Light mode only.**
- **No grey components at all**, so everything is clean: no grey backgrounds, tracks, fills or tiles
  anywhere. That includes the top bar, whose tab track is grey in `new_design/`. Components are white.
- **The four-section top bar animates**: when a section is chosen, its highlight slides from the previous
  tab to the new one (and stays put under `prefers-reduced-motion`).
- **Text fields have no focus effect around them**: no ring, glow, outline, shadow or border change on
  focus. This covers inputs, textareas, the JSON editor and the search and filter fields; the caret shows
  focus. Buttons, links, tabs, switches, chips and other controls keep a visible keyboard focus
  (`:focus-visible`), which keyboard users need.
- **The FIDO MDS page keeps its structure** (the owner finds it acceptable): port it, fix the problems listed
  below, and make the enhancements found along the way.
- **Keep everything the current UI shows.** Change presentation, alignment, formatting and structure, never
  content: every field, label, value, section, message, finding, badge, action and tooltip (in English and
  中文) stays. `new_design/` is out of date about content (see below); the current app is the source of truth.
- Improve on `new_design/` where it helps. The result should not merely look like it.

## What `new_design/` is

A visual prototype, built against the code as it was before Phase 24:

- React renders the legacy markup, with its ids and inline `onclick` handlers, as one static string
  (`dangerouslySetInnerHTML`); the untouched legacy scripts drive it, proxied from Flask by a Next.js
  **Node server** (App Router, `force-dynamic`, `output: 'standalone'`).
- The legacy CSS sits in a cascade layer (`pq-legacy`) under a 1,638-line theme (`styles/theme.css`).
- Its CSP puts `'unsafe-inline'` back for scripts and styles.

None of that architecture carries over. What carries over is the look.

**Take from it:** the tokens (Apple-like neutrals `#1d1d1f` / `#6e6e73`, accent `#0071e3`, semantic
success/warning/danger, radii 6/10/14/20, soft shadows, easing curves); Geist and Geist Mono; the header with
a segmented tab control, Analyze Browser and GitHub, and a menu sheet on phones; the Advanced toolbar
(sub-tab switch, Saved Credentials with a count opening a drawer, Reset, the primary action); form sections
as cards on a 2–3 column grid; switches for single booleans; toggle chips for sets (algorithms with ML-DSA
grouped, hints); floating toasts; the Codec's input card above an output card; sectioned MDS detail pages;
motion that honours `prefers-reduced-motion`.

**Fix or avoid** (observed by the tech lead running it at 1024, 1440 and 375 px):

1. **Wide screens.** At 1440 px the Advanced form fills only the left half, the right half is empty and the
   JSON editor drops below; the toolbar, sub-tab switch and cards do not share one alignment.
2. **Grey fills on large areas**: the segmented tab track, secondary buttons, read-only and disabled fields,
   switch rows, hovered or expanded credential cards, the Codec textarea, the JSON editor, side panels and
   summary tiles.
3. **Focus rings on text fields**: a global `:focus-visible` outline plus `.form-control:focus` and the filter
   and textarea `box-shadow` rings.
4. **Inconsistent field rows**: switch pills beside label-above controls, so heights and baselines differ;
   disabled switches as grey blocks.
5. **Cards nested in cards**, which wastes width, badly on phones.
6. **Simple tab**: two small cards leave most of the width empty; "Saved Credentials" wraps beside its
   "Clear All"; the two buttons are stacked at different widths.
7. **Monospace leaking into buttons** inside the JSON editor.
8. **MDS explorer**: the legacy table re-skinned, with tall centred rows, certification text wrapping to 3–4
   lines, and user-verification badges stacked and **clipped at the right edge** (the table is wider than its
   card); the filter inputs form a second header row. The detail page nests cards, breaks AAGUIDs mid-UUID and
   squeezes long text into narrow columns.
9. **Stale content.** The markup predates Phases 20–24: the Analyze Browser panel crashes
   (`TypeError` in `renderIdentity`), and the ceremony result panel, the EDN view, the current findings and
   the `data-action` wiring are missing.

## Design principles (binding)

- Light only: no dark theme, no theme switch, no `prefers-color-scheme` rules.
- White page, white components, **no grey backgrounds anywhere**: not the tab track, buttons, chips,
  badges, tiles, table headers, textareas, code or JSON blocks, read-only or disabled fields, hover states or
  panels. Grey exists only as text colour (secondary text) and hairline borders. A read-only or disabled field
  is white with muted text; a hover is a darker hairline or a faint accent tint; a selected chip or tab uses the
  accent (or white with a shadow on a white track), never grey. Semantic tints (success, warning, danger,
  info) are colours, not grey, and stay allowed for status.
- The top bar's four sections use a segmented control on a white track with a hairline border. The active
  highlight is one element that slides to the chosen tab (transform, about 280 ms on the `--ease` curve), with
  no slide under `prefers-reduced-motion`. The same control is used for the Registration / Authentication and
  Decode / Encode switches. The highlight is white with a hairline and a soft shadow (the owner's choice,
  2026-09-25): the one shadow outside a floating layer.
- Hierarchy through type, space and hairlines rather than fills: large, confident page titles; restrained
  colour (one accent, plus semantic success, warning and danger); shadows only on floating layers (menus,
  popovers, drawers, modals, toasts).
- Geist for text and Geist Mono for data: identifiers, AAGUIDs, hex, base64, PEM, JSON, EDN. Self-host both
  (the `geist` npm package; OFL), so no font origin appears in the CSP.
- One component per job, with the same control height, radius, padding and label placement everywhere. A
  field row always has its label in the same place, whatever the control.
- No cards inside cards. Sections are separated by space and hairlines.
- Long values are never cut off silently: truncate with a copy button and a way to see the whole value.
- Layouts use the width they are given (the Advanced form beside a sticky JSON editor on wide screens) and
  collapse cleanly to 375 px with no horizontal page scroll.

### The MDS explorer

Keep today's structure: the dataset summary and Manage Metadata, the table with its per-column filters and
sorting, the detail page, the certificate views, the custom-metadata panel and the raw views. Fix what is
broken in `new_design/` (item 8 above): nothing clipped (long cells truncate with the full value available,
and the table scrolls inside its own container if it must), compact left-aligned rows, certification text that
does not wrap to four lines, badges that fit, no nested cards on the detail page, AAGUIDs never broken
mid-UUID (mono, with copy). Enhance where it helps along the way. All data shown today stays.

## Architecture (binding)

- **`web/`**: Next.js 15, **Pages Router**, TypeScript, Tailwind CSS v4, **`output: 'export'`**. Flask serves
  the export, so there is still one Cloud Run service, one origin (session cookies and the WebAuthn origin
  unchanged) and no Node server in production.
- **Why the Pages Router:** measured on 2026-09-25, a minimal static export from the App Router contains 7
  inline executing scripts (`self.__next_f.push(...)`), and one from the Pages Router contains none. The
  strict CSP from Phase 24 (`script-src 'self'`, `style-src 'self'`, no `'unsafe-inline'`) stays as it is. A
  test scans every exported HTML file for executing inline scripts, `<style>` elements and style attributes;
  styles set at run time through the CSSOM are fine.
- **During the migration the new UI lives at `/beta`** (`basePath`), unlisted, for review. The legacy UI stays
  at `/` until the cutover phase. Both read and write the same `localStorage` records in the same format, so a
  credential saved in one UI works in the other.
- **Reuse logic, rewrite views.** The logic modules (storage and record migration, base64, the Analyze
  Browser's identity and WebAuthn facts, the failed-response reader, request and option building, the JSON
  editor's synchronisation, codec request handling, MDS filtering and sorting, certificate parsing) keep their
  behaviour and have one copy. Until the cutover they stay in `frontend/static/scripts`, where the legacy UI
  runs them, and `web/` imports them in place (`experimental.externalDir`, the `@legacy/*` alias); at the
  cutover they move into `web/` with their tests. Logic still inside a view module is first moved out into a
  DOM-free module both UIs import (Phase 25: `shared/browser/report.js` out of `analyze.js`).
  `tests/app/tooling/test_web_source_rules.py` fails if `web/src` redefines an imported module's export or
  repeats its sentences. React components replace the code that builds DOM. No legacy markup strings, no
  `dangerouslySetInnerHTML`, no `innerHTML`.
- The server stays the API. Only additive endpoints: for example the data `index.html` inlines today becomes
  JSON a page fetches.
- **Tests:** vitest with Testing Library for components; the moved logic tests keep passing; Playwright
  end-to-end tests in Chromium with its virtual authenticator (the DevTools WebAuthn domain) run real
  registrations and authentications in CI. The Cloud Build gate builds `web/` and runs its unit tests.
  The Playwright tests run in GitHub CI (`ci-web.yml`) and not yet in Cloud Build: they need Python, Node
  and Chromium in one step and are the kind most likely to flake, and today they guard only `/beta` and one
  legacy ceremony. They join the Cloud Build gate at the cutover, when `/` is the new UI.
- **The CSP during the migration:** unchanged. The Google Fonts origins (`https://fonts.googleapis.com` in
  `style-src`, `https://fonts.gstatic.com` in `font-src`) stay until the cutover because the legacy UI loads
  its fonts from there; `web/` self-hosts Geist and needs neither. Remove both at the cutover.

## Decisions made in Phase 25 (2026-09-25)

- **Sections not yet ported** show their title, their description and a short note with a link to the
  current UI at `/` (a plain link: `next/link` would add `/beta`). In Phase 25 that is all four.
- **Section switching** is client-side; the URL hash (`#simple`, `#advanced`, `#codec`, `#mds`, the legacy tab
  ids) is written with `replaceState`, read after hydration and followed on `hashchange`.
- **Overlays** (Dialog, Drawer, Sheet) are one portal-based overlay rather than the native `<dialog>`, to keep
  the legacy panel's focus behaviour exactly (the panel takes focus; Tab and Shift+Tab wrap; Escape and the
  backdrop close; focus returns to the trigger) and to be testable in jsdom. The page behind is `inert` while
  one is open and is not scroll-locked, as the legacy panel was not.
- **Toasts** are white with a hairline, a floating shadow and a coloured dot, not a dark pill.
- **`/beta` paths** with no file answer 404 with the export's own `404.html` (a plain 404 with no export).
- **Dependencies:** Next 15 pins a `postcss` with advisories; `web/package.json` overrides it with a fixed
  release. Dependabot skips majors of `next` and `typescript`. If an advisory is ever fixed only in a newer
  Next major, the owner decides between the upgrade and the charter's Next 15; the audit threshold stays.

## Content parity (every surface phase)

Before porting a surface, list everything it shows and every action it offers, from the current app (the
running UI, its templates and scripts), in `docs/ui-parity/<surface>.md`. After porting, map each item to the
new component and check it in a browser. A phase is not done while an item is unmapped.

## Phases

| Phase | Surface |
|---|---|
| 25 | Foundation: `web/`, tokens and primitives, the app shell, Flask serving `/beta`, the CSP scan, the build and CI pipeline, Playwright with a virtual authenticator; the Analyze Browser panel as the pilot. **Done** (see docs/MODERNIZATION_PLAN.md, Phase 25) |
| 26 | Codec |
| 27 | MDS explorer: the table and filters, the detail page, certificates, custom metadata, raw views (split in two if the plan shows it is too large for one) |
| 28 | Saved credentials (cards, detail modal, registration result) and the Simple tab |
| 29 | Advanced tab: registration and authentication forms, JSON editor, drawer, result modals |
| 30 | Cutover: `/` serves the new UI; the legacy templates, scripts and styles and `new_design/` are deleted; the MDS snapshot files move out of `frontend/static/`; the logic modules move into `web/`; the Google Fonts origins leave the CSP; the Playwright tests join the Cloud Build gate |
