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
  DOM-free module both UIs import (Phase 25: `shared/browser/report.js` out of `analyze.js`; Phase 26:
  `decoder/codec/request.js`, `result.js` and `values.js` out of the Codec's renderers).
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
  current UI at `/` (a plain link: `next/link` would add `/beta`). In Phase 25 that was all four; since Phase 26, three; since Phase 28A, one (Advanced).
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

## Decisions made in Phase 26 (2026-09-25)

- **The Codec's layout**: from 1280 px the input column sits beside the output (the input stays in view, sticky,
  while a long answer scrolls); below that one above the other. "Supported Inputs" is the output column's empty
  state. The Decode / Encode switch is the top bar's `SegmentedControl`, small.
- **Messages**: a success is a toast (as before); a failure or a refused input stays in its panel, in red, until
  that panel's next run or Clear, with the refusal's offset and path shown on their own. A toast that leaves after
  five seconds cannot hold where the input stops being well-formed.
- **Findings** show the category as a chip (amber when the server also counts the finding as malformed), which the
  current UI left out; the source, offset and path are in Geist Mono.
- **Blocks** (`ui/CodeBlock`): EDN, Expanded JSON, PEM, long hex and the raw views are white blocks with copy; a long
  one starts at 16 rem with "Show all", and the whole text stays in the page. The EDN block is open at once (the
  current UI keeps it in a closed disclosure).
- **Nested values**: a map or list inside a map goes under its label, indented behind a hairline; a label and a
  plain value sit side by side only where the map has room (a container query), so nothing deep is squeezed.
- **Raw views stay dialogs** (`Dialog`), titled as before; they now close on Escape and give focus back to "Raw".
- **`npm run dev` sends Flask's CSP**, with only the two allowances the dev server needs (`'unsafe-eval'` for its
  eval source maps, `style-src-elem 'unsafe-inline'` for its injected style elements); a style attribute, an inline
  script or another origin is refused there as in production. The export still carries none of that.
- **Parity check**: `web/e2e/parity.ts` compares what a region shows in both UIs, word for word per section, each
  expected difference with its reason. Each later surface adds its own parity spec over it.

## Decisions made in Phase 27A (2026-09-26)

- **The split.** 27A ports the list page; 27B the authenticator detail page, the certificate page, the raw views
  and the jump from a saved credential. Until 27B an entry opened at `/beta` shows its name and identifier (with
  copy), Back, and a plain link to the full page in the current interface.
- **Filters** are a bar above the table, each field labelled with its column (six to a row on a wide screen, four at
  1024 px, down to one on a phone, where the bar folds behind "Show filters"), not a second header row. The bar says
  how many filters are in use and has one "Clear filters"; a filtered column's header carries an accent dot. The
  seven filters with a list are ARIA 1.2 comboboxes (the listbox, the arrow keys wrapping, Enter picking the option
  highlighted, Escape closing the list and then clearing); User Verification and Algorithms show their list whole.
- **The table** sits in a frame that scrolls both ways by itself, at most the window's height: the header row stays in
  view, the sideways scrollbar is always within reach, and the page never scrolls sideways. Rows are one line (41 px),
  left-aligned; a long value ends in an ellipsis with the whole value as the cell's tooltip, and a row expands (the
  chevron before its name) to show every word, lists as pills. Certification is one badge for the level, coloured by
  status, the descriptor and number after it; the ID is Geist Mono on one line with copy; icons are 28 px.
- **Performance.** Every row stays in the page (find-in-page and the parity check read them all), but each row is a
  grid on one column template (`--mds-columns`, set through the CSSOM, as the resized widths are) rather than a table
  row, so `content-visibility: auto` lets the browser skip laying out and painting rows out of view: bringing back
  all 517 rows went from 41 ms of layout to under 2. The table roles are written out, since the display is not a
  table's. Filtering follows the typing through `useDeferredValue`. No dependency was added.
- **Sorting** is announced with `aria-sort`; the columns resize from the keyboard too (a focusable separator).
- **An entry is a URL**: `#mds/<entryId>` (the id encoded, its colons kept; an AAID's `#` as `%23`). Opening one
  pushes a history entry (switching sections still replaces the hash), so the browser's Back and the page's Back both
  return to the list, which stayed mounted: its filters, sort, widths and scroll are as they were, and the focus is on
  the row. While the app shell is shown, Next's router is told (`beforePopState`) to leave Back to the page: it would
  otherwise put back the URL it remembers from before a section switch.
- **Manage Trusted Metadata** is a `Dialog` (focus in, Escape and the backdrop close it, focus back to its button). It
  lists the files the session uploaded, with Delete (the current panel never fills its list; the owner chose to fix
  that in `/beta` only), shows the progress as a line inside the dialog rather than an overlay over the tab, and keeps
  the server's reason for a refused upload or delete.
- **Loading** starts the first time the section is shown, from `GET /api/mds/metadata/info` (what the index inlines,
  built by the same function). With no snapshot the table says the packaged metadata is unavailable (the current
  table says that no authenticator matches the filters).
- **The server** gains, additively: the info endpoint; `FIDO_SERVER_MDS_SNAPSHOT_DIR`, read whenever a path is needed
  from a Flask-free leaf (`server/app/mds_snapshot_dir.py`) that the loaders, the provisioning, the served snapshot and
  the updater follow (the first step of Phase 30's move); upload and delete recording whether the session has uploads,
  so a reload never loads the packaged file over the session's own. The legacy scripts request the MDS endpoints by
  absolute path.
- **Tests and fixtures.** Every test runs against an empty snapshot directory of its own run; the MDS tests serve a
  small synthetic snapshot (`tests/fixtures/mds`) built with the updater's own code, which the browser tests' Flask
  serves too. `web/e2e/parity.ts` gains a row reader; `mds-parity.spec.ts` compares the two tables row by row.
- **Never shown, not ported:** "Refresh Metadata" and what only it reaches, the floating sideways scrollbar, the
  client's row builder for a payload without `entryId`, the inlined snapshot page data. They go with the legacy tree at
  the cutover rather than now: the legacy tests exercise them, and rewriting those tests for code about to be deleted
  buys nothing. The snapshot URL's year-long immutable caching (the snapshot changes at runtime, the build id only on a
  deploy) is reported, not changed (the owner's decision).

## Decisions made in Phase 27B (2026-09-26)

- **An entry is a page, a certificate is a page under it.** `#mds/<entryId>` shows the entry under the section's title
  (the list stays in the page, hidden); `#mds/<entryId>/certificate/<n>` (n counting the non-empty certificates from 1,
  as "Certificate n" does) shows one attestation root over the entry, which stays in the page. The hash's parts after
  the section are segments, each encoded on its own. The page's Back and the browser's return one level at a time,
  with the focus on what was opened; a path the page does not know shows the entry and the URL is corrected.
- **Sections, not cards.** Each of the detail page's sections is a heading and a hairline; fields sit on a grid in
  regular weight (long text across it), chips wrap, the user-verification combinations are a list with hairlines.
  Identifiers (AAGUID, AAID, key identifiers, the getInfo AAGUID, certificate and serial numbers) are Geist Mono, whole,
  with copy. Certification is the list's badge. The status reports use the `ui/Table` primitives (their first user) and
  stack on a phone, each value after its column's name, which CSS writes from `data-label`.
- **The condensed header** is a white bar with a hairline, no shadow, under the top bar once a page's title has
  scrolled away: Back, the title and subtitle truncated with their `title`, and Raw. It is fixed rather than sticky, so
  showing it moves nothing, and it renders in the overlay layer, because a section sliding in (a transform) would
  otherwise carry it along.
- **An entry the list does not hold** (a link to another session's upload, an entry gone since) is asked of
  `GET /api/mds/metadata/resolve`, and the server's sentences are shown; MDS-J2's sentences say what happens meanwhile
  and after. The current page keeps ignoring them.
- **The raw view is a dialog**, not a popup window: popups are blocked in some browsers and in the desktop app's
  browser pane, and the Codec's raw views are dialogs. It keeps the window's title, subtitle and text (checked equal),
  with copy, Show all and "Download JSON".
- **The link from a saved credential opens the entry's page**, `#mds/aaguid:<aaguid>` (the entry's own id), rather than
  highlighting a row, which a URL cannot keep; it leaves the list's filters as they are. `openMdsEntryForAaguid` and
  `useOpenMdsEntry` open it as one pushed history entry through the shell's `useSectionNavigation`, so Back returns to
  the credential. Phase 28 puts it on the cards.
- **User-verification descriptors** (new, the owner may veto): the biometric and pattern accuracy (`baDesc`, `paDesc`)
  are shown beside the code accuracy the current page shows; the parity check lists them as expected, in that section
  only.
- **A failed certificate decode** keeps the current sentence; `/beta` adds the server's reason under it.
- **Back keeps 27A's form**: a button named "Back" with the title "Return to authenticator list" (or "Return to ${name}"
  from a certificate), rather than a "←" whose label and title are the other way round.
- **Links are plain `<a>`**, `next/link` included: following one made Next's router add page scripts (which the Trusted
  Types policy reports) and left the browser's Back on the app with the 404's URL. The source rules refuse it, and the
  shell leaves Back to Next for any path that is not its own.
- **The snapshot's URL carries its version** (`?v=<serial>.<digest of ETag and generation time>`, which the route
  ignores), reversing 27A's report-only decision at the tech lead's request: the file changes at runtime while its URL
  was cached for a year. The page is given that URL only while the file is there and matches the verified snapshot, and
  no route serves any other snapshot file.

## Decisions made in Phase 28A (2026-09-27)

- **The split.** The surface is about 8,200 lines, and the logic `/beta` imports was 60–97 % covered, so Phase 28 is two:
  28A the Simple tab, its ceremonies and the saved-credential list, with the records shared by both UIs; 28B the
  credential detail and the registration result with its certificate and authenticator-data views. Until 28B a
  credential's details open at their URL with its name, its id and a plain link to the current interface.
- **Legacy import paths stay.** The current UI's tests mock modules by path; a module `/beta` needs that reads the page
  or imports a `/ui/` module has the part `/beta` needs moved into a leaf, and the old module wraps or re-exports it
  (the storage's page-data seed moved to `shared/storage/local.js` over the new `records.js`; the algorithm's tag took
  its COSE describer as a parameter). Where a current view is driven by injected functions, the new model takes their
  results as values (`describeCredentialCard`).
- **Held at 100 % per file**: the storage, the ceremonies and the result panel's sentences, what a row shows, deleting
  and clearing, and what they rest on (`failed-response`, `debug/auth`, `binary`, `base64`, `state`, the credential
  helpers, the attestation context, the certificate helpers, the COSE names). Guards no value reaches were dropped
  rather than covered with mocks; the vendored WebAuthn ponyfill is checked for the DOM, not held.
- **Layout.** The Simple tab is two cards from 1024 px: the form (about 26 rem, sticky under the measured header) and
  the saved credentials; one above the other below. One control height, the label above the field, the random
  username a button inside the field, Register Passkey and Authenticate at one width.
- **Messages.** A success is a toast; a failure stays in place until the next ceremony (an empty username is the
  field's error); the progress is a line with a spinner and the pressed button busy; neither button can be pressed
  again meanwhile. The result panel is set off by a hairline inside the form's card, and a warning is an amber box.
- **The saved credentials** are one component the Advanced drawer will reuse (Phase 29), its state in a provider at
  the shell's level: a card with the count (new) and Clear All, rows separated by hairlines, the checks as chips with a
  mark and a word for screen readers, the tags as badges, and (as the brief asks) the credential ID and AAGUID in Geist
  Mono with copy under the row, whole wherever the row has room. The row a ceremony used is tinted for 2.2 s. The
  records are read after hydration and after every change, and warmed up after each read as the current list is.
- **Questions in a dialog.** Delete and Clear All ask in `ui/ConfirmDialog` (focus on Cancel) with the current
  sentences, not the browser's `confirm`, which some embedded browsers block and none lets the page style.
- **A credential's details are a `Dialog` with a URL** (`#simple/credential/<key>`, the storage's own identifier): Back,
  Escape and × close it, a link or a reload opens it, an unknown key corrects the URL. A dialog rather than a drawer:
  the details are wide (JSON, hex, certificates), and in Phase 29 they open from the Advanced tab's drawer. In 28B the
  certificate and authenticator-data views become levels inside the same dialog, not overlays on overlays.
- **Routes.** A section is given the route only while it is shown (`CLOSED_ROUTE` otherwise), and the page's URL
  without a hash is the default section, so Back from an entry another section opened returns there.
- **The fixes from 27B's verification:** a cold instance's MDS endpoints and the browsers' snapshot wait for the
  provisioning under way (the index does not); the MDS entry's identifiers take two columns below 1280 px; the header
  is measured into `--header-height`; the MDS table's Icon column follows the window's width; the static asset tests
  close their responses; long component tests are split, one behaviour each.

## Decisions made in Phase 28B (2026-09-27)

- **A credential's details are one dialog with levels, each a URL** (the owner's choice for the registration): the
  detail (`#simple/credential/<key>`), the registration (`…/registration`, its own level rather than the detail's last
  sections), a certificate (`…/registration/certificate/<n>`) and the authenticator data (`…/registration/authenticator-data`).
  Each level is a pushed history entry: the header's Back and the browser's go up one, with the focus on what opened
  the level left; ×, Escape and the backdrop close them all in one step (`useSection`'s `closeAll`, the depth kept in
  the pushed mark); a link or a reload opens any level, and one the credential lacks is corrected to the level above.
  The parent levels stay in the page, hidden, their scroll kept. Levels, not modals over modals: the current second
  modal reads whichever registration was composed last.
- **After a Simple registration only the toast shows**, as today (the owner's choice); the registration is reached from
  the new credential's details. Phase 29's advanced registration opens the same dialog at `…/registration`.
- **The detail in the MDS entry page's language**: each section a heading and a hairline, never a card in the dialog;
  true, false and N/A as `StatusChip`s; every identifier's spellings in Geist Mono with copy, whole where they fit;
  JSON as `CodeBlock`s. **A certificate's level** shows the MDS certificate page's summary above the current text (the
  owner's choice; the parity check lists the summary's words). FIDO MDS sits beside the AAGUID (the current modal
  keeps a status line for that jump that nothing fills). The credential's name is the detail's title.
- **Logic out of the views, the state passed in.** The current registration view kept one module-level state its second
  modal read at click time; `registration-state.js` takes the state as a parameter, the current UI binding its one
  (`registration-state-runtime.js`, `certificate-state.js`), the new UI one per credential. What the sections, the
  registration view and its sub-views show is data (`detail-sections.js`, `registration-view.js`, composed by
  `compose.js`), rendered by the current builders (whose signatures stay: their tests call them) and by React. Each
  refactor left the current modal's HTML byte for byte equal for eight records (a scratch comparison against the tree
  before it). Held at 100 % per file; guards no value reaches were dropped, each claim checked.
- **The artifact** is fetched when an advanced record's details open without a v2 snapshot, on a copy, remembered by
  storage id for the page; a failure says the logged sentence in the dialog, and the details show what the browser
  keeps.
- **Fixes found or asked for, in both UIs:** a stored AAGUID with no base64 length no longer stops the list or the
  details (shown as stored, marked unreadable), and a dashed GUID reads as one; client data that is not base64url is
  shown as stored; another tab's change is followed (the storage event), which also stops a stale tab's write
  overwriting another's; the warm-up reads the list again only after a real change; a registration reads the list
  once (the current tab's second read a second later dated from when the list came from the server); an algorithm the
  COSE labels do not name is tagged `COSE${id}`; the Simple registration names its algorithm from `describe_algorithm`
  (EdDSA was "Other (Classical)"); both registrations wait for a cold instance's snapshot provisioning, as the MDS
  routes do; after a deletion the focus goes to the next row, else the previous one, else the list's heading.
- **Phone widths.** On a phone an identifier's copy button sits beside its label and the value has the row's (or the
  dialog's) whole width, whole: an AAGUID on one line, a longer credential ID wrapping rather than cut; a long name
  wraps. `MonoValue` measures overflow as if its "Show all" were not there, and again when the fonts arrive: before,
  a value measured in the fallback font kept its "Show all" and stayed cut.

## Content parity (every surface phase)

Before porting a surface, list everything it shows and every action it offers, from the current app (the
running UI, its templates and scripts), in `docs/ui-parity/<surface>.md`. After porting, map each item to the
new component and check it in a browser. A phase is not done while an item is unmapped.

## Phases

| Phase | Surface |
|---|---|
| 25 | Foundation: `web/`, tokens and primitives, the app shell, Flask serving `/beta`, the CSP scan, the build and CI pipeline, Playwright with a virtual authenticator; the Analyze Browser panel as the pilot. **Done** (see docs/MODERNIZATION_PLAN.md, Phase 25) |
| 26 | Codec. **Done** (see docs/MODERNIZATION_PLAN.md, Phase 26) |
| 27A | MDS explorer, the list page: the header, counts and status line, the table with its sorting, filters and resizing, Back to top, Manage Trusted Metadata, and the route that opens an entry (`#mds/<entryId>`). The explorer is 75 modules and 10,294 lines of JavaScript, seven times the Codec, so Phase 27 is split in two (docs/ui-parity/mds.md marks each item 27A or 27B). **Done** (see docs/MODERNIZATION_PLAN.md, Phase 27A) |
| 27B | MDS explorer, the rest: the authenticator detail page, the certificate page, the raw views, and the jump from a saved credential to its entry. **Done** (see docs/MODERNIZATION_PLAN.md, Phase 27B) |
| 28A | The Simple tab (its form, both ceremonies, the ceremony result panel) and the saved-credential list (its rows, delete, Clear All, the jump to FIDO MDS), the records shared by both UIs, and the credential detail's dialog and URL with a stub body. The surface is 8,200 lines, and the logic web imports is 60–97 % covered before this phase holds it at 100 %, so Phase 28 is split in two (docs/ui-parity/credentials.md marks each item 28A or 28B). **Done** (see docs/MODERNIZATION_PLAN.md, Phase 28A) |
| 28B | Saved credentials, the rest: the credential detail's every section, and the registration result with its certificate and authenticator-data views as levels of one dialog, each at its URL; the fixes 28A and its verification found. **Done** (see docs/MODERNIZATION_PLAN.md, Phase 28B) |
| 29A | Advanced tab, first half: the tab's frame (the Registration / Authentication switch, the toolbar, the saved credentials in a drawer over Phase 28's list and details, the result panel with its challenge row), one request that the form and the JSON editor both show and change, the registration form and the registration ceremony with its result (28B's dialog levels); the fixes 28B's verification found. The surface is about 3,700 lines of script and 1,300 of templates, 55 controls and 29 info popups, and the editor's logic is 52–88 % covered and inside view modules, so Phase 29 is split in two (docs/ui-parity/advanced.md marks each item 29A or 29B) |
| 29B | Advanced tab, the rest: the authentication form (the credential selection and allowCredentials, the fake allow IDs, the hints, the hash algorithm, largeBlob and prf with their capability checks), the authentication ceremony and its result |
| 30 | Cutover: `/` serves the new UI; the legacy templates, scripts and styles and `new_design/` are deleted; the MDS snapshot files move out of `frontend/static/`; the logic modules move into `web/`; the Google Fonts origins leave the CSP; the Playwright tests join the Cloud Build gate |
