# AGENTS.md

This file is a quick orientation guide for coding agents working in this repository.

## Repository Purpose

This project is a Flask-based WebAuthn/FIDO2 demo and developer tool focused on:

- Simple registration and authentication flows
- Advanced WebAuthn request editing and debugging
- Post-quantum credential and algorithm experiments
- Credential inspection, attestation decoding, and metadata exploration
- A browser-based decoder for WebAuthn / CTAP structures

The repo includes both the application and a local `fido2/` library copy used by the server.

## High-Level Layout

- `server/app/`
  Flask app, route handlers, configuration, storage, attestation processing, metadata bootstrap, decoder logic.
- `frontend/templates/`
  Jinja/HTML templates for the main tabs and shared UI fragments.
- `frontend/static/scripts/`
  Frontend behavior, organized by feature area.
- `frontend/static/styles/`
  Shared and advanced-tab CSS.
- `web/`
  The new UI (Next.js 15 Pages Router, TypeScript, Tailwind CSS v4), exported as static
  files that Flask serves at `/beta` until the cutover. See "The new UI (`web/`)" below.
- `tests/`
  App, library, PQC, and optional device tests.
- `fido2/`
  Local Python FIDO2 implementation used by the app. Treat changes here as library-level changes, not normal UI work.

## Frontend Map

**The UI is moving to Next.js + Tailwind CSS in `web/` (Phases 25–30).** Read
`docs/UI_MIGRATION.md` before changing anything under `frontend/` or `web/`: it holds the owner's design
direction, the binding architecture (Pages Router static export served by Flask, the strict CSP kept) and
the content-parity rule.

### The new UI (`web/`)

Phase 25 laid the foundation; each later phase ports one surface (docs/UI_MIGRATION.md,
"Phases"). Until the cutover the legacy UI stays at `/` and the new one lives at `/beta`,
unlisted.

- `web/src/pages/`: `index.tsx` (the app shell), `design.tsx` (the unlisted
  `/beta/design` review page: every component in every state), `404.tsx`, `500.tsx`
  and `_error.tsx` (Next's own error pages use style attributes the CSP refuses),
  `_app.tsx` (Geist and Geist Mono from the `geist` package, self-hosted through
  `next/font/local`; the fonts' variables sit on a wrapper holding `#app-root` and
  `#overlay-root`, so portalled overlays inherit them) and `_document.tsx`.
- `web/src/styles/globals.css`: the design tokens (`@theme`). Tailwind's palette,
  type scale, radii and shadows are cleared first, so only named tokens exist: white
  surfaces, grey only as text and hairlines, one accent, semantic tints, shadows for
  floating layers (and the segmented highlight). Text fields carry `data-text-field`
  and show no focus effect; every other control keeps the `:focus-visible` ring. The
  `hover-or-demo` / `focus-or-demo` / `active-or-demo` variants let the design page
  show a state still through `data-demo`.
- `web/src/components/ui/`: the primitives (Button and IconButton, the text fields
  and Select, Switch, ToggleChip, SegmentedControl, Card, Badge and StatusChip,
  Overlay with Dialog / Drawer / Sheet, Toast, InfoPopover, the table primitives,
  MonoValue, CodeBlock, KeyValueGrid, ConfirmDialog). `SegmentedControl` moves its one highlight through the
  CSSOM (`element.style`) from a ref, never a `style` prop. `CodeBlock` is data text
  (EDN, JSON, PEM, hex) on white: it wraps instead of scrolling the page, starts
  collapsed at 16 rem with "Show all" when long (the whole text stays in the DOM),
  and copies; `useCopy` is the copy logic it shares with `MonoValue`. `KeyValueGrid`
  items can be `plain` (regular weight), `wide` (the whole row) and `identifier` (two
  columns below 1280 px, so a whole AAGUID fits); `Table` and `THead` take classes and
  roles (their first user is the MDS status reports). `Overlay` takes a dialog's `size`
  (`sm` for a question), its `role` (`alertdialog`, `describedBy`) and `initialFocus`;
  `ConfirmDialog` asks before something that cannot be undone (focus on Cancel) in
  place of the browser's `confirm`. Overlays stack: a module-level list of the open
  layers, each one's z-index from its depth (whatever the portals' order), only the top
  one handling Escape and Tab, those under it inert until it closes, the focus returned
  layer by layer (a question or a credential's details open over the Advanced drawer).
  `FieldRow` takes `group` for a set of controls (`role="group"` named by its label),
  `Switch` an `aside`. `OverlayHeader` takes `back` for a level inside a
  panel (`BackButton`, "Back" titled with where it returns to, which the MDS pages use
  too). `MonoValue` measures whether a value fits as if its "Show all" were not there,
  and again when the fonts arrive; `wrapOnPhone` gives it a phone's whole width, the
  copy button at the top right of the nearest positioned box (beside the value's label).
- `web/src/components/shell/`: the header (title, the four sections, Analyze Browser,
  GitHub; the phone menu sheet below 900 px), the footer, and `AppShell`, which renders
  each section's own component (`SimpleSection` for `#simple`, `AdvancedSection` for
  `#advanced`, `CodecSection` for `#codec`, `MdsSection` for `#mds`), all mounted, and
  gives the route only to the section shown: the others get `CLOSED_ROUTE`. `NAV_ID` and
  `APP_TITLE` (the header's title, which is also the relying party's name the Advanced
  request carries) are in `lib/sections.ts`.
  The header measures itself into `--header-height` on `<html>` (a `ResizeObserver`,
  through the CSSOM): it takes two rows between 900 and 1280 px, and the scroll padding,
  the Codec's sticky column, the MDS frame and the Simple form follow it.
  `web/src/lib/useSection.ts` keeps the section in the URL hash (`#simple`,
  `#advanced`, `#codec`, `#mds`) with `replaceState`, and what is open inside one as
  segments after it (`#mds/<entryId>/certificate/<n>`, each segment encoded on its own:
  `routeFromHash` / `hashPath` in `sections.ts`): `open(path)` pushes, so the browser's
  Back closes one level; `close(parent)` goes back, or on a link replaces with the
  parent; `replace(path)` corrects a path the page does not know; `closeAll(parent)`
  closes every level this page opened in one step (the pushed mark holds the depth,
  `pqcOpened: n`: it goes back that many entries, then replaces a first level reached by a
  link; switching sections drops the depth). No hash is the default
  section (the page's own URL, which Back returns to after a section opened something in
  another). The export chooses no section (its HTML is the same for every hash): the
  first render has none, and a layout effect reads the hash before the hydrated page's
  first frame, so a hashed load never shows Simple first; a first hash that names no
  section opens the default. `SegmentedControl` takes no value (no tab chosen), and a
  placement it does not slide is instant for the tabs' colours too (`data-instant` on the
  list, `in-data-instant:transition-none`). `lib/entrance.ts` (`useEntrance`) gives a
  section, a Codec mode or an MDS page its entrance only for what the person brings up
  (after a key, a pointer or the history moves), never for what the URL opens. It tells Next's
  router (`beforePopState`) to leave Back to the page while Back stays on this page's
  path (Next would otherwise put an older URL back), and to Next for any other path.
  `AppShell` gives sections `useSectionNavigation()`, which opens something in another
  section as one pushed entry. The header carries `data-shell-header` (the MDS pages'
  condensed header sits under it). `lib/download.ts` saves text as a file.
- `web/src/components/simple/` and `web/src/components/credentials/`: the Simple tab and
  the saved credentials (Phase 28A). `SimpleSection` (the form's card beside the list's
  from 1024 px, the form sticky under the header), `useSimpleCeremony` (the username, a
  busy button, each step's sentence, a success as a toast, a failure in place, the result
  panel, the row a ceremony used tinted), `model.ts` (the casts of `simple/ceremony.js`,
  `shared/auth/random-username.js` and the storage). `SavedCredentialsProvider` /
  `useSavedCredentials` (at the shell's level, so the Advanced drawer shares it: the
  records from `shared/storage/records.js`, read after hydration and after each change,
  the warm-up after each read, delete and Clear All through
  `advanced/credentials/delete-flow.js`, the tint), `SavedCredentials` (the Simple tab's
  card: the heading, the count, Clear All, over `SavedCredentialList`, the rows, which the
  Advanced drawer holds too; `useCredentialDeletion` keeps the questions in
  `ConfirmDialog` and where the focus goes when no row is left),
  `CredentialRow` (the name opening the details, the checks as `StatusChip`s, the tags,
  the credential ID and AAGUID in Geist Mono under the row, FIDO MDS through 27B's
  `useOpenMdsEntry`, Delete; a stored AAGUID no spelling reads shown as stored and
  marked; on a phone each identifier the row's width), `model.ts`. The provider follows
  another tab's change (the storage event) and gives the focus, after a deletion, to the
  next row's name, else the previous one's, else the list's heading.
  `CredentialDetailDialog` (Phase 28B) is one `Dialog` with four levels, each a pushed
  history entry: the detail (`#simple/credential/<key>`), the registration
  (`…/registration`), a certificate (`…/registration/certificate/<n>`, counted from 1 as
  their buttons are) and the authenticator data (`…/registration/authenticator-data`);
  the header's Back and the browser's go up one level (the focus on what opened the one
  left), ×, Escape and the backdrop `closeAll`; a level the credential lacks is corrected
  to the one above. It takes the section's route, so the Advanced tab reuses it
  (`#advanced/credential/<key>/…`), and `returnFocusTo`. `credentials/detail/`: `model.ts`
  (the casts of the logic below),
  `useCredentialDetail` (an advanced record completed from its artifact first, on a copy,
  remembered by storage id for the page; then everything composed once into a
  registration state of its own), `DetailSections` (the detail's sections in the MDS
  entry page's language: a heading and a hairline each, values as `StatusChip`s, every
  identifier's spellings in Geist Mono with copy, FIDO MDS beside the AAGUID) and
  `RegistrationLevels` (the registration, a certificate with 27B's `CertificateSummary`
  above its text, the authenticator data).
  `web/src/components/ceremony/CeremonyResult.tsx` is the result panel (`showChallenge`
  adds the Advanced tab's challenge row). Their tests render the characterization
  goldens' real answers
  through `tests/frontend/simple/ceremony-answers.js` (`@legacy-tests`; the root tests use
  it too), which also stands in for the authenticator; `src/test/credentials.ts` keeps
  records in the storage and forgets its read cache, `src/test/fetch.ts` answers `fetch`
  by path. `docs/ui-parity/simple.md` and `credentials.md` map every item.
- `web/src/components/advanced/`: the Advanced tab (Phases 29A, its frame and registration,
  and 29B, authentication).
  `AdvancedSection` (the toolbar: the Registration / Authentication `SegmentedControl`,
  Saved Credentials with its count, and the segment's Reset and Create Credential or
  Assert Credential; the segment's own progress line, failure in place and `CeremonyResult`
  with its challenge row; each segment's form beside its JSON editor from 1280 px, both
  segments mounted; one ceremony at a time; `CredentialDetailDialog` at
  `#advanced/credential/<key>/…`), `CredentialsDrawer`
  (the saved credentials in a `Drawer` over `SavedCredentialList`, the count and Clear All
  in its header; not a URL, closed on leaving the section), `requestEditor.ts` (what both
  requests keep alike: the text is the request, the keys an edit holds beside `publicKey`,
  the edit's reading, and the form's request the text last followed; `followedText` writes
  a form change over the text with `followForm` (`request-patch.js`), so what the form did
  not change stays as typed; a background change (the saved credentials) leaves text that
  does not parse alone; `resetText` is the editor's Reset), `useAdvancedRequest`
  (registration's: a form change follows the form; an edit is read by `readEditedRequest`,
  and one the form can read updates the form at once and becomes the baseline; one that
  does not parse or that a check refuses leaves the form as it was and says why and where;
  the host and the random values set after hydration), `useAuthenticationRequest`
  (authentication's, the same way: Allow Credentials' choices from the saved credentials
  the registration settings' hints or attachment allow (`allowChoices`), a choice that
  goes falling back to All, and largeBlob and prf cleared where the credentials cannot use
  them (`settled`); it starts once the saved list is read; its Reset keeps the Hash
  Algorithm and leaves the registration alone), `RegistrationForm` and
  `AuthenticationForm` (section cards, each a container-query grid of field rows) over
  `FieldControls` (`FormSection`, `toggled` (a set's order kept), `SelectField` (options,
  locked, some options unusable, a note), `SwitchField`, `ChipGroupField` / `Chip`,
  `HexField` with its refresh button and a note, `FakeCredentialField`, `About`, the info
  popup), `JsonEditor` (by scope: a Geist Mono textarea named by its heading, the keys of
  `json-editing.js`, the note with the line and column and Go to line, Reset),
  `useRegistrationCeremony` (the shared ceremony: a busy button,
  the steps' sentences, toasts, a failure in place; the record and its snapshot saved,
  then the dialog opened at the registration with the detail one Back below, only while
  the tab is shown), `useAuthenticationCeremony` (over `assertion.js`: the toast, the
  result with the counter and the challenge, the counter kept, the row tinted green or
  red, the values drawn again; no dialog), `fieldText.ts` (the templates' labels, options,
  errors and info popups in English and 中文, generated from
  `frontend/templates/advanced/tab/`, without the words logic modules hold) and `model.ts`
  (the casts of the logic below). Tests: `src/test/advanced.tsx` renders either form with
  its editor; the recorded registrations and authentications come through
  `tests/frontend/advanced/auth/advanced-answers.js` (`@legacy-tests`), which also stands
  in for the authenticator. `docs/ui-parity/advanced.md` maps every item.
- `web/src/components/analyze-browser/`: the first ported surface, over the logic
  modules in `frontend/static/scripts/shared/browser/`, imported through the
  `@legacy/*` alias (`experimental.externalDir`), never copied. They move into
  `web/` at the cutover. `docs/ui-parity/analyze-browser.md` maps every item of the
  old panel to the new one.
- `web/src/components/codec/`: the Codec (Phase 26). `CodecSection` (the Decode /
  Encode `SegmentedControl`, both panels mounted, input beside output from 1280 px),
  `useCodec` (one panel's input, options, answer and failure: checks before it
  clears, a busy button, Clear drops an answer still coming), `CodecOutput` (header,
  lenient note, `Findings` with the category chip, sections), `ValueView` (a decoded
  value by `values.js`'s rules; a nested map under its label, side by side only where
  a container query finds room), `EncodedOutput`, `RawDialog`, `FailureNotice`
  (failures stay in the panel, with the 422's offset and path), `SupportedInputs`.
  `model.ts` types the logic imported from `frontend/static/scripts/decoder/codec/`
  (`request.js`, `result.js`, `values.js`, `encoding/summary.js`), which both UIs use.
  Its tests render real answers: `web/src/test/codec-answers.json`, which
  `tests/app/tooling/test_web_codec_answers.py` keeps equal to what `/api/codec`
  answers (`CODEC_ANSWERS_WRITE=1` rewrites it). `docs/ui-parity/codec.md` maps every
  item of the old tab.
- `web/src/components/mds/`: the MDS explorer (Phases 27A, the list, and 27B, the rest).
  `MdsSection` (the header and count, the status line, the filter bar, the table, an
  open entry, Manage Metadata), `useMdsExplorer` (GET `/api/mds/metadata/info`, then
  the packaged snapshot or the session's list, the status sentences, Retry, a snapshot
  from an upload shown at once), `useExplorerView` (filters through
  `useDeferredValue`, their options, the sort reset per snapshot, expanded rows),
  `ExplorerTable` / `ExplorerRow` (13 columns in a frame that scrolls both ways, the
  header sticky; every row in the page, each a grid on one column template set
  through the CSSOM (`--mds-columns`) with `content-visibility: auto`, so rows out of
  view are neither laid out nor painted; explicit table roles; one-line cells with
  their tooltip, a row expands; resizing by pointer and keys; the Icon column narrow
  on a phone; a white fade on the right edge while the frame scrolls further; Back to
  top), `FilterBar` / `FilterCombobox` (the 11 filters above the table, the seven with
  a list as ARIA comboboxes), `ManageMetadataDialog` / `useCustomMetadata`, `ListState`,
  `model.ts` (the types and the casts of the imported logic, the columns' and filters'
  template words). An entry (27B): `EntryRouter` (`#mds/<entryId>` and
  `…/certificate/<n>`; the entry stays in the page under a certificate, Back returns to
  its button; an unknown path is corrected), `useEntryDetail` (the entry from the
  list, else `GET /api/mds/metadata/resolve`, with MDS-J2's sentences and Retry),
  `EntryPage` / `EntryHeader` / `EntrySections` / `UserVerification` / `StatusReports`
  (the sections as headings and hairlines, identifiers in Geist Mono with copy, the
  reports stacking on a phone), `CondensedBar` (a white bar under the top bar once a
  page's title has scrolled away; in the overlay layer, since a section sliding in is
  a transform), `CertificatePage` / `CertificateSummary` / `useCertificateDecode` (one
  decode per certificate), `RawEntryDialog` (the entry as MDS publishes it, copy, a
  JSON download), `entryLink.ts` (`mdsEntryPath(aaguid)`, `openMdsEntryForAaguid`,
  `useOpenMdsEntry`: how Phase 28's saved credentials open an AAGUID's entry, the URL
  being `#mds/aaguid:<aaguid>`) and `entryModel.ts` (their types and casts). The logic
  is `frontend/static/scripts/advanced/mds/explorer/*.js`, `raw-data.js`,
  `raw-stringify.js` and the leaves under them.
  Component tests render the fixture snapshot (`tests/fixtures/mds`, through the
  `@test-fixtures` alias; `src/test/mds.ts` answers `fetch` like Flask serving it).
  `docs/ui-parity/mds.md` maps every item of the old tab.
- `web/scripts/check-export-csp.mjs`: parses every HTML file of the export and
  fails on an inline script that would run, a `<style>`, a style attribute, an `on*`
  attribute, a `javascript:` URL or a script or stylesheet from outside `/beta/`.
- `web/e2e/`: Playwright in Chromium. `serve-flask.mjs` starts Flask with every store
  in a temporary directory and a copy of the MDS fixture as its snapshot
  (`FIDO_SERVER_MDS_SNAPSHOT_DIR`); `virtual-authenticator.ts` adds a CTAP2 authenticator
  through the DevTools WebAuthn domain; `fixtures.ts` fails a test on any console
  error, page error, CSP violation or report. `simple-ceremony.spec.ts` registers and
  authenticates on the current UI at `/`; `beta-smoke.spec.ts` covers `/beta` (and a
  hashed load of each section, frame by frame, with the scripts held back);
  `codec.spec.ts` the Codec; `design-rules.ts` finds grey fills. `parity.ts` compares
  what a region shows in the current UI and in `/beta`, word for word per section
  (layout, separators and controls set aside), each expected difference with its
  reason; `codec-parity.spec.ts` runs it over inputs from `tests/app/codec_corpus.py`
  (read through `E2E_PYTHON`), and a later surface's parity spec uses it the same way;
  an expected difference may be scoped to one section.
  `readShownRows` reads a table a row at a time, keyed by a cell (controls' text kept);
  `mds-parity.spec.ts` compares the MDS tables' rows for several filters and a sort,
  `mds-entry-parity.spec.ts` five entries' pages, a certificate and the raw view,
  `mds.spec.ts` covers the MDS list and `mds-entry.spec.ts` an entry, its certificates,
  its raw view and the AAGUID link. `simple.spec.ts` registers and authenticates in
  `/beta`, and proves the saved credentials shared both ways (registered in one UI,
  listed, used, deleted and cleared in the other); `credential-detail.spec.ts` opens a
  credential's every level (registered in either UI, by click and by URL, Back through
  the levels, 1440 / 1024 / 375 px, another tab followed) and
  `credential-detail-parity.spec.ts` compares the details, the registration, each
  certificate's and the authenticator data's text, and an advanced registration's result,
  with the current UI (its helpers, `credential-views.ts`, shared with the Advanced parity);
  `simple-parity.spec.ts` compares the
  tab, each row with its checks' verdicts, the result panel and the success sentences.
  `advanced.spec.ts` registers and authenticates in `/beta#advanced` from the form and
  from an edited JSON, refuses an edit that does not parse, keeps what an edit typed
  through a form change, says a refused authentication in place (Hash Algorithm SHA-512),
  opens a credential from the drawer, uses credentials across both UIs (chosen in Allow
  Credentials) and fits 1440 / 1024 / 375 px in each segment; `advanced-parity.spec.ts`
  compares each form's words, its info popups (English and 中文), its choices, the editor's
  text byte for byte for the same settings, a registration's details and an
  authentication's result, with the current tab. Every section is mounted, and both
  Advanced segments: scope a query to its tabpanel (`#advanced-ceremony-panel-<segment>`).

Rules for `web/src` (`tests/app/tooling/test_web_source_rules.py` holds them):
no `style` prop (the export would render a style attribute), no
`dangerouslySetInnerHTML` or other markup sink, no `<style>` / `<script>`, no
`next/script`, no `next/link` (following one makes Next's router add page scripts,
which the Trusted Types policy reports, and leaves the browser's Back on the app), no
`eval`, nothing written to `window`, no `atob`, and no copy of
the logic modules' exports or sentences (comments count). The logic modules are the test's
`LOGIC_ROOTS` (Analyze Browser's, the Codec's, the MDS explorer's, the failed-response reader,
the saved credentials' storage, the Simple tab's ceremonies, what a credential's row shows, a
credential's details and registration view with their state, and the Advanced tab's requests,
editor, form change, form rules, Allow Credentials choices, extensions' availability and both
ceremonies) plus
whatever `web/src` imports through `@legacy/`, followed through their imports, and
none of them may touch the DOM: a surface splits its logic out of its view first
and adds it to `LOGIC_ROOTS`. No `Suspense` on the server-rendered path:
React would put an inline script in the export. Links are plain: `<a href="/">` to the
current UI, `<a href="/beta">` to the new one.

Running it locally (Node 22):

- `cd web && npm ci`
- `npm run dev`: the dev server at `http://localhost:3000/beta`, proxying `/api` to
  Flask at `FLASK_URL` (default `http://localhost:8000`, `python -m server.app.app`).
  WebAuthn ceremonies need the Flask origin; use the export for those. It sends
  Flask's CSP (`web/scripts/dev-csp.mjs`) with only the two allowances the dev server
  needs (`'unsafe-eval'` in `script-src`, `style-src-elem 'unsafe-inline'`), so an
  inline script, a style attribute or another origin shows as a violation in the
  console while developing; `tests/app/tooling/test_web_dev_csp.py` keeps the copy
  equal to Flask's defaults.
- `npm run build`: the export in `web/out`, which Flask serves at `/beta`
  (`FIDO_SERVER_WEB_EXPORT_ROOT` points elsewhere). Without a build `/beta` is a 404.
- `npm run typecheck`, `npm test` (vitest, jsdom, Testing Library),
  `npm run test:coverage` (with the floors in `web/vitest.config.mts`),
  `npm run check:csp` (after a build), and `npm run e2e` (after a build; Chromium
  once with `npx playwright install chromium`; `E2E_PYTHON` names the Python with
  the app's dependencies, `.venv/bin/python` by default).

### The current UI (`frontend/`)

The app is a multi-tab UI wired together from `frontend/static/scripts/main.js`.

Important frontend entry points:

- `frontend/static/scripts/simple/auth-simple.js`
  Simple register/authenticate flows.
- `frontend/static/scripts/advanced/auth/advanced.js`
  Advanced register/authenticate flows.
- `frontend/static/scripts/advanced/credentials/index.js`
  Shared saved-credential list, card rendering, credential detail modal, list refresh behavior.
- `frontend/static/scripts/advanced/editor/index.js`
  Advanced JSON editor state and synchronization.
- `frontend/static/scripts/shared/ui/navigation.js`
  Top-level tab switching and advanced sub-tab switching.
- `frontend/static/scripts/shared/storage/records.js` and `local.js`
  Browser-side stored credential records and serialization sent back to the server:
  one `localStorage` array both UIs read and write. `records.js` is the API and reads no
  page; `local.js`, the current UI's barrel, seeds it from the `initial-credential-records`
  page data its tests give (`seedUnifiedCredentialRecords`) and re-exports it. The storage
  keeps what it read until another tab changes it: `followStoredCredentialChanges` drops
  what was read on the storage event (so the next write builds on the other tab's
  records) and calls back; both UIs follow it. Held at 100 % per file.
- `frontend/static/scripts/simple/ceremony.js`
  The Simple tab's two ceremonies with no DOM (the requests, the ponyfill, every step's
  and outcome's sentence, the result panel's input); `auth-simple.js` is the current
  tab's view over it, keeping the storage calls its tests mock. The new UI runs it too.
- `frontend/static/scripts/advanced/credentials/saved-list.js`, `delete-flow.js`,
  `algorithm-tag.js`, and `advanced/cose-labels.js`
  What a saved credential's row shows (`describeCredentialCard`, given the indicators,
  the algorithm's tag and the hex id as values), the list's records and warm-up,
  deleting and clearing (given `confirm`, the storage and where messages go), a
  credential's algorithm and tag (given the COSE describer; an algorithm the labels do
  not name is tagged `COSE${id}`). The current views render them with the functions
  their tests inject or mock; the new UI with the real ones.
- `frontend/static/scripts/advanced/credential-display/` and `advanced/credentials/hydrate.js`
  A saved credential's details and the registration view, whose logic is DOM-free and
  both UIs build from (Phase 28B): `registration-state.js` (the registration's state,
  always passed in: the current UI keeps one, `state.js`'s `registrationDetailState`,
  which its second modal reads when a button is pressed; the new UI one per credential),
  `registration-view.js` (what the registration view, a certificate's and the
  authenticator data's own views show, as data; `composeRegistration`; the snapshot a
  registration keeps), `decode-payload.js` (`POST /api/decode`), `certificate-text.js`,
  the sanitisers, `credential-detail-runtime/detail-sections.js` (one describer per
  section, with the current builders' own inputs, since their tests call them) and
  `compose.js` (`needsArtifact`, `composeCredentialDetail`), and `hydrate.js` (the
  artifact merged into a record, given the fetch and the snapshot's save). The current
  views (`sections-*.js`, `registration-compose-runtime.js`, `entry.js`,
  `registration-result.js`, `detail-nodes.js`) render the data; `registration-state-runtime.js`
  and `certificate-state.js` bind the current UI's one state. All are held at 100 % per
  file (`vitest.config.mjs`) and are `LOGIC_ROOTS`.
- The Advanced tab's logic, DOM-free, which both UIs run (Phase 29A), under
  `frontend/static/scripts/advanced/`: `json-editor/registration-request.js`
  (`registrationDefaults`, with no random values; `buildCreationOptions(settings,
  context)`, the relying party's name, host,
  stored credentials and fake IDs passed in; `readCreationOptions`, the settings a request
  says, reading back everything the form writes; `changeRegistration`, the form's rules,
  whose DOM copy `main.js` keeps until the cutover; `registrationControls`;
  `decodeJsonBinaryToHex`), `json-editor/editor-model.js` (the editor's titles and
  sentences, `requestText`, the structure checks, `topLevelExtras`,
  `locateJsonSyntaxError`'s line and column, `readEditedRequest`: unparsed, refused or
  accepted), `json-editor/algorithm-options.js` (the algorithm table, ML-DSA first),
  `editor/json-editing.js` (the editor's keys over a `{value, selectionStart,
  selectionEnd}` copy), `auth/hint-rules.js`, `auth/fake-credentials.js`,
  `auth/hex-input.js`, `auth/ceremony.js` (`registerAdvancedCredential(text, …)` sends the
  editor's text; its sentences; the hint rules, the storage and the values the form reads
  passed in) and `credential-display/registration-snapshot.js`
  (`keepRegistrationSnapshot`). Authentication's (Phase 29B): `json-editor/authentication-request.js`
  (`authenticationDefaults`, `buildRequestOptions`, `readRequestOptions` (reading back
  everything the form writes: a list the choice builds keeps it, IDs no saved credential
  has are the fake allow IDs), `changeAuthentication`, `withAvailability`,
  `authenticationControls`), `auth/allow-credentials.js` (the choices and their words,
  given the attachment filter and the record helpers; `keptChoice`),
  `auth/capabilities.js` (largeBlob and prf availability and their notes) and
  `auth/assertion.js` (`authenticateAdvancedCredential(text, …)`: the hints' check, the
  records sent, the Hash Algorithm and the fake length passed in; it returns the result
  panel's input and a refused credential's ID). `json-editor/request-patch.js`
  (`patchRequest`, `followForm`) applies a form change to the editor's text in both UIs:
  the current `editor-flow.js` keeps the form's last request as its baseline
  (`updateJsonEditor` follows, `rebuildJsonEditor` for a reset; a sub-tab switch
  rebuilds). The current modules keep their paths and wrap or re-export
  them (`hints.js`, `exclude-credentials.js`, `forms.js`, `creation-options.js`,
  `request-options.js`, `form-sync.js`, `editor-flow.js`, `dom-helpers.js`, `resets.js`,
  `advanced.js`, `list-render.js`, `registration-result.js`), since their tests mock by
  path. Held at 100 % per file with the editor's `schema.js`, `validation-*.js` and
  `merge-prune.js`, and `LOGIC_ROOTS`.
- `frontend/static/styles/shared/layout.css`
  Shared layout and credential card animation styles.
- `frontend/static/scripts/shared/browser/`
  The Analyze Browser panel (header button). It reports what the browser says and
  says where each answer came from, or that it cannot know; it never guesses.
  `identity.js` copies what the browser exposes (`readIdentityInputs`) and names the
  browser, version, engine and system from that copy (`determineIdentity`, a pure
  function): a brand's version is never another brand's, "Google Chrome" only when
  the brand list says so, "Chromium-based browser" for a list of only Chromium.
  `webauthn-facts.js` asks the WebAuthn questions and keeps each answer in one of
  four states (`yes`, `no`, `unavailable` when the method is missing, `undetermined`
  when it threw, with why); it also reads `getClientCapabilities()`. `report.js`
  gathers both, groups the capabilities, builds the report and copies it, with no
  DOM: the new UI imports it too. `analyze.js` renders the legacy panel and handles
  its dialog (focus in, Tab kept inside, Escape, focus back to the button). `probe.js` reads an API that
  may be missing or throw. Web pages cannot ask which authenticator transports a
  browser supports: do not reintroduce WebUSB/WebHID/Web Bluetooth/Web Serial
  checks, which say nothing about WebAuthn. The identity cases are real
  user-agent strings with their Client Hints in
  `tests/frontend/shared/browser/identity-matrix.js`; add a browser there.
- `frontend/static/scripts/decoder/codec/`
  The Codec tab. Its logic is DOM-free and both UIs import it: `request.js` (the
  checks before a request, `POST /api/codec`, the progress, success and failure
  sentences, the raw view's JSON), `result.js` (what the output shows for an answer
  and in what order: pill, type, lenient note, findings, malformed line, sections by
  type), `values.js` (how one value is shown, and the interpretation badges),
  `labels.js` / `constants.js` (`formatKey`, the 88 labels), and in `encoding/`
  `summary.js` (the encoded bytes' views and length), `can-encode.js`, `format.js`,
  `binary.js`. The legacy views build their DOM over them: `process.js`,
  `render-sections.js`, `render-values.js`, `encoding/format-elements.js` (plus
  `mode.js`, `dom-state.js`, `panel-actions.js`). The root coverage counts the whole
  Codec, and holds the logic leaves at 100 % (`vitest.config.mjs`). A failed codec
  request's `offset` and `path` are in `readFailedResponse`'s answer.
- `frontend/static/scripts/advanced/mds/explorer/`
  The MDS explorer's logic, DOM-free, which both UIs import: `loading.js` (which
  source and in what order, what an answer means, the entries shown, GET
  `/api/mds/metadata/info`), `status.js` (the status line's sentences, the count),
  `filter-sort.js` (matching, sorting, the click cycle), `options.js` (each filter's
  list), `rows.js` (cell fallbacks, the certification badge, the identifier's kind),
  `columns.js`, `custom-metadata.js` (Manage Trusted Metadata's requests and every
  message), and for an entry `detail.js` (the detail page's sections, fields, labels
  and order: `detailSections`), `certificate.js` (the decode request and its sentences,
  a certificate's title and summary: `describeCertificate`) and `entry-link.js` (the
  resolve request, `entryIdForAaguid`, the credential jump's sentences). `raw-data.js`
  and `raw-stringify.js` (the raw view: the entry as MDS publishes it, its text, its
  words) are logic too. The legacy views call them. The server builds every row
  (`mds_snapshot.build_explorer_entry`); the client's own row builder
  (`utils/entry-transform.js`, the lazy loader) is only for a payload without
  `entryId`, which the server never sends, and goes at the cutover
  (`docs/ui-parity/mds.md`, "Never shown"). The paths in `constants.js` are absolute,
  so they resolve the same from `/beta/`. `explorer/*.js`, the raw view's two modules
  and the leaves under them are held at 100 % (`vitest.config.mjs`). They import the
  leaves (`utils/formatters.js`, ...), never the `utils.js` barrel, which reaches the
  legacy DOM builders.
- `frontend/static/scripts/shared/ui/dom.js`
  How every view that shows data is built: `el(tag, {className, attrs, dataset,
  style, text}, ...children)` and `fragment()`. Strings become text nodes or
  attribute values, never markup, and an `on*`, `innerHTML`, `outerHTML` or `srcdoc`
  attribute throws; handlers are added with `addEventListener`. The `style` option
  is applied through CSSOM (`element.style`), which the CSP allows. No script hands
  the browser markup to parse -- no `innerHTML`/`outerHTML`, `insertAdjacentHTML`,
  `document.write`, `DOMParser`, even with a fixed string, since each is a Trusted
  Types sink; empty a container with `replaceChildren()` (see Testing Guidance). The
  credential cards, the credential detail modal (`credential-detail-runtime/`,
  `detail-nodes.js`), the registration result and its certificate / authenticator-data
  sub-modal (`registration-compose-runtime.js`) and the MDS raw-data popup
  (`advanced/mds/raw-window.js`, an `about:blank` window that shares the page's CSP,
  styled by `styles/advanced/mds-raw-window.css`) are built this way.
- `frontend/static/scripts/shared/ui/actions.js`
  How a template control does something. The markup names the action,
  `data-action="switch-tab"`, with any argument in another `data-*` attribute
  (`data-tab="codec"`), and never holds code: there is no inline `on*=` handler and
  nothing is put on `window`. The module that owns the behaviour exports a table
  (`navigationActions`, `formActions`, `codecActions`, ...) and a `bind...Actions()`
  that calls `bindActions(root, table)`: one delegated listener on the root of the
  area its controls sit in -- the tab, or `document` when they span areas (the
  sticky mini-header shows a clone of the top navigation) -- so a table entry never
  fires twice. `callWith(fn, 'tab')` makes the usual entry; an entry may also be
  `{ mouseenter, mouseleave }` (the info popups), dispatched only for the element
  that names the action. A disabled control is skipped. `main.js` calls the binders
  when it loads; a click before then does nothing. Names are local to their area, as
  the Analyze Browser panel's `close` / `copy-report` are.
  `tests/frontend/page-actions.test.js` renders the real templates
  (`tests/frontend/page-template.js`), loads `main.js` and checks that every
  `[data-action]` runs exactly its owner's entry; add a new owner's table there.
- `frontend/static/scripts/shared/utils/page-data.js`
  The page's data for its scripts: `index.html` renders
  `<script type="application/json" id="initial-mds-info">`, which the browser never
  runs, and `readPageData(id)` parses it. `initial-mds-snapshot` and
  `initial-credential-records` are read the same way; the server renders neither
  (the page reads the browser's storage), tests give theirs through
  `tests/frontend/page-data-helper.js` (`setup.js` writes the defaults).
- Registration detail snapshots (`registrationDetailSnapshot`, schemaVersion 2) hold
  the registration as data -- `state` (decoded attestation, certificates,
  authenticator data) and `response` (`credential`, `relyingParty`) -- never markup.
  `snapshot-sanitize.js` keeps each `response` part whole or drops it; the detail modal
  builds from a v2 snapshot without a request and otherwise hydrates the credential
  from its server artifact. Composed HTML from older versions, and the raw
  `registrationDetailHtml`-style keys, are never read.
- `frontend/static/scripts/shared/api/failed-response.js`
  The one reader of a failed response, for both tabs, the codec and the decode
  request: `readFailedResponse(response)` gives the server's `error` (or short plain
  text; never an HTML page), `failedCredentialId`, `signCountStatus`,
  `challengeSource`, `challengeStatus`, a codec refusal's `offset` and `path`, and the body, and adds what to do for a 400
  about the ceremony state, 409, 413 and 503 unless the message already says;
  `FailedResponseError` carries it. Do not show a raw response body.
- `frontend/static/scripts/shared/ui/ceremony-result.js` (over `shared/ceremony/result.js`)
  The panel under each tab's buttons (`#simple-ceremony-result`,
  `#advanced-ceremony-result`) that says what the server made of the last ceremony:
  the signature counter with a sentence for `ok`, `not-supported` and `regressed`
  (a possible clone; a warning), and in the advanced tab where the challenge came
  from (`challengeSource`, `challengeStatus`). Not a `.status` toast: it stays until
  the next ceremony starts.
- `frontend/static/scripts/shared/utils/base64.js`
  Bytes on the wire are base64url, unpadded, in every field the server sends; a
  field named for base64 (`derBase64`, `publicKeyBase64`, `userHandleBase64`, the
  codec's `base64` views) is standard base64. Decode API data with the strict
  `base64UrlToBytes` (or `base64ToBytes` for such a field): one spelling per byte
  string, anything else throws `Base64Error`. `forgivingBase64ToBytes` does what
  `atob` did and is only for text a person typed (the editor's helpers in
  `binary.js` use it). No `atob` outside the vendored `shared/webauthn/json-ponyfill.js`.
- `frontend/static/scripts/shared/storage/local/record-migration.js`
  Brings records saved by earlier versions to today's format as they are read
  (`storage-core.js`, and artifacts in `hydrateCredentialFromServer`), persisting
  when anything changed: drops stored registration markup, and re-spells standard
  base64 as base64url in the known byte fields (`credentialId`, `publicKey`,
  `publicKeyBytes`, `userHandle`, `publicKeyCose` strings, `attestationStatement`
  byte strings). Fields named for base64, extension outputs and properties are left
  alone. Add a step here, with an old-format fixture in
  `tests/frontend/shared/storage/`, when a stored format changes.

Important templates:

- `frontend/templates/simple/tab.html`
- `frontend/templates/advanced/tab.html`
- `frontend/templates/decoder/tab.html`
- `frontend/templates/shared/navigation.html`
- `frontend/templates/shared/analyze-browser.html` (the panel's test renders this file)

## Backend Map

Flask app setup starts in:

- `server/app/app.py`
  The WSGI entry point, `server.app.app:app = create_app()`, in a checkout and in
  the image alike: the Dockerfile copies `server/app` to `/app/server/app`, so every
  module has one import path. Do not add `server.X` / `server.app.X` fallbacks.
- `server/app/factory.py`
  `create_app(config=None)` builds a fresh, fully configured app: settings from
  each config submodule's `config_from_env()`, then the `config` overrides, then
  `INIT_STEPS` in order (logging, secret, ProxyFix, gzip, security headers, static
  assets, blueprints, RP warning). `tests/app/core/test_app_factory.py` pins the
  order; changing it is a behaviour change.
- `server/app/config/`
  What `create_app()` is built from: `application.py` (`build_app()`),
  `logs.py`, `session_secret.py`, `compression.py`, `proxy.py`,
  `session_cookie.py`, `security_headers.py` (a strict CSP -- `script-src 'self'`,
  `style-src 'self' https://fonts.googleapis.com`, no `'unsafe-inline'` -- plus a
  `Content-Security-Policy-Report-Only` with `require-trusted-types-for 'script'`,
  both reporting to `/api/csp-report` by `report-uri` and, through
  `Reporting-Endpoints`, `report-to`; each settable in the environment, and
  `FIDO_SERVER_CONTENT_SECURITY_POLICY` replaces the whole enforced policy),
  `origins.py`, `attestation_trust.py`,
  `mds.py`, `relying_party.py` (RP ID, `create_fido_server`), `paths.py`,
  `request_limits.py` (`MAX_CONTENT_LENGTH`, 8 MiB, and the metadata upload's own
  16 MiB, chosen from the sizes measured in Phase 21 and settable in the
  environment; a larger body is answered 413 in JSON by `routes/errors.py`).
  Importing it configures nothing. The routes call `config.create_fido_server` /
  `config.determine_rp_id` through the package, so route tests patch those on the
  package; patch every other name in its submodule.
- `config.app` is a lazy alias for `server.app.app.app`, kept so the tests written
  against the old singleton still work. Nothing in `server/` may read it
  (a test enforces that): request code uses `flask.current_app`, and code outside
  a request takes the app as an argument.
- Importing any module under `server/app`, except the entry point, must not write
  to disk. `tests/app/core/test_import_side_effects.py` imports every module
  under an audit hook and fails on any write.
- Log with `logger = logging.getLogger(__name__)`, never `app.logger`. The app is
  named `server.app`, so module loggers are children of `app.logger` and reach
  the stderr handler `config/logs.py` makes sure exists;
  `tests/app/core/test_logging_reaches_stderr.py` checks that under gunicorn.
- On Cloud Run (`K_SERVICE` set) the app refuses to start without
  `FIDO_SERVER_SECRET_KEY` or a readable `FIDO_SERVER_SECRET_KEY_FILE`; only local
  development generates and persists `instance/session-secret.key`. A test run
  never does: `tests/conftest.py` sets a test `FIDO_SERVER_SECRET_KEY` when it is
  imported, before any test module imports the entry point, and a test of the
  secret's own handling removes it with `monkeypatch.delenv`.
- `server/app/mds_trust.py`
  The MDS trust anchor. A leaf on purpose: `tools/update_mds_snapshot.py` imports
  it without anything from Flask.
- `server/app/mds_snapshot_dir.py`
  Where the MDS snapshot is: its seven file names and `snapshot_dir()`, which reads
  `FIDO_SERVER_MDS_SNAPSHOT_DIR` whenever a path is needed (default
  `frontend/static`). A Flask-free leaf too: the server (`webauthn/metadata/blob.py`,
  `routes/general.py`), the provisioning, the served snapshot
  (`/assets/<id>/fido-mds3.explorer.full.json`) and the updater all follow it.

Main route modules:

- `server/app/routes/simple/`
  Simple WebAuthn begin/complete endpoints. `__init__.py` holds the Flask rules on
  the `simple` blueprint (`bp`); `registration.py`, `authentication.py` and
  `credential_list.py` hold the bodies. `registration.py` runs register-complete's
  stages: `registration_record.py` builds the record (attestation summary, credential
  info, authenticator data, relying-party and debug views, stored credential) and
  `registration_persistence.py` saves it -- appending to the user's credential list by
  compare-and-swap, retrying a lost race up to eight times, 409 after that, and 503
  when the stored list could not be read or did not decode -- then updates the
  session list and the device log. `authentication.py` checks the
  signature counter against the larger of the stored and the browser's copy. It
  fails closed: stored records that could not be read reject the assertion with 503
  (the browser's copy alone can be omitted or lowered); records that were read but
  hold nothing for the credential fall back to the browser's copy. The 200 and the
  regression rejection carry `signCountStatus` (`server/app/webauthn/sign_count.py`),
  which the tab's result panel shows. `credential_list.py`
  answers `GET /api/credentials` with `{"credentials": [...]}` plus `unreadableCount`
  (and the `X-Unreadable-Credentials` header) when a stored copy did not decode or a
  record could not be shown, and 503 when the store could not be read.
- `server/app/routes/advanced/`
  Advanced WebAuthn begin/complete endpoints, algorithm handling, request
  validation, metadata-heavy flows. Same shape: rules on the `advanced` blueprint
  in `__init__.py`, bodies in `registration.py`, `authentication.py`, `artifacts.py`.
  The bodies are short orchestrators over modules named for their stage:
  registration begin in `registration_options.py` (request checks, RP and server,
  authenticator selection, exclude list, extensions) with the algorithm offer in
  `algorithms.py`; registration complete in `registration_inputs.py` (request, state,
  fido2 verification), `registration_attestation.py` (origin allowlist, attestation
  checks and their summary), `registration_record.py` (credential info, debug view,
  relying-party view, stored credential) and `registration_persistence.py` (artifact,
  device log, answer); authentication in `assertion_credentials.py` (which stored
  credentials may answer), `assertion_options.py` (begin's server, UV, extensions) and
  `assertion_verification.py` (fido2's verdict and the answer). The challenge-source
  names live in `constants.py`, the binary request-field decode in `binary.py`, the
  attachment-hint check in `server/app/attachments.py`. The try blocks and the order
  of session reads in the bodies are behaviour; keep moved code inside them.
- `server/app/routes/general.py`
  Index page, metadata bootstrap helpers, decoder endpoints, misc app routes, on
  the `general` blueprint. `_initial_mds_info()` builds what the index inlines as
  `initial-mds-info` and what `GET /api/mds/metadata/info` answers (no-store,
  `Vary: Cookie`); its `snapshotUrl` is there only while the packaged file is there with
  a meta that matches the verified snapshot, and carries `?v=<serial>.<digest>` (the
  file changes at runtime; its URL is cached for a year). The routes that read the
  snapshot, the browsers' snapshot file at its versioned URL, and both registrations'
  complete (which look the new credential's AAGUID up and record what they found), wait
  for a provisioning under way (`mds_provisioning.waits_for_the_snapshot`, over
  `ensure_snapshot_available()`, which a cold instance's warm-up is running; the tests make
  the process's first attempt at session start, `tests/app/conftest.py`);
  the index does not (unless it bootstraps the metadata itself). An upload or delete records
  whether the session has uploads. `routes/web_export.py` (the `web_export` blueprint) serves
  the new UI's export at `/beta`: HTML `no-cache`, `/beta/_next/static/` immutable for
  a year with the build-time `.gz` copies (`static_assets.send_precompressed`), the
  export's `404.html` for an unknown path, a plain 404 with no export; the export
  root is `config/web_export.py` (`web/out`, or `FIDO_SERVER_WEB_EXPORT_ROOT`).
  `static_assets.py` has its own `static_assets`
  blueprint. Endpoint names are therefore `general.index`, `simple.register_begin`
  and so on; nothing refers to them today (no `url_for`).
- `server/app/routes/csp_report.py`
  `POST /api/csp-report`, on the `csp_report` blueprint: where browsers send CSP
  and Trusted Types violations. It bounds the body itself (512 KiB, answered 413
  without `errors.py`'s per-request log line), and `server/app/csp_reports.py` reads
  both wire formats and logs each violation as one WARNING line,
  `CSP violation: directive=... blocked=... path=...`, keeping nothing else (no
  query, user agent, address or sample). A token bucket per app (burst 30, 30 a
  minute) bounds a flood and says how many lines it dropped. A breakage the policy
  causes in production shows in the Cloud Run logs as these lines.

Related backend modules:

- `server/app/webauthn/attestation/`
  Attestation parsing and validation. `checks.py` (the checks), `trust.py`, `pqc.py`,
  `classical.py`. `certificates.py` serialises a certificate and extracts an
  attestation's details; it draws on `certificate_names.py` (a leaf: name
  spellings), `certificate_extensions.py` (one handler per extension; signed
  certificate timestamps are records, never `str()` of cryptography's objects),
  `certificate_public_keys.py` (loadable keys, and the best effort for one
  cryptography will not load) and `certificate_summary.py` (the text summary, a
  section at a time).
- `server/app/webauthn/signature_algorithms.py`
  The one spelling of a certificate's signature algorithm (`ECDSA_SHA256`,
  `ED25519_SHA512`, `RSASSA-PSS_SHA256` with the hash from the PSS parameters,
  `ECDSA_SHA3-256`, `ML-DSA-44` with no hash), for the certificate view and the MDS explorer
  (`mds_snapshot.py`) alike. A leaf outside the attestation package, whose
  `__init__` imports the whole stack: `tools/update_mds_snapshot.py` reaches it
  without Flask, which `tests/app/tooling/test_update_mds_snapshot.py` checks in a
  fresh interpreter.
- `server/app/webauthn/metadata/`
  FIDO MDS resolution: `blob.py`, `snapshots` via `effective.py`, `sessions.py`.
- `server/app/webauthn/pqc.py`
  The ML-DSA adapter.
- `server/app/storage/`
  Persistence: `credentials.py`, `record_format.py` (the JSON envelope and the
  restricted reader for legacy `.pkl` copies), `session_metadata.py`, `cloud.py`,
  `common.py`; credential artifacts are `server/app/credential_artifacts.py`. Every
  read-modify-write goes through compare-and-swap (`read_for_update` /
  `save_if_unchanged`). A read that fails raises `StorageReadError` (503), never a
  shorter list; content that does not decode is logged by name and counted, never
  overwritten unread.
  **Read `docs/STORAGE.md` before changing `server/app/storage` or `credential_artifacts.py`.**
- `server/app/decoder/`
  The codec behind the Decoder tab: `decode/` shows what input holds, `encode/`
  writes a value back. It shows what was sent -- it never repairs, synthesizes or
  drops a field -- and puts interpretation beside the decoded value, never in its
  place. Input is parsed only by `decode/cbor_parser.py`; encoder bytes come only
  from `decoder/cbor_canonical.py` and the EDN reader; `ctap_tables.py` and
  `cose_tables.py` are the only copies of their registries.
  **Read `docs/DECODER.md` before changing anything under `server/app/decoder`.**

Each of these packages keeps its public surface in `__init__.py` and its
implementation in submodules named for what they do. Import the submodule you
need; patch there rather than on the package's re-export, because the submodules
call each other through module objects.

## How Data Flows

For authentication work, the important path is usually:

1. Frontend collects stored credentials from browser-side storage.
2. Begin endpoint issues request options and stores server-side state in Flask session.
3. Browser performs `navigator.credentials.create/get`.
4. Complete endpoint verifies the response using `create_fido_server(...)`.
5. Frontend updates local saved credential state and refreshes the shared credential list.

The saved credential cards shown in simple and advanced tabs are rendered by the same shared display module, so UI changes there often affect both tabs.

## Common Places To Edit

- Credential card visuals or behavior:
  `frontend/static/scripts/advanced/credentials/index.js`
  `frontend/static/styles/shared/layout.css`
- Simple auth UX:
  `frontend/static/scripts/simple/auth-simple.js`
  `server/app/routes/simple/`
- Advanced auth UX:
  `frontend/static/scripts/advanced/auth/advanced.js`
  `server/app/routes/advanced/`
- JSON editor or advanced request shaping:
  `frontend/static/scripts/advanced/editor/index.js`
  `frontend/static/scripts/advanced/auth/forms.js`
  `frontend/static/scripts/advanced/auth/hints.js`

## Testing Guidance

Fast checks:

- Frontend syntax:
  `node --check <file>`
- Python syntax:
  `python -m compileall <file-or-dir>`
- Focused pytest:
  `pytest -q tests/app/<target_test>.py`

Repo test layout:

- `tests/app/`
  Flask/app behavior.
- `tests/fido2/`
  Library-level tests for the local `fido2/` copy.
- `tests/pqc/`
  PQC-related tests.
- `tests/device/`
  Hardware tests. These are skipped unless explicitly enabled.

If you are changing only UI logic plus lightweight server responses, prefer targeted tests over the full suite first.

Ten checks guard the code and the checkout rather than behaviour:

- `tests/app/tooling/test_html_sinks.py` fails on any `.innerHTML` / `.outerHTML`
  assignment, `insertAdjacentHTML`, `document.write`, `parseFromString`,
  `createContextualFragment` or `setHTMLUnsafe` in `frontend/static/scripts`, fixed
  string or not: each is a Trusted Types sink the report-only policy reports. Its
  `ALLOWED` list is empty; an entry needs its reason and may only be removed.
- `tests/app/tooling/test_inline_code.py` keeps out what the strict CSP refuses:
  an `on*=` attribute, a `style=` attribute or a `<script>` without `src` (other
  than `type="application/json"`) in a template; `setAttribute('style')` or markup
  written in a string with an `on...=` or `style=` in a script; and any write to
  `window` / `globalThis` / `self` (assignment, `delete`, `Object.assign`,
  `defineProperty`). Its `ALLOWED_*` dicts are empty and may only shrink.
- `tests/app/tooling/test_frontend_base64.py` fails on any `atob(` in
  `frontend/static/scripts` outside its `ALLOWED` list, which holds only the
  vendored `json-ponyfill.js`.

- `tests/app/tooling/test_web_source_rules.py` holds `web/src` to the same rules,
  with the readers of the two tests above, plus no `style` prop, no
  `dangerouslySetInnerHTML`, `<style>`/`<script>`, `next/script` or `eval`, and no
  copy of the logic modules web imports (their exports or their sentences:
  `LOGIC_ROOTS` and every `@legacy/` import, followed through their imports), which
  must also touch no DOM. Its `ALLOWED` dict is empty and may only shrink.
- `tests/app/tooling/test_web_dev_csp.py` fails when the policy `npm run dev` sends
  (`web/scripts/dev-csp.mjs`) is no longer Flask's default; the dev server's two
  allowances and their reasons are held by `web/scripts/dev-csp.test.ts`.
- `tests/app/tooling/test_npm_lockfiles.py` fails when a lockfile (root or `web/`)
  lacks an optional dependency one of its packages declares: the per-platform
  native builds (`@next/swc-*`, `@tailwindcss/oxide-*`, `lightningcss-*`,
  `@rolldown/binding-*`) the Linux runner and the image need.

- `tests/app/tooling/test_no_silent_monkeypatch.py` fails on a
  `monkeypatch.setattr(..., raising=False)` (or `mock.patch(..., create=True)`):
  such a patch keeps passing after the name it patches moves, while patching
  nothing. Its `ALLOWED` list holds the few that must create an attribute, each
  with the reason it cannot exist (a builtin shadowed in one module, a
  Windows-only `ctypes` name).
- `tests/app/tooling/test_code_size_ratchet.py` fails on a function over 80 lines
  or a module over 700 in `server/app`, except those listed at their current
  length. Entries only go down: shrink one and lower its entry, get one under the
  limit and remove it; never raise one. Split along the stages of the work, not by
  line count.
- `tests/app/characterization/` records what the ceremony routes, the decoder and
  the attestation serialisers answer, byte for byte, in a pinned environment
  (fixed clock, seeded randomness, stores in a temporary directory, no MDS), and
  compares with `golden/`. An intended change of output, or a dependency bump that
  changes it (cryptography's extension text, say), is regenerated with
  `CHARACTERIZATION_WRITE=1 pytest tests/app/characterization` and the diff
  reviewed before committing; `python tests/app/characterization/encoding_diff.py
  [REVISION]` shows whether a golden diff is byte spellings only. `material.py`
  builds the keys and certificates
  deterministically; the only frozen input is ML-DSA signatures (`inputs/frozen.json`),
  since ML-DSA signing is randomised.
- `tests/checkout_guard.py`, a pytest plugin `tests/conftest.py` loads, fails the run
  when a test created, changed or removed anything under `server/runtime/`,
  `instance/`, the legacy credential stores (`server/app/session-credentials/`,
  `server/app/*_credential_data.pkl`), `.hypothesis/` or the MDS snapshot files in
  `frontend/static/`. What is there mixes the owner's local data with old test
  leftovers: the guard compares a listing taken in `pytest_configure`, before any
  test module is collected (so a write made while importing one is seen), with one
  taken when the session finishes, and never deletes.
  `tests/app/tooling/test_checkout_guard.py` runs it in a subprocess rooted at a
  directory of its own (`--checkout-root`). Give a test its own stores in
  `tmp_path`. `tests/app/conftest.py` also points the session-metadata store at a
  directory of the run's for the whole session: a session-cleanup thread can
  outlive the test that started it, and one that lists the checkout's directory
  removes the inactive sessions it finds there. `tests/conftest.py` points
  `FIDO_SERVER_MDS_SNAPSHOT_DIR` at an empty directory of the run's (and turns the
  upstream refresh off), so no test reads a developer's real snapshot; a test that
  needs one uses `mds_fixture_snapshot` (`tests/app/metadata/conftest.py`), a copy of
  the fixture in `tests/fixtures/mds/`. That fixture is built by
  `tests/app/metadata/mds_fixture.py` with the updater's own `snapshot_files()` from a
  synthetic, signed BLOB; `test_mds_fixture.py` fails when the committed files differ
  (`MDS_FIXTURE_WRITE=1` rewrites them).

For a test that needs an app configured differently, use the `make_app` fixture in
`tests/app/conftest.py` (or `app` / `client`): it calls `create_app()` with a fixed
test secret, reading the environment at that moment, so `monkeypatch.setenv` before
it configures that app and no other. Do not `importlib.reload` config modules.

## Linting

- Ruff config lives in the root `ruff.toml`, not in `pyproject.toml` (that file is
  the vendored `fido2/` library's manifest).
- Run it with `uvx ruff@0.16.8 check .` Ruff is deliberately kept out of
  `uv.lock` and the venv, so do not `uv add` it.
- CI fails on any violation of the gated set (`E4`, `E7`, `E9`, `F`, `I`,
  `UP006/UP007/UP035/UP045`). It is at zero; keep it there.
- `F821` is gated at zero with nothing ignored, and `ruff.toml` has no
  `[lint.per-file-ignores]` section at all. Every module imports the names it
  uses; the old "carrier" modules that rebuilt their fragments' functions against
  their own globals are gone. Read `ruff.toml` before changing this, and do not
  reintroduce globals rebinding anywhere.
- The only `# noqa: F401` markers left are in
  `server/app/decoder/encode/__init__.py`, where the package deliberately
  re-exports encoder internals for callers and tests.
- Do not run `ruff format` -- the repo is not format-clean and it would rewrite
  about 69% of the files.

## Python Dependencies

- App dependencies are declared only in `server/pyproject.toml`; resolved versions are locked in `uv.lock`.
  The Docker image, CI and local venvs all install from that lock.
- Set up or refresh a local venv: `uv sync --locked`
- Add or change a dependency: edit `server/pyproject.toml`, run `uv lock`, commit both files.
  A stale lock fails the Docker build and CI.
- The root `pyproject.toml` is the vendored `fido2/` library's manifest, not the app's.
- Its build backend is pinned exactly (`poetry-core==X.Y.Z`): `uv.lock` does not lock
  build requirements, so a range lets a new release break an unchanged commit, as
  poetry-core 2.5.0 did on 2026-09-23. Keep it an exact pin;
  `tests/app/tooling/test_build_backend_pin.py` enforces that. Dependabot cannot bump
  it (it skips `[build-system]` in a Poetry project), so
  `.github/workflows/update-build-backend.yml` checks PyPI weekly, builds fido2 with
  the new release through uv and pip, runs pytest, and only then opens a bot PR.

## CI, Deploys And Bots

- Two independent pipelines run on a push to `main`: GitHub Actions
  (`.github/workflows/ci-*.yml`) and Cloud Build (`cloudbuild.yaml`). A red CI
  run does not stop Cloud Build, so `cloudbuild.yaml` runs pytest and vitest
  itself before it builds an image. Keep that gate: it is the only thing
  between a commit and production.
- `ci-*.yml` run on `pull_request` and on `push` to `main` only. Do not drop the
  branch filter; without it a same-repo PR runs everything twice.
- Every action is pinned to a commit SHA with the version in a trailing comment.
  Dependabot bumps both. Do not reintroduce a floating tag -- and note that
  `astral-sh/setup-uv` publishes no floating major tag at all.
- No workflow pushes to `main`. `update-footer-year.yml` and
  `update-build-backend.yml` commit to a bot branch through
  `.github/actions/open-bot-pr` and open a pull request, staging an explicit path
  list rather than `git add -A`. GitHub does not start workflow
  runs for events signed by `GITHUB_TOKEN`, so set a `BOT_PR_TOKEN` secret if
  those pull requests should get CI automatically. Enforcement still depends on
  branch protection on `main`, which lives in repository settings, not here.
- Scheduled workflows (`update-fido-mds.yml`, `update-footer-year.yml`,
  `update-build-backend.yml`, and `ci-security.yml`'s weekly run) fail where nobody
  looks. `ci-scheduled-runs.yml` reads their latest run on `main` on every push and
  pull request and emits a warning annotation while one has failed. It holds only
  `actions: read` and never fails the build. Issues are disabled on this
  repository, so it does not open one. Add any new scheduled workflow to its list.
- Coverage is a gate, not a published number: the floors in `.coveragerc` and
  `vitest.config.mjs` fail CI, and there is no coverage badge or badge workflow.
  Do not add one back.
- `fido2/hid/macos.py` is omitted from coverage on purpose: its only test module
  skips itself off Darwin, so measuring it made the total depend on the runner's
  OS and the floor could not hold on both.
- Frontend installs use `npm ci` everywhere, at the root and in `web/`. Each
  `package-lock.json` must list every platform's native build (fifteen
  `@rolldown/binding-*` at the root; in `web/` also `@next/swc-*`,
  `@tailwindcss/oxide-*` and `lightningcss-*`) -- the Linux runner and the image
  need their own; `test_npm_lockfiles.py` checks it. If a lock regeneration drops
  them, delete `node_modules` and `package-lock.json` and run `npm install` from
  clean; npm prunes foreign-platform optional dependencies when it reconciles
  against a partial tree (npm/cli#4828).
- `web/package.json` overrides the `postcss` Next 15 pins (8.4.31, with advisories)
  with a fixed release, so `npm audit` stays clean without leaving Next 15. Dependabot
  (`/web`) skips majors of `next`, `typescript` and `@types/node`: the charter names
  Next 15, whose build type-checks with TypeScript 5.
- `ci-web.yml` runs `web/`'s typecheck, unit tests with coverage floors, build and
  CSP scan, and the Playwright browser tests. `cloudbuild.yaml`'s `Web tests` step
  runs all but the browser tests before any image is built; the browser tests join
  the Cloud Build gate at the cutover (docs/UI_MIGRATION.md).
- The `Dockerfile`'s first stage (`node:22-slim`) builds `web/` and scans the export;
  only `web/out` reaches the runtime image, at `/app/web/out`, precompressed by
  `tools/build_static_assets.py --precompress-only`. No Node runs in production.
- `ci-security.yml` fails the build on a `pip-audit` finding against `uv.lock`,
  on `npm audit --audit-level=moderate` at the root and in `web/`, and on a fixable
  HIGH/CRITICAL Trivy finding in the image. Each threshold is justified in a comment next to it. If
  a scan starts failing, fix the dependency -- do not widen the threshold.
- The runtime stage of the `Dockerfile` runs `apt-get upgrade`. Removing it puts
  thirteen fixable HIGH/CRITICAL Debian CVEs back into the image.

## The FIDO MDS Snapshot

- The ~30MB generated snapshot under `frontend/static/` is **not tracked in git**
  and **not baked into the image**. `server/app/mds_provisioning.py` fetches it at
  runtime: local files, then Cloud Storage, then a verified upstream refresh.
- Working locally: run `python tools/update_mds_snapshot.py` once. Without it the
  explorer APIs answer 200 with no entry (and `/api/mds/metadata/base` 404), and the
  explorer is empty; that is the documented fallback, not a bug.
- `FIDO_SERVER_MDS_SNAPSHOT_DIR` puts the snapshot elsewhere (`server/app/mds_snapshot_dir.py`);
  the browser tests and pytest point it at a copy of `tests/fixtures/mds/snapshot`.
- Browsers get one snapshot file, the explorer's, at its versioned URL from the snapshot
  directory; Flask's root static route and the versioned route refuse every other
  snapshot name and the `.gz` sibling (`static_assets._SNAPSHOT_FILES`), since what sits in
  `frontend/static` may be another snapshot.
- Never commit those files and never write a test that reads the real snapshot
  path. `docs/MDS_SNAPSHOT.md` has the full picture.

## Repo-Specific Gotchas

- The current UI (`frontend/`) is plain JS modules; the new UI (`web/`) is React through Next.js, exported as static files.
- Templates hold no code: a control names its action with `data-action`, and nothing is put on `window` (`shared/ui/actions.js`). The CSP has no `'unsafe-inline'`, so an inline handler, `<script>` or `style=` added back simply does not run.
- The simple and advanced tabs share the saved credential display, so re-render logic can have cross-tab side effects.
- Flask session state matters in begin/complete flows. Be careful not to break the fallback `__session_state` handling.
- The local `fido2/` directory is part of the repo. Do not assume behavior matches the latest upstream package.

## Good First Step For Most Tasks

Before changing code, identify:

1. Which tab or route owns the user-visible behavior.
2. Whether the change affects shared credential rendering.
3. Whether the server returns data that the frontend currently needs but does not receive.
4. The smallest focused test that proves the change.

## Recommended Working Style

- Read the specific route and its matching frontend module together.
- Prefer focused fixes over broad refactors unless the task explicitly asks for restructuring.
- Verify both simple and advanced flows whenever you touch shared credential UI or browser storage behavior.
- When adding server response fields, update both the frontend handling and at least one focused app test.
