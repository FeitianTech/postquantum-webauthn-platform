# FIDO MDS explorer — content parity

> **Since Phase 30A (2026-09-28)** the current UI this list describes is gone: the files cited are in the
> history (`git show <commit>:<path>`), and the parity specs it cites compare the new UI with recordings of what
> the current UI showed (`web/e2e/recorded/`, made before it was removed), not with the running current UI.

Everything the current FIDO MDS tab shows and does, taken from the running code at `692b84f7`
(`frontend/templates/advanced/mds-tab.html`, `mds-content.html`, `frontend/templates/index.html`,
`frontend/templates/shared/navigation.html`, the 75 modules under `frontend/static/scripts/advanced/mds/`, the
credential cards' jump in `advanced/credential-display/` and `advanced/credentials/index.js`, the styles under
`frontend/static/styles/advanced/mds*`) and the server routes and builders it relies on (`server/app/routes/general.py`,
`server/app/mds_snapshot.py`, `server/app/webauthn/metadata/effective.py`, `sessions.py`). The charter
(`docs/UI_MIGRATION.md`, "Content parity") requires every item to be mapped to the new component and checked in a
browser before the phase that ports it is done.

Phase 27 is split: **27A** ports the list page (the header, the status line, the table, its sorting, filters and
resizing, Back to top, Manage Trusted Metadata, and the route that opens an entry); **27B** ports the authenticator
detail page, the certificate page, the raw views and the jump from a saved credential. The **Phase** column says
which; 27B items are listed now so that nothing is forgotten, and are mapped in 27B.

Line references are to `692b84f7`; scripts are under `frontend/static/scripts/advanced/mds/` unless another path is
given. "Verbatim" text is quoted exactly; `${...}` marks a value filled in at run time. The **New** column names the
component (under `web/src/components/mds/` unless another path is given), the test that holds it, and how it was
checked in a browser:

- *unit*: `MdsSection.test.tsx` (loading and status), `ExplorerTable.test.tsx` (columns, cells, sort, resize, expand,
  copy, opening, Back to top, the phone's Icon column, the edge fade), `FilterBar.test.tsx`,
  `ManageMetadataDialog.test.tsx`, `EntryRoute.test.tsx`, and for 27B `EntryPage.test.tsx` (the entry page, its
  sections, the raw view, the condensed header, an entry resolved through the server), `CertificatePage.test.tsx`,
  `entryLink.test.tsx` and `web/src/lib/{sections,useSection,download}.test.ts[x]`, over the fixture snapshot's real
  entries (`tests/fixtures/mds`, built by `tests/app/metadata/mds_fixture.py` with the server's own code); test names
  carry the MDS id.
- *logic*: `tests/frontend/advanced/mds/explorer/*.test.js`, over the DOM-free modules both UIs import:
  `explorer/loading.js`, `status.js`, `filter-sort.js`, `options.js`, `rows.js`, `columns.js`, `custom-metadata.js`, and
  the leaves under them (`constants.js`, `metadata/explorer-source.js`, `metadata/metadata-helpers.js`,
  `sort-filter-normalise.js`, `utils/{formatters,status-reports,resolvers,extractors}.js`), all at 100 %; for 27B
  `explorer/detail.js`, `certificate.js`, `entry-link.js` and `raw-data.js`, `raw-stringify.js` (`raw.test.js`), also
  at 100 %.
- *pytest*: `tests/app/metadata/test_metadata_info_route.py`, `test_mds_fixture.py`, `test_mds_snapshot_dir.py`.
- *e2e*: `web/e2e/mds.spec.ts`, Playwright's Chromium 153 against Flask serving the export and the fixture under the
  strict CSP.
- *e2e (27B)*: `web/e2e/mds-entry.spec.ts`, the same way.
- *parity*: `web/e2e/mds-parity.spec.ts`: the rows both tables show for six filter sets and a sort, cell for cell; for
  27B `web/e2e/mds-entry-parity.spec.ts`: five entries' pages, a certificate and the raw view, word for word per
  section (below).
- *pane*: by hand in the desktop app's Chromium 152 at `http://localhost:8765/beta#mds` (and `/`), strict CSP, the
  owner's 517-entry snapshot, 2026-09-26, at 1440, 1024 and 375 px; no console message. For 27B the same pane at
  `http://localhost:8765/beta#mds/…` over a scratch copy of that snapshot (`FIDO_SERVER_MDS_SNAPSHOT_DIR`), and a
  script in Playwright's Chromium 153 at the three widths: entries by click and by URL, a certificate, the raw view,
  both Backs, the AAGUID URL, 404 then Back, and `/`; no console, CSP or Trusted Types message.

The words themselves are not copied: every sentence from logic comes from the modules above, which `web/` imports
(`@legacy/*`); `tests/app/tooling/test_web_source_rules.py` fails if `web/src` redefines one of their exports or
repeats one of their sentences. Only the template's own text (the headers, labels and placeholders, the dialog's
texts, the loading row, Back to top) is written in the components.

## How the rows are made

The server builds every row. Both places the page loads its data from, the packaged file at `snapshotUrl`
(`fido-mds3.explorer.full.json`) and `GET /api/mds/metadata/explorer/full`, send entries that already carry an
`entryId` and every column's text (`server/app/mds_snapshot.py:475-605`, `build_explorer_entry`); the page clones them
and shows them. `utils/entry-transform.js`, the lazy loader, the background certificate decode and the verified-meta
request are the client's own row builder for a payload whose entries have no `entryId` (`metadata/explorer-load.js:134-148`),
which the server never sends: see "Never shown".

## The tab and the header

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-H1 | Reached from the top navigation's "FIDO MDS Authenticators" tab (`data-action="switch-tab" data-tab="mds"`). | `shared/navigation.html:5` | 27A | `shell/AppShell.tsx` renders `mds/MdsSection.tsx` for the top bar's "FIDO MDS Authenticators" (`#mds`). `AppShell.test.tsx`; `beta-smoke.spec.ts` (ported: no note); pane. |
| MDS-H2 | Heading "FIDO MDS Authenticators" (`h2`) and the description "Explore the authenticators published by the FIDO Metadata Service (MDS)." | `mds-content.html:4-7` | 27A | `MdsSection` h2 and description from `lib/sections.ts` (the same words). unit MDS-H2; e2e; pane. |
| MDS-H3 | The count line, `aria-live="polite"`: "Entries: " then the number shown (`toLocaleString()`, "0" at load) and, when the total is not zero, "of ${total} total" (e.g. "Entries: 12 of 517 total"); the total is blank when it is zero. | `mds-content.html:8-11`, `status-controls.js:1-8` | 27A | `ExplorerHeader.tsx` `EntryCount`: "Entries: " and the numbers from `formatEntryCount` (`explorer/status.js`), `aria-live="polite"`; it counts the rows the filters let through. unit MDS-H3; e2e; pane ("Entries: 517 of 517 total" in both UIs). |
| MDS-H4 | A button "Manage Metadata", `aria-haspopup="dialog"`, `aria-expanded` "false" / "true" with the panel. | `mds-content.html:13-17`, `state/state-initializer-dom.js:86-100` | 27A | A secondary `ui/Button` "Manage Metadata", `aria-haspopup="dialog"`, `aria-expanded` with the dialog. unit MDS-H4; e2e; pane. |
| MDS-H5 | When the explorer cannot start, the whole tab is replaced by "Unable to load authenticator explorer. Check the console for details." | `runtime/bootstrap.js:89-96` | 27A | Changed: nothing can fail to start (the section is a component); each failure of the data is MDS-S6. — |

## When the data is loaded and from where

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-L1 | The page's data for the explorer is `initial-mds-info`, inlined by the index as JSON: the packaged summary (`source`, `legalHeader`, `no`, `nextUpdate`, `entryCount`, `lastModified`, `lastModifiedIso`, `etag`, `fetchedAt`, `generatedAt`; absent without a snapshot), `snapshotUrl` (`/assets/<BUILD_ID>/fido-mds3.explorer.full.json`) and `customEntriesState` (`none` for a session created by this request, else what the session last recorded, `none` / `present`, else `unknown`). | `index.html:58`, `general.py:196-218`, `index.js:150-159` | 27A | `useMdsExplorer.ts` asks `GET /api/mds/metadata/info` (`fetchExplorerInfo`, `explorer/loading.js`; new endpoint, built by the index's own `_initial_mds_info()`); without an answer it starts from nothing, as the current page does without page data. pytest `test_metadata_info_route.py`; unit MDS-L1; e2e. |
| MDS-L2 | Loading does not start with the page: it starts when the MDS tab is shown, when the pointer enters or focus reaches its top-navigation tab, once the app is ready and idle (skipped when the connection asks to save data or is 2G), or after 10 s; showing the tab again loads again unless already loaded. | `runtime/bootstrap.js:1-127` | 27A | Changed: it loads when the section is first shown (never before, never twice); there is no preload on idle or hover. unit MDS-L2. |
| MDS-L3 | The source: the packaged file at `snapshotUrl` (browser cache allowed) when `customEntriesState` is `none` and the load is not forced; otherwise `GET api/mds/metadata/explorer/full` with `cache: 'no-store'` (`'reload'` when forced). The API path is relative. | `metadata/explorer-source.js:18-46`, `constants.js:2` | 27A | `createExplorerSource` (unchanged) and `requestExplorerSnapshot` (`explorer/loading.js`); the paths are now absolute in both UIs (`constants.js`), and `snapshotUrl` is used as the server gives it. unit MDS-L3; logic; e2e (`/beta/#mds` requests no `/beta/api/`). |
| MDS-L4 | If the packaged file fails (not ok, not an object, or a network error other than an abort), the API is asked instead, silently. | `metadata/explorer-load.js:85-104` | 27A | `requestExplorerSnapshot`, the same fallback. unit MDS-L4; logic. |
| MDS-L5 | A loaded snapshot's `meta.hasCustomEntries` updates `customEntriesState` (`present` / `none`) for later loads. | `metadata/explorer-source.js:39-43`, `explorer-load.js:130-132` | 27A | `noteSnapshotMeta`, on every snapshot shown (loads, uploads, deletes). The server now also records the session's state on an upload and a delete (`general.py`; before, a reload after an upload could load the packaged file). unit; pytest. |
| MDS-L6 | Applying a snapshot: the entries are cloned, merged with any entry already resolved in full, the sort is reset to its default (MDS-O1) and the filters kept, the option lists rebuilt, the table redrawn, resizing enabled when there are entries, Retry hidden. | `metadata/explorer-state-loader.js:48-133` | 27A | `prepareSnapshotEntries`, `explorerLoadedStatus` (`explorer/loading.js`, `status.js`); `useExplorerView` resets the sort to its default for each snapshot and keeps the filters. unit; logic. |
| MDS-L7 | A load while one is running waits for it; a load after a successful one does nothing unless forced; a forced load clears the entries already resolved in full. | `metadata/explorer-load.js:37-52` | 27A | `useMdsExplorer`: a later load, or an upload's snapshot, drops the answer of one still out; Retry is there only after a failure, so no load waits for another. unit ("shows an upload over a load still out"). |
| MDS-L8 | The server answers a missing snapshot with 200, `entries: []` and zeroed counts (its 404 branch is not reached: the composed snapshot always has a `meta`), and the packaged file 404s. | `general.py:229-252`, `webauthn/metadata/effective.py:103-112` | 27A | `isMissingSnapshot` (`explorer/loading.js`): no entry at all shows MDS-E3's sentence in the table (the current table says "No authenticators match the selected filters."). pytest (no snapshot: 200, zero entries); unit MDS-S5/E3. |

## Status line and Retry

The line is `#mds-status`, coloured by its variant (info, success, error), with the snapshot's legal header as its
tooltip once loaded. Retry sits under it.

| ID | Current behaviour (verbatim) | Where | Phase | New |
|---|---|---|---|---|
| MDS-S1 | Before anything runs (template), and with no usable summary: "Packaged FIDO metadata is available. Explorer data is loading in the background." (info) | `mds-content.html:56-58`, `metadata/metadata-helpers.js:57-60,77-79` | 27A | `formatInitialExplorerStatus` (`metadata/metadata-helpers.js`, imported) before anything is known. unit MDS-S1; pane. |
| MDS-S2 | With a summary: "${parts joined by " • "}. Explorer data is loading in the background.", the parts being "Snapshot ${no}", "${entryCount} authenticators" and "last updated ${date}" where each is known; the date is the first of `generatedAt`, `generated_at`, `fetchedAt`, `fetched_at`, `lastModifiedIso`, `last_modified_iso`, `lastModified`, `last_modified`, shown in the browser's locale (medium date, short time), or as written when it is not a date. | `metadata/metadata-helpers.js:17-82`, `runtime/bootstrap.js:76-86` | 27A | The same, over the info endpoint's summary. unit; pane. |
| MDS-S3 | While loading: "Loading authenticator explorer…"; when forced: "Refreshing authenticator explorer…" (info). Retry hides. | `metadata/explorer-load.js:54-57` | 27A | `explorerLoadingStatus` (`explorer/status.js`), with a spinner in the status line; Retry hidden. unit MDS-S3. |
| MDS-S4 | Loaded (success; info when there are no entries): "Loaded ${n} authenticators." then "Last updated ${date}." (the snapshot's `meta`, as MDS-S2; no colon), then "Including ${n} session metadata entry." / "…entries." when the session has uploads, then a note ("Explorer refreshed." after Retry, "Custom metadata updated." after an upload or delete), joined by spaces. The line's `title` is the snapshot's `legalHeader`. | `metadata/metadata-derived-info.js:143-164`, `explorer-state-loader.js:116-132` | 27A | `buildLoadedStatus` / `explorerLoadedStatus` (`explorer/status.js`): the same sentence, notes and variant (a green dot for success), the legal header as the line's `title`. unit MDS-S4; e2e; pane (both UIs: "Loaded 517 authenticators. Last updated Sep 15, 2026, 7:42 PM."). |
| MDS-S5 | A 404 from the source: the answer's `error`, else "Packaged FIDO metadata is unavailable. Please verify the bundled snapshot is present." (info), also as the table's only row; the count reads 0 with no total. (Unreached: see MDS-L8.) | `metadata/explorer-load.js:108-117`, `explorer-state-loader.js:3-46`, `constants.js:9-10` | 27A | `classifyExplorerAnswer` (`explorer/loading.js`): the same sentence in the status line, and MDS-E3 in the table. unit MDS-S5. |
| MDS-S6 | Another failure (error), and Retry shows: the answer's `error`, else "Explorer request failed with status ${status}."; a body that is not an object: "Explorer response was not valid JSON."; anything else: "Unable to load the packaged authenticator explorer." | `metadata/explorer-load.js:119-160` | 27A | `classifyExplorerAnswer` / `explorerLoadFailure`: the same sentences, in red, with Retry in the status line and in the table. unit MDS-S6. |
| MDS-S7 | Retry ("Retry", hidden until a failure) runs a forced load: "Refreshing authenticator explorer…", then MDS-S4 with the note "Explorer refreshed."; Retry is disabled meanwhile. Pressed while a load runs: "Metadata is currently loading. Please wait for the current operation to finish." A failure that escapes: "Unable to refresh the packaged authenticator explorer." (error). | `mds-content.html:59-63`, `runtime/runtime-refresh-metadata.js:1-53`, `state/state-initializer-dom.js:207-215` | 27A | Retry runs a forced load with the note "Explorer refreshed." (`EXPLORER_REFRESHED_NOTE`). Changed: Retry is not there while a load runs, so "Metadata is currently loading…" cannot show. unit MDS-S6/S7. |
| MDS-S8 | Status text is written as text only, never markup. | `status-controls.js:10-14`, `tests/frontend/advanced/mds/mds-status-xss.test.js` | 27A | React text nodes only; no markup sink in `web/src` (`test_web_source_rules.py`). rules test. |

## The table's columns

A table of 13 columns, header row sticky at the top of its container, the container scrolling sideways
(`overflow-x: auto`, a 1,500 px minimum width). Every cell is text only.

| ID | Header | Cell (current behaviour) | Where | Phase | New |
|---|---|---|---|---|---|
| MDS-C1 | Icon | The entry's `icon` (a `data:` URL) as an image, at most 36 × 36 in a 44 × 44 box, alt "${name, else "Authenticator"} icon"; without one, "N/A". | `table-cells.js:42-61`, `styles/advanced/mds/table.css:257-274` | 27A | `ExplorerRow.tsx`: the `data:` icon at 28 px (`object-contain`, `loading="lazy"`), alt from `iconAltText`, "N/A" (`explorer/rows.js`). unit MDS-C1; parity; pane. |
| MDS-C2 | Name | The entry's `name` as a button that opens the detail page (MDS-D1); an empty name or "—" is plain text. The server's name: the description, else the first alternative description, else the first status report's descriptor, else "Unknown Authenticator". | `table-cells.js:10-34`, `utils/resolvers.js` | 27A | The name as a link to `#mds/<entryId>` (Enter opens it), truncated with its `title`; a row click opens it too (MDS-N1). unit; parity; e2e; pane. |
| MDS-C3 | Protocol | `protocol`, or "—": "FIDO2", "U2F" and, as the server spells it, "Uaf". | `table-render.js:105`, `utils/formatters.js:30-40` | 27A | As sent ("FIDO2", "U2F", "Uaf"). unit MDS-C3; parity (protocol Uaf). |
| MDS-C4 | Certification | `certification`, or "—", as one text that wraps: the latest status report's status, descriptor and "(certificate number)" joined by " • ", e.g. "FIDO Certified L1 • Security Key by Yubico • (U2F110020191017010)", "NOT FIDO Certified", "Revoked". | `table-render.js:106`, `utils/formatters.js:79-108` | 27A | Changed: one `ui/Badge` for the level (`certificationParts`, `explorer/rows.js`: green certified, white not, red revoked or compromised), then the descriptor and number muted on the same line; the whole text as the cell's `title`, and every word when the row is expanded. unit MDS-C4; parity (the same words); pane. |
| MDS-C5 | ID | `id`, or "—", in a monospace cell: the AAGUID, else the AAID, else the first attestation key identifier. | `table-cells.js:36-40` | 27A | Geist Mono, on one line (never broken mid-UUID), in a column that fits a whole AAGUID, with a copy button named by the id's kind ("Copy AAGUID", "Copy AAID", "Copy key identifier"). unit; e2e (clipboard read back); pane. |
| MDS-C6 | User Verification | `userVerificationList` as pills stacked one per line, or "—": the distinct methods across every combination, sorted (e.g. "Fingerprint Internal", "Passcode External", "None"). | `table-cells.js:63-84` | 27A | Changed: the values joined by ", " on one line (the pills' words), the whole list as the `title`, and as pills when the row is expanded. unit; parity; e2e. |
| MDS-C7 | Attachment | `attachmentList` as pills, or "—" (e.g. "External", "Wired", "Nfc"). | same | 27A | As MDS-C6. unit; parity. |
| MDS-C8 | Transports | `transportsList` as pills, or "—" (e.g. "Usb", "Nfc", "Ble", "Hybrid", "Internal"). | same | 27A | As MDS-C6. unit; parity. |
| MDS-C9 | Key Protection | `keyProtectionList` as pills, or "—" (e.g. "Hardware", "Secure Element"). | same | 27A | As MDS-C6. unit; parity. |
| MDS-C10 | Algorithms | `algorithmsList` as pills, or "—" (e.g. "SECP256R1 Ecdsa SHA256 Raw"). | same | 27A | As MDS-C6. unit; parity. |
| MDS-C11 | Algorithm Info | `certificateAlgorithmInfoList` as pills, or "—": the attestation roots' signature algorithm and hash (e.g. "ECDSA_SHA256"). | same | 27A | As MDS-C6. unit; parity. |
| MDS-C12 | CN | `certificateCommonNameList` as pills, or "—": the attestation roots' subject common names (up to 954 characters in all in the live snapshot). | same | 27A | As MDS-C6: the fixture's 973-character CN list is one line with its `title`, and 15 pills that wrap inside the cell when expanded. unit MDS-C12; e2e (every pill inside its cell); pane. |
| MDS-C13 | Date Updated | `dateUpdated`, or "—" (e.g. "Sep 18, 2023", written by the server in English), with the raw date (`dateTooltip`, e.g. "2023-09-18") as its tooltip. | `table-render.js:115`, `table-cells.js:1-8` | 27A | The text in a `<time dateTime>` with the raw date as its `title`. unit; parity. |
| MDS-C14 | — | Rows are drawn in full, every row at once (no virtual scrolling); after drawing, each row's height is measured and fixed. Tall rows: the pills stack vertically. | `table-render.js:83-132`, `row-layout.js:34-89`, `table.css` | 27A | Changed: compact one-line rows (41 px); every row is in the page, each a grid on one column template so the browser skips laying out and painting the rows out of view (`content-visibility`); a row expands to show every word. unit; e2e; timing (below). |
| MDS-C15 | — | A row carries `data-aaguid` (the AAGUID, lower case) or `data-entry-id` (the `id`, for AAID and key-identifier rows); a click elsewhere in the row does nothing. | `table-render.js:85-101` | 27A | Rows carry `data-entry-id` (the server's `entryId`); a click anywhere in a row but its controls opens the entry. unit; e2e. |
| MDS-C16 | — | Uploaded (session) entries come first and replace a packaged entry with the same AAGUID; nothing in the row marks them (only MDS-S4's "Including … session metadata …"). | `webauthn/metadata/effective.py:114-149` | 27A | Kept: no marker in the row; the status line says "Including N session metadata entries." unit; e2e. |

## Sorting

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-O1 | Default: Date Updated, newest first; also restored whenever a snapshot is applied. | `sort-filter-controller.js:8-9,209-221`, `explorer-state-loader.js:93` | 27A | `defaultExplorerSort` (`explorer/filter-sort.js`), also reset for each snapshot. unit MDS-O1; parity (order). |
| MDS-O2 | Each header has a sort button (no text; CSS draws ↕ / ↑ / ↓), `aria-label` "Sort ${label} column" at load and then "Sort ${label} (ascending)", "(descending)" or "(no sorting)", `aria-pressed` true on the active one; there is no `aria-sort`. | `mds-content.html:69-237`, `sort-filter-controller.js:176-207` | 27A | Changed: each header is a button with its name; the column's order is `aria-sort` on the header (the current "Sort X (ascending)" labels and `aria-pressed` are gone), and an accent chevron. unit MDS-O2/O3; e2e. |
| MDS-O3 | A column's clicks go none → ascending → descending → none; reaching none restores MDS-O1. Date Updated goes none → descending, ascending → descending, descending → ascending. Clicking another column starts it from none. | `sort-filter-controller.js:11-23,166-174,241-272` | 27A | `nextExplorerSort` (`explorer/filter-sort.js`), the same cycles. unit MDS-O3; logic; parity (Name both ways). |
| MDS-O4 | Sort values: Icon by "1_${name}" with an icon and "0_${name}" without (so ascending puts the entries without an icon first), Algorithm Info and CN by their joined text, Date Updated by the tooltip's date, every other column by its text; "—" and empty sort as empty, numeric text as a number, other text lower-cased; ties by the lower-cased text, then the text, then the entry's `index`. Descending is the ascending order reversed. | `sort-filter-controller.js:25-51,102-164`, `sort-filter-normalise.js` | 27A | `MDS_SORT_ACCESSORS` / `compareExplorerSortValues`, the same. logic; parity. |
| MDS-O5 | Sorting keeps the table's scroll position. | `sort-filter-controller.js:271`, `table-render.js:24-62` | 27A | The frame keeps its scroll on a sort. e2e. |

## Filters

A second header row of search fields, one under each column but Icon and Date Updated. Filters combine (all must
match) and apply on each keystroke; the count (MDS-H3) follows.

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-F1 | Name: placeholder "Search name"; free text. | `mds-content.html:241`, `constants.js:26` | 27A | `FilterBar.tsx`: a search field labelled "Name", placeholder verbatim. unit MDS-F1..F11; e2e; parity. |
| MDS-F2 | Protocol: placeholder "Protocol"; a list of the protocols present. | `mds-content.html:242`, `constants.js:27` | 27A | `FilterCombobox.tsx` labelled "Protocol". unit; parity (Uaf). |
| MDS-F3 | Certification: placeholder "Certification"; a list of "FIDO Certified", "FIDO Certified L1", "FIDO Certified L2", "NOT FIDO Certified", "Revoked" (always, even before data) plus every other status present, formatted (e.g. "FIDO Certified L3plus"). | `mds-content.html:243`, `constants.js:17-33`, `state/state-initializer.js:113-118`, `utils/entry-transform.js:54-80` | 27A | Combobox "Certification": `explorerFilterOptionLists` (`explorer/options.js`) with the static statuses always offered. unit MDS-F13; parity (FIDO Certified, L2). |
| MDS-F4 | ID: placeholder "AAGUID or AAID"; free text, matched against the ID column's text. | `mds-content.html:244`, `constants.js:34` | 27A | Search field "ID", placeholder verbatim. unit MDS-F14. |
| MDS-F5 | User Verification: placeholder "User verification"; a list of every method present, shown whole (no inner scroll). | `mds-content.html:245`, `constants.js:35-40`, `table.css:167` | 27A | Combobox "User Verification", its list shown whole. unit MDS-F5/F9; parity; pane. |
| MDS-F6 | Attachment: placeholder "Attachment"; a list. | `mds-content.html:246`, `constants.js:41` | 27A | Combobox "Attachment". unit. |
| MDS-F7 | Transports: placeholder "Transports"; a list. | `mds-content.html:247`, `constants.js:42` | 27A | Combobox "Transports". unit; parity. |
| MDS-F8 | Key Protection: placeholder "Key protection"; a list. | `mds-content.html:248`, `constants.js:43` | 27A | Combobox "Key Protection". unit. |
| MDS-F9 | Algorithms: placeholder "Algorithms"; a list, shown whole. | `mds-content.html:249`, `constants.js:44-49` | 27A | Combobox "Algorithms", shown whole. unit MDS-F5/F9. |
| MDS-F10 | Algorithm Info: placeholder "Algorithm info"; free text. | `mds-content.html:250`, `constants.js:50` | 27A | Search field "Algorithm Info". unit. |
| MDS-F11 | CN: placeholder "CN"; free text. | `mds-content.html:251`, `constants.js:51` | 27A | Search field "CN". unit; e2e. |
| MDS-F12 | Matching: the typed text, trimmed, is found in the column's joined text ignoring case. Certification: when the text names one of the list's options, the entry's status must equal it, except "FIDO Certified", which matches every certified level; other text is found in the certification text or status. | `sort-filter-controller.js:62-100`, `state/state-initializer.js:78-108` | 27A | `matchesExplorerFilters` (`explorer/filter-sort.js`), given the certification list rather than reading a dropdown. unit MDS-F12; logic; parity (six filter sets). |
| MDS-F13 | A list opens on focus or click (when it has options), narrows to the options containing the typed text, sorted ignoring case and accents; "No matches" when none do. ArrowDown / ArrowUp move (wrapping; ArrowUp with nothing chosen goes to the next-to-last), Enter picks, Escape closes; a click on an option picks it; one list open at a time; a click outside closes it. Picking fills the field and filters. No listbox or combobox roles. | `dropdown.js:1-185` | 27A | Changed: an ARIA 1.2 combobox (`role="combobox"`, a `listbox`, `aria-activedescendant`); the options from `matchingFilterOptions`; the arrow keys wrap from nothing to the first or the last (the current list lands on the next-to-last); Enter picks only a highlighted option; Escape closes the list, then clears; "No matches" (`NO_MATCHING_OPTIONS`). unit MDS-F13. |
| MDS-F14 | In a field, Enter applies it (it already has) and Escape clears it. | `state/state-initializer.js:92-108` | 27A | Escape clears a text filter; typing filters at once (Enter needs nothing). unit MDS-F14. |
| MDS-F15 | There is no count of active filters and no way to clear them all at once. | — | 27A | New: the bar's head says how many filters are in use ("2 active") and has one "Clear filters" (also in the no-match row); a filtered column's header has an accent dot ("(filtered)" for a screen reader). unit; e2e. |

## Column widths

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-R1 | Every header but the last has a drag handle on its right edge (title "Drag to resize column", hidden from assistive technology, no keyboard), enabled once entries are loaded. Dragging with the main button widens or narrows that column only; the table grows and scrolls sideways. | `column-resizers.js:249-284`, `column-resizers-pointer.js` | 27A | `ColumnResizer` in `ExplorerTable.tsx`: `role="separator"`, focusable, `aria-valuenow`, pointer capture, arrow keys ±16 px (new), title "Drag to resize column". unit MDS-R1; e2e (keys and drag); pane. |
| MDS-R2 | Widths start from the header cells' measured widths; no column goes under 64 px; the widths are kept while the page is open (filters and sorting keep them) and never saved. | `column-resizers.js:13-121`, `index.js:84` | 27A | Widths start from each column's own width and are kept while the page is open (never saved), no column under 64 px (`MDS_MIN_COLUMN_WIDTH`, `normaliseExplorerColumnWidths`), the ID column never under a whole AAGUID. unit; logic. |

## Loading, empty and no-match rows

| ID | Current behaviour (verbatim) | Where | Phase | New |
|---|---|---|---|---|
| MDS-E1 | Before data: one row "Authenticator metadata is loading…". | `mds-content.html:255-258` | 27A | `ListState.tsx`: a spinner and the sentence, in the table, pinned to the frame's left edge. unit MDS-E1. |
| MDS-E2 | No entry matches the filters (and a snapshot with no entries at all): one row "No authenticators match the selected filters." | `table-render.js:67-81` | 27A | `EXPLORER_NO_MATCHES` with a "Clear filters" button. unit MDS-F2/E2; e2e. |
| MDS-E3 | A missing snapshot (MDS-S5): one row with that message. | `explorer-state-loader.js:32-45` | 27A | `MISSING_METADATA_MESSAGE` in the table whenever there is no entry at all (MDS-L8). unit MDS-S5/E3. |

## Back to top

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-B1 | A round "↑" button fixed at the top centre of the window, `aria-label` "Back to top of the authenticator list", title "Back to top", shown while the tab is visible, there are more than five rows and the fifth row has scrolled above the table's header; it scrolls the window to the top (smoothly). | `mds-content.html:262-271`, `scroll-top-button-visibility.js`, `scroll-metrics.js`, `styles/advanced/mds/overview.css:389-418` | 27A | `BackToTop` in `ExplorerTable.tsx`: the same label and title, floating at the table frame's lower right once five rows have scrolled past, taking the frame back to its first row (instantly under reduced motion). unit MDS-B1; pane. |

## Manage Trusted Metadata

| ID | Current behaviour (verbatim) | Where | Phase | New |
|---|---|---|---|---|
| MDS-M1 | "Manage Metadata" opens a dialog (`role="dialog"`, `aria-modal="true"`) titled "Manage Trusted Metadata" (`h3`), with a close button labelled "Close" (×), and focus on the drop zone. Only the × closes it: its backdrop and Escape do not. Focus goes back to the button. Scrolling inside does not scroll the page. | `mds-content.html:20-54`, `custom/custom-panel-utils.js:179-276`, `custom-panel-scroll-guard.js` | 27A | `ManageMetadataDialog.tsx` on the `ui/Overlay` `Dialog`: the title, a close button "Close"; changed: focus moves in, Escape and the backdrop close it, focus returns to Manage Metadata, the page behind is `inert`; the panel's body keeps its own scroll (`overscroll-contain`). unit MDS-H4/M1; e2e; pane. |
| MDS-M2 | The description "Drop JSON metadata files here or select them from your device. Uploaded files are trusted only for this browser session." | `mds-content.html:30-32` | 27A | The same words. unit MDS-M2/M3. |
| MDS-M3 | The drop zone (focusable): a folder icon (📁, hidden from assistive technology), "Drop JSON files here or click to browse" and the hint "Only `.json` files are accepted." (`.json` as code). Click, Enter or Space opens the file chooser (`accept=".json,application/json"`, several files); files dropped on it are taken too; it is highlighted while files are dragged over it. | `mds-content.html:33-50`, `state/state-initializer-dom.js:102-127`, `runtime/runtime-custom-metadata-adapters.js:41-64` | 27A | A drop zone around a button with the same words (the icon a line drawing, hidden from assistive technology), the hint with `.json` as code (the button's description), a hidden `input type=file accept=".json,application/json" multiple`; dropped files are taken; it is lit (accent tint) while files are over it. unit MDS-M2/M3; e2e (`setInputFiles`). |
| MDS-M4 | Choosing files: names not ending in ".json" are refused with "Ignored non-JSON files: ${names joined by ", "}" ("Unnamed file" for a file without a name) (warning); with no JSON file left and none refused: "Please select one or more JSON files." (warning). | `runtime/runtime-custom-metadata-adapters.js:98-116`, `metadata/metadata-helpers.js:106-128` | 27A | `describeFileSelection` (`explorer/custom-metadata.js`), the same sentences. unit MDS-M4; logic. |
| MDS-M5 | Uploading: `POST api/mds/metadata/upload`, the files as `files` (a nameless one as "metadata.json"); "Uploading metadata…" (info). Success: "Metadata uploaded successfully." (success) or "Metadata uploaded with warnings: ${errors joined by " "}" (warning); failure: "Failed to upload metadata files." (error; the server's reason is composed first but then replaced). With no files: "Please choose one or more JSON files." (warning). | `custom/custom-metadata-actions.js:1-83` | 27A | `requestCustomMetadataUpload` / `describeUploadAnswer`: the same request and sentences; changed: a refused upload keeps the server's reason (the current panel replaces it). unit MDS-M5; logic; e2e; pane. |
| MDS-M6 | Deleting an item: `DELETE api/mds/metadata/custom/${stored name}`; "Removing ${name}…" (info), then "${name} removed." (success); a 404: the server's message ("Metadata entry not found.") as a warning; other failures "Failed to delete metadata file." (error); no stored name: "Unable to delete the metadata file." (error). The item's button is busy meanwhile. | `custom/custom-metadata-actions.js:85-181` | 27A | `requestCustomMetadataDelete` / `describeDeleteAnswer`: the same request and sentences, the item's button busy; changed: a refusal keeps the server's reason. "Unable to delete the metadata file." cannot show: an item without a stored name has no Delete. unit MDS-M6; logic; e2e. |
| MDS-M7 | An upload or delete answer carrying a snapshot is applied at once, with the note "Custom metadata updated." (MDS-S4); without one, a forced load. | `custom/custom-metadata-actions.js:59-66,153-159` | 27A | `useCustomMetadata` hands the snapshot to `useMdsExplorer.applySnapshot` (note "Custom metadata updated."), or asks for a forced load. unit MDS-M7; e2e. |
| MDS-M8 | Meanwhile an overlay covers the tab (`role="alertdialog"`, a spinner and a message): upload "Updating Metadata...", "Uploading metadata…", "Applying metadata…" or "Reloading metadata…", then "Completing metadata update..." or "Metadata update failed."; delete "Removing metadata...", "Removing metadata…", "Applying metadata…" or "Refreshing metadata…" (or "No metadata changes detected."), then "Completing metadata removal..." or "Metadata removal failed."; its default "MDS is updating…"; a "Cancel update" button that is never shown (not cancellable); "Metadata update cancelled." / "Metadata removal cancelled." on a cancel. | `custom/update-overlay.js`, `state/state-initializer-dom.js:1-54`, `custom-metadata-actions.js:67-74,162-168` | 27A | Changed: the same texts (`UPLOAD_PROGRESS`, `DELETE_PROGRESS`) as a progress line with a spinner inside the dialog, which stays usable, instead of an overlay over the tab; the last text stays 520 / 720 ms as the overlay did. The never-shown "Cancel update" is not ported. unit MDS-M8. |
| MDS-M9 | The messages area (`aria-live="polite"`), coloured by variant (info, success, warning, error), hidden when empty. | `mds-content.html:51`, `custom/custom-panel-utils.js:53-75` | 27A | A message under the drop zone, `aria-live="polite"`, tinted by its variant (green, amber, red; info white with a hairline). unit. |
| MDS-M10 | The list of uploaded files (`aria-live="polite"`): each item shows the original file name (else the stored one, else "metadata.json"), a "Delete" button (`aria-label` and title "Delete ${name}") when it has a stored name, and "Uploaded ${date and time in the browser's locale}" and "Includes legal header" joined by " · "; with no items, "No custom metadata has been added yet." **The list is never filled**: it is drawn once, empty, when the page starts; `api/mds/metadata/custom` is never asked and the upload's `items` are ignored, so the Delete buttons never appear. | `custom/custom-panel-utils.js:77-170`, `state/state-initializer.js:293`, `index.js:120`, `constants.js:5` | 27A | Fixed (/beta only, the owner's decision): the list is asked for (`GET /api/mds/metadata/custom`, `requestCustomMetadataList`) when the dialog opens and after each change, under a heading "Uploaded files" (new); each item from `describeCustomMetadataItem`, with its Delete; the empty sentence otherwise. unit MDS-M10; e2e; pane. |

## Opening an entry

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-N1 | Only the Name button opens an entry; there is no URL for it (no hash, `pushState` or `popstate` anywhere), so the browser's Back does nothing and a link cannot open one. | `table-cells.js:10-34`, `row-highlight.js:82-123` | 27A | Changed: a row opens its entry at `#mds/<entryId>` (the id encoded, `:` kept, an AAID's `#` as `%23`), a history entry of its own, so the browser's Back and Forward work and a link can open an entry (`lib/useSection.ts`, `lib/sections.ts`). In 27A the entry was a stub (`EntryView.tsx`); since 27B it is `EntryPage.tsx` (MDS-D1..D9), and a certificate is `#mds/<entryId>/certificate/<n>` (MDS-X1). unit (`EntryRoute.test.tsx`, `EntryPage.test.tsx`, `sections.test.ts`, `useSection.test.tsx`); e2e; pane. |
| MDS-N2 | Opening keeps the list (filters, sort, widths) and the window's scroll position; closing restores the scroll. Focus moves to the detail page's back button and does not come back to the row. | `authenticator-modal.js:40-231`, `detail-layout.js` | 27A | Changed: the list stays mounted while an entry is shown; Back (the page's or the browser's) returns to it with its filters, sort, widths and scroll (window and frame), and the focus on the row's name. unit; e2e; pane. |

## The authenticator detail page (27B)

The 27B rows below were read again at `30b8183f`, before porting, and their line references are to that commit
(the page's modules have not changed since `692b84f7`). The page is built by `detail-content.js` from the entry the
list holds: every entry the server sends carries its detail inline (`metadataStatement`, compacted, with the roots, key
identifiers and icon moved to `attestationCertificates`, `attestationKeyIdentifiers` and `icon`; `statusReports`;
`rawEntry` null), so `hasInlineDetail` holds and the page asks the server for nothing.

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-D1 | A page over the list (`#mds-authenticator-modal`): a back button "←" (`aria-label` "Return to authenticator list", title "Back"), the title (the entry's name as written when it is not blank, else "Authenticator"), the subtitle "AAGUID: ${aaguid} • ID: ${id} • ${protocol}" (each part only when present; ID only when it differs from the AAGUID), and a "Raw" button (title "View raw authenticator data", or disabled, out of the tab order, with "Raw authenticator data unavailable" when the entry has no raw data at all). A condensed copy of the header (back, title, subtitle, Raw) sticks to the top once the page scrolls. Body scroll is locked; the page slides in and out (500 ms). Focus goes to the back button. | `mds-content.html:304-326`, `authenticator-modal.js:17-141`, `runtime/runtime-detail-view-adapters.js:79-88`, `detail-user-sections.js:1-17`, `detail-sticky-header.js` | 27B | `EntryPage.tsx`, `EntryHeader.tsx`: Back (named "Back", title "Return to authenticator list", as in 27A), the h3 title (`detailTitle`, `explorer/detail.js`), the subtitle's parts (`detailSubtitleParts`) with the AAGUID and ID in Geist Mono with copy (on a line of their own on a phone) and the protocol as a badge, and Raw (`RAW_DATA_BUTTON_TITLE`, or disabled with `RAW_DATA_UNAVAILABLE_TITLE`, `raw-data.js`). Changed: the condensed header (`CondensedBar.tsx`) is a white bar with a hairline under the top bar once the title has scrolled away (Back, the name and subtitle truncated with their `title`, Raw), in the overlay layer; nothing is scroll-locked, nothing slides; focus goes to the title. unit MDS-D1; e2e; parity; pane. |
| MDS-D2 | An entry without its detail inline (`hasInlineDetail`) is fetched from `api/mds/metadata/resolve` with `entryId=`, else `aaguid=` (normalised), else `aaid=`, `cache: 'no-store'`. The server answers 400 "Provide exactly one of entryId, aaguid, or aaid." or 404 "Metadata entry not found.", but the page never shows either: any answer that is not ok becomes `null`, a body that is not JSON is logged as a warning, and the page opens with what the list had. Unreached today (every listed entry has its detail inline). | `authenticator-modal.js:58-76`, `metadata/explorer-state-loader.js:155-185`, `general.py:268-297` | 27B | `useEntryDetail.ts`: from the list (every listed entry has its detail), else `requestResolvedEntry` (`explorer/entry-link.js`, the query `resolveQueryForEntry`, the same order), MDS-J2's "Opening…" / "Locating…" meanwhile. Changed: the server's sentences are shown, under "Authenticator metadata not found." (404) or "Unable to open authenticator metadata." with Retry (anything else); the current page still ignores them (its adapter keeps mapping a refusal to `null`). unit (`EntryPage.test.tsx` "an entry the list does not hold", `EntryRoute.test.tsx`); logic; e2e (the list's answer stripped of the entry); pane. |
| MDS-D3 | "Overview" (`h4`), a grid of label and value: Identifier (the `id`, else "—"; always), AAGUID, Protocol, Certification (the list's text, e.g. "FIDO Certified L1 • Fixture Security Key • (FIDO2…)"), Authenticator Version, Date Updated (the list's text), each only when present. | `detail-content.js:20-39` | 27B | `EntrySections.tsx` over `detailSections` (`explorer/detail.js`): the same fields in the same order, sections as a heading and a hairline; Identifier and AAGUID in Geist Mono with copy, named by the id's kind; Certification as the list's badge and its detail (`certificationParts`, the same words). unit MDS-D3; logic; parity; pane. |
| MDS-D4 | "Metadata Statement" (`h4`, shown even when nothing follows it): Description, Legal Header, Schema, Crypto Strength, "Attestation Certificate Key IDs" (each identifier as code, trimmed, blanks dropped), UPV (each "major.minor", joined by ", "), each only when present and not blank; then the chip lists, each only when it has an item, of the raw values (a string as written, a number as written, a boolean "true" / "false", anything else as its JSON): "Authentication Algorithms", "Public Key Algorithms", "Attestation Types", "Key Protection", "Matcher Protection", "Attachment Hints", "TC Display". | `detail-content.js:41-93`, `detail-render-utils.js:15-139` | 27B | The same fields, rules and chip lists (`detailSections`, `rawListValues`); Legal Header, Description and any value over 64 characters span the row and wrap (URLs anywhere); each key identifier in Geist Mono with copy; chips wrap. unit MDS-D4; logic; parity; pane. |
| MDS-D5 | "User Verification Details" (only when a combination has something to show): per combination a card "Combination ${n}" (n counts every combination, those skipped for having nothing included), each method's name as published (e.g. "fingerprint_internal"), and under a method with `caDesc` a line of "Base: ${base}", "Min length: ${minLength}", "Max retries: ${maxRetries}", "Block slowdown: ${blockSlowdown}" (each when present) joined by " • ". A method's `baDesc` and `paDesc` are not shown. | `detail-user-sections.js:19-85` | 27B | `UserVerification.tsx`: each combination under "Combination ${n}" (the same count), a list with hairlines rather than cards, method names in Geist Mono, the code-accuracy line as before. Changed (new; the owner may veto it): a method's `baDesc` ("Self-attested FRR", "Self-attested FAR", "Max templates", "Max retries", "Block slowdown") and `paDesc` ("Min complexity", "Max retries", "Block slowdown") are shown in the same form. unit MDS-D5; logic; parity (the expected difference, scoped to this section); pane. |
| MDS-D6 | "Attestation Root Certificates" (only with a certificate): a button "Certificate ${n}" per non-empty certificate (`attestationCertificates`), opening the certificate page (MDS-X1). | `detail-content.js:102-110`, `detail-user-sections.js:87-110` | 27B | The certificate buttons in `EntrySections.tsx` ("Certificate ${n}", the non-empty ones), busy while the decode runs, opening the certificate at its URL (MDS-X1). unit MDS-D6; e2e; pane. |
| MDS-D7 | "Authenticator Get Info" (when the statement has `authenticatorGetInfo`, even `{}`): AAGUID (dashed, lower case), Max Message Size, Max Credential Count, Max Credential ID Length, Max Serialized Large Blob Array, Min PIN Length, Firmware Version, Max Cred Blob Length, "Max RP IDs for Set Min PIN Length", Remaining Discoverable Credentials (each when present); chips Versions, Extensions, Transports, Algorithms (objects as their JSON), "pinUvAuth Protocols", Options ("${key}: ${value}", `true` / `false`, an option without a value left out). | `detail-authenticator-info.js` | 27B | The same fields, labels and chips (`detailSections`); the AAGUID in Geist Mono with copy. unit MDS-D7; logic; parity; pane. |
| MDS-D8 | "Status Reports" (only with a report): a table, head Status, Effective Date, Authenticator Version, Certificate Number, Descriptor; each report a row, "—" for a missing status, date or version (an empty status stays empty) and for a missing or empty certificate number; Descriptor holds "${descriptor} • ${url}" (each when present) and under it "Policy: ${policy} • Requirements: ${requirements} • Changed: ${date}" (each when present; the date in the browser's locale, medium), or "—" when neither line has anything. A report's `timeOfLastStatusChange` is not an MDS3 field: fido2 drops it, so "Changed:" never shows on a packaged snapshot. Reports appear in the order published. | `detail-status-reports.js` | 27B | `StatusReports.tsx` on the `ui/Table` primitives (their first user; the roles written out): the same columns, cells and lines (`statusReportRows`); the certificate number in Geist Mono with copy; descriptors and URLs wrap in their column; below 640 px each report is a block with each column's name before its value (CSS `attr(data-label)`, adding no text). "Changed:" is kept, and cannot show on a packaged snapshot. unit MDS-D8; logic; e2e (375 px: every cell inside the viewport); parity; pane. |
| MDS-D9 | Values: "—" when missing, booleans "true" / "false", lists joined by ", ". | `utils/formatters.js:17-28` | 27B | Kept in the model (`formatDetailValue`, "—" through `MISSING_CELL_TEXT`). unit MDS-D9; logic. |

## The certificate page (27B)

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-X1 | "Certificate ${n}" first decodes (MDS-X2); meanwhile the button is busy (`aria-busy`, disabled, `is-loading`) and the page shows a progress cursor (`mds-certificate-loading-cursor` on the root and body). Then a page over the detail page: back "←" (the list's label, "Return to authenticator list", title "Back", although it returns to the entry), title the certificate's subject (else "Attestation Certificate"), subtitle its issuer (hidden when none); a summary (MDS-X3, else "No decoded certificate details available."), then "Raw" (the base64 as given, whitespace removed) and "Decoded Output" (the answer's `summary` text, else its JSON indented by two, else "No decoded certificate details available."). Focus goes to back; the condensed header is the certificate's. A certificate that is blank after removing whitespace opens nothing. | `mds-content.html:275-302`, `certificate-page.js`, `certificate-utils.js` | 27B | `CertificatePage.tsx`, `CertificateSummary.tsx`, routed by `EntryRouter.tsx`, decoded by `useCertificateDecode.ts`: the button busy (`aria-busy`, a spinner) while the decode runs, then the page at `#mds/<entryId>/certificate/<n>` over the entry (which stays in the page): the title (`describeCertificate`, `explorer/certificate.js`), the issuer, the summary or "No decoded certificate details available.", then Raw and Decoded Output as `CodeBlock`s with copy and Show all. Changed: a URL of its own, so a link or a reload opens it ("Decoding certificate ${n}…" meanwhile); Back is "Back", titled "Return to ${name}"; no progress cursor (the button's spinner says it); a condensed header. unit (`CertificatePage.test.tsx`); logic; e2e; parity; pane. |
| MDS-X2 | The decode: `POST /api/mds/decode-certificate` `{"certificate": …}` (JSON, `no-store`), cached per certificate for the page's life. A failure opens the page anyway, with the title "Attestation Certificate", no subtitle and the failure's message in the summary and in Decoded Output: "Certificate decode failed with status ${status}" for an answer that is not ok (the server's reason, e.g. "Invalid certificate encoding.", is not read), the error's own message otherwise, "Unable to decode certificate." for a throw that is not an `Error`. The server answers bytes that are not DER with 200 and a `summary` saying so. | `metadata/certificate-decode.js`, `certificate-page.js:36-73`, `general.py:518-542` | 27B | `requestCertificateDecode`: the same request and sentences ("Certificate decode failed with status ${status}", the error's message, "Unable to decode certificate."); a failure opens the page with them in red. Changed: `/beta` adds the server's reason (e.g. "Invalid certificate encoding.") under the sentence; a success is decoded once for the page's life, a failure is asked again on the next click. unit X2; logic. |
| MDS-X3 | The summary: Subject, Issuer, Not Before, Not After (both as UTC strings), Serial Number (decimal, else hex), Serial Number (Hex) (the first five emphasised); "Public Key": Algorithm (its name, else the key type), Named Curve, Key Size ("${n} bit"), Public Exponent, Modulus, Uncompressed Point, Value (the last three as code); "Signature": Algorithm, Hash ("sha256" → "SHA-256", else upper case), Value (code). Each item only when present, each section only with an item. | `utils/certificate-sections.js`, `utils/certificate-primitives.js`, `utils/formatters.js:128-157` | 27B | `certificateSummary` → `CertificateSummary.tsx`: the same items, order and sections; the first five emphasised; serial numbers in Geist Mono with copy; code values as blocks with copy. unit; logic; parity (a certificate: no difference); pane. |
| MDS-X4 | Back returns to the detail page (its condensed header comes back) and the window's scroll to where it was. | `certificate-page.js:166-273` | 27B | The page's Back and the browser's return to the entry at its scroll position with the focus on that certificate's button; a link's Back replaces it with the entry. unit; e2e; pane. |

## The raw view (27B)

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-W1 | "Raw" opens a popup window (80 % of the window, at least 640 × 480; reused, focused and resized when already open), styled by `styles/advanced/mds-raw-window.css`: title and heading "${name} – Authenticator Raw Data" ("Authenticator Raw Data" without a name), the MDS-D1 subtitle (hidden when empty), and a read-only text area (no wrapping, focused at its start) labelled "Raw authenticator metadata" holding the entry rebuilt as MDS publishes it (`raw-data.js`: the entry's `rawEntry` when it has one, else its statement with the roots and key identifiers put back, its status reports, AAGUID, id and `timeOfLastStatusChange`), as JSON indented by four spaces (big integers, maps, sets, buffers and cycles written out; a line-per-key fallback). A browser that blocks the popup shows nothing. | `raw-window.js`, `raw-data.js`, `raw-stringify.js` | 27B | `RawEntryDialog.tsx`: a `Dialog` titled by `authenticatorRawTitle` (`raw-data.js`), the subtitle, and a `CodeBlock` labelled "Raw authenticator metadata" holding `stringifyAuthenticatorRawData(getAuthenticatorRawData(entry))` (the same text, checked against the popup's), with copy, Show all and "Download JSON" (`lib/download.ts`, `${entryId made file-safe}.json`); Escape and the backdrop close it, focus back on the Raw used. Changed: a dialog, not a popup window (popups are blocked in some browsers and in the desktop app's pane), so no window size or reuse. unit MDS-W1; logic; e2e (clipboard read back, the downloaded file); parity (exact text); pane. |

## From a saved credential (27B)

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-J1 | A credential card whose AAGUID the MDS knows has a "FIDO MDS" button (title "Open authenticator metadata"); it switches to the MDS tab, clears the filters, highlights the entry's row, scrolls it to the middle of the window and focuses its name. Only AAGUID rows can be highlighted. The detail page is not opened. | `advanced/credential-display/list-render.js:187-196`, `credential-display/navigation.js:48-305`, `authenticator-navigation.js`, `row-highlight.js` | 27B | `entryLink.ts`: `mdsEntryPath(aaguid)` is `#mds/aaguid:<the AAGUID dashed, lower case>` (`entryIdForAaguid`, `explorer/entry-link.js`), the entry's own URL; `openMdsEntryForAaguid(aaguid, go)` and `useOpenMdsEntry()` open it as one history entry through the shell's `useSectionNavigation`, so Back returns to the caller. Changed (the owner's recommended choice): the entry's page opens, rather than a highlighted row a URL cannot keep, and the list's filters are left as they are. The saved credentials' button uses it in Phase 28. unit (`entryLink.test.tsx`); e2e (by URL: listed, resolved through the server, unknown). |
| MDS-J2 | Its messages, in the card's status line (with a spinner while working, cleared after 4 s) and the shared credential status: "Locating metadata entry..." while the entry is resolved and its row found; "Opening authenticator metadata..." between finding the row and focusing it; "Authenticator metadata not found." when nothing resolves; "Unable to locate metadata entry." when the entry resolved but its row could not be highlighted; "Unable to open authenticator metadata." on an error (red); "Authenticator metadata entry unavailable." when the explorer gave no answer (amber). | `credential-display/navigation.js`, `credential-detail-runtime/sections-aaguid.js:103-106` | 27B | `ENTRY_LINK_MESSAGES` (`explorer/entry-link.js`; the current cards import them too): "Opening authenticator metadata..." while the list loads, "Locating metadata entry..." while the server is asked, "Authenticator metadata not found." with the server's sentence for a 404, "Unable to open authenticator metadata." with Retry otherwise; "Authenticator metadata entry unavailable." is what `openMdsEntryForAaguid` returns for a value that is no AAGUID. "Unable to locate metadata entry." has no counterpart: only a row highlight could fail after the entry was found. unit; logic; e2e. |
| MDS-J3 | Leaving the MDS tab clears the highlight and hides Back to top. | `state/state-initializer-tab-change.js` | 27B | Choosing another section leaves the entry (its path is cleared); coming back shows the list (`EntryRoute.test.tsx`). Back to top is the list's own. unit. |

## Never shown

Code the page never reaches, and what happens to it. None of it is ported. It goes with the legacy tree at the
cutover (Phase 30): the legacy tests exercise most of it, and rewriting those tests now for code about to be deleted
buys nothing.

| ID | Code | Why it never shows | Where |
|---|---|---|---|
| MDS-Z1 | "Refresh Metadata" (`#mds-update-button`): `setUpdateButtonBusy`, `setUpdateButtonMode`, `UPDATE_BUTTON_STATES` ("Refresh Metadata", "Refreshing…"), and a refresh while the list is healthy. | No template renders the button; only the tests' own markup has it. `refreshMetadata` itself is reached through Retry (MDS-S7). | `state/state-initializer-dom.js:217-222`, `status-controls.js:54-97`, `constants.js:12-15` |
| MDS-Z2 | The floating sideways scrollbar (`#mds-horizontal-scroll`) and its metrics. | No template renders the element. | `scroll-metrics.js` |
| MDS-Z3 | `MDS_EXPLORER_PATH` (`api/mds/metadata/explorer`) and `CUSTOM_METADATA_LIST_PATH` (`api/mds/metadata/custom`). | Never requested (see MDS-M10). | `constants.js:1,5` |
| MDS-Z4 | The client's own row builder for entries without `entryId`: `utils/entry-transform.js` (but `collectOptionSets`), the lazy loader and its background batches ("Processing full details in background…", "Processing full details… ${p}% complete", "… Background processing encountered an error."), the certificate-derived Algorithm Info and CN, "Loaded ${n} authenticators. Last updated: ${date}." (with a colon), and the global loader's phases. (Its request for `fido-mds3.verified.json.meta.json` through Flask's root static route, which does not follow the snapshot directory, was removed in 27B: the page's info carries the timestamp whenever there is a snapshot.) | The server always sends `entryId`. | `metadata/metadata-entry-loading.js`, `metadata-entry-lazy.js`, `metadata-background-loading.js`, `metadata-derived-info.js:1-141`, `lazy-loader.js` |
| MDS-Z5 | The `initial-mds-snapshot` page data (a snapshot inlined in the page). | The server never renders it. | `index.js:59-72,156` |
| MDS-Z6 | `setStatus`'s `restoreDefault`, the `mds-tag--neutral` pill, the "warning" status variant. | No caller passes them (and no style exists for the last). | `status-controls.js:16-52`, `table-cells.js:63-84` |

## What changed (27A)

Nothing the list shows or does was dropped. What looks or behaves differently:

- **Layout.** Compact, left-aligned one-line rows (41 px) instead of tall centred ones; a long value truncates with an
  ellipsis and the whole value as the cell's tooltip, and a row expands (the chevron before its name) to show every
  word, lists as pills. The table sits in a frame that scrolls both ways by itself, the header row in view, the
  sideways scrollbar always within reach; the page never scrolls sideways (375 px included). White throughout.
- **Certification** is one badge for the level, coloured by status, with the descriptor and number after it on the
  same line (four lines before).
- **ID** in Geist Mono on one line, never broken, with copy.
- **Filters** are a bar above the table, each labelled with its column (six to a row on a wide screen, folded behind
  "Show filters" on a phone), not a second header row; they say how many are in use and clear with one button; a
  filtered column's header is marked. The seven with a list are ARIA comboboxes (the wrap, Enter and Escape as the
  ARIA pattern has them).
- **Sorting** is announced with `aria-sort`; the headers' "Sort X (…)" labels and `aria-pressed` are gone.
- **Resizing** also works from the keyboard (the handle is focusable, arrow keys ±16 px).
- **Opening an entry**: a click anywhere in the row, or Enter on its name, opens it at `#mds/<entryId>`, with the
  browser's Back and Forward; the list comes back as it was, focus on the row. The entry itself is a stub until 27B.
- **Manage Trusted Metadata** is a dialog that Escape and its backdrop also close and that gives focus back; it lists
  the session's uploads (the current panel never does) under "Uploaded files"; the progress is a line inside it, not
  an overlay over the tab; a refused upload or delete keeps the server's reason.
- **Loading** starts when the section is first shown (no preload on idle or hover); with no snapshot the table says
  "Packaged FIDO metadata is unavailable…" (the current table says no authenticator matches the filters); Retry is
  offered only after a failure, in the status line and in the table.
- **Not ported (never shown):** MDS-Z1..Z6; "Refresh Metadata" among them. They go with the legacy tree at the
  cutover.

## The parity check (27A)

`web/e2e/mds-parity.spec.ts` loads the fixture snapshot in the current UI at `/` and in `/beta`, applies the same
filters in both, and reads each row's cells (`readShownRows` in `web/e2e/parity.ts`: the text of every cell, the
names' buttons included, images and what is hidden left out), keyed by the ID. Filter sets: none, protocol "Uaf",
certification "FIDO Certified L2", certification "FIDO Certified" (every level), name "Security Key", user
verification "Fingerprint Internal" with transports "Nfc"; and the list sorted by name both ways. Result on
2026-09-26: **every set shows the same rows in the same order, with the same words in every row; no expected
difference is needed.** On the owner's 517-entry snapshot the two UIs say the same status sentence and count.

## What changed (27B)

Nothing the detail page, the certificate page or the raw view shows was dropped. What looks or behaves differently:

- **Layout.** The entry is a page under the section's title, not a layer over the list: sections are a heading and a
  hairline (no cards in cards), fields on a grid that uses the width (long text across it), chips that wrap, the
  user-verification combinations as a list with hairlines. Identifiers (AAGUID, AAID, key identifiers, the getInfo
  AAGUID, certificate and serial numbers) are Geist Mono, whole, with copy; on a phone the subtitle's identifiers take a
  line of their own. Certification is the list's badge. The status reports are a table that stacks on a phone.
- **Condensed header.** Once the title has scrolled under the top bar, a white bar with a hairline stays there with
  Back, the name, the subtitle and Raw (the certificate page has its own). The page is not scroll-locked and does not
  slide in or out.
- **URLs.** An entry is `#mds/<entryId>` (27A); a certificate is `#mds/<entryId>/certificate/<n>`, so a link or a
  reload opens it and the browser's Back returns to the entry with the focus on that certificate's button. A path the
  page does not know shows the entry and the URL is corrected.
- **An entry the list does not hold** is asked of the server, as the current page does for an entry without its
  detail, but the server's sentences are shown (the current page ignores them), with Retry after a failure.
- **User verification:** the biometric and pattern accuracy (`baDesc`, `paDesc`) are shown beside the code accuracy
  (new; the current page leaves them out).
- **Certificates:** the decode's button is busy (no progress cursor); `/beta` adds the server's reason under a
  failure's sentence; a failure is asked again on the next click.
- **Raw view:** a dialog with copy, Show all and "Download JSON", not a popup window (popups are blocked in some
  browsers and in the desktop app's pane). Its text is the same.
- **The link from a saved credential** opens the entry's page (`#mds/aaguid:…`) rather than highlighting a row, and
  leaves the list's filters as they are; its sentences go to the states they describe (MDS-J2).
- **Back** keeps 27A's form: named "Back", titled "Return to authenticator list" (the current "←" has that as its
  label and "Back" as its title); the certificate page's is titled "Return to ${name}", since it returns to the entry.

## The parity check (27B)

`web/e2e/mds-entry-parity.spec.ts` opens the same entry in the current UI at `/` (its name's button in the table) and
in `/beta` (its URL), reads each page's text by section (`h4`; the header before the first), and compares them word for
word (`compareShownText` in `web/e2e/parity.ts`: layout, separators and controls' own labels set aside). An expected
difference may now name its section. Entries: Fixture Security Key L1 (FIDO2, getInfo, three status reports), Fixture
Key With Every User Verification Method (every descriptor), Fixture U2F Key, Fixture UAF Authenticator, and Fixture
Uploaded Authenticator (the fixture statement uploaded through the API in the session both UIs share). Then one
certificate's page (Fixture Security Key L2's RSA root: the summary with its Public Key and Signature sections, Raw and
Decoded Output), and the raw view's text against the current popup's.

Result on 2026-09-26: **every entry shows the same sections in the same order with the same words; the only
differences are the biometric and pattern accuracy words `/beta` adds under User Verification Details (entry 7), each
listed with its reason. The certificate page has no difference, and the raw view's title, subtitle and text are
identical.** On the owner's 517-entry snapshot, both UIs show the same six sections for YubiKey Bio Series, and the
real `baDesc` values (for example "Self-attested FRR: 0") show in `/beta` only.
