# FIDO MDS explorer — content parity

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
given. "Verbatim" text is quoted exactly; `${...}` marks a value filled in at run time. The **New** column is filled
in once the port is done.

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
| MDS-H1 | Reached from the top navigation's "FIDO MDS Authenticators" tab (`data-action="switch-tab" data-tab="mds"`). | `shared/navigation.html:5` | 27A | to map |
| MDS-H2 | Heading "FIDO MDS Authenticators" (`h2`) and the description "Explore the authenticators published by the FIDO Metadata Service (MDS)." | `mds-content.html:4-7` | 27A | to map |
| MDS-H3 | The count line, `aria-live="polite"`: "Entries: " then the number shown (`toLocaleString()`, "0" at load) and, when the total is not zero, "of ${total} total" (e.g. "Entries: 12 of 517 total"); the total is blank when it is zero. | `mds-content.html:8-11`, `status-controls.js:1-8` | 27A | to map |
| MDS-H4 | A button "Manage Metadata", `aria-haspopup="dialog"`, `aria-expanded` "false" / "true" with the panel. | `mds-content.html:13-17`, `state/state-initializer-dom.js:86-100` | 27A | to map |
| MDS-H5 | When the explorer cannot start, the whole tab is replaced by "Unable to load authenticator explorer. Check the console for details." | `runtime/bootstrap.js:89-96` | 27A | to map |

## When the data is loaded and from where

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-L1 | The page's data for the explorer is `initial-mds-info`, inlined by the index as JSON: the packaged summary (`source`, `legalHeader`, `no`, `nextUpdate`, `entryCount`, `lastModified`, `lastModifiedIso`, `etag`, `fetchedAt`, `generatedAt`; absent without a snapshot), `snapshotUrl` (`/assets/<BUILD_ID>/fido-mds3.explorer.full.json`) and `customEntriesState` (`none` for a session created by this request, else what the session last recorded, `none` / `present`, else `unknown`). | `index.html:58`, `general.py:196-218`, `index.js:150-159` | 27A | to map |
| MDS-L2 | Loading does not start with the page: it starts when the MDS tab is shown, when the pointer enters or focus reaches its top-navigation tab, once the app is ready and idle (skipped when the connection asks to save data or is 2G), or after 10 s; showing the tab again loads again unless already loaded. | `runtime/bootstrap.js:1-127` | 27A | to map |
| MDS-L3 | The source: the packaged file at `snapshotUrl` (browser cache allowed) when `customEntriesState` is `none` and the load is not forced; otherwise `GET api/mds/metadata/explorer/full` with `cache: 'no-store'` (`'reload'` when forced). The API path is relative. | `metadata/explorer-source.js:18-46`, `constants.js:2` | 27A | to map |
| MDS-L4 | If the packaged file fails (not ok, not an object, or a network error other than an abort), the API is asked instead, silently. | `metadata/explorer-load.js:85-104` | 27A | to map |
| MDS-L5 | A loaded snapshot's `meta.hasCustomEntries` updates `customEntriesState` (`present` / `none`) for later loads. | `metadata/explorer-source.js:39-43`, `explorer-load.js:130-132` | 27A | to map |
| MDS-L6 | Applying a snapshot: the entries are cloned, merged with any entry already resolved in full, the sort is reset to its default (MDS-O1) and the filters kept, the option lists rebuilt, the table redrawn, resizing enabled when there are entries, Retry hidden. | `metadata/explorer-state-loader.js:48-133` | 27A | to map |
| MDS-L7 | A load while one is running waits for it; a load after a successful one does nothing unless forced; a forced load clears the entries already resolved in full. | `metadata/explorer-load.js:37-52` | 27A | to map |
| MDS-L8 | The server answers a missing snapshot with 200, `entries: []` and zeroed counts (its 404 branch is not reached: the composed snapshot always has a `meta`), and the packaged file 404s. | `general.py:229-252`, `webauthn/metadata/effective.py:103-112` | 27A | to map |

## Status line and Retry

The line is `#mds-status`, coloured by its variant (info, success, error), with the snapshot's legal header as its
tooltip once loaded. Retry sits under it.

| ID | Current behaviour (verbatim) | Where | Phase | New |
|---|---|---|---|---|
| MDS-S1 | Before anything runs (template), and with no usable summary: "Packaged FIDO metadata is available. Explorer data is loading in the background." (info) | `mds-content.html:56-58`, `metadata/metadata-helpers.js:57-60,77-79` | 27A | to map |
| MDS-S2 | With a summary: "${parts joined by " • "}. Explorer data is loading in the background.", the parts being "Snapshot ${no}", "${entryCount} authenticators" and "last updated ${date}" where each is known; the date is the first of `generatedAt`, `generated_at`, `fetchedAt`, `fetched_at`, `lastModifiedIso`, `last_modified_iso`, `lastModified`, `last_modified`, shown in the browser's locale (medium date, short time), or as written when it is not a date. | `metadata/metadata-helpers.js:17-82`, `runtime/bootstrap.js:76-86` | 27A | to map |
| MDS-S3 | While loading: "Loading authenticator explorer…"; when forced: "Refreshing authenticator explorer…" (info). Retry hides. | `metadata/explorer-load.js:54-57` | 27A | to map |
| MDS-S4 | Loaded (success; info when there are no entries): "Loaded ${n} authenticators." then "Last updated ${date}." (the snapshot's `meta`, as MDS-S2; no colon), then "Including ${n} session metadata entry." / "…entries." when the session has uploads, then a note ("Explorer refreshed." after Retry, "Custom metadata updated." after an upload or delete), joined by spaces. The line's `title` is the snapshot's `legalHeader`. | `metadata/metadata-derived-info.js:143-164`, `explorer-state-loader.js:116-132` | 27A | to map |
| MDS-S5 | A 404 from the source: the answer's `error`, else "Packaged FIDO metadata is unavailable. Please verify the bundled snapshot is present." (info), also as the table's only row; the count reads 0 with no total. (Unreached: see MDS-L8.) | `metadata/explorer-load.js:108-117`, `explorer-state-loader.js:3-46`, `constants.js:9-10` | 27A | to map |
| MDS-S6 | Another failure (error), and Retry shows: the answer's `error`, else "Explorer request failed with status ${status}."; a body that is not an object: "Explorer response was not valid JSON."; anything else: "Unable to load the packaged authenticator explorer." | `metadata/explorer-load.js:119-160` | 27A | to map |
| MDS-S7 | Retry ("Retry", hidden until a failure) runs a forced load: "Refreshing authenticator explorer…", then MDS-S4 with the note "Explorer refreshed."; Retry is disabled meanwhile. Pressed while a load runs: "Metadata is currently loading. Please wait for the current operation to finish." A failure that escapes: "Unable to refresh the packaged authenticator explorer." (error). | `mds-content.html:59-63`, `runtime/runtime-refresh-metadata.js:1-53`, `state/state-initializer-dom.js:207-215` | 27A | to map |
| MDS-S8 | Status text is written as text only, never markup. | `status-controls.js:10-14`, `tests/frontend/advanced/mds/mds-status-xss.test.js` | 27A | to map |

## The table's columns

A table of 13 columns, header row sticky at the top of its container, the container scrolling sideways
(`overflow-x: auto`, a 1,500 px minimum width). Every cell is text only.

| ID | Header | Cell (current behaviour) | Where | Phase | New |
|---|---|---|---|---|---|
| MDS-C1 | Icon | The entry's `icon` (a `data:` URL) as an image, at most 36 × 36 in a 44 × 44 box, alt "${name, else "Authenticator"} icon"; without one, "N/A". | `table-cells.js:42-61`, `styles/advanced/mds/table.css:257-274` | 27A | to map |
| MDS-C2 | Name | The entry's `name` as a button that opens the detail page (MDS-D1); an empty name or "—" is plain text. The server's name: the description, else the first alternative description, else the first status report's descriptor, else "Unknown Authenticator". | `table-cells.js:10-34`, `utils/resolvers.js` | 27A | to map |
| MDS-C3 | Protocol | `protocol`, or "—": "FIDO2", "U2F" and, as the server spells it, "Uaf". | `table-render.js:105`, `utils/formatters.js:30-40` | 27A | to map |
| MDS-C4 | Certification | `certification`, or "—", as one text that wraps: the latest status report's status, descriptor and "(certificate number)" joined by " • ", e.g. "FIDO Certified L1 • Security Key by Yubico • (U2F110020191017010)", "NOT FIDO Certified", "Revoked". | `table-render.js:106`, `utils/formatters.js:79-108` | 27A | to map |
| MDS-C5 | ID | `id`, or "—", in a monospace cell: the AAGUID, else the AAID, else the first attestation key identifier. | `table-cells.js:36-40` | 27A | to map |
| MDS-C6 | User Verification | `userVerificationList` as pills stacked one per line, or "—": the distinct methods across every combination, sorted (e.g. "Fingerprint Internal", "Passcode External", "None"). | `table-cells.js:63-84` | 27A | to map |
| MDS-C7 | Attachment | `attachmentList` as pills, or "—" (e.g. "External", "Wired", "Nfc"). | same | 27A | to map |
| MDS-C8 | Transports | `transportsList` as pills, or "—" (e.g. "Usb", "Nfc", "Ble", "Hybrid", "Internal"). | same | 27A | to map |
| MDS-C9 | Key Protection | `keyProtectionList` as pills, or "—" (e.g. "Hardware", "Secure Element"). | same | 27A | to map |
| MDS-C10 | Algorithms | `algorithmsList` as pills, or "—" (e.g. "SECP256R1 Ecdsa SHA256 Raw"). | same | 27A | to map |
| MDS-C11 | Algorithm Info | `certificateAlgorithmInfoList` as pills, or "—": the attestation roots' signature algorithm and hash (e.g. "ECDSA_SHA256"). | same | 27A | to map |
| MDS-C12 | CN | `certificateCommonNameList` as pills, or "—": the attestation roots' subject common names (up to 954 characters in all in the live snapshot). | same | 27A | to map |
| MDS-C13 | Date Updated | `dateUpdated`, or "—" (e.g. "Sep 18, 2023", written by the server in English), with the raw date (`dateTooltip`, e.g. "2023-09-18") as its tooltip. | `table-render.js:115`, `table-cells.js:1-8` | 27A | to map |
| MDS-C14 | — | Rows are drawn in full, every row at once (no virtual scrolling); after drawing, each row's height is measured and fixed. Tall rows: the pills stack vertically. | `table-render.js:83-132`, `row-layout.js:34-89`, `table.css` | 27A | to map |
| MDS-C15 | — | A row carries `data-aaguid` (the AAGUID, lower case) or `data-entry-id` (the `id`, for AAID and key-identifier rows); a click elsewhere in the row does nothing. | `table-render.js:85-101` | 27A | to map |
| MDS-C16 | — | Uploaded (session) entries come first and replace a packaged entry with the same AAGUID; nothing in the row marks them (only MDS-S4's "Including … session metadata …"). | `webauthn/metadata/effective.py:114-149` | 27A | to map |

## Sorting

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-O1 | Default: Date Updated, newest first; also restored whenever a snapshot is applied. | `sort-filter-controller.js:8-9,209-221`, `explorer-state-loader.js:93` | 27A | to map |
| MDS-O2 | Each header has a sort button (no text; CSS draws ↕ / ↑ / ↓), `aria-label` "Sort ${label} column" at load and then "Sort ${label} (ascending)", "(descending)" or "(no sorting)", `aria-pressed` true on the active one; there is no `aria-sort`. | `mds-content.html:69-237`, `sort-filter-controller.js:176-207` | 27A | to map |
| MDS-O3 | A column's clicks go none → ascending → descending → none; reaching none restores MDS-O1. Date Updated goes none → descending, ascending → descending, descending → ascending. Clicking another column starts it from none. | `sort-filter-controller.js:11-23,166-174,241-272` | 27A | to map |
| MDS-O4 | Sort values: Icon by "1_${name}" with an icon and "0_${name}" without (so ascending puts the entries without an icon first), Algorithm Info and CN by their joined text, Date Updated by the tooltip's date, every other column by its text; "—" and empty sort as empty, numeric text as a number, other text lower-cased; ties by the lower-cased text, then the text, then the entry's `index`. Descending is the ascending order reversed. | `sort-filter-controller.js:25-51,102-164`, `sort-filter-normalise.js` | 27A | to map |
| MDS-O5 | Sorting keeps the table's scroll position. | `sort-filter-controller.js:271`, `table-render.js:24-62` | 27A | to map |

## Filters

A second header row of search fields, one under each column but Icon and Date Updated. Filters combine (all must
match) and apply on each keystroke; the count (MDS-H3) follows.

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-F1 | Name: placeholder "Search name"; free text. | `mds-content.html:241`, `constants.js:26` | 27A | to map |
| MDS-F2 | Protocol: placeholder "Protocol"; a list of the protocols present. | `mds-content.html:242`, `constants.js:27` | 27A | to map |
| MDS-F3 | Certification: placeholder "Certification"; a list of "FIDO Certified", "FIDO Certified L1", "FIDO Certified L2", "NOT FIDO Certified", "Revoked" (always, even before data) plus every other status present, formatted (e.g. "FIDO Certified L3plus"). | `mds-content.html:243`, `constants.js:17-33`, `state/state-initializer.js:113-118`, `utils/entry-transform.js:54-80` | 27A | to map |
| MDS-F4 | ID: placeholder "AAGUID or AAID"; free text, matched against the ID column's text. | `mds-content.html:244`, `constants.js:34` | 27A | to map |
| MDS-F5 | User Verification: placeholder "User verification"; a list of every method present, shown whole (no inner scroll). | `mds-content.html:245`, `constants.js:35-40`, `table.css:167` | 27A | to map |
| MDS-F6 | Attachment: placeholder "Attachment"; a list. | `mds-content.html:246`, `constants.js:41` | 27A | to map |
| MDS-F7 | Transports: placeholder "Transports"; a list. | `mds-content.html:247`, `constants.js:42` | 27A | to map |
| MDS-F8 | Key Protection: placeholder "Key protection"; a list. | `mds-content.html:248`, `constants.js:43` | 27A | to map |
| MDS-F9 | Algorithms: placeholder "Algorithms"; a list, shown whole. | `mds-content.html:249`, `constants.js:44-49` | 27A | to map |
| MDS-F10 | Algorithm Info: placeholder "Algorithm info"; free text. | `mds-content.html:250`, `constants.js:50` | 27A | to map |
| MDS-F11 | CN: placeholder "CN"; free text. | `mds-content.html:251`, `constants.js:51` | 27A | to map |
| MDS-F12 | Matching: the typed text, trimmed, is found in the column's joined text ignoring case. Certification: when the text names one of the list's options, the entry's status must equal it, except "FIDO Certified", which matches every certified level; other text is found in the certification text or status. | `sort-filter-controller.js:62-100`, `state/state-initializer.js:78-108` | 27A | to map |
| MDS-F13 | A list opens on focus or click (when it has options), narrows to the options containing the typed text, sorted ignoring case and accents; "No matches" when none do. ArrowDown / ArrowUp move (wrapping; ArrowUp with nothing chosen goes to the next-to-last), Enter picks, Escape closes; a click on an option picks it; one list open at a time; a click outside closes it. Picking fills the field and filters. No listbox or combobox roles. | `dropdown.js:1-185` | 27A | to map |
| MDS-F14 | In a field, Enter applies it (it already has) and Escape clears it. | `state/state-initializer.js:92-108` | 27A | to map |
| MDS-F15 | There is no count of active filters and no way to clear them all at once. | — | 27A | to map |

## Column widths

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-R1 | Every header but the last has a drag handle on its right edge (title "Drag to resize column", hidden from assistive technology, no keyboard), enabled once entries are loaded. Dragging with the main button widens or narrows that column only; the table grows and scrolls sideways. | `column-resizers.js:249-284`, `column-resizers-pointer.js` | 27A | to map |
| MDS-R2 | Widths start from the header cells' measured widths; no column goes under 64 px; the widths are kept while the page is open (filters and sorting keep them) and never saved. | `column-resizers.js:13-121`, `index.js:84` | 27A | to map |

## Loading, empty and no-match rows

| ID | Current behaviour (verbatim) | Where | Phase | New |
|---|---|---|---|---|
| MDS-E1 | Before data: one row "Authenticator metadata is loading…". | `mds-content.html:255-258` | 27A | to map |
| MDS-E2 | No entry matches the filters (and a snapshot with no entries at all): one row "No authenticators match the selected filters." | `table-render.js:67-81` | 27A | to map |
| MDS-E3 | A missing snapshot (MDS-S5): one row with that message. | `explorer-state-loader.js:32-45` | 27A | to map |

## Back to top

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-B1 | A round "↑" button fixed at the top centre of the window, `aria-label` "Back to top of the authenticator list", title "Back to top", shown while the tab is visible, there are more than five rows and the fifth row has scrolled above the table's header; it scrolls the window to the top (smoothly). | `mds-content.html:262-271`, `scroll-top-button-visibility.js`, `scroll-metrics.js`, `styles/advanced/mds/overview.css:389-418` | 27A | to map |

## Manage Trusted Metadata

| ID | Current behaviour (verbatim) | Where | Phase | New |
|---|---|---|---|---|
| MDS-M1 | "Manage Metadata" opens a dialog (`role="dialog"`, `aria-modal="true"`) titled "Manage Trusted Metadata" (`h3`), with a close button labelled "Close" (×), and focus on the drop zone. Only the × closes it: its backdrop and Escape do not. Focus goes back to the button. Scrolling inside does not scroll the page. | `mds-content.html:20-54`, `custom/custom-panel-utils.js:179-276`, `custom-panel-scroll-guard.js` | 27A | to map |
| MDS-M2 | The description "Drop JSON metadata files here or select them from your device. Uploaded files are trusted only for this browser session." | `mds-content.html:30-32` | 27A | to map |
| MDS-M3 | The drop zone (focusable): a folder icon (📁, hidden from assistive technology), "Drop JSON files here or click to browse" and the hint "Only `.json` files are accepted." (`.json` as code). Click, Enter or Space opens the file chooser (`accept=".json,application/json"`, several files); files dropped on it are taken too; it is highlighted while files are dragged over it. | `mds-content.html:33-50`, `state/state-initializer-dom.js:102-127`, `runtime/runtime-custom-metadata-adapters.js:41-64` | 27A | to map |
| MDS-M4 | Choosing files: names not ending in ".json" are refused with "Ignored non-JSON files: ${names joined by ", "}" ("Unnamed file" for a file without a name) (warning); with no JSON file left and none refused: "Please select one or more JSON files." (warning). | `runtime/runtime-custom-metadata-adapters.js:98-116`, `metadata/metadata-helpers.js:106-128` | 27A | to map |
| MDS-M5 | Uploading: `POST api/mds/metadata/upload`, the files as `files` (a nameless one as "metadata.json"); "Uploading metadata…" (info). Success: "Metadata uploaded successfully." (success) or "Metadata uploaded with warnings: ${errors joined by " "}" (warning); failure: "Failed to upload metadata files." (error; the server's reason is composed first but then replaced). With no files: "Please choose one or more JSON files." (warning). | `custom/custom-metadata-actions.js:1-83` | 27A | to map |
| MDS-M6 | Deleting an item: `DELETE api/mds/metadata/custom/${stored name}`; "Removing ${name}…" (info), then "${name} removed." (success); a 404: the server's message ("Metadata entry not found.") as a warning; other failures "Failed to delete metadata file." (error); no stored name: "Unable to delete the metadata file." (error). The item's button is busy meanwhile. | `custom/custom-metadata-actions.js:85-181` | 27A | to map |
| MDS-M7 | An upload or delete answer carrying a snapshot is applied at once, with the note "Custom metadata updated." (MDS-S4); without one, a forced load. | `custom/custom-metadata-actions.js:59-66,153-159` | 27A | to map |
| MDS-M8 | Meanwhile an overlay covers the tab (`role="alertdialog"`, a spinner and a message): upload "Updating Metadata...", "Uploading metadata…", "Applying metadata…" or "Reloading metadata…", then "Completing metadata update..." or "Metadata update failed."; delete "Removing metadata...", "Removing metadata…", "Applying metadata…" or "Refreshing metadata…" (or "No metadata changes detected."), then "Completing metadata removal..." or "Metadata removal failed."; its default "MDS is updating…"; a "Cancel update" button that is never shown (not cancellable); "Metadata update cancelled." / "Metadata removal cancelled." on a cancel. | `custom/update-overlay.js`, `state/state-initializer-dom.js:1-54`, `custom-metadata-actions.js:67-74,162-168` | 27A | to map |
| MDS-M9 | The messages area (`aria-live="polite"`), coloured by variant (info, success, warning, error), hidden when empty. | `mds-content.html:51`, `custom/custom-panel-utils.js:53-75` | 27A | to map |
| MDS-M10 | The list of uploaded files (`aria-live="polite"`): each item shows the original file name (else the stored one, else "metadata.json"), a "Delete" button (`aria-label` and title "Delete ${name}") when it has a stored name, and "Uploaded ${date and time in the browser's locale}" and "Includes legal header" joined by " · "; with no items, "No custom metadata has been added yet." **The list is never filled**: it is drawn once, empty, when the page starts; `api/mds/metadata/custom` is never asked and the upload's `items` are ignored, so the Delete buttons never appear. | `custom/custom-panel-utils.js:77-170`, `state/state-initializer.js:293`, `index.js:120`, `constants.js:5` | 27A | to map |

## Opening an entry

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-N1 | Only the Name button opens an entry; there is no URL for it (no hash, `pushState` or `popstate` anywhere), so the browser's Back does nothing and a link cannot open one. | `table-cells.js:10-34`, `row-highlight.js:82-123` | 27A | to map |
| MDS-N2 | Opening keeps the list (filters, sort, widths) and the window's scroll position; closing restores the scroll. Focus moves to the detail page's back button and does not come back to the row. | `authenticator-modal.js:40-231`, `detail-layout.js` | 27A | to map |

## The authenticator detail page (27B)

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-D1 | A page over the list (`#mds-authenticator-modal`): a back button "←" (`aria-label` "Return to authenticator list", title "Back"), the title (the entry's name, else "Authenticator"), the subtitle "AAGUID: ${aaguid} • ID: ${id} • ${protocol}" (ID only when it differs), and a "Raw" button (title "View raw authenticator data", or disabled with "Raw authenticator data unavailable"). A condensed header follows while the page scrolls. Body scroll is locked. | `mds-content.html:304-326`, `authenticator-modal.js`, `detail-user-sections.js:1-17`, `detail-sticky-header.js` | 27B | — |
| MDS-D2 | An entry without its detail inline is fetched from `api/mds/metadata/resolve?entryId=` (else `aaguid=`, else `aaid=`); errors "Provide exactly one of entryId, aaguid, or aaid." (400) and "Metadata entry not found." (404). | `authenticator-modal.js:40-141`, `metadata/explorer-state-loader.js:135-214`, `general.py:255-284` | 27B | — |
| MDS-D3 | "Overview": Identifier, AAGUID, Protocol, Certification, Authenticator Version, Date Updated. | `detail-content.js` | 27B | — |
| MDS-D4 | "Metadata Statement": Description, Legal Header, Schema, Crypto Strength, "Attestation Certificate Key IDs" (code list), UPV (major.minor); chip lists (raw values): "Authentication Algorithms", "Public Key Algorithms", "Attestation Types", "Key Protection", "Matcher Protection", "Attachment Hints", "TC Display". | `detail-content.js`, `detail-render-utils.js` | 27B | — |
| MDS-D5 | "User Verification Details": one card per combination, "Combination ${n}", each method with "Base:", "Min length:", "Max retries:", "Block slowdown:" when present. | `detail-user-sections.js` | 27B | — |
| MDS-D6 | "Attestation Root Certificates": a button "Certificate ${n}" per certificate, opening the certificate page (MDS-X1). | `detail-content.js` | 27B | — |
| MDS-D7 | "Authenticator Get Info": AAGUID, Max Message Size, Max Credential Count, Max Credential ID Length, Max Serialized Large Blob Array, Min PIN Length, Firmware Version, Max Cred Blob Length, "Max RP IDs for Set Min PIN Length", Remaining Discoverable Credentials; chips Versions, Extensions, Transports, Algorithms, "pinUvAuth Protocols", Options ("key: value"). | `detail-authenticator-info.js` | 27B | — |
| MDS-D8 | "Status Reports": a table Status, Effective Date, Authenticator Version, Certificate Number, Descriptor ("descriptor • url"), with a line "Policy: … • Requirements: … • Changed: ${date}". | `detail-status-reports.js` | 27B | — |
| MDS-D9 | Values: "—" when missing, booleans "true" / "false", lists joined by ", ". | `utils/formatters.js:17-28` | 27B | — |

## The certificate page (27B)

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-X1 | Over the detail page: back "←" (as MDS-D1), title the certificate's subject (else "Attestation Certificate"), subtitle its issuer (hidden when none); a summary, then "Raw" (the base64) and "Decoded Output" (the summary text, else its JSON, else "No decoded certificate details available."). The button that opened it is busy meanwhile. | `mds-content.html:275-302`, `certificate-page.js`, `certificate-utils.js` | 27B | — |
| MDS-X2 | The decode: `POST /api/mds/decode-certificate` `{"certificate": …}`; a failure shows its message, else "Unable to decode certificate." (e.g. "Certificate decode failed with status 500"). | `metadata/certificate-decode.js`, `general.py:497-521` | 27B | — |
| MDS-X3 | The summary: Subject, Issuer, Not Before, Not After (UTC), Serial Number, Serial Number (Hex); "Public Key": Algorithm, Named Curve, Key Size ("${n} bit"), Public Exponent, Modulus, Uncompressed Point, Value; "Signature": Algorithm, Hash, Value. | `utils/certificate-sections.js`, `utils/certificate-primitives.js` | 27B | — |
| MDS-X4 | Back returns to the detail page. | `certificate-page.js` | 27B | — |

## The raw view (27B)

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-W1 | "Raw" opens a popup window (80 % of the window, at least 640 × 480; reused when open), styled by `styles/advanced/mds-raw-window.css`: title and heading "${name} – Authenticator Raw Data", the MDS-D1 subtitle, and a read-only text area labelled "Raw authenticator metadata" holding the entry rebuilt as MDS publishes it (`raw-data.js`), as JSON indented by four spaces (big integers, maps, sets, buffers and cycles written out; a line-per-key fallback). | `raw-window.js`, `raw-data.js`, `raw-stringify.js` | 27B | — |

## From a saved credential (27B)

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| MDS-J1 | A credential card whose AAGUID the MDS knows has a "FIDO MDS" button (title "Open authenticator metadata"); it switches to the MDS tab, clears the filters, highlights the entry's row, scrolls it to the middle of the window and focuses its name. Only AAGUID rows can be highlighted. The detail page is not opened. | `advanced/credential-display/list-render.js:187-196`, `credential-display/navigation.js:48-305`, `authenticator-navigation.js`, `row-highlight.js` | 27B | — |
| MDS-J2 | Its messages: "Locating metadata entry...", "Opening authenticator metadata...", "Unable to locate metadata entry.", "Unable to open authenticator metadata.", "Authenticator metadata entry unavailable.", "Authenticator metadata not found." | `credential-display/navigation.js`, `credential-detail-runtime/sections-aaguid.js:103-106` | 27B | — |
| MDS-J3 | Leaving the MDS tab clears the highlight and hides Back to top. | `state/state-initializer-tab-change.js` | 27B | — |

## Never shown

Code the page never reaches, and what happens to it. None of it is ported. It goes with the legacy tree at the
cutover (Phase 30): the legacy tests exercise most of it, and rewriting those tests now for code about to be deleted
buys nothing.

| ID | Code | Why it never shows | Where |
|---|---|---|---|
| MDS-Z1 | "Refresh Metadata" (`#mds-update-button`): `setUpdateButtonBusy`, `setUpdateButtonMode`, `UPDATE_BUTTON_STATES` ("Refresh Metadata", "Refreshing…"), and a refresh while the list is healthy. | No template renders the button; only the tests' own markup has it. `refreshMetadata` itself is reached through Retry (MDS-S7). | `state/state-initializer-dom.js:217-222`, `status-controls.js:54-97`, `constants.js:12-15` |
| MDS-Z2 | The floating sideways scrollbar (`#mds-horizontal-scroll`) and its metrics. | No template renders the element. | `scroll-metrics.js` |
| MDS-Z3 | `MDS_EXPLORER_PATH` (`api/mds/metadata/explorer`) and `CUSTOM_METADATA_LIST_PATH` (`api/mds/metadata/custom`). | Never requested (see MDS-M10). | `constants.js:1,5` |
| MDS-Z4 | The client's own row builder for entries without `entryId`: `utils/entry-transform.js` (but `collectOptionSets`), the lazy loader and its background batches ("Processing full details in background…", "Processing full details… ${p}% complete", "… Background processing encountered an error."), the certificate-derived Algorithm Info and CN, "Loaded ${n} authenticators. Last updated: ${date}." (with a colon), the request for `fido-mds3.verified.json.meta.json`, and the global loader's phases. | The server always sends `entryId`. | `metadata/metadata-entry-loading.js`, `metadata-entry-lazy.js`, `metadata-background-loading.js`, `metadata-derived-info.js:1-141`, `lazy-loader.js` |
| MDS-Z5 | The `initial-mds-snapshot` page data (a snapshot inlined in the page). | The server never renders it. | `index.js:59-72,156` |
| MDS-Z6 | `setStatus`'s `restoreDefault`, the `mds-tag--neutral` pill, the "warning" status variant. | No caller passes them (and no style exists for the last). | `status-controls.js:16-52`, `table-cells.js:63-84` |
