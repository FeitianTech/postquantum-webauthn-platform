# Saved credentials — content parity

Everything the current UI shows and does with saved credentials, taken from the running code at `b163738d`: the list
both tabs show (`frontend/templates/simple/tab.html:41-65`, `advanced/tab/credentials-column.html`), the credential
detail and registration views (`shared/modals/credential-details.html`, `registration-result.html`), the 28 modules
under `advanced/credential-display/`, `advanced/credentials/`, the storage under `shared/storage/`, and the server
routes they call (`server/app/routes/simple/`, `routes/advanced/artifacts.py`). The Simple tab's form and ceremonies
are in `docs/ui-parity/simple.md`. The charter (`docs/UI_MIGRATION.md`, "Content parity") requires every item to be
mapped to the new component and checked in a browser before the phase that ports it is done.

Phase 28 is split: **28A** ports the list (its rows, delete, Clear All, the jump to FIDO MDS) and keeps the records
shared; **28B** ports the credential detail and the registration result with its certificate and authenticator-data
views. The **Phase** column says which; 28B items are listed now so that nothing is forgotten.

Scripts are under `frontend/static/scripts/` unless another path is given; `display/` is short for
`advanced/credential-display/`. "Verbatim" text is quoted exactly; `${...}` marks a value filled in at run time. The
**New** column is filled in when the item is ported: the component (under `web/src/components/` unless another path
is given), the test that holds it, and how it was checked in a browser.

The words themselves are not copied: every sentence from logic comes from the modules `web/` imports (`@legacy/*`);
`tests/app/tooling/test_web_source_rules.py` fails if `web/src` redefines one of their exports or repeats one of their
sentences.

## The list

| ID | Current behaviour (verbatim) | Where | Phase | New |
|---|---|---|---|---|
| CRED-L1 | Both tabs show the same list: the Simple tab beside its form, the Advanced tab in its credentials column. Each has the heading "Saved Credentials" (`h3`) and a "Clear All" button (danger, small). There is no count. | `simple/tab.html:41-65`, `advanced/tab/credentials-column.html` | 28A | `credentials/SavedCredentials.tsx`, one component the Advanced tab's drawer will show too (Phase 29): the heading, how many there are (a badge, new) and Clear All on one line. unit CRED-L1/L2; parity (the count listed). |
| CRED-L2 | Every saved credential, simple and advanced, in the order stored (`getAllStoredCredentialsInOrder`); each list gets its own copy of the cards. Advanced records are given `storageId` / `localStorageId`, a normalised `aaguidHex`, and both kinds `credentialIdHex` and `userHandleHex`. | `display/list-render.js:85-132,321-330`, `shared/storage/local.js:35-60` | 28A | `useSavedCredentials.tsx` (a provider at the shell's level, shared by every section): `listSavedCredentials` (`advanced/credentials/saved-list.js`) over `getAllStoredCredentialsInOrder` (`shared/storage/records.js`), the same order and fields. unit; logic `saved-list.test.js`; e2e; parity (the same rows in the same order). |
| CRED-L3 | No credential: "No credentials registered yet." | `simple/tab.html:61`, `list-render.js:293-300` | 28A | `SAVED_LIST_TEXT.empty`. unit CRED-L3; e2e; parity. |
| CRED-L4 | "Clear All" is disabled while the list is empty or a deletion runs. | `list-render.js:281-286` | 28A | The same. unit CRED-L3; e2e. |
| CRED-L5 | The list is drawn when the page loads, after a registration, an authentication, a delete, Clear All and a warm-up that changed something (CRED-W1). It is read from the browser's storage only; nothing asks `GET /api/credentials`. | `main.js:470`, `advanced/credentials/index.js:192-203` | 28A | Read after hydration (the export has no storage to read) and again after each registration, authentication, deletion and Clear All; the warm-up after each read (CRED-W1). unit; e2e. 28B: another tab's change (either UI) is followed too: the storage event drops what was read and the list is read again, in both UIs (`followStoredCredentialChanges`, `storage-core.js`); a registration reads the list once in both (the current tab's second read a second later is gone). unit; logic `storage-core.test.js`, `other-tabs.test.js`; e2e (two tabs). |
| CRED-L6 | Each drawing also updates the Advanced tab's large-blob availability, its allow-credentials list ("All credentials", "Empty (resident key only)", then `${name, else "Credential ${n}"} (${algorithm})` and ` • ${attachment}`) and its extension availability. | `list-render.js:3-82,275-279` | 29 | Phase 29, with the Advanced tab's forms. |

## A credential's card

`buildCredentialCard` (`display/list-render.js:157-249`).

| ID | Current behaviour (verbatim) | Where | Phase | New |
|---|---|---|---|---|
| CRED-C1 | A card (`role="button"`, focusable, `data-credential-id` the credential ID in lower-case hex). Its name: `userName`, else `username`, else `email`, else "Unknown User". | `list-render.js:216-228` | 28A | `CredentialRow.tsx`: the name (`describeCredentialCard`'s fallback to "Unknown User") as a button that opens the details. unit; parity (the names checked equal; controls' labels are set aside). |
| CRED-C2 | A line of four words, "Signature", "Root", "RPID", "AAGUID", each green (`#11b66d`) when the check passed, red (`#dc3545`) when it failed, grey (`#6c757d`) when unknown. Signature, Root and RPID come from the attestation summary (`signatureValid`, `rootValid`, `rpIdHashValid`), else the properties (`attestation*Valid`), else the record; AAGUID compares the attestation certificate's AAGUID with the authenticator data's, else the recorded `aaguidMatch`. | `list-render.js:147-180`, `display/attestation-context.js:114-242` | 28A | `StatusChip`s: the same words in the same order, each with its mark (✓ green, ✕ red, – muted) and, new, a word for screen readers ("passed", "failed", "not known"); the values from `deriveCredentialStatusIndicators` (imported, now at 100 %). unit CRED-C2; logic `attestation-context.test.js`; parity (each row's verdicts equal). |
| CRED-C3 | Tags: the algorithm (`ES256`, `MLDSA65`, `RS256`, `EDDSA`, …; an unknown one from its description, "Unknown" or `COSE${id}`), "Discoverable" when `residentKey` or `discoverable` is true, "Large blob" when `largeBlob` or `largeBlobSupported` is true. | `list-render.js:182-185,302-313`, `display/algorithm.js` | 28A | `Badge`s: the algorithm in the accent colour (`describeCredentialAlgorithmTagWith`, `advanced/credentials/algorithm-tag.js`, with `advanced/cose-labels.js`), then Discoverable and Large blob. unit CRED-C3; logic `algorithm-tag.test.js`; parity. 28B: an algorithm the COSE labels do not name is tagged by its identifier (`COSE-46`, as the server's "COSE alg -46"), in both UIs, not "ALGORITHM". logic `algorithm-tag.test.js`. |
| CRED-C4 | No identifier is shown on the card. | `list-render.js` | 28A | Changed (the brief asks for identifiers): the credential ID (base64url) and the AAGUID (dashed, when there is one) in Geist Mono with copy, under the row across its width, one per line until the row has room for both, so a whole one is never cut where it fits ("Show all" where it does not). unit; e2e (whole from 800 px); parity (listed). 28B: a stored AAGUID no spelling reads ("abcde") is shown as stored and marked "Unreadable" (no FIDO MDS), and no longer stops the list's drawing in either UI; on a phone each identifier has the row's width, its copy button beside its label, a long one wrapping whole. unit; logic; e2e (both UIs; 375 px). |
| CRED-C5 | "FIDO MDS" (secondary, small; title "Open authenticator metadata"; `data-aaguid` the dashed AAGUID in lower case), only when the credential has an AAGUID and its root is valid or its metadata is available. It opens the AAGUID's entry (CRED-J1). | `list-render.js:187-196`, `attestation-context.js:199-241` | 28A | The same condition (`describeCredentialCard`'s `mdsAaguid`) and title; it opens the entry's page (CRED-J1). unit; e2e. |
| CRED-C6 | "Delete" (danger, small; disabled while a deletion runs): CRED-D1. Its click does not open the detail. | `list-render.js:198-214` | 28A | "Delete" (danger, small; unusable while a deletion runs), which asks first (CRED-D1). unit; e2e. |
| CRED-C7 | A click on the card, or Enter or Space on it, opens the credential's detail (CRED-M1). | `list-render.js:235-246` | 28A (the dialog), 28B (its content) | Changed: the name is the button (Enter or Space on it), and a click in the row outside its controls and identifiers opens the details too, in a dialog at `#simple/credential/<key>` (28A: its stub; CRED-M1). unit; e2e. |
| CRED-C8 | Values are written as text only, never markup, whatever a record holds. | `shared/ui/dom.js`, `tests/frontend/advanced/credentials/credential-list-xss.test.js`, `hostile-record.test.js` | 28A | React text only; no markup sink in `web/src` (`test_web_source_rules.py`). rules test. |
| CRED-C9 | After an authentication, the card of the credential used flashes green (`credential-item--recent-auth-success`); after a refusal that names the credential, red (`--recent-auth-failure`); only in the list of the visible tab, until its animation ends or 2.2 s. | `display/flash.js`, `simple/auth-simple.js:199,206` | 28A | The row's tint (`data-flash`, the success or danger tint) for 2.2 s (`FLASH_MS`), matched by `credentialFlashKey` (`saved-list.js`), without a transition under reduced motion. unit CRED-C9, SIM-A7/A8; e2e. |

## Delete and Clear All

`display/deletion.js`. Messages go to both tabs' toasts (`display/shared-status.js`), and so show in the Simple tab
(the last one written); progress shows in both tabs' progress bars.

| ID | Current behaviour (verbatim) | Where | Phase | New |
|---|---|---|---|---|
| CRED-D1 | Delete asks the browser's `confirm`: "Are you sure you want to delete the credential for ${name, else "this credential"}? This action cannot be undone." Cancel does nothing. | `deletion.js:22-29` | 28A | Changed: `ui/ConfirmDialog` (an `alertdialog`, focus on Cancel; Escape, the backdrop and × cancel) with `deleteConfirmation`'s question verbatim, instead of the browser's `confirm`, which some embedded browsers block. unit; e2e. |
| CRED-D2 | Then, the Clear All buttons and the Delete buttons disabled, the messages dismissed, the progress "Deleting credential...". A simple record is removed from the browser: "Deletion successful." (success) or "Unable to remove credential from this browser." (error). | `deletion.js:31-50` | 28A | `deleteSavedCredential` (`advanced/credentials/delete-flow.js`, DOM-free; the current runtime passes it the browser's `confirm`): the same steps and sentences. The progress in the list's header; the success a toast; the rest under the header. unit; logic `delete-flow.test.js`; e2e. 28B: once a deletion ends the focus goes to the next row's name, else the previous one's, else the list's heading (after Clear All too), and back to Delete on a row the server kept. unit. |
| CRED-D3 | An advanced record with a `storageId` is first deleted on the server (`DELETE /api/advanced/credential-artifacts/${storageId}`): a failure is the server's error or "Unable to delete credential from server storage." (error), and the record is kept; then removed from the browser: "Credential was deleted from server but could not be removed locally." (error), "Credential was already absent from server storage and has been removed locally." (warning, when the server had none) or "Deletion successful.". Without a `storageId` it is removed from the browser only, as a simple one. | `deletion.js:52-87`, `shared/storage/artifacts-client.js:118-192` | 28A | The same (the server first, then here): a refusal's reason under the header (`role="alert"`), the absent artifact's warning. unit; logic; e2e (the warning). |
| CRED-D4 | The artifact client's own failures: "Invalid storage identifier.", "Request failed with status ${status}", "Delete request failed.". | `artifacts-client.js:122,175,189` | 28A | The same sentences, from `artifacts-client.js` (imported). logic `artifacts-client-coverage.test.js`. |
| CRED-D5 | Delete pressed while a deletion runs: "A credential deletion is already in progress." (info). | `deletion.js:16-19,109-112` | 28A | Kept in the flow; in `/beta` it cannot show: Delete and Clear All are unusable while a deletion runs. logic. |
| CRED-D6 | Clear All with nothing saved: "No saved credentials to clear." (info). Otherwise `confirm`: "Are you sure you want to delete all saved credentials? This action cannot be undone."; then the progress "Clearing all credentials...": the simple records removed from the browser, each advanced record deleted on the server and then from the browser. | `deletion.js:114-178` | 28A | `clearSavedCredentials`, after `ui/ConfirmDialog` with `CLEAR_ALL_CONFIRMATION` verbatim. "No saved credentials to clear." cannot show in `/beta` (Clear All is unusable while the list is empty). unit; logic; e2e (in `/beta`, and at `/` for what `/beta` registered). |
| CRED-D7 | Clear All's outcome: any failure "Clearing completed with issues: ${n} credential(s) could not be deleted from server storage and was/were kept." (error); else any absent "Clearing complete. ${n} credential was / credentials were already absent from server storage." (warning); else "Deletion successful."; a throw "Failed to clear all credentials. Please try again." (error). | `deletion.js:180-221` | 28A | The same sentences and tones (a success as a toast; the rest under the header). unit; logic; e2e. |

## The warm-up

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| CRED-W1 | After each drawing, once at a time: advanced records holding heavy data are uploaded to the server (`PUT /api/advanced/credential-artifacts/${storageId}`, merged) and trimmed in the browser, and missing registration snapshots are fetched (`POST /api/advanced/credential-artifacts/bulk`); when anything changed the list is drawn again. A failure is logged ("Failed to warm saved credential state", and the sync's own warnings) and changes nothing. | `advanced/credentials/index.js:79-104`, `shared/storage/local/advanced-sync.js` | 28A | `warmSavedCredentials` (`saved-list.js`): the same steps after each read of the list; its own re-read does not warm up again. unit CRED-W1; logic `advanced-sync.test.js`, `saved-list.test.js`. 28B: the warm-up reports a change only when a record's stored copy changes, so the list is not read once more after each read. logic `advanced-sync.test.js`. |

## From a card to FIDO MDS

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| CRED-J1 | "FIDO MDS" switches to the MDS tab, clears its filters, highlights the AAGUID's row and focuses it, with MDS-J2's sentences ("Locating metadata entry...", "Opening authenticator metadata...", "Authenticator metadata not found.", "Unable to locate metadata entry.", "Unable to open authenticator metadata.", "Authenticator metadata entry unavailable."). Changed in 27B for `/beta`: the entry's page opens at `#mds/aaguid:<aaguid>` (`docs/ui-parity/mds.md`, MDS-J1..J3). | `display/navigation.js`, `advanced/mds/explorer/entry-link.js` | 28A | The row's "FIDO MDS" calls 27B's `useOpenMdsEntry`: the entry's page at `#mds/aaguid:<aaguid>` as one pushed history entry; Back returns to `#simple` (or to the page's URL without a hash, which `useSection` now reads as the default section). unit `AppShell.test.tsx` CRED-J1; e2e. |

## What is stored, and where

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| CRED-S1 | One `localStorage` key, `postquantum-webauthn.credentials`: a JSON array of every record, simple and advanced. Records under the old keys `postquantum-webauthn.simpleCredentials` and `…advancedCredentials` are merged in when read and those keys removed when the array is saved. Records are de-duplicated by `storage:<storageId>` or `id:<credentialId>`; new ones are appended. | `shared/storage/local/constants.js:1-3`, `storage-core.js`, `id-utils.js:109-125`, `partition-core.js` | 28A | Unchanged, and shared: `/beta` reads and writes through `shared/storage/records.js`, the same modules the current UI's barrel (`local.js`) re-exports after seeding its tests' page data; all held at 100 %. logic `shared/storage/*.test.js`; e2e (registered, used, deleted and cleared in each UI, seen in the other). |
| CRED-S2 | A simple record is the server's `storedCredential` (the registration's answer: `userName`, `displayName`, the credential ID in base64url and hex, the AAGUID, the public key and its COSE map, `signCount`, `createdAt`, the extension outputs, the attestation format and statement, `properties`, the attachment, `clientDataJSON`, `attestationObject`, the authenticator data, `relyingParty`, `registrationResponse`, `userHandle`) with `type: "simple"`, `email`, `credentialIdBase64Url` and a `signCount`. | `routes/simple/registration_record.py:374-409`, `simple-credentials.js:36-89` | 28A | Unchanged (`keepRegistered`, SIM-R8). unit SIM-R8; e2e. |
| CRED-S3 | An advanced record is the server's summary (without the heavy fields, which stay in the server's artifact) with `type: "advanced"`, `storageId` (`${credentialId}::${createdAt}::${uuid}`), `email`, `username`, `signCount`, and later its `registrationDetailSnapshot`; it is trimmed further when storage is full. | `advanced-credentials.js`, `advanced-storage-shaping.js`, `id-utils.js:67-97` | 28A | Unchanged. logic `advanced-credentials.test.js`, `advanced-storage-shaping.test.js`. |
| CRED-S4 | Records saved by earlier versions are brought to today's format as they are read and saved back: stored registration markup dropped, standard base64 re-spelled as base64url in the byte fields. | `record-migration.js` | 28A | Unchanged (`record-migration.js`, imported). logic. |
| CRED-S5 | An authentication updates the stored counter of every record with that credential ID to the server's (simple ceremony) or the advanced records' (advanced ceremony). | `simple-credentials.js:128-173`, `advanced-credentials.js` | 28A | Unchanged (`keepSignCount`, SIM-A7). unit SIM-A7; e2e. |
| CRED-S6 | A registration snapshot (`schemaVersion` 2: the decoded state and the response) is kept only as far as the sanitiser allows: certificates' bytes replaced by nulls, hex and details capped, each part of the response kept whole under 120,000 characters or dropped. | `snapshot-sanitize.js` | 28B | Unchanged and whole: `sanitiseRegistrationDetailSnapshot` (imported), applied to an artifact's snapshot when a detail opens (`advanced/credentials/hydrate.js`, CRED-M1) as the current UI applies it. logic `snapshot-sanitize*.test.js`, `hydrate.test.js`; unit CRED-M1. |

## The credential detail (28B)

A modal (`#credentialModal`, "Credential Details", a close button "Close credential details"), built by
`display/credential-detail-runtime/entry.js`. Headings are `h4`.

| ID | Current behaviour (verbatim) | Where | Phase | New |
|---|---|---|---|---|
| CRED-M1 | Opening: an advanced record whose snapshot does not hold the registration is first completed from its server artifact (`GET /api/advanced/credential-artifacts/${storageId}`; its fields merged, its snapshot sanitised and saved), with a progress cursor meanwhile; a failure is only logged ("Unable to fetch credential artifact") and the modal opens with what the record has. A simple record is never fetched. The body scrolls back to the top. | `entry.js:48-162`, `advanced/credentials/index.js:111-166` | 28B | 28A: the dialog at `#simple/credential/<key>`. 28B: `credentials/detail/useCredentialDetail.ts` completes an advanced record without a v2 snapshot from its artifact first (`hydrateCredentialFromServer`, moved to the DOM-free `advanced/credentials/hydrate.js`, on a copy; a completed one remembered by storage id for the page; the saved snapshot makes the list read again), then composes every section once (`composeCredentialDetail`, `credential-detail-runtime/compose.js`, over a registration state of its own, the decoder asked as today). Meanwhile a spinner line. unit `CredentialDetailDialog.test.tsx` CRED-M1; logic `hydrate.test.js`, `credential-detail-compose.test.js`; e2e (an advanced credential registered at `/` opened in `/beta`). |
| CRED-M2 | "Properties": "Discoverable (resident key):" and "Supports largeBlob:" (true green, false red, "N/A" grey when absent, else the value), "Authenticator minPinLength:" when known; then, under a hairline, the note "In formal WebAuthn, any **false** result below causes registration to fail. This platform keeps registration valid for data inspection purposes." and the rows "Signature Valid:", "Root Valid:" (followed by "(FIDO MDS, Chain)", each coloured by its check, when the checks name them), "RPID Hash Valid:", "AAGUID Match:"; then the metadata's `verification_warning` in amber, when there is one. | `sections-properties.js`, `detail-nodes.js` | 28B | `detail/DetailSections.tsx` over `describeProperties` (`credential-detail-runtime/detail-sections.js`): a section (heading and hairline); the two properties and minPinLength on a `KeyValueGrid`, each value a `StatusChip` with the same word (true ✓ green, false ✕ red, N/A – neutral); the note with its bold false; the four checks as rows with hairlines, Root Valid followed by FIDO MDS and Chain as chips in their verdict's tone (not a list in parentheses); the warning in an amber box. unit CRED-M2; logic `detail-sections.test.js`; parity (the parentheses listed). |
| CRED-M3 | "User info at creation": "Name:" (`userName`, else `email`, else "N/A"), "Display name:" (`displayName`, else `userName`, else `email`, else "N/A"); "User handle (User ID):" and "Credential ID:", each as **b64**, **b64u** and **hex** of the stored base64url, or the value as stored with "Not valid base64url: shown as stored."; then "AAGUID" with an empty status line and its **b64**, **b64u**, **hex** and **guid**, each "N/A" when unknown. | `sections-main.js:34-84`, `sections-aaguid.js` | 28B | `DetailSections.tsx` over `describeUserInfo` and `describeAaguid`: Name and Display name on a grid; each identifier's b64 / b64u / hex (the AAGUID's guid too) a `MonoValue` on a row of its own, whole where it fits (on a phone the copy button beside the spelling's name); a value kept as stored with the same sentence; FIDO MDS beside the AAGUID under the row's condition (CRED-M10); a stored AAGUID no spelling reads shown as stored and marked. unit CRED-M3; e2e (whole at 375 px); parity. |
| CRED-M4 | "Attestation Format": the format, else "none". | `sections-main.js:86-90`, `entry.js:115-124` | 28B | A section with the format (`describeAttestationFormat`; `compose.js` gives "none"). unit; parity. |
| CRED-M5 | "Authenticator Data (registration)", when the record has flags: "AT: …, BE: …, BS: …, ED: …, UP: …, UV: …" and "Signature Counter:" (else 0). | `sections-main.js:92-111` | 28B | A section with each flag and the counter on a grid, in Geist Mono (`describeAuthenticatorDataFlags`); absent without flags, as today (a Simple record keeps none). logic; parity. |
| CRED-M6 | "Client extension outputs (registration)", when not empty: the outputs as JSON indented by two. | `sections-main.js:113-125` | 28B | A section with the outputs as a `CodeBlock` (copy, Show all) (`describeExtensions`). unit CRED-M4..M7; parity. |
| CRED-M7 | "Public Key", when the record has an algorithm or a COSE key: "Algorithm:" (e.g. "ES256 (-7)", "ML-DSA-65 (PQC) (-49)", `Algorithm (${alg})`, "Unknown"), "COSE key type:" (e.g. "EC2 (2)"), "ML-DSA parameter set:" (ML-DSA only). | `sections-main.js:127-154`, `advanced/ui/display-utils.js`, `advanced/constants.js` | 28B | A section on a grid (`describePublicKey`, given `cose-labels.js`'s describers): "ES256 (-7)", "EdDSA (-8)", "ML-DSA-65 (PQC) (-49)" with its parameter set, the key type. unit CRED-M7 (ES256, EdDSA, ML-DSA-65); e2e (EdDSA live, ES256 recorded); parity. |
| CRED-M8 | Then the registration view (CRED-G1..G3). ("Registration detail data is not available for this credential." cannot show: the view is always built.) | `sections-main.js:156-165` | 28B | Changed (the owner's choice, 2026-09-27): the registration is its own level of the dialog, `…/registration` (CRED-G1..G5), reached by "Show registration details" in a last section headed "Registration Details". unit; e2e; parity (that heading listed). |
| CRED-M9 | No date is shown (`createdAt` and a snapshot's `capturedAt` are stored only); there is no copy or download. | `display/` | 28B | Kept: no date, no download; `/beta` adds copy on every identifier and block (new). |
| CRED-M10 | Under "AAGUID", an empty status line (`role="status"`, a hidden spinner) that the FIDO MDS jump fills with MDS-J2's sentences while the modal is open. No control in the modal starts the jump; only a card's "FIDO MDS" does, and the modal is closed then. | `sections-aaguid.js:103-106`, `navigation.js:67-110` | 28B | Changed: "FIDO MDS" beside the AAGUID (the row's condition and title), opening the entry's page as the row's does; Back returns to the details. unit; e2e (the list's jump, 28A). |
| CRED-M11 | The modal is filled before it opens; while an advanced record's artifact is fetched the page shows the progress cursor, and nothing says it failed: "Unable to fetch credential artifact" goes to the console only, and the modal shows what the browser keeps. | `entry.js:58-69`, `advanced/credentials/index.js:151-156`, `cursor.js` | 28B | Changed: a spinner line while the details are composed; a failed artifact fetch says the logged sentence (`HYDRATE_TEXT.failed`) in an amber note above the sections, which show what the browser keeps. unit CRED-M1 (the failure); logic `hydrate.test.js`. |

## The registration view (28B)

Shown after an advanced registration (the "Registration Details" modal, `#registrationResultModal`, a close button
"Close registration details"; Phase 29) and at the end of every credential's detail (CRED-M8). Built by
`display/registration-compose-runtime.js` over the state `registration-state-runtime.js` prepares (a snapshot's state
as it is, or the record's attestation object and authenticator data decoded through `POST /api/decode`). Headings are
`h3`.

| ID | Current behaviour (verbatim) | Where | Phase | New |
|---|---|---|---|---|
| CRED-G1 | "Authenticator Response": a numbered list, "Response for navigator.credentials.create()" (the credential's JSON, else "No credential response captured.") and "Parsed clientDataJSON" (the parsed JSON, else its text, else "No clientDataJSON available."). "Server-retrieved Data": the relying party's view with the certificates and signatures stripped, as JSON, else "No relying party data returned." | `registration-compose-runtime.js:188-260`, `sanitize-common.js` | 28B | `detail/RegistrationLevels.tsx` (`RegistrationLevel`) over `composeRegistration` (`credential-display/registration-view.js`): Authenticator Response as a numbered list, each part a `CodeBlock` or the same placeholder; Server-retrieved Data a `CodeBlock`. At `…/registration`, header "Registration Details" with Back. unit CRED-G1; logic `registration-view.test.js`; e2e; parity (the current modal after an advanced registration equal word for word). |
| CRED-G2 | "Attestation Information" (only with an attestation): "Attestation Object" (`h4`), the decoded object with `fmt` first and each `x5c` certificate replaced by its index, details, summary or error, in a read-only text area; else "Unable to prepare decoded attestationObject.", the decode error or "Unable to decode attestationObject.", or "No attestationObject was provided."; then a button per certificate that parsed ("Attestation Certificate", or "Attestation Certificate ${n}" when there are several) and "Authenticator Data" when it decoded; "No attestation certificates available." when none; the authenticator data's decode error. | `registration-compose-runtime.js:93-186`, `sanitize-attestation-object.js`, `certificate-core.js:316-361` | 28B | The Attestation Object as a `CodeBlock` (or the same sentences), the certificate and Authenticator Data buttons opening levels, the messages (`describeAttestationSection`). unit CRED-G2; logic; e2e; parity. |
| CRED-G3 | The decode's failures: "Decoder payload must be a non-empty string.", "Decoder response did not include data.", "Failed to decode attestationObject.", "Failed to decode authenticatorData.", or the server's message. | `registration-result.js:5-32`, `registration-state-runtime.js` | 28B | The same sentences (`decode-payload.js`, `registration-state.js`); the server's message in red (`role="alert"`). unit CRED-G3; logic `decode-payload.test.js`, `registration-state.test.js`. |
| CRED-G4 | A certificate's view (`#registrationDetailModal`, a close button "Close registration detail"): titled "Attestation Certificate" or "Attestation Certificate ${n}", the certificate as text in a read-only text area (the decoder's `summary` when there is one, else "Version:", "Certificate Serial Number:" (decimal and hex), "Signature Algorithm:", "Issuer:", "Validity:", "Not Before:", "Not After:", "Subject:", "Subject Public Key Info:", "X509v3 extensions:" with "[critical]", "Fingerprint:" lines of 16 colon-separated bytes; keys naming base64 left out), else the parse error in red, else "No decoded certificate details available.". | `registration-compose-runtime.js:386-420`, `display/formatting.js:122-351` | 28B | A level, `…/registration/certificate/<n>` (n counting the listed certificates from 1), titled as today: the MDS certificate page's language above (the subject, the issuer, 27B's `CertificateSummary` over `certificateSummary`, the same serializer's output; new, the owner's choice), then the current text under "Decoded Output" (`formatCertificateDetails`, moved to `certificate-text.js`), its parse error in red, or the placeholder. unit CRED-G4; logic `certificate-text.test.js`; e2e (by link and reload); parity (the text equal). |
| CRED-G5 | "Authenticator Data" view: titled "Authenticator Data", the decoded authenticator data as JSON indented by two. | `registration-compose-runtime.js:422-429` | 28B | A level, `…/registration/authenticator-data`, titled as today, the JSON as a `CodeBlock` (`describeAuthenticatorData`). unit CRED-G5; e2e; parity (the text equal). |
| CRED-G6 | After an advanced registration the view's state is saved as the record's snapshot (`schemaVersion` 2, `capturedAt`, `state`, `response` with `credential` and `relyingParty`), in the browser and on the server (`PUT …/credential-artifacts/${storageId}/snapshot`). | `registration-result.js:75-86`, `advanced-snapshot-update.js` | 28B/29 | 28B: the payload as data (`registrationSnapshotPayload`, `registration-view.js`), which the current result modal now builds through; Phase 29 saves it after an advanced registration in `/beta`. logic. |
| CRED-G7 | The certificate and authenticator-data views are a second modal over the first (`#registrationDetailModal`, its title set to the view's, "Detail" until then), and they show the registration composed last: its state is one module-level object (`registrationDetailState`) that each composition resets and the buttons read when clicked. | `registration-compose-runtime.js:366-429`, `state.js:1-8` | 28B | Changed: levels of the one dialog, each at its URL; Back (the header's, or the browser's) goes up one level with the focus on what opened it, ×, Escape and the backdrop close every level (`useSection`'s `closeAll`); each level composed into the credential's own state, never another's. unit (levels, focus, × from the deepest, a link to a level the credential lacks corrected); e2e. |
| CRED-G8 | After an advanced registration, when the attestation holds no certificate, the view takes them from the relying party's answer, under any of eight spellings (`attestationCertificate(s)`, `attestation_certificate(s)`, and the same under `registrationData`). | `registration-result.js:52-61` | 28B/29 | The same eight spellings (`registrationResultInput`, `registration-view.js`, which the current result modal builds through); Phase 29 gives them to `/beta`'s result. logic. |

## Never shown

| ID | Code | Why it never shows | Where |
|---|---|---|---|
| CRED-Z1 | `GET /api/credentials` (with `unreadableCount` and `X-Unreadable-Credentials`) and `DELETE /api/credentials`, with their sentences ("The stored credentials could not be read, so none are listed.", "…so none were deleted."). | No script asks either; the list is the browser's own. | `server/app/routes/simple/credential_list.py` |
| CRED-Z2 | "Registration detail data is not available for this credential." | The registration view is always built (CRED-M8). | `sections-main.js:156-165` |
| CRED-Z3 | `clearAdvancedCredentials`. | Clear All removes advanced records one by one (CRED-D6). | `advanced-credentials.js:147` |
| CRED-Z4 | The `initial-credential-records` page data (records inlined in the page). | The server never renders it; only the tests give it. | `shared/storage/local/storage-core.js:17-20` |

## What changed (28A)

Nothing the list shows or does was dropped. What looks or behaves differently:

- **Layout.** The list is one card beside the Simple tab's form (below it on a phone): the heading, how many
  credentials there are (new) and Clear All on one line, then a row per credential separated by hairlines, never a
  card in the card.
- **Checks** are chips with the same words in the same order, each with a mark (✓, ✕, –) besides its colour and a
  word for screen readers; the current card says them by colour alone.
- **Identifiers** (new, as the brief asks): each row shows its credential ID and AAGUID in Geist Mono with copy,
  whole wherever the row has room.
- **Opening the details**: the name is a button, and a click elsewhere in the row but its controls and identifiers
  opens them too, in a dialog at its own URL (`#simple/credential/<key>`) that Back closes. Until 28B it names the
  credential, gives its id and leads to the current interface.
- **Deleting and clearing** ask in a dialog (focus on Cancel) rather than the browser's `confirm`; the progress shows
  in the list's header; a success is a toast; a warning or failure stays under the header until the next one.
- **FIDO MDS** opens the entry's page (27B's decision), and Back returns to the list.
- **Never shown, not ported:** CRED-Z1..Z4.

## The parity check (28A)

`web/e2e/simple-parity.spec.ts` stores the same four records (a simple packed/x5c credential, a simple ML-DSA-65
one, an advanced packed/x5c one, and one with a fixture AAGUID and a valid root) in the storage both UIs read, then
reads each row in the current UI at `/` and in `/beta` (`readShownText`, `web/e2e/parity.ts`) and compares them word
for word, the actions' labels and each check's verdict (the current card's colour, `/beta`'s chip). Result on
2026-09-27: **every row shows the same words in the same order, the same actions and the same verdicts; the only
differences are the ones listed with their reasons: the account's name, which `/beta` shows as the button that
opens the details (checked equal on its own), and the credential ID and AAGUID each row now shows.** The rows'
order is the same in both UIs.

## What changed (28B)

Nothing the details or the registration view show was dropped. What looks or behaves differently:

- **Levels, not modals over modals.** A credential's details are one dialog with four levels, each at its URL: the
  detail (`#simple/credential/<key>`), the registration (`…/registration`, the owner's choice: its own level rather
  than the detail's last sections), a certificate (`…/registration/certificate/<n>`) and the authenticator data
  (`…/registration/authenticator-data`). Back in the header, or the browser's, goes up one level with the focus on
  what opened it; ×, Escape and the backdrop close them all; a link or a reload opens any level, and a level the
  credential does not have is corrected to the one above.
- **Sections in the MDS entry page's language**: a heading and a hairline each, never a card in the dialog; true,
  false and N/A as chips with a mark; Root Valid's roots (FIDO MDS, Chain) as chips rather than a parenthesised list;
  every identifier's spellings in Geist Mono with copy, whole where they fit; every JSON as a block with copy and
  Show all.
- **The certificate level** shows the MDS certificate page's summary (subject, issuer, validity, serial numbers, key,
  signature) above the current text (the owner's choice).
- **New:** the credential's name as the detail's title; FIDO MDS beside the AAGUID (the current modal keeps a status
  line for this jump that nothing fills); the artifact fetch's failure said in the dialog (the current modal only
  logs it); copy everywhere.
- **Fixed in both UIs:** a stored AAGUID with no base64 length no longer stops the list or the details, and a dashed
  GUID reads as one; client data that is not base64url is shown as stored instead of the details failing to open;
  another tab's change is followed; the warm-up reads the list again only after a real change; the registration
  reads the list once; an algorithm the labels do not name is tagged `COSE${id}`; the Simple registration names
  EdDSA "EdDSA".
- **Not changed:** after a Simple registration only the toast shows, as today (the owner's choice); the registration
  is reached from the new credential's details.

## The parity check (28B)

`web/e2e/credential-detail-parity.spec.ts` stores four recorded registrations (ES256, EdDSA, ML-DSA-65 and a packed
one with a certificate: `registration-detail-decodes`) in the storage both UIs read, opens each in the current modal
at `/` and in `/beta`'s dialog, and compares what they show, word for word per section (the current modal's h4 and h3
headings against the detail's and the registration level's), then each certificate's and the authenticator data's
text in the current second modal against `/beta`'s levels. A second test registers an advanced credential at `/` with
Chromium's virtual authenticator and compares the current "Registration Details" modal with `/beta`'s registration
level for that credential. Result on 2026-09-27: **every section shows the same words; the only differences are the
three listed with their reasons (the name as the detail's title, the "Registration Details" heading of the way to the
registration's level, the parentheses around Root Valid's roots); every certificate's and authenticator data's text is
equal; the advanced registration's result equals `/beta`'s registration level with no difference at all.**
