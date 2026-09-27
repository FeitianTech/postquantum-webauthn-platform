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
| CRED-L5 | The list is drawn when the page loads, after a registration, an authentication, a delete, Clear All and a warm-up that changed something (CRED-W1). It is read from the browser's storage only; nothing asks `GET /api/credentials`. | `main.js:470`, `advanced/credentials/index.js:192-203` | 28A | Read after hydration (the export has no storage to read) and again after each registration, authentication, deletion and Clear All; the warm-up after each read (CRED-W1). unit; e2e. |
| CRED-L6 | Each drawing also updates the Advanced tab's large-blob availability, its allow-credentials list ("All credentials", "Empty (resident key only)", then `${name, else "Credential ${n}"} (${algorithm})` and ` • ${attachment}`) and its extension availability. | `list-render.js:3-82,275-279` | 29 | Phase 29, with the Advanced tab's forms. |

## A credential's card

`buildCredentialCard` (`display/list-render.js:157-249`).

| ID | Current behaviour (verbatim) | Where | Phase | New |
|---|---|---|---|---|
| CRED-C1 | A card (`role="button"`, focusable, `data-credential-id` the credential ID in lower-case hex). Its name: `userName`, else `username`, else `email`, else "Unknown User". | `list-render.js:216-228` | 28A | `CredentialRow.tsx`: the name (`describeCredentialCard`'s fallback to "Unknown User") as a button that opens the details. unit; parity (the names checked equal; controls' labels are set aside). |
| CRED-C2 | A line of four words, "Signature", "Root", "RPID", "AAGUID", each green (`#11b66d`) when the check passed, red (`#dc3545`) when it failed, grey (`#6c757d`) when unknown. Signature, Root and RPID come from the attestation summary (`signatureValid`, `rootValid`, `rpIdHashValid`), else the properties (`attestation*Valid`), else the record; AAGUID compares the attestation certificate's AAGUID with the authenticator data's, else the recorded `aaguidMatch`. | `list-render.js:147-180`, `display/attestation-context.js:114-242` | 28A | `StatusChip`s: the same words in the same order, each with its mark (✓ green, ✕ red, – muted) and, new, a word for screen readers ("passed", "failed", "not known"); the values from `deriveCredentialStatusIndicators` (imported, now at 100 %). unit CRED-C2; logic `attestation-context.test.js`; parity (each row's verdicts equal). |
| CRED-C3 | Tags: the algorithm (`ES256`, `MLDSA65`, `RS256`, `EDDSA`, …; an unknown one from its description, "Unknown" or `COSE${id}`), "Discoverable" when `residentKey` or `discoverable` is true, "Large blob" when `largeBlob` or `largeBlobSupported` is true. | `list-render.js:182-185,302-313`, `display/algorithm.js` | 28A | `Badge`s: the algorithm in the accent colour (`describeCredentialAlgorithmTagWith`, `advanced/credentials/algorithm-tag.js`, with `advanced/cose-labels.js`), then Discoverable and Large blob. unit CRED-C3; logic `algorithm-tag.test.js`; parity. |
| CRED-C4 | No identifier is shown on the card. | `list-render.js` | 28A | Changed (the brief asks for identifiers): the credential ID (base64url) and the AAGUID (dashed, when there is one) in Geist Mono with copy, under the row across its width, one per line until the row has room for both, so a whole one is never cut where it fits ("Show all" where it does not). unit; e2e (whole from 800 px); parity (listed). |
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
| CRED-D2 | Then, the Clear All buttons and the Delete buttons disabled, the messages dismissed, the progress "Deleting credential...". A simple record is removed from the browser: "Deletion successful." (success) or "Unable to remove credential from this browser." (error). | `deletion.js:31-50` | 28A | `deleteSavedCredential` (`advanced/credentials/delete-flow.js`, DOM-free; the current runtime passes it the browser's `confirm`): the same steps and sentences. The progress in the list's header; the success a toast; the rest under the header. unit; logic `delete-flow.test.js`; e2e. |
| CRED-D3 | An advanced record with a `storageId` is first deleted on the server (`DELETE /api/advanced/credential-artifacts/${storageId}`): a failure is the server's error or "Unable to delete credential from server storage." (error), and the record is kept; then removed from the browser: "Credential was deleted from server but could not be removed locally." (error), "Credential was already absent from server storage and has been removed locally." (warning, when the server had none) or "Deletion successful.". Without a `storageId` it is removed from the browser only, as a simple one. | `deletion.js:52-87`, `shared/storage/artifacts-client.js:118-192` | 28A | The same (the server first, then here): a refusal's reason under the header (`role="alert"`), the absent artifact's warning. unit; logic; e2e (the warning). |
| CRED-D4 | The artifact client's own failures: "Invalid storage identifier.", "Request failed with status ${status}", "Delete request failed.". | `artifacts-client.js:122,175,189` | 28A | The same sentences, from `artifacts-client.js` (imported). logic `artifacts-client-coverage.test.js`. |
| CRED-D5 | Delete pressed while a deletion runs: "A credential deletion is already in progress." (info). | `deletion.js:16-19,109-112` | 28A | Kept in the flow; in `/beta` it cannot show: Delete and Clear All are unusable while a deletion runs. logic. |
| CRED-D6 | Clear All with nothing saved: "No saved credentials to clear." (info). Otherwise `confirm`: "Are you sure you want to delete all saved credentials? This action cannot be undone."; then the progress "Clearing all credentials...": the simple records removed from the browser, each advanced record deleted on the server and then from the browser. | `deletion.js:114-178` | 28A | `clearSavedCredentials`, after `ui/ConfirmDialog` with `CLEAR_ALL_CONFIRMATION` verbatim. "No saved credentials to clear." cannot show in `/beta` (Clear All is unusable while the list is empty). unit; logic; e2e (in `/beta`, and at `/` for what `/beta` registered). |
| CRED-D7 | Clear All's outcome: any failure "Clearing completed with issues: ${n} credential(s) could not be deleted from server storage and was/were kept." (error); else any absent "Clearing complete. ${n} credential was / credentials were already absent from server storage." (warning); else "Deletion successful."; a throw "Failed to clear all credentials. Please try again." (error). | `deletion.js:180-221` | 28A | The same sentences and tones (a success as a toast; the rest under the header). unit; logic; e2e. |

## The warm-up

| ID | Current behaviour | Where | Phase | New |
|---|---|---|---|---|
| CRED-W1 | After each drawing, once at a time: advanced records holding heavy data are uploaded to the server (`PUT /api/advanced/credential-artifacts/${storageId}`, merged) and trimmed in the browser, and missing registration snapshots are fetched (`POST /api/advanced/credential-artifacts/bulk`); when anything changed the list is drawn again. A failure is logged ("Failed to warm saved credential state", and the sync's own warnings) and changes nothing. | `advanced/credentials/index.js:79-104`, `shared/storage/local/advanced-sync.js` | 28A | `warmSavedCredentials` (`saved-list.js`): the same steps after each read of the list; its own re-read does not warm up again. unit CRED-W1; logic `advanced-sync.test.js`, `saved-list.test.js`. |

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
| CRED-S6 | A registration snapshot (`schemaVersion` 2: the decoded state and the response) is kept only as far as the sanitiser allows: certificates' bytes replaced by nulls, hex and details capped, each part of the response kept whole under 120,000 characters or dropped. | `snapshot-sanitize.js` | 28B | — |

## The credential detail (28B)

A modal (`#credentialModal`, "Credential Details", a close button "Close credential details"), built by
`display/credential-detail-runtime/entry.js`. Headings are `h4`.

| ID | Current behaviour (verbatim) | Where | Phase | New |
|---|---|---|---|---|
| CRED-M1 | Opening: an advanced record whose snapshot does not hold the registration is first completed from its server artifact (`GET /api/advanced/credential-artifacts/${storageId}`; its fields merged, its snapshot sanitised and saved), with a progress cursor meanwhile; a failure is only logged ("Unable to fetch credential artifact") and the modal opens with what the record has. A simple record is never fetched. The body scrolls back to the top. | `entry.js:48-162`, `advanced/credentials/index.js:111-166` | 28B | 28A: `CredentialDetailDialog.tsx`, a `Dialog` at `#simple/credential/<key>` (a pushed history entry: Back, Escape and × close it; a link or a reload opens it; an unknown key corrects the URL), holding the name, the credential ID with copy and a plain link to the current interface. 28B: the artifact's hydration and every section below. unit `CredentialDetailDialog.test.tsx`; e2e. |
| CRED-M2 | "Properties": "Discoverable (resident key):" and "Supports largeBlob:" (true green, false red, "N/A" grey when absent, else the value), "Authenticator minPinLength:" when known; then, under a hairline, the note "In formal WebAuthn, any **false** result below causes registration to fail. This platform keeps registration valid for data inspection purposes." and the rows "Signature Valid:", "Root Valid:" (followed by "(FIDO MDS, Chain)", each coloured by its check, when the checks name them), "RPID Hash Valid:", "AAGUID Match:"; then the metadata's `verification_warning` in amber, when there is one. | `sections-properties.js`, `detail-nodes.js` | 28B | — |
| CRED-M3 | "User info at creation": "Name:" (`userName`, else `email`, else "N/A"), "Display name:" (`displayName`, else `userName`, else `email`, else "N/A"); "User handle (User ID):" and "Credential ID:", each as **b64**, **b64u** and **hex** of the stored base64url, or the value as stored with "Not valid base64url: shown as stored."; then "AAGUID" with an empty status line and its **b64**, **b64u**, **hex** and **guid**, each "N/A" when unknown. | `sections-main.js:34-84`, `sections-aaguid.js` | 28B | — |
| CRED-M4 | "Attestation Format": the format, else "none". | `sections-main.js:86-90`, `entry.js:115-124` | 28B | — |
| CRED-M5 | "Authenticator Data (registration)", when the record has flags: "AT: …, BE: …, BS: …, ED: …, UP: …, UV: …" and "Signature Counter:" (else 0). | `sections-main.js:92-111` | 28B | — |
| CRED-M6 | "Client extension outputs (registration)", when not empty: the outputs as JSON indented by two. | `sections-main.js:113-125` | 28B | — |
| CRED-M7 | "Public Key", when the record has an algorithm or a COSE key: "Algorithm:" (e.g. "ES256 (-7)", "ML-DSA-65 (PQC) (-49)", `Algorithm (${alg})`, "Unknown"), "COSE key type:" (e.g. "EC2 (2)"), "ML-DSA parameter set:" (ML-DSA only). | `sections-main.js:127-154`, `advanced/ui/display-utils.js`, `advanced/constants.js` | 28B | — |
| CRED-M8 | Then the registration view (CRED-G1..G3). ("Registration detail data is not available for this credential." cannot show: the view is always built.) | `sections-main.js:156-165` | 28B | — |
| CRED-M9 | No date is shown (`createdAt` and a snapshot's `capturedAt` are stored only); there is no copy or download. | `display/` | 28B | — |

## The registration view (28B)

Shown after an advanced registration (the "Registration Details" modal, `#registrationResultModal`, a close button
"Close registration details"; Phase 29) and at the end of every credential's detail (CRED-M8). Built by
`display/registration-compose-runtime.js` over the state `registration-state-runtime.js` prepares (a snapshot's state
as it is, or the record's attestation object and authenticator data decoded through `POST /api/decode`). Headings are
`h3`.

| ID | Current behaviour (verbatim) | Where | Phase | New |
|---|---|---|---|---|
| CRED-G1 | "Authenticator Response": a numbered list, "Response for navigator.credentials.create()" (the credential's JSON, else "No credential response captured.") and "Parsed clientDataJSON" (the parsed JSON, else its text, else "No clientDataJSON available."). "Server-retrieved Data": the relying party's view with the certificates and signatures stripped, as JSON, else "No relying party data returned." | `registration-compose-runtime.js:188-260`, `sanitize-common.js` | 28B | — |
| CRED-G2 | "Attestation Information" (only with an attestation): "Attestation Object" (`h4`), the decoded object with `fmt` first and each `x5c` certificate replaced by its index, details, summary or error, in a read-only text area; else "Unable to prepare decoded attestationObject.", the decode error or "Unable to decode attestationObject.", or "No attestationObject was provided."; then a button per certificate that parsed ("Attestation Certificate", or "Attestation Certificate ${n}" when there are several) and "Authenticator Data" when it decoded; "No attestation certificates available." when none; the authenticator data's decode error. | `registration-compose-runtime.js:93-186`, `sanitize-attestation-object.js`, `certificate-core.js:316-361` | 28B | — |
| CRED-G3 | The decode's failures: "Decoder payload must be a non-empty string.", "Decoder response did not include data.", "Failed to decode attestationObject.", "Failed to decode authenticatorData.", or the server's message. | `registration-result.js:5-32`, `registration-state-runtime.js` | 28B | — |
| CRED-G4 | A certificate's view (`#registrationDetailModal`, a close button "Close registration detail"): titled "Attestation Certificate" or "Attestation Certificate ${n}", the certificate as text in a read-only text area (the decoder's `summary` when there is one, else "Version:", "Certificate Serial Number:" (decimal and hex), "Signature Algorithm:", "Issuer:", "Validity:", "Not Before:", "Not After:", "Subject:", "Subject Public Key Info:", "X509v3 extensions:" with "[critical]", "Fingerprint:" lines of 16 colon-separated bytes; keys naming base64 left out), else the parse error in red, else "No decoded certificate details available.". | `registration-compose-runtime.js:386-420`, `display/formatting.js:122-351` | 28B | — |
| CRED-G5 | "Authenticator Data" view: titled "Authenticator Data", the decoded authenticator data as JSON indented by two. | `registration-compose-runtime.js:422-429` | 28B | — |
| CRED-G6 | After an advanced registration the view's state is saved as the record's snapshot (`schemaVersion` 2, `capturedAt`, `state`, `response` with `credential` and `relyingParty`), in the browser and on the server (`PUT …/credential-artifacts/${storageId}/snapshot`). | `registration-result.js:75-86`, `advanced-snapshot-update.js` | 28B/29 | — |

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

