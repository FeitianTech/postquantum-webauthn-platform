# Simple tab — content parity

> **Since Phase 30A (2026-09-28)** the current UI this list describes is gone: the files cited are in the
> history (`git show <commit>:<path>`), and the parity specs it cites compare the new UI with recordings of what
> the current UI showed (`web/e2e/recorded/`, made before it was removed), not with the running current UI.

Everything the current Simple tab shows and does, taken from the running code at `b163738d`
(`frontend/templates/simple/tab.html`, `frontend/templates/shared/navigation.html`, `simple/auth-simple.js`,
`shared/ui/ceremony-result.js`, `shared/ui/status.js`, `shared/api/failed-response.js`, `shared/auth/username.js`,
`main.js`, the styles under `frontend/static/styles/shared/`) and the server routes it calls
(`server/app/routes/simple/`). The charter (`docs/UI_MIGRATION.md`, "Content parity") requires every item to be
mapped to the new component and checked in a browser before the phase that ports it is done. The saved credentials,
which the Simple tab shows beside its form, are in `docs/ui-parity/credentials.md`.

Phase 28 is split: **28A** ports the Simple tab, its ceremonies and the saved-credential list; **28B** the credential
detail and the registration result. Every item on this page is 28A's.

Scripts are under `frontend/static/scripts/` unless another path is given. "Verbatim" text is quoted exactly;
`${...}` marks a value filled in at run time. The **New** column is filled in when the item is ported: the component
(under `web/src/components/` unless another path is given), the test that holds it, and how it was checked in a
browser.

The words themselves are not copied: every sentence from logic comes from the modules `web/` imports (`@legacy/*`);
`tests/app/tooling/test_web_source_rules.py` fails if `web/src` redefines one of their exports or repeats one of their
sentences. Only the template's own text (the heading, label, placeholder, button names) is written in the components.

## The tab

| ID | Current behaviour (verbatim) | Where | New |
|---|---|---|---|
| SIM-T1 | Reached from the top navigation's "Simple Authentication" tab (`data-action="switch-tab" data-tab="simple"`), the tab shown when the page opens. | `shared/navigation.html:2`, `index.html:35` | `shell/AppShell.tsx` renders `simple/SimpleSection.tsx` for the top bar's "Simple Authentication" (`#simple`, the default section; the page's URL without a hash is that section too, which Back now returns to after a section opened something in another). unit `AppShell.test.tsx`, `useSection.test.tsx`; e2e `simple.spec.ts`; pane. |
| SIM-T2 | Heading "Simple Authentication" (`h2`) and the description "Register and authenticate with passkeys using default presets." | `simple/tab.html:5-6` | `SimpleSection` h2 and description from `lib/sections.ts` (the same words). unit `AppShell.test.tsx`; parity (the tab's words: the same). |
| SIM-T3 | Beside the form, the saved credentials (`docs/ui-parity/credentials.md`, CRED-L and CRED-C). | `simple/tab.html:41-65` | `credentials/SavedCredentials.tsx` beside the form: two cards from 1024 px (the form about 26 rem, sticky under the measured header), one above the other below that. unit; e2e (1440, 1024, 800, 375 px); pane. |

## The form

| ID | Current behaviour (verbatim) | Where | New |
|---|---|---|---|
| SIM-F1 | A text field labelled "Username" (`#simple-email`, placeholder "Enter username"). | `simple/tab.html:14-16` | `ui/Field` `TextField` labelled "Username" (label above, no focus effect), placeholder verbatim. unit SIM-F1/F3; parity. |
| SIM-F2 | Beside it a small button with a refresh icon, `title` and `aria-label` "Generate random username": it fills the field with ten characters from `A–Z`, `a–z`, `0–9`. | `simple/tab.html:17-24`, `shared/auth/username.js:5-12,50-57` | An `IconButton` "Generate random username" inside the field's right edge; the name from `generateRandom10DigitUsername` (`shared/auth/random-username.js`, imported). unit SIM-F2; logic `random-username.test.js`. |
| SIM-F3 | When the page has loaded, the field is filled once with such a username. | `main.js:178`, `shared/auth/username.js:40-48` | Filled once after hydration (the exported page has the field empty, so hydration does not differ). unit SIM-F1/F3; pane. |
| SIM-F4 | Two buttons: "Register Passkey" (primary) and "Authenticate" (secondary), with no `type` attribute. | `simple/tab.html:29-30` | "Register Passkey" (primary) and "Authenticate" (secondary) side by side, one height and one width. Changed: the pressed one is busy (a spinner, `aria-busy`) and both are unusable while a ceremony runs. unit SIM-R2..R7; e2e; parity (control labels set aside). |

## Registration

`simpleRegister` (`simple/auth-simple.js:30-122`).

| ID | Current behaviour (verbatim) | Where | New |
|---|---|---|---|
| SIM-R1 | An empty username: the toast "Please enter a username." (error); nothing else happens (no progress, the result panel is left as it is). | `auth-simple.js:31-35` | Changed: the field's error under it (its description), not a toast; nothing is asked. unit SIM-R1/A1. |
| SIM-R2 | The toast is hidden, the result panel cleared (SIM-C5), and the progress says "Starting registration...". | `auth-simple.js:38-40` | `useSimpleCeremony.ts`: the last failure and result cleared, then each step's sentence from `registerSimplePasskey`'s `onProgress` (`simple/ceremony.js`) as a line with a spinner in the form. unit SIM-R2..R7; logic `ceremony.test.js`. |
| SIM-R3 | `POST /api/register/begin?email=${username, URI-encoded}` with the body `{}` (JSON). The server ignores the username: the user entity is fixed (`user_id`, "a_user", "A. User"), cross-platform, user verification discouraged, the algorithms ML-DSA-87, -65, -44, EdDSA, ES256, RS256, ES384 as fido2 supports them. A refusal: `FailedResponseError` with the context "Registration could not start" (SIM-E1). | `auth-simple.js:42-52`, `server/app/routes/simple/registration.py:241-305` | `registerSimplePasskey` (`simple/ceremony.js`): the same request, body and refusal context. logic; unit (goldens); e2e. |
| SIM-R4 | The answer's `__session_state` is kept aside (the simple server never sends one), the options parsed with the ponyfill (`parseCreationOptionsFromJSON`), and the answer's extensions merged back after `convertExtensionsForClient` (the simple server sends none). `state.lastFakeCredLength` is set to 0. | `auth-simple.js:54-69` | The same, in `registerSimplePasskey` (the extension merge, `lastFakeCredLength`). logic. |
| SIM-R5 | The progress says "Connecting your authenticator device..." while `navigator.credentials.create` runs (through the ponyfill, which adds `toJSON`). | `auth-simple.js:71-77`, `shared/webauthn/json-ponyfill.js:176-180` | The same sentence and call (the ponyfill's `create`). logic; unit; e2e (Chromium's virtual authenticator). |
| SIM-R6 | The progress says "Completing registration..."; `POST /api/register/complete?email=${username}` with the credential's JSON (`type`, `id`, `rawId`, `authenticatorAttachment`, `response` with `clientDataJSON`, `attestationObject`, `transports`, `clientExtensionResults`), and `__session_state` when one was kept. A refusal: context "Registration failed" (SIM-E1). | `auth-simple.js:79-103` | The same sentence, request and context. logic; unit. |
| SIM-R7 | Success: the registration is printed to the console (`printRegistrationDebug`); the toast "Registration successful! Algorithm: ${algo, else "Unknown"}" (success), `algo` being "ML-DSA-87 (PQC)", "ML-DSA-65 (PQC)", "ML-DSA-44 (PQC)", "ES256 (ECDSA)", "RS256 (RSA)" or "Other (Classical)". | `auth-simple.js:87-92`, `shared/debug/auth.js:27-89`, `routes/simple/registration_record.py:25-31,187` | The toast (`ui/Toast`, success) with `registeredText`'s sentence; the console print in `registerSimplePasskey`. unit SIM-R2..R7; e2e; parity (the same sentence in both UIs). Changed in 28B, for both UIs (the server's answer): `algo` is `webauthn/pqc.py`'s `describe_algorithm`, the one COSE name table the Advanced route already used, so EdDSA is "EdDSA" and ES384 "ES384 (ECDSA)" where both were "Other (Classical)", and an algorithm outside the table "COSE alg ${alg}". |
| SIM-R8 | The answer's `storedCredential`, with the username as `email`, is saved in the browser (`saveSimpleCredential`; credentials.md, CRED-S) and the saved list is drawn again, then once more a second later. | `auth-simple.js:94-99` | `keepRegistered` (`saveSimpleCredential`, `shared/storage/records.js`) with the username as `email`, then the list read again. Changed: read once (the current tab reads again a second later; the storage gives the same records). unit SIM-R8; e2e (then listed, used and deleted at `/`). |
| SIM-R9 | The result panel stays empty after a registration: only authentication fills it. | `auth-simple.js` | Kept: a registration leaves the panel empty. unit. |

## Authentication

`simpleAuthenticate` (`simple/auth-simple.js:124-234`).

| ID | Current behaviour (verbatim) | Where | New |
|---|---|---|---|
| SIM-A1 | An empty username: "Please enter a username." (error), as SIM-R1. | `auth-simple.js:125-129` | As SIM-R1. unit SIM-R1/A1. |
| SIM-A2 | The toast hidden, the panel cleared, the progress "Starting authentication...". | `auth-simple.js:132-134` | As SIM-R2, through `authenticateSimplePasskey`. unit; logic. |
| SIM-A3 | The username's credentials saved in this browser (simple records whose `email`, `userName` or `username` equals it, ignoring case); none: "No credentials stored in this browser for the provided username. Please register first." (error). | `auth-simple.js:136-139`, `shared/storage/local/simple-credentials.js:25-34` | `authenticateSimplePasskey` with `getSimpleCredentialsForEmail`: the same sentence, in place, and nothing asked. unit SIM-A3; logic; e2e. |
| SIM-A4 | `POST /api/authenticate/begin?email=${username}` with `{"credentials": [...]}`, each `{credentialId, aaguid, publicKey, signCount, algorithm}` (`prepareCredentialsForServer`). A 404 (the server found no usable credential; its answer is an HTML page): "No credentials found for this username. Please register first."; another refusal: context "Authentication could not start" (SIM-E1). | `auth-simple.js:141-156`, `simple-credentials.js:175-197`, `routes/simple/authentication.py:43-75` | The same request and sentences. unit SIM-A4; logic. |
| SIM-A5 | `__session_state` kept aside, the options parsed (`parseRequestOptionsFromJSON`), `state.lastFakeCredLength` set to 0, the progress "Connecting your authenticator device..." while `navigator.credentials.get` runs. | `auth-simple.js:158-171` | The same (the ponyfill's `get`). logic; e2e. |
| SIM-A6 | The progress "Completing authentication..."; `POST /api/authenticate/complete?email=${username}` with the assertion's JSON (`response` with `clientDataJSON`, `authenticatorData`, `signature`, `userHandle`). | `auth-simple.js:173-179` | The same sentence and request. logic. |
| SIM-A7 | Success: printed to the console (`printAuthenticationDebug`); the toast "Authentication successful! You have been verified." (success); the result panel (SIM-C1) with the title "Last authentication", the counter and its verdict; the credential's stored counter updated to the server's (`updateSimpleCredentialSignCount`, simple and advanced records with that id); its card flashes green (credentials.md, CRED-C9); the list drawn again. | `auth-simple.js:181-202` | The toast, `ceremony/CeremonyResult.tsx` ("Last authentication", the counter and its verdict), `keepSignCount` (`updateSimpleCredentialSignCount`), the row tinted green for 2.2 s, the list read again. unit SIM-A7; e2e (the counter read back from the authenticator); parity (the panel: the same words but the counter's value). |
| SIM-A8 | A refusal: the answer is read (`readFailedResponse`); when it names `failedCredentialId`, that card flashes red; the result panel shows the answer's `signCountStatus` with "Authentication was rejected." after a `regressed` verdict (no counter number is passed, so only `regressed` fills the panel; otherwise it is cleared); the toast is the failure's text with no context (SIM-E1). | `auth-simple.js:203-215` | The same: the refusal read by `readFailedResponse`, the row tinted red, the panel with "Authentication was rejected." after a `regressed` verdict, the refusal's text. Changed: in place (SIM-E4). unit SIM-A8/C4. |

## Failures

| ID | Current behaviour (verbatim) | Where | New |
|---|---|---|---|
| SIM-E1 | A refused request's text is `readFailedResponse`'s: the server's `error` (or short plain text; never an HTML page), else the status's sentence (400 "The server could not accept the request.", 404 "The server has nothing at that address.", 409 "The stored credentials changed while the request was handled.", 413 "The request is larger than the server accepts.", 500 "The server failed while handling the request.", 502 "The server could not be reached.", 503 "The server is unavailable.", 504 "The server did not answer in time.", else "The server answered with status ${status}.", or "The server did not answer."), then what to do unless the message already says it (409 "Try again.", 413 "Send a smaller request.", 503 "Try again in a moment.", and "Start the ceremony again." after a 400 about the ceremony state or with no server message), prefixed by the context and ": " when there is one. E.g. "Registration could not start: The stored credentials could not be read. Please try again." | `shared/api/failed-response.js` | `readFailedResponse` (imported; now held at 100 %): the same sentences and advice. Changed: in place, in red (`role="alert"`), until the next ceremony. unit SIM-E1/E3; logic `failed-response*.test.js`. |
| SIM-E2 | The browser's refusals, by the error's name: `NotAllowedError` "User cancelled or authenticator not available"; `InvalidStateError` "Authenticator is already registered for this account" (registration) or "Authenticator error or invalid credential" (authentication); `SecurityError` "Security error - check your connection and try again"; `NotSupportedError` "WebAuthn is not supported in this browser"; anything else its own message. | `auth-simple.js:105-117,217-229` | `ceremonyErrorText` (`simple/ceremony.js`): the same four names, `InvalidStateError` said per ceremony. unit SIM-E2; logic. |
| SIM-E3 | The server's refusals the goldens hold, as the tab shows them: "Registration failed: Registration state not found or has expired. Please restart the registration process.", "…This registration challenge has already been used…", "…Invalid origin in CollectedClientData.", "…Ceremony origin is not permitted by the configured FIDO_SERVER_ALLOWED_ORIGINS allowlist.", "Registration failed: Registration verification failed." (its `attestationErrors` are not shown), "Registration failed: Invalid credential name: …", 503 "Registration could not start: The stored credentials could not be read. Please try again.", 500 "Registration failed: Unable to persist registered credential.", 409 "…too many times, so the registration was not saved. Please try again.", 413 "…larger than the limit of ${n} bytes this server accepts. Send a smaller request.", "Invalid signature.", "Signature counter did not increase (stored ${s}, received ${r}). This authenticator may have been cloned, so authentication was rejected.", the 400 HTML answer "The server could not accept the request. Start the ceremony again." | `tests/app/characterization/golden/routes/simple-*.json`, `routes/simple/*.py` | The same sentences, over the goldens' answers (Invalid signature, the counter, the 404 page). unit; logic. |
| SIM-E4 | Every failure is a toast (SIM-M1): it leaves after five seconds, with the next message, or when another tab's message shows. | `shared/ui/status.js` | Changed: a failure stays in place until the next ceremony (the charter's rule since Phase 26); a success is a toast that leaves after 5 s or when dismissed. unit; e2e. |

## Messages and progress

| ID | Current behaviour (verbatim) | Where | New |
|---|---|---|---|
| SIM-M1 | `#simple-status`: a toast at the bottom centre of the window, coloured by its type (success, error, warning, info), shown on the next frame, hidden after 5 s; showing one hides every other tab's; raised above the progress bar while that is shown. | `simple/tab.html:8`, `shared/ui/status.js`, `styles/shared/actions.css:92-143` | `ui/Toast` for successes (white, a coloured dot, `role="status"`), bottom centre, 5 s. Changed: failures are not toasts (SIM-E4). unit; e2e; parity (the same sentences). |
| SIM-M2 | `#simple-progress`: a floating bar with a spinner and the step's sentence (template default "Processing...", never shown: every call gives a sentence), shown while a ceremony runs and hidden when it ends. The buttons stay enabled meanwhile. | `simple/tab.html:33-36`, `shared/ui/status.js`, `styles/shared/editor.css:258-295` | Changed: a line with a spinner inside the form and the pressed button busy, not a floating bar. The template's default "Processing...", which every step replaces before it shows, is not ported (parity lists it). unit SIM-R2..R7. |

## The ceremony result panel

`#simple-ceremony-result` (`role="status"`, `aria-live="polite"`, hidden while empty), built by
`shared/ui/ceremony-result.js`. It stays until the next ceremony starts, unlike the toast.

| ID | Current behaviour (verbatim) | Where | New |
|---|---|---|---|
| SIM-C1 | The title ("Last authentication"; "Last ceremony" when a caller gives none) and a list of rows. | `ceremony-result.js:78-101` | `ceremony/CeremonyResult.tsx` over `describeCeremonyResult` (`shared/ceremony/result.js`, DOM-free; the current panel renders the same model): the same title and rows. unit `CeremonyResult.test.tsx`; logic `result.test.js`; parity. |
| SIM-C2 | "Signature counter": the number (when given) then the verdict: `ok` "Higher than the last counter the server saw for this credential, as it should be."; `not-supported` "This authenticator keeps no counter: it reported 0, as synced passkeys do, so the counter cannot show whether it was cloned."; `regressed` "Not higher than the counter the server stored: the authenticator may have been cloned." followed by the caller's consequence ("Authentication was rejected."); another status `The server reported "${status}".`; none "The server did not say how this counter compares with the stored one." No number and no status: no row. | `ceremony-result.js:10-14,38-52` | The same sentences; the counter in Geist Mono. unit; logic; parity (the same words, the counter's value aside). |
| SIM-C3 | "Challenge" (only when a caller asks for it: the Advanced tab; never in the Simple tab): `server-session` "Issued by this server for this ceremony.", `client-supplied` "Taken from the request, not issued by this server.", then `fresh` "First use.", `replayed` "Used before: this is a replay.", `expired` "Expired before it was used.", `not-tracked` "Not tracked for reuse."; others `The server reported "${value}".`; no source "Its source was not reported."; neither "Not reported by the server." | `ceremony-result.js:16-27,54-72` | The same row, ready for the Advanced tab (Phase 29). unit; logic. |
| SIM-C4 | A `regressed` counter (or a replayed challenge) marks the panel as a warning (`data-verdict="warning"`). | `ceremony-result.js:95-99`, `styles/shared/actions.css:145-196` | Amber (a semantic tint) with a mark, `data-verdict="warning"`. unit SIM-A8/C4. |
| SIM-C5 | With no row the panel is emptied and hidden; each ceremony clears it when it starts. | `ceremony-result.js:87-90,103-111` | The live region stays in the page, hidden and empty when there is nothing to say; each ceremony clears it when it starts. Changed: inside the form's card it is set off by a hairline, a box only when it warns (no card in a card). unit SIM-C5. |

## What is stored, and where

| ID | Current behaviour | Where | New |
|---|---|---|---|
| SIM-S1 | The server keeps the registration in its credential store (per username) and the ceremony's state in the Flask session; the browser keeps the credential in `localStorage` (credentials.md, CRED-S1..S5). Authentication sends the browser's copies (SIM-A4); the server checks the counter against the larger of its own and the browser's. | `routes/simple/`, `shared/storage/` | Unchanged: both UIs keep the same records in the same storage (`docs/ui-parity/credentials.md`, CRED-S1..S5). e2e (both ways). |

## What changed (28A)

Nothing the Simple tab shows or does was dropped. What looks or behaves differently:

- **Layout.** From 1024 px the form is a card of its own (about 26 rem, staying in view under the header) beside the
  saved credentials; below that one above the other. The username's label is above its field, the random username a
  button inside the field's edge; Register Passkey and Authenticate share one row at one height and width.
- **Messages.** A success is a toast, as before. A failure stays in place, in red, until the next ceremony, and an
  empty username is the field's own error; the current tab shows every message as a toast that leaves after five
  seconds.
- **Progress.** A line with a spinner inside the form, and the pressed button busy; neither button can be pressed
  again meanwhile (the current tab lets a second ceremony start over the first).
- **The result panel** keeps its words; inside the form's card it is set off by a hairline, and a warning is an amber
  box with a mark. The counter is in Geist Mono.
- **The list** is read once after a registration (the current tab reads it again a second later).
- **Not ported:** the progress bar's default text "Processing...", which every step replaces before it shows.

## The parity check (28A)

`web/e2e/simple-parity.spec.ts` compares, in the current UI at `/` and in `/beta`, word for word by section
(`readShownText` / `compareShownText`, `web/e2e/parity.ts`): the tab's own words with nothing saved; the result panel
after an authentication in each UI with the same passkey (Chromium's virtual authenticator); and the registration's
success sentence. Result on 2026-09-27: **the same headings and the same words; the only differences are listed with
their reasons: the current template's "Processing..." (never shown) and the list's count (new) in the tab, and the
counter's value in the panel, which each authentication raises (the same credential was used in `/beta` first). The
success sentences are equal.** The saved credentials' rows are compared in `docs/ui-parity/credentials.md`.

