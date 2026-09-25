# Analyze Browser — content parity

Everything the current Analyze Browser panel shows and does, taken from the running code at `ee84eafe`
(`frontend/templates/shared/analyze-browser.html`, `frontend/templates/shared/header.html`,
`frontend/static/scripts/shared/browser/{analyze,identity,webauthn-facts,probe}.js`,
`frontend/static/styles/shared/analyze-browser.css`) and its tests
(`tests/frontend/shared/ui/analyze-browser.test.js`, `tests/frontend/shared/browser/`). The charter
(`docs/UI_MIGRATION.md`, "Content parity") requires every item to be mapped to the new component and checked in
a browser before the phase is done.

Line references are to `ee84eafe`. "Verbatim" text is quoted exactly; `${...}` marks a value filled in at run
time. The **New** column names the React component (under `web/src/components/`), the test that holds it, and
how it was checked in a browser:

- *unit*: `web/src/components/analyze-browser/AnalyzeBrowser.test.tsx` (the test named by its AB id), or the file named.
- *e2e*: `web/e2e/beta-smoke.spec.ts`, Playwright's Chromium 153 against Flask serving the export under the
  strict CSP.
- *pane*: by hand in the desktop app's Chromium 152 at `http://localhost:8765/beta`, strict CSP, 2026-09-25
  (driven through the DOM, as the hidden pane did not take pointer clicks); zero console messages.
- *not in a browser*: a state no browser at hand produces (a throwing browser, iOS); held by the unit test.

The words themselves are not copied: labels, notes, states, sources and the report come from the logic modules
(`identity.js`, `webauthn-facts.js`, `report.js`), which `web/` imports; `tests/app/tooling/test_web_source_rules.py`
fails if `web/src` redefines one of their exports or repeats one of their sentences. Only the template's own text
(headings, the WebKit note, the transports statement, the ML-DSA note, the intro) is written in the components.

## The trigger

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-T1 | A header button labelled "Analyze Browser", `aria-haspopup="dialog"`, `aria-controls="analyze-browser-panel"`. On phones (≤ 640 px) it spans the header's width. | `header.html:27-36`, `analyze-browser.css:363-366` | `shell/Header.tsx`: a secondary Button "Analyze Browser", `aria-haspopup="dialog"`, `aria-controls="analyze-browser-panel"`. On phones (< 900 px) it moves into the menu sheet as a full-width button. unit: `AppShell.test.tsx` (header, menu sheet); e2e (both); pane. |
| AB-T2 | The first click gathers the analysis (identity inputs and WebAuthn facts together), renders it, then opens the panel. | `analyze.js:271-287` | `analyze-browser/useBrowserAnalysis.ts`: `gatherAnalysis()` from `report.js`, then opens. unit AB-T2; e2e; pane. |
| AB-T3 | While the analysis runs the button is disabled (opacity .45, `not-allowed`), and further clicks are ignored. No other loading indicator. | `analyze.js:275-285`, `analyze-browser.css:37-40` | `useBrowserAnalysis` `running` → the trigger's `disabled` (Button: opacity .45, `not-allowed`); a click while running is ignored. unit AB-T3; pane (first open). |
| AB-T4 | The analysis is asked once per page and reused on every later open (enrolling a fingerprint needs a reload to show). | `analyze.js:276-284` | `useBrowserAnalysis` keeps the first analysis for the page's life. unit AB-T4; pane (reopens at once). |
| AB-T5 | If gathering throws, the panel does not open and the next click tries again. | `analyze.js:279-285` | `useBrowserAnalysis`: a rejection leaves it closed, re-enables the trigger, logs the error, and the next click asks again. unit `useBrowserAnalysis.test.tsx`; not in a browser. |

## The dialog

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-D1 | A modal dialog: `role="dialog"`, `aria-modal="true"`, `aria-labelledby` its heading, "Browser Analysis" (`h2`). | `analyze-browser.html:3-9,24` | `ui/Overlay.tsx` `Dialog` (`role="dialog"`, `aria-modal="true"`, `aria-labelledby`) with `OverlayHeader` title "Browser Analysis" (`h2`). unit AB-D1, `Overlay.test.tsx`; e2e; pane. |
| AB-D2 | On open, the content is scrolled to the top and the dialog element itself takes focus (`tabindex="-1"`, `preventScroll`). | `analyze.js:186-197` | `Overlay` focuses the panel (`tabindex="-1"`, `preventScroll`) and resets `[data-overlay-scroll]` to the top on each open. unit AB-D1/D2; e2e; pane. |
| AB-D3 | Tab and Shift+Tab go round the dialog's controls and never leave it: from the last to the first and back, and from the dialog itself or anywhere outside it to the first (Tab) or last (Shift+Tab). Disabled controls and anything hidden are skipped. | `analyze.js:199-216` | `Overlay` `keepFocusInside()`, the same rule (first/last, from the panel or outside); disabled and hidden controls skipped. unit AB-D3, `Overlay.test.tsx`; pane (Shift+Tab → close, Tab → Copy report). |
| AB-D4 | The report text box counts among those controls once it is shown (it is then the last). | `analyze.js:17,200-203`; test "counts the report text…" | The fallback `textarea` is among the panel's controls once shown. unit AB-D3/D4; pane (Tab from it → Copy report). |
| AB-D5 | Tab is left alone while the panel is closed. | `analyze.js:260-269` | The keydown listener exists only while open. unit AB-D5; pane. |
| AB-D6 | Escape closes it. | `analyze.js:264-265` | `Overlay` closes on Escape (an open InfoPopover inside takes its own Escape first). unit AB-D6; e2e; pane. |
| AB-D7 | A close button with the accessible name "Close browser analysis" (an × icon) closes it. | `analyze-browser.html:10-20`, `analyze.js:247-258` | `OverlayHeader`'s IconButton, accessible name "Close browser analysis", × icon. unit AB-D7; pane. |
| AB-D8 | A click on the backdrop closes it; other clicks inside the panel do nothing. | `analyze-browser.html:2`, `analyze.js:247-258` | `[data-overlay-backdrop]` closes; clicks inside the panel do nothing. unit AB-D8, `Overlay.test.tsx`; pane. |
| AB-D9 | On close, focus goes back to the Analyze Browser button (`preventScroll`). | `analyze.js:241-245` | `returnFocusTo`: the button that opened it (the header button, or the Menu button when opened from the phone sheet). unit AB-D9 and "opens from the phone menu"; e2e (both); pane. |
| AB-D10 | The page behind is not scroll-locked (removed on purpose in 2e22a3a0, recorded in Phase 22). | `shared/ui/core.js:211-228` | `Overlay` locks no scroll (body and html overflow stay visible). New: the page behind (`#app-root`) is `inert` while open, so assistive technology stays in the dialog too. unit AB-D10; pane. |
| AB-D11 | Backdrop dims the page (`rgba(0,0,0,.4)` with a blur); the dialog is up to 980 px wide and 92 vh tall, its content scrolls. | `advanced/mds/overview.css:156-210`, `analyze-browser.css:48-59,349-375` | Scrim `bg-scrim` (`rgba(0,0,0,.22)`) with a 3 px blur; panel `min(100vw-2rem, 60rem)` wide and `min(88vh, 60rem)` tall, its body scrolls (`OverlayBody`); white, `shadow-float-lg`, radius 20. Screenshots at 1440, 1024 and 375 px. |

## Identity

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-I1 | Four rows, in order, each with a label, a value and where the value came from: "Browser", "Version", "Engine", "System". | `analyze-browser.html:36-65`, `analyze.js:16,51-58` | `analyze-browser/IdentitySummary.tsx` on `ui/KeyValueGrid.tsx`: "Browser", "Version", "Engine", "System" with value and source line; four columns wide, two on a tablet, one on a phone. unit AB-I1; e2e; pane. |
| AB-I2 | A value the browser does not report shows "Not reported". | `analyze.js:54` | `NOT_REPORTED` from `report.js`. unit AB-I2; not in a browser. |
| AB-I3 | The source line under each value is one of (verbatim, `identity.js:8-15`): "from User-Agent Client Hints"; "from the user-agent string, which browsers reduce and can be spoofed"; "from navigator.brave.isBrave()"; "from navigator.platform "MacIntel" with a touch screen, which no Mac has"; "every browser on iOS and iPadOS uses WebKit"; "the browser does not report this". | `identity.js:8-15`, `analyze.js:55` | `SOURCE_TEXT` from `identity.js`, as each value's hint line. unit AB-I1/I5; pane ("from User-Agent Client Hints"). |
| AB-I4 | The values themselves come from `determineIdentity(readIdentityInputs())` unchanged: the brand's own version, "Google Chrome" only when the brand list says so, "Chromium-based browser" for a list of only Chromium, "Brave" from `navigator.brave`, iPadOS from `MacIntel` + touch, "ChromeOS" spelled so, and so on (23 real browsers in `tests/frontend/shared/browser/identity-matrix.js`). | `identity.js:121-313` | `determineIdentity(readIdentityInputs())`, imported unchanged; the 23-browser matrix stays in `tests/frontend/shared/browser/identity.test.js`. unit AB-I1/I5 (the matrix's Chromium-only and iPhone entries); pane ("Chromium-based browser", 152.0.7977.130, Blink, macOS). |
| AB-I5 | On iOS and iPadOS a note shows (hidden otherwise): "On iOS and iPadOS every browser uses Apple's WebKit engine, so WebAuthn here is Safari's, whichever browser this is." | `analyze-browser.html:66-69`, `analyze.js:57` | `IdentitySummary`: the note, verbatim, in an accent-tinted box, only when `onAppleWebKit`. unit AB-I5; not in a browser. |

## States (used by every fact and capability)

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-S1 | "Yes" with a green ✓. | `webauthn-facts.js:7-12`, `analyze-browser.css:297-300` | `analyze-browser/FactList.tsx` `STATE_TONES.yes` → `ui/Badge.tsx` `StatusChip` success: "Yes" ✓ on a green tint. unit AB-S1–5; pane; design page. |
| AB-S2 | "No" with a red ✕. | same, `:302-305` | `StatusChip` danger: "No" ✕ on a red tint. unit AB-S1–5; design page. |
| AB-S3 | "Not available in this browser" with a muted –, text muted too. | same, `:307-312` | `StatusChip` neutral: "Not available in this browser" – on white with a hairline, muted. unit AB-S1–5; design page. |
| AB-S4 | "Could not be determined" with an amber !, and the reason shown as a note under the label. | same, `:314-317` | `StatusChip` warning: "Could not be determined" ! on an amber tint; the reason as the row's note. unit AB-S1–5; design page. |
| AB-S5 | Each fact row shows its label, the API it comes from in code type (where it has one), its note when there is one, and the state. The state is carried in words and a mark, never colour alone. | `analyze.js:30-49` | `FactRow`: label, API in `code` (mono), note, chip with `data-state`; words always, the mark `aria-hidden`. unit AB-S1–5. |

## WebAuthn (section heading "WebAuthn")

| ID | Label (verbatim) | API shown | States and notes | New |
|---|---|---|---|---|
| AB-W1 | "Secure context" | `window.isSecureContext` | yes; no with "WebAuthn works only over HTTPS or on localhost."; unavailable when not a boolean; undetermined when reading throws (the error, e.g. "SecurityError: The operation is insecure.") | `FactList` over `WEBAUTHN_FACTS` (labels, APIs, states and notes from `webauthn-facts.js`). unit AB-S1–5 and "explains a page that is not a secure context"; e2e (`yes`); pane (`yes`). |
| AB-W2 | "WebAuthn API" | `PublicKeyCredential, navigator.credentials` | yes; unavailable with "Missing: ${items joined by "; "}." (items "PublicKeyCredential", "navigator.credentials.create() and get()"), plus " Browsers offer WebAuthn only in a secure context." when AB-W1 is no; undetermined when reading throws | The same list. unit (not a secure context: the missing-API note); pane (`yes`). |
| AB-W3 | "Passkey autofill (conditional mediation)" | `PublicKeyCredential.isConditionalMediationAvailable()` | yes / no from the answer; unavailable when the method is missing, or with "The WebAuthn API is not available on this page." without `PublicKeyCredential`; undetermined when it throws, rejects, or answers a non-boolean ("The browser answered ${value}, not true or false.") | The same list. unit AB-S1–5 (`no`); pane (`yes`). |
| AB-W4 | "Read registration options from JSON" | `PublicKeyCredential.parseCreationOptionsFromJSON()` | yes when a function; unavailable otherwise (or with the no-WebAuthn note); undetermined when reading throws | The same list. unit AB-S1–5 (`unavailable`); pane (`yes`). |
| AB-W5 | "Read authentication options from JSON" | `PublicKeyCredential.parseRequestOptionsFromJSON()` | as AB-W4 | The same list. unit (Chromium-only case); pane (`yes`). |
| AB-W6 | "Write a credential as JSON" | `PublicKeyCredential.prototype.toJSON()` | as AB-W4 | The same list. unit (Chromium-only case); pane (`yes`). |

Source: `WEBAUTHN_FACTS` and the fact functions in `webauthn-facts.js:14-33,80-133`.

## Client capabilities (section heading "Client capabilities")

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-C1 | Intro: "What `PublicKeyCredential.getClientCapabilities()` returned (WebAuthn Level 3)." with the method in code type. | `analyze-browser.html:78-80` | `AnalyzeBrowserDialog` "Client capabilities" section intro, verbatim, with the method in `code`. unit (Chromium-only case); pane. |
| AB-C2 | When the answer is not "yes", one line: the state and its note — unavailable "The WebAuthn API is not available on this page."; unavailable "getClientCapabilities() is a WebAuthn Level 3 feature this browser does not offer."; undetermined with the error (e.g. "NotAllowedError: Document is not focused."); undetermined "The browser answered ${value}, not a record.". | `analyze.js:76-84`, `webauthn-facts.js:146-166` | `analyze-browser/ClientCapabilities.tsx`: one line, the state's chip and the note. unit AB-C2 (both); not in a browser (Chromium offers the method). |
| AB-C3 | When it returned nothing: "The browser returned no capabilities." | `analyze.js:88-90` | `NO_CAPABILITIES` from `report.js`. unit AB-C3. |
| AB-C4 | Group "Defined by WebAuthn Level 3": each defined key with its plain label and the key in code type, in the spec's order (below), whatever order the browser used. | `analyze.js:20-24,91-99`, `webauthn-facts.js:48-59` | `groupCapabilities()` from `report.js` (moved out of `analyze.js`); `FactRow` with the key in `code`. unit (Chromium-only case); pane (9). |
| AB-C5 | Group "Extensions": each `extension:` key, labelled without the prefix, no code, in the browser's order, laid out in a grid. | `analyze.js:20-24`, `webauthn-facts.js:137-139`, `analyze-browser.css:249-253` | Same group, laid out in a grid (2–3 columns), label without the prefix, no `code`. unit; pane (14). |
| AB-C6 | Group "Not recognised by this page, as the browser wrote them": any other key as written, no code, in the browser's order, in a grid. | same | Same, keys as written, no `code`. unit AB-C6; pane (1, `immediateGet`). |
| AB-C7 | A group with no entries is not shown. | `analyze.js:96-98` | `groupCapabilities()` drops empty groups. unit AB-C3/C7, `report.test.js`. |
| AB-C8 | Each capability's state is yes / no, or undetermined with "The browser answered ${value}, not true or false." | `webauthn-facts.js:70-78,135-144` | The states and notes of `gatherWebAuthnFacts()`, unchanged. unit AB-C6/C8. |
| AB-C9 | Defined keys the browser left out: "Left out by the browser, so not known: ${keys joined by ", "}." in the spec's order. | `analyze.js:100-107` | `omittedNote()` from `report.js`. unit AB-C9, `report.test.js`. |
| AB-C10 | The defined labels (verbatim): conditionalCreate "Create a passkey without a prompt of its own (conditional create)"; conditionalGet "Passkey autofill (conditional get)"; hybridTransport "Use a phone or tablet (hybrid transport)"; passkeyPlatformAuthenticator "Passkeys on this device or a phone (passkey platform authenticator)"; userVerifyingPlatformAuthenticator "Built-in authenticator that verifies the user"; relatedOrigins "Related origin requests"; signalAllAcceptedCredentials "Tell the authenticator which credentials the site still accepts"; signalCurrentUserDetails "Tell the authenticator the user's current name"; signalUnknownCredential "Tell the authenticator a credential the site does not know". | `webauthn-facts.js:48-59` | `CLIENT_CAPABILITY_LABELS` from `webauthn-facts.js`. unit (Chromium-only case); pane. |

## Authenticators (section heading "Authenticators")

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-A1 | "Built-in authenticator that verifies the user", API `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`, states as AB-W3. | `webauthn-facts.js:35-46,88-101` | `FactList` over `AUTHENTICATOR_FACTS`. unit AB-S1–5; e2e (two facts); pane. |
| AB-A2 | "A phone or tablet, over hybrid", API `getClientCapabilities().hybridTransport`: the capabilities' own state and note when they are not "yes"; undetermined "getClientCapabilities() did not include hybridTransport, so its availability is not known." when the key is absent; otherwise its value. | `webauthn-facts.js:181-190` | The same list; states from `gatherWebAuthnFacts()`. unit AB-C2/C6/W1; pane. |
| AB-A3 | The transports statement (verbatim): "A web page cannot ask which authenticator transports a browser supports. USB, NFC and Bluetooth security keys are handled by the browser and the operating system and cannot be detected here; the only way to know is to try one." | `analyze-browser.html:88-92` | `AnalyzeBrowserDialog` "Authenticators" section, verbatim. unit (Chromium-only case); pane. |

## Post-quantum (section heading "Post-quantum")

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-P1 | The ML-DSA note (verbatim): "The browser passes the algorithms a site offers on to the authenticator, ML-DSA included (COSE -48 ML-DSA-44, -49 ML-DSA-65, -50 ML-DSA-87). Whether a credential uses ML-DSA depends on the authenticator, and only a registration can show it: offer ML-DSA in the Advanced Authentication tab and read the new credential's algorithm." | `analyze-browser.html:96-101` | `AnalyzeBrowserDialog` "Post-quantum" section, verbatim. unit (Chromium-only case); e2e; pane. |

## Copy report

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-R1 | A "Copy report" button beside the heading. | `analyze-browser.html:25` | `OverlayHeader` actions: a secondary Button "Copy report". unit AB-R1–R4; e2e; pane. |
| AB-R2 | It copies the raw findings as JSON, indented by two spaces: `{ report: "Analyze Browser", generatedAt, page (the origin), identity: { name, version, engine, system, sources, inputs (everything read) }, webauthn: { facts (all eight), clientCapabilities: { state, note (only when set), returned, omitted } } }`. | `analyze.js:120-152` | `buildReport()` / `reportText()` in `report.js` (moved out of `analyze.js`: one copy for both UIs), same keys, order and indent. `tests/frontend/shared/browser/report.test.js`; unit AB-R1–R4; e2e (read back from the clipboard); pane (the fallback's JSON). |
| AB-R3 | Clipboard: `navigator.clipboard.writeText`, read defensively; no `execCommand` fallback. | `analyze.js:159-169` | `writeToClipboard()` in `report.js`: `navigator.clipboard.writeText`, read defensively, no `execCommand`. `report.test.js`. |
| AB-R4 | Success: "Report copied to the clipboard." in a status line (`role="status"`, `aria-live="polite"`), and the text box is hidden again. | `analyze-browser.html:27`, `analyze.js:171-176` | `copyReport()` → the status line (`role="status"`, `aria-live="polite"`, green), the text box hidden. unit AB-R1–R4; e2e (clipboard allowed). |
| AB-R5 | Failure: "Could not copy the report: ${reason} The report is below, selected, to copy by hand." in red, where the reason is the error ("NotAllowedError: Write permission denied.") or "the clipboard is not available on this page", given a full stop unless it ends in `.`, `!` or `?`. | `analyze.js:177-183`, `analyze-browser.css:106-114` | `copyFailedMessage()` in `report.js`, shown in red (`text-danger`). unit AB-R5/R6/R7; pane ("NotAllowedError: Failed to execute 'writeText' on 'Clipboard': Write permission denied."). |
| AB-R6 | On failure the read-only text box (10 rows, accessible name "Browser analysis report, as JSON") shows the JSON, takes focus and has it selected. | `analyze-browser.html:28-35`, `analyze.js:180-183` | The fallback `textarea` (rows 10, `readonly`, the same accessible name) is shown, focused and fully selected. unit AB-R5/R6; pane. |
| AB-R7 | The status line is empty (and takes no space) until the first copy; the status and the text box stay as they are across closing and reopening, until the next copy. | `analyze-browser.css:106-110`, `analyze.js:154-184` | The status line is `sr-only` (no room) until the first copy; the outcome lives in `AppShell` state, so it stays across closing and reopening until the next copy. unit AB-R7 (two tests); pane (kept after reopening). |

## What changed, in presentation only

Nothing the panel shows or does was dropped. What looks or sits differently:

- The identity is a four-column grid of label, value and source separated by space, not grey tiles.
- A state is a chip in its tone's tint with its words and mark, in place of bold text followed by a coloured mark.
- On a phone the header shows the title and Menu; Analyze Browser is in the menu sheet (it was a full-width
  button in the header), and focus returns to the Menu button when the panel closes.
- While the panel is open the page behind it is `inert`, not only kept out of Tab.
- The panel rises in as it fades in, and fades out on closing (the old one faded in and vanished at once); the new one does not move under `prefers-reduced-motion`.
