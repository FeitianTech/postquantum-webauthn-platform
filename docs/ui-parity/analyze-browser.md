# Analyze Browser — content parity

Everything the current Analyze Browser panel shows and does, taken from the running code at `ee84eafe`
(`frontend/templates/shared/analyze-browser.html`, `frontend/templates/shared/header.html`,
`frontend/static/scripts/shared/browser/{analyze,identity,webauthn-facts,probe}.js`,
`frontend/static/styles/shared/analyze-browser.css`) and its tests
(`tests/frontend/shared/ui/analyze-browser.test.js`, `tests/frontend/shared/browser/`). The charter
(`docs/UI_MIGRATION.md`, "Content parity") requires every item to be mapped to the new component and checked in
a browser before the phase is done.

Line references are to `ee84eafe`. "Verbatim" text is quoted exactly; `${...}` marks a value filled in at run
time. The **New** column names the React component (under `web/src/components/`) and the test that proves it.

## The trigger

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-T1 | A header button labelled "Analyze Browser", `aria-haspopup="dialog"`, `aria-controls="analyze-browser-panel"`. On phones (≤ 640 px) it spans the header's width. | `header.html:27-36`, `analyze-browser.css:363-366` | |
| AB-T2 | The first click gathers the analysis (identity inputs and WebAuthn facts together), renders it, then opens the panel. | `analyze.js:271-287` | |
| AB-T3 | While the analysis runs the button is disabled (opacity .45, `not-allowed`), and further clicks are ignored. No other loading indicator. | `analyze.js:275-285`, `analyze-browser.css:37-40` | |
| AB-T4 | The analysis is asked once per page and reused on every later open (enrolling a fingerprint needs a reload to show). | `analyze.js:276-284` | |
| AB-T5 | If gathering throws, the panel does not open and the next click tries again. | `analyze.js:279-285` | |

## The dialog

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-D1 | A modal dialog: `role="dialog"`, `aria-modal="true"`, `aria-labelledby` its heading, "Browser Analysis" (`h2`). | `analyze-browser.html:3-9,24` | |
| AB-D2 | On open, the content is scrolled to the top and the dialog element itself takes focus (`tabindex="-1"`, `preventScroll`). | `analyze.js:186-197` | |
| AB-D3 | Tab and Shift+Tab go round the dialog's controls and never leave it: from the last to the first and back, and from the dialog itself or anywhere outside it to the first (Tab) or last (Shift+Tab). Disabled controls and anything hidden are skipped. | `analyze.js:199-216` | |
| AB-D4 | The report text box counts among those controls once it is shown (it is then the last). | `analyze.js:17,200-203`; test "counts the report text…" | |
| AB-D5 | Tab is left alone while the panel is closed. | `analyze.js:260-269` | |
| AB-D6 | Escape closes it. | `analyze.js:264-265` | |
| AB-D7 | A close button with the accessible name "Close browser analysis" (an × icon) closes it. | `analyze-browser.html:10-20`, `analyze.js:247-258` | |
| AB-D8 | A click on the backdrop closes it; other clicks inside the panel do nothing. | `analyze-browser.html:2`, `analyze.js:247-258` | |
| AB-D9 | On close, focus goes back to the Analyze Browser button (`preventScroll`). | `analyze.js:241-245` | |
| AB-D10 | The page behind is not scroll-locked (removed on purpose in 2e22a3a0, recorded in Phase 22). | `shared/ui/core.js:211-228` | |
| AB-D11 | Backdrop dims the page (`rgba(0,0,0,.4)` with a blur); the dialog is up to 980 px wide and 92 vh tall, its content scrolls. | `advanced/mds/overview.css:156-210`, `analyze-browser.css:48-59,349-375` | |

## Identity

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-I1 | Four rows, in order, each with a label, a value and where the value came from: "Browser", "Version", "Engine", "System". | `analyze-browser.html:36-65`, `analyze.js:16,51-58` | |
| AB-I2 | A value the browser does not report shows "Not reported". | `analyze.js:54` | |
| AB-I3 | The source line under each value is one of (verbatim, `identity.js:8-15`): "from User-Agent Client Hints"; "from the user-agent string, which browsers reduce and can be spoofed"; "from navigator.brave.isBrave()"; "from navigator.platform "MacIntel" with a touch screen, which no Mac has"; "every browser on iOS and iPadOS uses WebKit"; "the browser does not report this". | `identity.js:8-15`, `analyze.js:55` | |
| AB-I4 | The values themselves come from `determineIdentity(readIdentityInputs())` unchanged: the brand's own version, "Google Chrome" only when the brand list says so, "Chromium-based browser" for a list of only Chromium, "Brave" from `navigator.brave`, iPadOS from `MacIntel` + touch, "ChromeOS" spelled so, and so on (23 real browsers in `tests/frontend/shared/browser/identity-matrix.js`). | `identity.js:121-313` | |
| AB-I5 | On iOS and iPadOS a note shows (hidden otherwise): "On iOS and iPadOS every browser uses Apple's WebKit engine, so WebAuthn here is Safari's, whichever browser this is." | `analyze-browser.html:66-69`, `analyze.js:57` | |

## States (used by every fact and capability)

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-S1 | "Yes" with a green ✓. | `webauthn-facts.js:7-12`, `analyze-browser.css:297-300` | |
| AB-S2 | "No" with a red ✕. | same, `:302-305` | |
| AB-S3 | "Not available in this browser" with a muted –, text muted too. | same, `:307-312` | |
| AB-S4 | "Could not be determined" with an amber !, and the reason shown as a note under the label. | same, `:314-317` | |
| AB-S5 | Each fact row shows its label, the API it comes from in code type (where it has one), its note when there is one, and the state. The state is carried in words and a mark, never colour alone. | `analyze.js:30-49` | |

## WebAuthn (section heading "WebAuthn")

| ID | Label (verbatim) | API shown | States and notes | New |
|---|---|---|---|---|
| AB-W1 | "Secure context" | `window.isSecureContext` | yes; no with "WebAuthn works only over HTTPS or on localhost."; unavailable when not a boolean; undetermined when reading throws (the error, e.g. "SecurityError: The operation is insecure.") | |
| AB-W2 | "WebAuthn API" | `PublicKeyCredential, navigator.credentials` | yes; unavailable with "Missing: ${items joined by "; "}." (items "PublicKeyCredential", "navigator.credentials.create() and get()"), plus " Browsers offer WebAuthn only in a secure context." when AB-W1 is no; undetermined when reading throws | |
| AB-W3 | "Passkey autofill (conditional mediation)" | `PublicKeyCredential.isConditionalMediationAvailable()` | yes / no from the answer; unavailable when the method is missing, or with "The WebAuthn API is not available on this page." without `PublicKeyCredential`; undetermined when it throws, rejects, or answers a non-boolean ("The browser answered ${value}, not true or false.") | |
| AB-W4 | "Read registration options from JSON" | `PublicKeyCredential.parseCreationOptionsFromJSON()` | yes when a function; unavailable otherwise (or with the no-WebAuthn note); undetermined when reading throws | |
| AB-W5 | "Read authentication options from JSON" | `PublicKeyCredential.parseRequestOptionsFromJSON()` | as AB-W4 | |
| AB-W6 | "Write a credential as JSON" | `PublicKeyCredential.prototype.toJSON()` | as AB-W4 | |

Source: `WEBAUTHN_FACTS` and the fact functions in `webauthn-facts.js:14-33,80-133`.

## Client capabilities (section heading "Client capabilities")

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-C1 | Intro: "What `PublicKeyCredential.getClientCapabilities()` returned (WebAuthn Level 3)." with the method in code type. | `analyze-browser.html:78-80` | |
| AB-C2 | When the answer is not "yes", one line: the state and its note — unavailable "The WebAuthn API is not available on this page."; unavailable "getClientCapabilities() is a WebAuthn Level 3 feature this browser does not offer."; undetermined with the error (e.g. "NotAllowedError: Document is not focused."); undetermined "The browser answered ${value}, not a record.". | `analyze.js:76-84`, `webauthn-facts.js:146-166` | |
| AB-C3 | When it returned nothing: "The browser returned no capabilities." | `analyze.js:88-90` | |
| AB-C4 | Group "Defined by WebAuthn Level 3": each defined key with its plain label and the key in code type, in the spec's order (below), whatever order the browser used. | `analyze.js:20-24,91-99`, `webauthn-facts.js:48-59` | |
| AB-C5 | Group "Extensions": each `extension:` key, labelled without the prefix, no code, in the browser's order, laid out in a grid. | `analyze.js:20-24`, `webauthn-facts.js:137-139`, `analyze-browser.css:249-253` | |
| AB-C6 | Group "Not recognised by this page, as the browser wrote them": any other key as written, no code, in the browser's order, in a grid. | same | |
| AB-C7 | A group with no entries is not shown. | `analyze.js:96-98` | |
| AB-C8 | Each capability's state is yes / no, or undetermined with "The browser answered ${value}, not true or false." | `webauthn-facts.js:70-78,135-144` | |
| AB-C9 | Defined keys the browser left out: "Left out by the browser, so not known: ${keys joined by ", "}." in the spec's order. | `analyze.js:100-107` | |
| AB-C10 | The defined labels (verbatim): conditionalCreate "Create a passkey without a prompt of its own (conditional create)"; conditionalGet "Passkey autofill (conditional get)"; hybridTransport "Use a phone or tablet (hybrid transport)"; passkeyPlatformAuthenticator "Passkeys on this device or a phone (passkey platform authenticator)"; userVerifyingPlatformAuthenticator "Built-in authenticator that verifies the user"; relatedOrigins "Related origin requests"; signalAllAcceptedCredentials "Tell the authenticator which credentials the site still accepts"; signalCurrentUserDetails "Tell the authenticator the user's current name"; signalUnknownCredential "Tell the authenticator a credential the site does not know". | `webauthn-facts.js:48-59` | |

## Authenticators (section heading "Authenticators")

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-A1 | "Built-in authenticator that verifies the user", API `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`, states as AB-W3. | `webauthn-facts.js:35-46,88-101` | |
| AB-A2 | "A phone or tablet, over hybrid", API `getClientCapabilities().hybridTransport`: the capabilities' own state and note when they are not "yes"; undetermined "getClientCapabilities() did not include hybridTransport, so its availability is not known." when the key is absent; otherwise its value. | `webauthn-facts.js:181-190` | |
| AB-A3 | The transports statement (verbatim): "A web page cannot ask which authenticator transports a browser supports. USB, NFC and Bluetooth security keys are handled by the browser and the operating system and cannot be detected here; the only way to know is to try one." | `analyze-browser.html:88-92` | |

## Post-quantum (section heading "Post-quantum")

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-P1 | The ML-DSA note (verbatim): "The browser passes the algorithms a site offers on to the authenticator, ML-DSA included (COSE -48 ML-DSA-44, -49 ML-DSA-65, -50 ML-DSA-87). Whether a credential uses ML-DSA depends on the authenticator, and only a registration can show it: offer ML-DSA in the Advanced Authentication tab and read the new credential's algorithm." | `analyze-browser.html:96-101` | |

## Copy report

| ID | Current behaviour | Where | New |
|---|---|---|---|
| AB-R1 | A "Copy report" button beside the heading. | `analyze-browser.html:25` | |
| AB-R2 | It copies the raw findings as JSON, indented by two spaces: `{ report: "Analyze Browser", generatedAt, page (the origin), identity: { name, version, engine, system, sources, inputs (everything read) }, webauthn: { facts (all eight), clientCapabilities: { state, note (only when set), returned, omitted } } }`. | `analyze.js:120-152` | |
| AB-R3 | Clipboard: `navigator.clipboard.writeText`, read defensively; no `execCommand` fallback. | `analyze.js:159-169` | |
| AB-R4 | Success: "Report copied to the clipboard." in a status line (`role="status"`, `aria-live="polite"`), and the text box is hidden again. | `analyze-browser.html:27`, `analyze.js:171-176` | |
| AB-R5 | Failure: "Could not copy the report: ${reason} The report is below, selected, to copy by hand." in red, where the reason is the error ("NotAllowedError: Write permission denied.") or "the clipboard is not available on this page", given a full stop unless it ends in `.`, `!` or `?`. | `analyze.js:177-183`, `analyze-browser.css:106-114` | |
| AB-R6 | On failure the read-only text box (10 rows, accessible name "Browser analysis report, as JSON") shows the JSON, takes focus and has it selected. | `analyze-browser.html:28-35`, `analyze.js:180-183` | |
| AB-R7 | The status line is empty (and takes no space) until the first copy; the status and the text box stay as they are across closing and reopening, until the next copy. | `analyze-browser.css:106-110`, `analyze.js:154-184` | |
