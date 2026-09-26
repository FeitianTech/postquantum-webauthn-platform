# Codec — content parity

Everything the current Codec tab shows and does, taken from the running code at `0c9e483a`
(`frontend/templates/decoder/tab.html`, `frontend/templates/shared/modals/{decoder,encoder}-raw.html`,
`frontend/static/scripts/decoder/codec.js` and `codec/**`, `shared/api/failed-response.js`,
`shared/ui/status.js`, the `openModal` / `closeModal` of `shared/ui/core.js` and the modal listeners in
`main.js`) and its tests (`tests/frontend/decoder/{codec,codec-sections,encoding,labels}.test.js`). The charter
(`docs/UI_MIGRATION.md`, "Content parity") requires every item to be mapped to the new component and checked in a
browser before the phase is done.

Line references are to `0c9e483a`. "Verbatim" text is quoted exactly; `${...}` marks a value filled in at run
time. The **New** column names the React component (under `web/src/components/codec/` unless another path is
given), the test that holds it, and how it was checked in a browser:

- *unit*: `CodecSection.test.tsx` (behaviour), `CodecOutput.test.tsx` (rendering real server answers: the eight
  attestation objects the characterization tests record and `web/src/test/codec-answers.json`, which
  `tests/app/tooling/test_web_codec_answers.py` keeps equal to what `/api/codec` answers) or `ValueView.test.tsx`;
  test names carry the CX id.
- *logic*: `tests/frontend/decoder/{request,result,values,encoded-output,labels}.test.js`, over the DOM-free
  modules both UIs import: `decoder/codec/request.js` (checks, request, sentences), `result.js` (what the output
  shows and in what order), `values.js` (how a value is shown), `encoding/summary.js` (the encoded bytes).
- *e2e*: `web/e2e/codec.spec.ts`, Playwright's Chromium (Chrome for Testing, Playwright 1.63) against Flask
  serving the export under the strict CSP.
- *parity*: `web/e2e/codec-parity.spec.ts`: twelve inputs from `tests/app/codec_corpus.py` decoded in both UIs, the
  text compared word for word per section.
- *pane*: by hand in the desktop app's Chromium 152 at `http://localhost:8765/beta#codec` (and `/` for the current
  UI), strict CSP, 2026-09-25, at 1440, 1024 and 375 px; no console message but the expected 422 of a refusal.

The words themselves are not copied: every sentence and label from logic comes from the modules above, which
`web/` imports (`@legacy/*`); `tests/app/tooling/test_web_source_rules.py` fails if `web/src` redefines one of
their exports or repeats one of their sentences. Only the template's own text (headings, placeholders, the lenient
wording, Supported Inputs, the format options, the raw views' titles) is written in the components.

## The tab

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-T1 | Heading "Codec" (`h2`) and the description "Decode or encode WebAuthn payloads to inspect their underlying data formats." | `tab.html:4-5` | `CodecSection.tsx`: h2 and description from `lib/sections.ts` (the same words). unit CX-T1; e2e; pane. |
| CX-T2 | Reached from the top navigation's "Codec" tab (`data-action="switch-tab" data-tab="codec"`). | `shared/navigation.html:4` | `shell/AppShell.tsx` renders `CodecSection` for the "Codec" section of the top bar (`#codec`). `AppShell.test.tsx`; `beta-smoke.spec.ts` (Codec is no longer "not moved"); pane. |

## The Decode / Encode switch

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-M1 | Two tabs in a `role="tablist"` (no accessible name): "Decode" (selected at load) and "Encode", each `role="tab"` with `aria-selected` and `aria-controls` naming its panel (`role="tabpanel"`, `aria-labelledby` the tab). | `tab.html:6-29,32-37,132-138` | `ui/SegmentedControl` named "Codec mode" (the sliding highlight of the top bar), tabs "Decode" (selected) and "Encode" controlling `codec-mode-panel-*` tabpanels labelled by their tab. unit CX-M1; e2e; pane. |
| CX-M2 | Choosing the other mode shows its panel and hides the other (`hidden`); choosing the mode already shown, or an unknown one, does nothing. | `mode.js:14-50` | The same: the chosen panel shows, the other is `hidden`; choosing the current tab does nothing (SegmentedControl). unit CX-M2; e2e; pane. |
| CX-M3 | Switching hides both status messages (decode and encode). | `mode.js:48-49` | Changed: nothing to hide. A success is a toast that leaves by itself; a failure stays in its own panel until that panel's next run or Clear (see "What changed"). unit CX-S6/CX-L1. |
| CX-M4 | The panels fade in over 200 ms on a switch (`codec-mode-animating`). | `mode.js:52-60` | The shown panel comes in as a section does (`section-in`: fade and rise, 480 ms), still under `prefers-reduced-motion`. unit CX-M4; pane. |
| CX-M5 | Each panel keeps its own input, result and raw view across switches (both stay in the page). | `tab.html:32-196` | Both panels stay mounted, each with its own `useCodec` state (input, options, answer, failure, raw view). unit CX-M2/M5; pane. |

## Decode input

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-D1 | A 10-row text area, placeholder "Paste something here to decode..." (three ASCII dots), no visible label; spell check, autocapitalise, autocomplete and Grammarly off. | `tab.html:82-93` | `CodecSection` `TextArea` (mono, 10 rows), the placeholder verbatim, the same attributes; new: a visible label "Input to decode". unit; e2e; pane. |
| CX-D2 | A checkbox, unticked at load, with the wording (verbatim) "Best effort (lenient): read CBOR that is not well-formed as far as it goes". | `tab.html:96-101` | `ui/Switch`, off at load: label "Best effort (lenient)" and, beside the switch, "read CBOR that is not well-formed as far as it goes" (the wording, split at its colon into the field row's label and description). unit CX-D2; e2e; pane. |
| CX-D3 | Buttons "Decode" (primary) and "Clear" (secondary). | `tab.html:103-106` | `ui/Button` "Decode" (primary) and "Clear" (secondary). unit; e2e; pane. |
| CX-D4 | The request: `POST /api/codec` with `{"payload": <the input as typed, untrimmed>, "mode": "decode"}`, plus `"lenient": true` only when the box is ticked (the key is absent otherwise). | `process.js:113-126` | `useCodec` over `buildCodecRequest` / `requestCodec` (`request.js`): the same body, `lenient: true` only when on. unit CX-D2/D4; logic; e2e; pane. |
| CX-D5 | While the request runs, a progress line with a spinner reads "Decoding…" (U+2026; the template's "Decoding..." is replaced before it shows). The button stays enabled: a second click sends a second request. | `tab.html:108-111`, `process.js:106-110` | `codecProgressText` "Decoding…" with a spinner in the output column (`role="status"`); changed: the button is busy (disabled) meanwhile, so no second request. unit CX-D5; pane. |

## Encode input

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-E1 | A select labelled "Encoding format" with seven options (value → text): "CBOR (canonical)" → "CBOR (canonical)" (selected at load); "EDN" → "EDN (exact bytes)"; "CBOR (CTAP/WebAuthn Data)" → "CBOR (CTAP/WebAuthn Data)"; "JSON (binary)" → "JSON (binary)"; "DER" → "DER"; "PEM" → "PEM"; "COSE" → "COSE". | `tab.html:141-152` | `ui/Select` "Encoding format", the seven options value → text verbatim (`model.ts` `ENCODER_FORMATS`), CBOR (canonical) at load. unit CX-E1; e2e (each format); pane. |
| CX-E2 | A 10-row text area, placeholder "Paste something here to encode...", no visible label, the same attributes as CX-D1. No lenient box in this mode. | `tab.html:155-166` | Mono `TextArea`, placeholder verbatim; new: the label "Input to encode". No lenient switch. unit; e2e; pane. |
| CX-E3 | Buttons "Encode" (primary) and "Clear" (secondary). | `tab.html:169-172` | "Encode" (primary), "Clear" (secondary). unit; e2e; pane. |
| CX-E4 | EDN is sent as written. Any other format is first read as JSON in the browser, then checked by `canEncodeToFormat`: CBOR, JSON and COSE need a value; DER and PEM need something convertible to bytes (a PEM, hex, base64 or base64url string, an array of 0–255, or such a value under `value`, `data`, `raw`, `binary`, `bytes`, `hex`, `base64`, `base64url`, `derBase64`, `pem`, searched recursively); "CBOR (CTAP/WebAuthn Data)" is not checked. | `process.js:47-78`, `encoding/index.js:7-22`, `encoding/binary.js` | `validateCodecInput` (`request.js`, `encoding/can-encode.js`): the same rules. logic; unit CX-S2–S5. |
| CX-E5 | The request: `{"payload": <input>, "mode": "encode", "format": <the option's value>}`; `lenient` is never sent. | `process.js:113-118` | `buildCodecRequest`: the same body. unit (each format's request equals the recorded one); e2e. |
| CX-E6 | Progress "Encoding…" (U+2026), as CX-D5. | `tab.html:174-177`, `process.js:106` | `codecProgressText` "Encoding…", as CX-D5. unit (progress); pane. |

## Status messages

Each is a toast at the bottom of the page: one at a time, hidden after 5 s (`status.js:1,24-48`), green for
success and red for an error.

| ID | Current behaviour (verbatim) | Where | New |
|---|---|---|---|
| CX-S1 | Decode with an empty (or blank) input: "Codec input is empty. Please paste something to process." | `process.js:38-44` | `validateCodecInput`, the sentence verbatim, in `FailureNotice` (`role="alert"`). unit CX-S1; logic. |
| CX-S2 | Encode with an empty input, whatever the format (EDN too): "Encoder input is empty. Provide JSON to encode." | `process.js:38-44` | The same, verbatim. unit CX-S2; logic. |
| CX-S3 | Encode with no format: "Select an encoding format before encoding." (the select always has one, so only a stripped page reaches it). | `process.js:53-56` | The same, verbatim (unreachable from the UI, as before: the select always has a value). logic. |
| CX-S4 | Encode, not EDN, input not JSON: "Encoder expects valid JSON input." | `process.js:60-67` | The same, verbatim. unit CX-S4; logic. |
| CX-S5 | Encode, input JSON but not convertible: "Input cannot be converted into ${the option's value}." (e.g. "Input cannot be converted into PEM."). | `process.js:69-75` | The same, verbatim ("Input cannot be converted into PEM."). unit CX-S5; logic. |
| CX-S6 | A validation message (CX-S1–S5) leaves the previous result, if any, where it was: validation returns before the output is cleared. | `process.js:37-78,87-101` | `useCodec` checks before it clears, so the previous answer stays under the message. unit CX-S6. |
| CX-S7 | Success: "Response decoded successfully!" / "Payload encoded successfully!" | `process.js:153-156` | `codecSuccessText` in a success toast (`ui/Toast`). unit CX-S7; e2e; pane. |
| CX-S8 | Failure: "Decoding failed: ${message}" / "Encoding failed: ${message}", where the message is the server's `error` (for a 422: "Not well-formed CBOR at offset 3 (${3}): map key 3 has no value", "Not JSON at offset 6 (${"a"}): NaN is not JSON: …", "EDN is not valid at offset 4: …"; the offset and path are shown only inside that sentence, the body's `offset` and `path` fields are not read). | `process.js:159-174`, `server/app/routes/general.py:422-476` | `codecFailureText` verbatim in `FailureNotice`; new: the 422's `offset` and `path` also shown on their own, in mono (`readFailedResponse` now keeps them). unit CX-S8; logic (`failed-response.test.js`, `request.test.js`); e2e (strict NaN: `6`, `${"a"}`); pane. |
| CX-S9 | A failed response is read by `readFailedResponse`: the server's `error`, else short plain text, else the status's sentence ("The server could not accept the request.", "The request is larger than the server accepts.", "The server failed while handling the request.", "The server is unavailable.", …), with the advice "Send a smaller request." (413), "Try again in a moment." (503), "Try again." (409); an HTML page is never shown. | `failed-response.js:8-137` | `readFailedResponse`, unchanged, through `requestCodec`. unit CX-S9 (503 HTML → "The server is unavailable. Try again in a moment."); logic. |
| CX-S10 | A 200 whose body is not JSON: "Decoding failed: Failed to parse decoder response." (the same sentence after "Encoding failed: " in encode mode). | `process.js:132-137` | `requestCodec`, the same sentence. unit CX-S10; logic. |
| CX-S11 | On failure the output is hidden, the Raw button disabled and an open raw view closed. | `process.js:159-169` | `useCodec`: a failure leaves no answer, so no output and no Raw (the raw view closes with it). unit CX-S8/S11; e2e. |

## Supported Inputs (decode only)

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-I1 | Title "Supported Inputs:", then six lines, each a format name and chips (verbatim): "JSON:" PublicKeyCredential (registration) · PublicKeyCredential (authentication) · Generic JSON payloads; "JSON (binary):" clientDataJSON · Generic JSON payloads; "CBOR:" Attestation objects · CTAP makeCredential request · CTAP makeCredential response · CTAP getAssertion request · CTAP getAssertion response · CTAP getInfo response · Generic CBOR payloads; "Binary:" Authenticator data · Signature fields; "PEM:" X.509 certificates · Certificate chains; "DER:" X.509 certificates. | `tab.html:40-79` | `SupportedInputs.tsx`: the six formats and every chip verbatim, as a definition list with white hairline chips (`ui/Badge` neutral); "Supported Inputs" as its heading (the colons dropped: the list's structure says it). unit CX-I1; e2e; pane. |
| CX-I2 | Shown whenever no decode result is shown (at load, after Clear, after a failure); hidden while one is. The encode panel has no such list. | `dom-state.js:23-40`, `process.js:20-24` | Shown in the output column whenever the decode panel shows no answer, no failure and no progress; never in Encode. unit CX-I1/I2; e2e; pane. |

## The output: header and notes

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-O1 | Hidden until a result arrives; a new request hides the old result first (cleared before the request is sent). | `process.js:87-104,146-148` | `useCodec` clears the answer before the request; `CodecOutput` shows only with an answer. unit CX-O1; e2e. |
| CX-O2 | Heading "Codec Output" (`h3`) with a "Raw" button (disabled until a result with content). | `tab.html:113-129,179-195` | `CodecOutput.tsx`: h3 "Codec Output" and a secondary "Raw" button (there only with an answer, so never disabled). unit; e2e; pane. |
| CX-O3 | A pill "Success" (green) or "Error" (red) from `success`, shown uppercased by CSS. | `render-sections.js:222-225` | `ui/StatusChip` "Success" (green ✓) or "Error" (red ✕) from `describeCodecResult` (`result.js`). unit CX-O3; e2e; pane. |
| CX-O4 | The answer's `type` beside it (e.g. "CBOR (SUCCESS status; GetInfo response)", "Attestation object", "EDN (encoded)"), or "Decoded data" when there is none. | `render-sections.js:227-230` | The type under the heading, from `describeCodecResult` ("Decoded data" when none). unit CX-O3/O4; e2e (each format's type); pane. |
| CX-O5 | An answer that is not an object: only "No decoded data available." | `render-sections.js:211-217` | `describeCodecResult` `empty`, verbatim. unit CX-O5; logic. |
| CX-O6 | `decodeMode` "lenient": the note "Decoded in lenient mode (best effort); skipped items are listed below." | `render-sections.js:234-239` | `CODEC_LENIENT_NOTE` in an amber note. unit CX-O6; e2e (lenient NaN); pane. |
| CX-O7 | No section to show: "No structured data available." | `render-sections.js:258-262` | `CODEC_NO_STRUCTURED_DATA`, verbatim. unit CX-O7; logic. |

## Findings

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-F1 | When `findings` is not empty: a heading "1 finding" or "${n} findings", then one line per finding, in the server's order. | `render-sections.js:183-206,241-243` | `Findings.tsx`: heading from `codecFindingsHeading`, one row per finding in the server's order. unit CX-F1; e2e; parity; pane. |
| CX-F2 | Each line: `${source}: ` when the finding has a `source` (a PublicKeyCredential field or SafetyNet part, e.g. "response.clientDataJSON"), then `offset ${n} · ` (U+00B7) only when the offset is an integer, then the path (e.g. `$`, `${1}`, `${"a"}`), then ` — ` (U+2014) and the message. A JSON finding (offset `null`) shows its path alone. | `render-sections.js:193-202` | Each row from `codecFindingParts`: the source, "offset N" and the path in mono, then the message; a JSON finding shows its path alone. unit CX-F1/F2; logic; e2e; parity; pane. |
| CX-F3 | A finding's `category` (`rendering`, `canonical`, `malformed`, `skipped`, `trailing`, `json`, `limit`, `input`, …) and `code` are not shown. | `render-sections.js:193-202` | Changed, by the brief: the category is shown, as a chip (amber when the server also lists the finding as malformed, white otherwise); `code` stays in the raw view. unit CX-F1; e2e; parity (the only difference it finds). |
| CX-F4 | When there are no findings but `malformed` is not empty: "Malformed segments: ${messages joined by ", "}", in encode mode too. | `render-sections.js:244-249` | `describeCodecResult` `malformed`, verbatim, in an amber note, only without findings, in both modes. unit CX-F4; logic. |
| CX-F5 | Text only: a message that quotes the input is never markup. | `render-sections.js:181-182`, `codec.test.js` | React text nodes only; no markup sink in `web/src` (`test_web_source_rules.py`). unit CX-F5; rules test. |

## Decoded sections

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-X1 | Each key of `data` is a section: its heading (CSS uppercases it) is `formatKey(key)`, its body the value. `data` that is `null`, a primitive or an array is one section headed `formatKey(type || 'Data')`; no `data`, no sections. | `render-sections.js:34-72,124-132` | `CodecOutput` `DecodedSection` per `codecSections` (`result.js`): h4 `formatKey(key)`, then the value. unit CX-X1/X2 (all eight attestation objects); logic; parity; pane. |
| CX-X2 | Order by the type before " (": PublicKeyCredential: credential, attestationObject, attestationStatementDecoded, authenticatorData, clientDataJSON, clientExtensionResults, extensionsDecoded, responseDetails · Attestation object: attestationObject, attestationStatementDecoded, authenticatorData, extensionsDecoded, extensions, edn · Authenticator data: authenticatorData · WebAuthn client data: clientDataJSON · X.509 certificate: raw, pem, parsedX5c, certificates · CBOR: ctapDecoded, getInfoDecoded, attestationStatementDecoded, extensionsDecoded, expandedJson, decodedValue, ctap, edn. Keys present come in that order, then every other key in the answer's order. | `render-sections.js:74-132` | `codecSections`, the same order table (moved out of `render-sections.js`). unit CX-X2; logic; parity. |
| CX-X3 | The 88 labels (verbatim, `formatKey` returns each unchanged): `aaguid` AAGUID · `alg` Algorithm · `attestationObject` Attestation object · `attStmt` Attestation statement · `authenticatorData` Authenticator data · `authenticatorAttachment` Authenticator attachment · `base64` Base64 · `base64url` Base64url · `bin` Binary · `cbor` CBOR · `byteLength` Byte length · `clientDataJSON` Client data JSON · `clientExtensionResults` Client extensions · `cose` COSE key · `counter` Counter · `expandedJson` Expanded JSON · `edn` EDN (exact bytes) · `decodedValue` Decoded value · `encodedValue` Encoded value · `ctap` CTAP metadata · `binary` Binary summary · `ctapDecoded` CTAP decoded · `paddingBytes` Padding bytes (all 00 or ff) · `trailingBytesHex` Trailing bytes (hex) · `makeCredentialResponse` MakeCredential response · `getAssertionResponse` GetAssertion response · `credential` Credential · `credentialId` Credential ID · `credentialIdLength` Credential ID length · `credProps` Credential properties · `data` Data · `derBase64` DER (Base64) · `extensions` Extensions · `fingerprint` Fingerprint · `hex` Hex · `issuer` Issuer · `key_size` Key size · `fmt` Format · `md5` MD5 · `not_valid_after` Not valid after · `not_valid_before` Not valid before · `origin` Origin · `parsedX5c` Certificate details · `publicKeyInfo` Public key info · `pem` PEM · `publicKey` Public key · `publicKeyAlgorithm` Public key algorithm · `pub` Public key bytes · `raw` Raw · `rawId` Raw ID · `rawJson` Raw JSON · `responseDetails` Response details · `rpIdHash` RP ID hash · `sig` Signature · `signature` Signature · `signature_algorithm` Signature algorithm · `sha1` SHA1 · `sha256` SHA256 · `structure` Structure · `signatureLength` Signature length · `subjectPublicKeyInfoBase64` Subject public key (Base64) · `subject` Subject · `subject_key_identifier` Subject key identifier · `subject_public_key_info` Subject public key info · `transports` Transports · `meaning` Meaning · `code` Code · `codeHex` Code (hex) · `kind` CTAP type · `payloadLength` Payload length · `valueSummary` Value summary · `keySummary` Key summary · `type` Type · `userHandle` User handle · `uuid` UUID · `uncompressedPoint` Uncompressed point · `x5c` X5C · `getInfoResponse` GetInfo response · `getInfoDecoded` GetInfo (interpreted) · `extensionsDecoded` Extensions (interpreted) · `attestationStatementDecoded` Attestation statement (interpreted) · `attestationTypesSupported` Attestation types supported · `defaultWhenAbsent` Default when absent · `notChecked` Not checked · `notInSyntax` Not in the format's syntax · `parseError` Parse error · `keyDescription` Key description · `spec` Spec | `constants.js:1-90` | `formatKey` / `SPECIAL_LABELS`, imported. logic (`labels.test.js`); unit (headings and terms); parity. |
| CX-X4 | Any other key through `formatKey`: a key the decoder spelled as data (a typed spelling such as `"1" (text)` or `h'01' (bytes)` with an optional ` #n`, an EDN start `"`, `'`, `h'`, `float'`, `simple(`, `invalid(`, `[`, `{`, an EDN number or word such as `-Infinity`, `NaN_2`, `1.5_3`, `true`, or a tag `1(…)`) is shown exactly as written; up to four capitals or digits as written; a leading `-` before a digit kept (COSE `-1`, `-2`, `-3`); otherwise `_` / `-` become spaces, camelCase is split, a word of one to three lower-case letters is upper-cased, others get a capital. Resulting quirks kept: `json` → "Json", `notRebuildable` → "NOT Rebuildable", `getAssertionRequest` → "GET Assertion Request", `colonHex` → "Colon Hex"; a non-string or empty key → "Value". | `labels.js:1-58`, `labels.test.js` | `formatKey`, imported, quirks kept ("Json"); new: a key the decoder wrote as data is set in mono. unit CX-V6/X4; logic; parity. |

## Values

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-V1 | `null` / `undefined`: "null" / "undefined" in muted text. | `render-values.js:40-45` | `ValueView.tsx` over `classifyCodecValue` (`values.js`): "null" / "undefined" muted mono. unit CX-V1; logic. |
| CX-V2 | A string: on one line in monospace, or as a preformatted block when it holds a newline or is longer than 80 characters. Bytes arrive as hex strings and are shown so. | `render-values.js:47-53` | Up to 80 characters on its line in mono, wrapping anywhere rather than overflowing; longer or multi-line in a `ui/CodeBlock` (collapsed past 16 rem with "Show all", copy). unit CX-V2; logic; pane (TPM certificates). |
| CX-V3 | A number or boolean: its text (`String(value)`). | `render-values.js:55-60` | Their text, mono. unit CX-V3; logic. |
| CX-V4 | An empty array "[]", an empty object "{}" (muted). | `render-values.js:62-68,80-87` | "[]" / "{}" muted mono. unit CX-V1; logic. |
| CX-V5 | An array: a list, one item per element (bullets), each rendered by these rules. | `render-values.js:70-77` | A bulleted list, each item by these rules. unit CX-V5; logic. |
| CX-V6 | An object: a definition list, term `formatKey(key)`, detail the value by these rules; nested lists indented under a left rule. | `render-values.js:89-105` | A definition list; changed in layout: a map or list inside a map goes under its label, indented behind a hairline, and a label and a plain value sit side by side only where the map has room (a container query), so deep certificate details are never squeezed or cut. unit CX-V6; pane (TPM x5c at 1440 and 375). |
| CX-V7 | Badges above an object's list: "Unknown" when `known` is `false`; "Not verified" when `verification` says "not verified" (any case); "Deprecated" when `deprecated` is `true` or a string. The `known`, `verification` and `deprecated` rows stay in the list. | `render-values.js:3-37` | `badgesFor`, imported: badges above the list, "Unknown" white with a hairline, "Not verified" amber, "Deprecated" red; the rows stay. unit CX-V7; unit (every attestation shows "Not verified"); logic. |
| CX-V8 | No copy control and no truncation anywhere; values, blocks and messages are selectable, headings, terms, pills and chips are not. | `styles/shared/text-selectability.css` | Changed, by the brief: long values and every block (EDN, Expanded JSON, PEM, hex, the raw views) have copy and "Show all"; nothing is cut off, as the whole text is always in the page. `ui/CodeBlock.test.tsx`; unit; pane. |

## EDN and Expanded JSON

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-N1 | `edn` (only when the decoder could write it exactly): a disclosure headed "EDN (exact bytes)", **closed** at first, holding the notation as text in a preformatted block (a non-string would be shown as its JSON). | `render-sections.js:12-32` | `CodeBlock` headed "EDN (exact bytes)" with copy, text from `codecEdnText`; changed: open at once, collapsed past 16 rem with "Show all" (it was a closed disclosure). unit CX-X1 (EDN text of every attestation); e2e; parity; pane. |
| CX-N2 | `expandedJson` at the top level: a read-only text area (no wrapping, sized to its content) holding `{"decoded json": <value>}` indented by two spaces, or "Unable to render expanded JSON" if that fails. Nested deeper, it is an ordinary object. | `render-sections.js:47-53`, `render-values.js:114-129` | `CodeBlock` with `codecExpandedJson` (the same text, and the same fallback sentence). unit CX-N2; logic. |

## Interpretation, CTAP metadata, certificates

These have no renderer of their own: they are sections and values under CX-X and CX-V.

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-P1 | `attestationStatementDecoded` "Attestation statement (interpreted)": `fmt`, `known`, `spec`, `attestationTypesSupported`, `verification` (hence "Not verified"), `fields`, `missing`, `notInSyntax`, `notChecked`, … | server `decode/interpretations.py`; CX-V7 | Sections and values as CX-X / CX-V, badges from `badgesFor`. unit CX-X1 (eight attestation objects, TPM with `missing` and `notChecked`); parity (tpm, packed, ML-DSA-44); pane. |
| CX-P2 | `extensionsDecoded` "Extensions (interpreted)": a list of blocks (`location`, `path`, `role`, `spec`, `basis`, `source`, `entries` each with `value`, `known`, `spec` or `meaning`, `note`); an unknown extension shows "Unknown". | same | The same. unit (every attestation with extensions); logic (`values.test.js` Unknown). |
| CX-P3 | `getInfoDecoded` "GetInfo (interpreted)": per member `value`, `meaning`, `defaultWhenAbsent`, `sent`, AAGUID `hex` and `guid`, … | same | The same. unit CX-P3 (framed getInfo: Default when absent, Meaning); parity (getInfo bare and framed). |
| CX-P4 | `ctap` "CTAP metadata": Code (may be "null"), Code (hex), `status` / `command`, CTAP type, Meaning, Message, Payload length, **Trailing bytes (hex)** and **Padding bytes (all 00 or ff)** when bytes follow the item, "NOT Rebuildable" when the view cannot be encoded back. | server `decode/ctap.py`, `ctap_prefix.py` | The same; "Trailing bytes (hex)", "Padding bytes (all 00 or ff)" and the trailing finding shown. unit CX-P4; parity (makeCredential with five padding bytes, the non-canonical response). |
| CX-P5 | `ctapDecoded` "CTAP decoded" and `expandedJson`: the message's members labelled as sent (`"1 (fmt)"`, …). | same | The same. unit CX-P3; parity. |
| CX-P6 | Certificates: for "X.509 certificate", Raw, PEM, Certificate details (version, serial number, signature algorithm, issuer, validity, subject, public key info, extensions, fingerprints, signature, DER (Base64), PEM), Certificates for a chain; inside an attestation object, `attStmt.x5c` entries with `parsedX5c`, `pem`, `raw`. | server `certificates.py`; CX-X, CX-V | The same (Raw, PEM, Certificate details; `x5c` entries). unit CX-P6; parity (TPM chain); pane (TPM at 1440 and 375). |

## Raw views

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-R1 | "Raw" opens a modal dialog (`role="dialog"`, `aria-modal="true"`) titled "Raw Codec Output" (decode) or "Raw Encoder Output" (encode), holding the **whole answer** (`JSON.stringify(payload, null, 2)`) in a focusable preformatted block. | `modals/decoder-raw.html`, `modals/encoder-raw.html`, `process.js:142-145` | `RawDialog.tsx` (`ui/Overlay` Dialog): titles verbatim, the whole answer from `codecRawJson` in an uncollapsed `CodeBlock` with copy. unit CX-R1; e2e; pane. |
| CX-R2 | Closed by its × button (accessible name "Close raw codec output" / "Close raw encoder output"), by a click on the backdrop, or by "Raw" again; Escape does not close it; focus is not moved in or back. | `panel-actions.js:59-87`, `main.js:339-346`, `core.js:246-345` | Closed by × (the same names), the backdrop, or Escape (new); focus moves into the dialog and back to "Raw" (new); the page behind is `inert`. "Raw" does not toggle it closed: the page behind cannot be clicked while it is open. unit CX-R1; e2e; pane. |
| CX-R3 | "Raw" does nothing while disabled or with no content; a new request, a failure and Clear close an open raw view. | `panel-actions.js:73-80`, `process.js:99-101,166-168` | "Raw" exists only with an answer; a run, a failure or Clear removes the answer and so the view. unit; e2e. |

## Encode output

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-C1 | The first binary summary in the answer (an object with a non-empty `hex`, `base64` or `base64url`: `data` itself, its `binary`, or deeper, in key order) is one section, headed by the key that holds it through `formatKey`, or "Encoded output" (a key reading "Binary" becomes "Encoded output"; `binary` itself reads "Binary summary"). | `render-sections.js:137-179`, `encoding/summary.js` | `describeEncodedOutput` (`encoding/summary.js`): the same search and label rules. unit (each format); logic (`encoded-output.test.js`). |
| CX-C2 | In it, one labelled block per view, in this order: "Hex", "Base64", "Base64url", "Colon Hex", then every other non-empty string in the summary (label by `formatKey`), except `encoding`. | `encoding/format-elements.js:3-57` | `EncodedOutput.tsx`: each view (label, then a `CodeBlock` with copy) in `listEncodedFormats` order. unit (each format); logic; e2e (each format); pane. |
| CX-C3 | Then "Byte length: ${n}" (`byteLength`, else `length`). | `render-sections.js:164-175` | "Byte length: ${n}", the number in mono; none when the summary gives none. unit CX-C3; e2e; pane. |
| CX-C4 | No summary, or no view in it: the decode sections (CX-X) instead. | `render-sections.js:139-147` | `describeCodecResult` falls back to the sections. logic; unit CX-F4. |
| CX-C5 | Not shown in the output (only in the raw view): `pem`, `derBase64`, `json`, `text`, `decodedValue`, `encodedValue`, `ctapDecoded`, `ctap`. | `render-sections.js:137-179` | The same: only in the raw view. unit (each format). |
| CX-C6 | The type reads as the server wrote it: "CBOR (canonical) (encoded)", "EDN (encoded)", "CBOR (CTAP/WebAuthn Data) (encoded ${message})", "JSON (encoded)", "DER (encoded)", "PEM (encoded)", "COSE (COSE_Key)". | server `encode/handlers_basic.py:24-40` | As the server writes it. unit and e2e (each format's type). |

## Clear

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-L1 | "Clear" empties that panel's input, result and raw view, disables Raw, closes an open raw view, hides that panel's status and progress, and (decode) shows Supported Inputs again. It keeps the lenient box and the format, and does not stop a request already sent (its answer is still shown when it arrives). | `panel-actions.js:16-57` | `useCodec.clear`: the same scope (the lenient switch and the format kept); changed: an answer still coming is dropped. unit CX-L1 (both panels, and after a refusal); pane. |

## What changed

Nothing the Codec shows or does was dropped. What looks or behaves differently:

- **Layout.** From 1280 px the input sits beside the output (the input stays in view while a long answer scrolls);
  below that one above the other; at 375 px nothing scrolls sideways. Supported Inputs is the output column's
  empty state (it hid itself the same way). White components throughout: no grey textarea, code block or panel.
- **Findings** are a list with the category as a chip and the source, offset and path in Geist Mono (the category
  was not shown before; the brief asks for it).
- **Copy and "Show all"** on every long value and every block (none before); blocks start collapsed at 16 rem and
  never cut text off. The EDN block is open at once (it was a closed disclosure).
- **Failures** stay in their panel until its next run or Clear, with the 422's offset and path on their own; the
  success message is still a toast. (Before, every message was a toast that left after 5 s, and switching modes
  hid them.)
- **A run in progress** makes its button busy, so a second click sends nothing; **Clear** drops an answer still
  coming (before, it was shown when it arrived).
- **Raw views** also close on Escape, take focus and give it back to "Raw", and make the page behind `inert`.
- **Labels**: the text areas have visible labels ("Input to decode", "Input to encode"); the lenient wording is the
  switch's label and description, split at its colon; the Encode panel's empty output says "The encoded bytes
  appear here."; keys the decoder wrote as data are in mono.

## The corpus parity check

`web/e2e/codec-parity.spec.ts` decodes twelve inputs in the current UI at `/` and in `/beta`, reads what each
output shows (`web/e2e/parity.ts`: text by section, controls and hidden text left out) and compares the words per
section. Inputs (from `tests/app/codec_corpus.py`): `literal:a30161616131616218016163`,
`literal:a241010162303102`, `real_vectors:GET_INFO` bare and with its status byte,
`real_vectors:MAKE_CREDENTIAL_RESPONSE` with its status byte and five bytes of padding,
`captured-attestation-object:tpm`, `captured-attestation-object:packed`, `registration:ML-DSA-44:none`,
`fido2-client:_MC_RESP (not canonical)`, `literal:5f4101580102ff`, `literal:d80100`, and `a2010203` read leniently
(the corpus is strict-only). Result on 2026-09-25: **all twelve match**; the only words `/beta` shows beyond the
current UI are the findings' categories (`rendering`, `canonical`, `input`, `trailing`, `skipped`), one per
finding, which the check lists with their reason. The current UI shows no word `/beta` does not.
