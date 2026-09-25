# Codec — content parity

Everything the current Codec tab shows and does, taken from the running code at `0c9e483a`
(`frontend/templates/decoder/tab.html`, `frontend/templates/shared/modals/{decoder,encoder}-raw.html`,
`frontend/static/scripts/decoder/codec.js` and `codec/**`, `shared/api/failed-response.js`,
`shared/ui/status.js`, the `openModal` / `closeModal` of `shared/ui/core.js` and the modal listeners in
`main.js`) and its tests (`tests/frontend/decoder/{codec,codec-sections,encoding,labels}.test.js`). The charter
(`docs/UI_MIGRATION.md`, "Content parity") requires every item to be mapped to the new component and checked in a
browser before the phase is done.

Line references are to `0c9e483a`. "Verbatim" text is quoted exactly; `${...}` marks a value filled in at run
time. The **New** column is filled in once the port is done.

## The tab

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-T1 | Heading "Codec" (`h2`) and the description "Decode or encode WebAuthn payloads to inspect their underlying data formats." | `tab.html:4-5` | to map |
| CX-T2 | Reached from the top navigation's "Codec" tab (`data-action="switch-tab" data-tab="codec"`). | `shared/navigation.html:4` | to map |

## The Decode / Encode switch

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-M1 | Two tabs in a `role="tablist"` (no accessible name): "Decode" (selected at load) and "Encode", each `role="tab"` with `aria-selected` and `aria-controls` naming its panel (`role="tabpanel"`, `aria-labelledby` the tab). | `tab.html:6-29,32-37,132-138` | to map |
| CX-M2 | Choosing the other mode shows its panel and hides the other (`hidden`); choosing the mode already shown, or an unknown one, does nothing. | `mode.js:14-50` | to map |
| CX-M3 | Switching hides both status messages (decode and encode). | `mode.js:48-49` | to map |
| CX-M4 | The panels fade in over 200 ms on a switch (`codec-mode-animating`). | `mode.js:52-60` | to map |
| CX-M5 | Each panel keeps its own input, result and raw view across switches (both stay in the page). | `tab.html:32-196` | to map |

## Decode input

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-D1 | A 10-row text area, placeholder "Paste something here to decode..." (three ASCII dots), no visible label; spell check, autocapitalise, autocomplete and Grammarly off. | `tab.html:82-93` | to map |
| CX-D2 | A checkbox, unticked at load, with the wording (verbatim) "Best effort (lenient): read CBOR that is not well-formed as far as it goes". | `tab.html:96-101` | to map |
| CX-D3 | Buttons "Decode" (primary) and "Clear" (secondary). | `tab.html:103-106` | to map |
| CX-D4 | The request: `POST /api/codec` with `{"payload": <the input as typed, untrimmed>, "mode": "decode"}`, plus `"lenient": true` only when the box is ticked (the key is absent otherwise). | `process.js:113-126` | to map |
| CX-D5 | While the request runs, a progress line with a spinner reads "Decoding…" (U+2026; the template's "Decoding..." is replaced before it shows). The button stays enabled: a second click sends a second request. | `tab.html:108-111`, `process.js:106-110` | to map |

## Encode input

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-E1 | A select labelled "Encoding format" with seven options (value → text): "CBOR (canonical)" → "CBOR (canonical)" (selected at load); "EDN" → "EDN (exact bytes)"; "CBOR (CTAP/WebAuthn Data)" → "CBOR (CTAP/WebAuthn Data)"; "JSON (binary)" → "JSON (binary)"; "DER" → "DER"; "PEM" → "PEM"; "COSE" → "COSE". | `tab.html:141-152` | to map |
| CX-E2 | A 10-row text area, placeholder "Paste something here to encode...", no visible label, the same attributes as CX-D1. No lenient box in this mode. | `tab.html:155-166` | to map |
| CX-E3 | Buttons "Encode" (primary) and "Clear" (secondary). | `tab.html:169-172` | to map |
| CX-E4 | EDN is sent as written. Any other format is first read as JSON in the browser, then checked by `canEncodeToFormat`: CBOR, JSON and COSE need a value; DER and PEM need something convertible to bytes (a PEM, hex, base64 or base64url string, an array of 0–255, or such a value under `value`, `data`, `raw`, `binary`, `bytes`, `hex`, `base64`, `base64url`, `derBase64`, `pem`, searched recursively); "CBOR (CTAP/WebAuthn Data)" is not checked. | `process.js:47-78`, `encoding/index.js:7-22`, `encoding/binary.js` | to map |
| CX-E5 | The request: `{"payload": <input>, "mode": "encode", "format": <the option's value>}`; `lenient` is never sent. | `process.js:113-118` | to map |
| CX-E6 | Progress "Encoding…" (U+2026), as CX-D5. | `tab.html:174-177`, `process.js:106` | to map |

## Status messages

Each is a toast at the bottom of the page: one at a time, hidden after 5 s (`status.js:1,24-48`), green for
success and red for an error.

| ID | Current behaviour (verbatim) | Where | New |
|---|---|---|---|
| CX-S1 | Decode with an empty (or blank) input: "Codec input is empty. Please paste something to process." | `process.js:38-44` | to map |
| CX-S2 | Encode with an empty input, whatever the format (EDN too): "Encoder input is empty. Provide JSON to encode." | `process.js:38-44` | to map |
| CX-S3 | Encode with no format: "Select an encoding format before encoding." (the select always has one, so only a stripped page reaches it). | `process.js:53-56` | to map |
| CX-S4 | Encode, not EDN, input not JSON: "Encoder expects valid JSON input." | `process.js:60-67` | to map |
| CX-S5 | Encode, input JSON but not convertible: "Input cannot be converted into ${the option's value}." (e.g. "Input cannot be converted into PEM."). | `process.js:69-75` | to map |
| CX-S6 | A validation message (CX-S1–S5) leaves the previous result, if any, where it was: validation returns before the output is cleared. | `process.js:37-78,87-101` | to map |
| CX-S7 | Success: "Response decoded successfully!" / "Payload encoded successfully!" | `process.js:153-156` | to map |
| CX-S8 | Failure: "Decoding failed: ${message}" / "Encoding failed: ${message}", where the message is the server's `error` (for a 422: "Not well-formed CBOR at offset 3 (${3}): map key 3 has no value", "Not JSON at offset 6 (${"a"}): NaN is not JSON: …", "EDN is not valid at offset 4: …"; the offset and path are shown only inside that sentence, the body's `offset` and `path` fields are not read). | `process.js:159-174`, `server/app/routes/general.py:422-476` | to map |
| CX-S9 | A failed response is read by `readFailedResponse`: the server's `error`, else short plain text, else the status's sentence ("The server could not accept the request.", "The request is larger than the server accepts.", "The server failed while handling the request.", "The server is unavailable.", …), with the advice "Send a smaller request." (413), "Try again in a moment." (503), "Try again." (409); an HTML page is never shown. | `failed-response.js:8-137` | to map |
| CX-S10 | A 200 whose body is not JSON: "Decoding failed: Failed to parse decoder response." (the same sentence after "Encoding failed: " in encode mode). | `process.js:132-137` | to map |
| CX-S11 | On failure the output is hidden, the Raw button disabled and an open raw view closed. | `process.js:159-169` | to map |

## Supported Inputs (decode only)

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-I1 | Title "Supported Inputs:", then six lines, each a format name and chips (verbatim): "JSON:" PublicKeyCredential (registration) · PublicKeyCredential (authentication) · Generic JSON payloads; "JSON (binary):" clientDataJSON · Generic JSON payloads; "CBOR:" Attestation objects · CTAP makeCredential request · CTAP makeCredential response · CTAP getAssertion request · CTAP getAssertion response · CTAP getInfo response · Generic CBOR payloads; "Binary:" Authenticator data · Signature fields; "PEM:" X.509 certificates · Certificate chains; "DER:" X.509 certificates. | `tab.html:40-79` | to map |
| CX-I2 | Shown whenever no decode result is shown (at load, after Clear, after a failure); hidden while one is. The encode panel has no such list. | `dom-state.js:23-40`, `process.js:20-24` | to map |

## The output: header and notes

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-O1 | Hidden until a result arrives; a new request hides the old result first (cleared before the request is sent). | `process.js:87-104,146-148` | to map |
| CX-O2 | Heading "Codec Output" (`h3`) with a "Raw" button (disabled until a result with content). | `tab.html:113-129,179-195` | to map |
| CX-O3 | A pill "Success" (green) or "Error" (red) from `success`, shown uppercased by CSS. | `render-sections.js:222-225` | to map |
| CX-O4 | The answer's `type` beside it (e.g. "CBOR (SUCCESS status; GetInfo response)", "Attestation object", "EDN (encoded)"), or "Decoded data" when there is none. | `render-sections.js:227-230` | to map |
| CX-O5 | An answer that is not an object: only "No decoded data available." | `render-sections.js:211-217` | to map |
| CX-O6 | `decodeMode` "lenient": the note "Decoded in lenient mode (best effort); skipped items are listed below." | `render-sections.js:234-239` | to map |
| CX-O7 | No section to show: "No structured data available." | `render-sections.js:258-262` | to map |

## Findings

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-F1 | When `findings` is not empty: a heading "1 finding" or "${n} findings", then one line per finding, in the server's order. | `render-sections.js:183-206,241-243` | to map |
| CX-F2 | Each line: `${source}: ` when the finding has a `source` (a PublicKeyCredential field or SafetyNet part, e.g. "response.clientDataJSON"), then `offset ${n} · ` (U+00B7) only when the offset is an integer, then the path (e.g. `$`, `${1}`, `${"a"}`), then ` — ` (U+2014) and the message. A JSON finding (offset `null`) shows its path alone. | `render-sections.js:193-202` | to map |
| CX-F3 | A finding's `category` (`rendering`, `canonical`, `malformed`, `skipped`, `trailing`, `json`, `limit`, `input`, …) and `code` are not shown. | `render-sections.js:193-202` | to map |
| CX-F4 | When there are no findings but `malformed` is not empty: "Malformed segments: ${messages joined by ", "}", in encode mode too. | `render-sections.js:244-249` | to map |
| CX-F5 | Text only: a message that quotes the input is never markup. | `render-sections.js:181-182`, `codec.test.js` | to map |

## Decoded sections

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-X1 | Each key of `data` is a section: its heading (CSS uppercases it) is `formatKey(key)`, its body the value. `data` that is `null`, a primitive or an array is one section headed `formatKey(type || 'Data')`; no `data`, no sections. | `render-sections.js:34-72,124-132` | to map |
| CX-X2 | Order by the type before " (": PublicKeyCredential: credential, attestationObject, attestationStatementDecoded, authenticatorData, clientDataJSON, clientExtensionResults, extensionsDecoded, responseDetails · Attestation object: attestationObject, attestationStatementDecoded, authenticatorData, extensionsDecoded, extensions, edn · Authenticator data: authenticatorData · WebAuthn client data: clientDataJSON · X.509 certificate: raw, pem, parsedX5c, certificates · CBOR: ctapDecoded, getInfoDecoded, attestationStatementDecoded, extensionsDecoded, expandedJson, decodedValue, ctap, edn. Keys present come in that order, then every other key in the answer's order. | `render-sections.js:74-132` | to map |
| CX-X3 | The 88 labels (verbatim, `formatKey` returns each unchanged): `aaguid` AAGUID · `alg` Algorithm · `attestationObject` Attestation object · `attStmt` Attestation statement · `authenticatorData` Authenticator data · `authenticatorAttachment` Authenticator attachment · `base64` Base64 · `base64url` Base64url · `bin` Binary · `cbor` CBOR · `byteLength` Byte length · `clientDataJSON` Client data JSON · `clientExtensionResults` Client extensions · `cose` COSE key · `counter` Counter · `expandedJson` Expanded JSON · `edn` EDN (exact bytes) · `decodedValue` Decoded value · `encodedValue` Encoded value · `ctap` CTAP metadata · `binary` Binary summary · `ctapDecoded` CTAP decoded · `paddingBytes` Padding bytes (all 00 or ff) · `trailingBytesHex` Trailing bytes (hex) · `makeCredentialResponse` MakeCredential response · `getAssertionResponse` GetAssertion response · `credential` Credential · `credentialId` Credential ID · `credentialIdLength` Credential ID length · `credProps` Credential properties · `data` Data · `derBase64` DER (Base64) · `extensions` Extensions · `fingerprint` Fingerprint · `hex` Hex · `issuer` Issuer · `key_size` Key size · `fmt` Format · `md5` MD5 · `not_valid_after` Not valid after · `not_valid_before` Not valid before · `origin` Origin · `parsedX5c` Certificate details · `publicKeyInfo` Public key info · `pem` PEM · `publicKey` Public key · `publicKeyAlgorithm` Public key algorithm · `pub` Public key bytes · `raw` Raw · `rawId` Raw ID · `rawJson` Raw JSON · `responseDetails` Response details · `rpIdHash` RP ID hash · `sig` Signature · `signature` Signature · `signature_algorithm` Signature algorithm · `sha1` SHA1 · `sha256` SHA256 · `structure` Structure · `signatureLength` Signature length · `subjectPublicKeyInfoBase64` Subject public key (Base64) · `subject` Subject · `subject_key_identifier` Subject key identifier · `subject_public_key_info` Subject public key info · `transports` Transports · `meaning` Meaning · `code` Code · `codeHex` Code (hex) · `kind` CTAP type · `payloadLength` Payload length · `valueSummary` Value summary · `keySummary` Key summary · `type` Type · `userHandle` User handle · `uuid` UUID · `uncompressedPoint` Uncompressed point · `x5c` X5C · `getInfoResponse` GetInfo response · `getInfoDecoded` GetInfo (interpreted) · `extensionsDecoded` Extensions (interpreted) · `attestationStatementDecoded` Attestation statement (interpreted) · `attestationTypesSupported` Attestation types supported · `defaultWhenAbsent` Default when absent · `notChecked` Not checked · `notInSyntax` Not in the format's syntax · `parseError` Parse error · `keyDescription` Key description · `spec` Spec | `constants.js:1-90` | to map |
| CX-X4 | Any other key through `formatKey`: a key the decoder spelled as data (a typed spelling such as `"1" (text)` or `h'01' (bytes)` with an optional ` #n`, an EDN start `"`, `'`, `h'`, `float'`, `simple(`, `invalid(`, `[`, `{`, an EDN number or word such as `-Infinity`, `NaN_2`, `1.5_3`, `true`, or a tag `1(…)`) is shown exactly as written; up to four capitals or digits as written; a leading `-` before a digit kept (COSE `-1`, `-2`, `-3`); otherwise `_` / `-` become spaces, camelCase is split, a word of one to three lower-case letters is upper-cased, others get a capital. Resulting quirks kept: `json` → "Json", `notRebuildable` → "NOT Rebuildable", `getAssertionRequest` → "GET Assertion Request", `colonHex` → "Colon Hex"; a non-string or empty key → "Value". | `labels.js:1-58`, `labels.test.js` | to map |

## Values

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-V1 | `null` / `undefined`: "null" / "undefined" in muted text. | `render-values.js:40-45` | to map |
| CX-V2 | A string: on one line in monospace, or as a preformatted block when it holds a newline or is longer than 80 characters. Bytes arrive as hex strings and are shown so. | `render-values.js:47-53` | to map |
| CX-V3 | A number or boolean: its text (`String(value)`). | `render-values.js:55-60` | to map |
| CX-V4 | An empty array "[]", an empty object "{}" (muted). | `render-values.js:62-68,80-87` | to map |
| CX-V5 | An array: a list, one item per element (bullets), each rendered by these rules. | `render-values.js:70-77` | to map |
| CX-V6 | An object: a definition list, term `formatKey(key)`, detail the value by these rules; nested lists indented under a left rule. | `render-values.js:89-105` | to map |
| CX-V7 | Badges above an object's list: "Unknown" when `known` is `false`; "Not verified" when `verification` says "not verified" (any case); "Deprecated" when `deprecated` is `true` or a string. The `known`, `verification` and `deprecated` rows stay in the list. | `render-values.js:3-37` | to map |
| CX-V8 | No copy control and no truncation anywhere; values, blocks and messages are selectable, headings, terms, pills and chips are not. | `styles/shared/text-selectability.css` | to map |

## EDN and Expanded JSON

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-N1 | `edn` (only when the decoder could write it exactly): a disclosure headed "EDN (exact bytes)", **closed** at first, holding the notation as text in a preformatted block (a non-string would be shown as its JSON). | `render-sections.js:12-32` | to map |
| CX-N2 | `expandedJson` at the top level: a read-only text area (no wrapping, sized to its content) holding `{"decoded json": <value>}` indented by two spaces, or "Unable to render expanded JSON" if that fails. Nested deeper, it is an ordinary object. | `render-sections.js:47-53`, `render-values.js:114-129` | to map |

## Interpretation, CTAP metadata, certificates

These have no renderer of their own: they are sections and values under CX-X and CX-V.

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-P1 | `attestationStatementDecoded` "Attestation statement (interpreted)": `fmt`, `known`, `spec`, `attestationTypesSupported`, `verification` (hence "Not verified"), `fields`, `missing`, `notInSyntax`, `notChecked`, … | server `decode/interpretations.py`; CX-V7 | to map |
| CX-P2 | `extensionsDecoded` "Extensions (interpreted)": a list of blocks (`location`, `path`, `role`, `spec`, `basis`, `source`, `entries` each with `value`, `known`, `spec` or `meaning`, `note`); an unknown extension shows "Unknown". | same | to map |
| CX-P3 | `getInfoDecoded` "GetInfo (interpreted)": per member `value`, `meaning`, `defaultWhenAbsent`, `sent`, AAGUID `hex` and `guid`, … | same | to map |
| CX-P4 | `ctap` "CTAP metadata": Code (may be "null"), Code (hex), `status` / `command`, CTAP type, Meaning, Message, Payload length, **Trailing bytes (hex)** and **Padding bytes (all 00 or ff)** when bytes follow the item, "NOT Rebuildable" when the view cannot be encoded back. | server `decode/ctap.py`, `ctap_prefix.py` | to map |
| CX-P5 | `ctapDecoded` "CTAP decoded" and `expandedJson`: the message's members labelled as sent (`"1 (fmt)"`, …). | same | to map |
| CX-P6 | Certificates: for "X.509 certificate", Raw, PEM, Certificate details (version, serial number, signature algorithm, issuer, validity, subject, public key info, extensions, fingerprints, signature, DER (Base64), PEM), Certificates for a chain; inside an attestation object, `attStmt.x5c` entries with `parsedX5c`, `pem`, `raw`. | server `certificates.py`; CX-X, CX-V | to map |

## Raw views

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-R1 | "Raw" opens a modal dialog (`role="dialog"`, `aria-modal="true"`) titled "Raw Codec Output" (decode) or "Raw Encoder Output" (encode), holding the **whole answer** (`JSON.stringify(payload, null, 2)`) in a focusable preformatted block. | `modals/decoder-raw.html`, `modals/encoder-raw.html`, `process.js:142-145` | to map |
| CX-R2 | Closed by its × button (accessible name "Close raw codec output" / "Close raw encoder output"), by a click on the backdrop, or by "Raw" again; Escape does not close it; focus is not moved in or back. | `panel-actions.js:59-87`, `main.js:339-346`, `core.js:246-345` | to map |
| CX-R3 | "Raw" does nothing while disabled or with no content; a new request, a failure and Clear close an open raw view. | `panel-actions.js:73-80`, `process.js:99-101,166-168` | to map |

## Encode output

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-C1 | The first binary summary in the answer (an object with a non-empty `hex`, `base64` or `base64url`: `data` itself, its `binary`, or deeper, in key order) is one section, headed by the key that holds it through `formatKey`, or "Encoded output" (a key reading "Binary" becomes "Encoded output"; `binary` itself reads "Binary summary"). | `render-sections.js:137-179`, `encoding/summary.js` | to map |
| CX-C2 | In it, one labelled block per view, in this order: "Hex", "Base64", "Base64url", "Colon Hex", then every other non-empty string in the summary (label by `formatKey`), except `encoding`. | `encoding/format-elements.js:3-57` | to map |
| CX-C3 | Then "Byte length: ${n}" (`byteLength`, else `length`). | `render-sections.js:164-175` | to map |
| CX-C4 | No summary, or no view in it: the decode sections (CX-X) instead. | `render-sections.js:139-147` | to map |
| CX-C5 | Not shown in the output (only in the raw view): `pem`, `derBase64`, `json`, `text`, `decodedValue`, `encodedValue`, `ctapDecoded`, `ctap`. | `render-sections.js:137-179` | to map |
| CX-C6 | The type reads as the server wrote it: "CBOR (canonical) (encoded)", "EDN (encoded)", "CBOR (CTAP/WebAuthn Data) (encoded ${message})", "JSON (encoded)", "DER (encoded)", "PEM (encoded)", "COSE (COSE_Key)". | server `encode/handlers_basic.py:24-40` | to map |

## Clear

| ID | Current behaviour | Where | New |
|---|---|---|---|
| CX-L1 | "Clear" empties that panel's input, result and raw view, disables Raw, closes an open raw view, hides that panel's status and progress, and (decode) shows Supported Inputs again. It keeps the lenient box and the format, and does not stop a request already sent (its answer is still shown when it arrives). | `panel-actions.js:16-57` | to map |
