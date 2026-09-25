# The decoder and encoder

`server/app/decoder/` is the codec behind the Decoder tab and `/api/decode`,
`/api/codec`: `decode/` reads what it is given and shows what it holds, `encode/`
writes a value back. These are its rules. Read them before changing anything
under `server/app/decoder`; `AGENTS.md` keeps only a summary.

## What the decoder shows

The decoder shows what was sent: it never synthesizes or drops a field (the old
"repair" code did, for a set of corrupt captures), and bytes after the top-level
item are reported, never decoded or dropped.

Interpretation sits beside the decoded value, never in place of it:
`decode/interpretations.py` adds `data.extensionsDecoded` (`decode/extensions.py`,
CTAP 2.2 section 12 and WebAuthn L3 section 10) and `data.attestationStatementDecoded`
(`decode/attestation_statement.py`, WebAuthn L3 section 8, which calls
`tpm_structures.py`, `android_key.py`, `safetynet.py`, `apple_anonymous.py`), and
`decode/get_info.py` reads authenticatorGetInfo. It shows, it does not verify:
every attestation view says so and lists what it did not check.

## Tables and registries

`ctap_tables.py` is the one CTAP table both sides read (command and status bytes,
request parameters, response members), derived from the vendored `fido2`; COSE
algorithm names come from `webauthn/pqc.py`'s `describe_algorithm`. Do not add
another copy of either. CTAP numbers and names (getInfo members and options,
extension identifiers) go in `ctap_tables.py`, COSE registries in
`decoder/cose_tables.py` (shared with `encode/cose_key.py`).

DER is read only through `cryptography` (`x509` and `hazmat.asn1`), never by hand.

## Reading CBOR

Decoder input is parsed only by `decode/cbor_parser.py`: strict, failing with
the offset and path where input stops being well-formed; lenient only when a
request sends `"lenient": true`, and the response then lists what it skipped.
Never decode input with `fido2.cbor`, cbor2 or fido2's `AttestationObject` /
`AuthenticatorData` (`test_decoder_parses_cbor_only_itself.py` checks).

## Readings

Text that is both hex and a JSON number is read by the precedence in
`decode/ambiguous_input.py` (hex only when it is one well-formed CBOR item), and
the response names the reading not taken.

## Findings

`decode/canonical.py` reports CTAP2 canonical-form violations as `findings` on
every decode; the CTAP2 key order is `decoder/ctap2_order.py`, shared with the
encoder.

Findings inside authData, a nested PublicKeyCredential field or a TPM structure
carry the input offset and path (`${2}<credentialPublicKey>{1}`; a nested field's
findings add `source`).

`malformed` lists the messages of the findings that the input is not well-formed
(RFC 8949 appendix F, trailing bytes included) or not in CTAP2 canonical form: the
categories `skipped`, `malformed`, `trailing` and `canonical` in
`decode/findings.py`. Notes about how the input was read or shown
(`ambiguous-input`, `json-key-collision`, `duplicate-json-key`, `ctap-prefix-not-read`,
`ctap-non-integer-key`, a CTAP limit) are in `findings` only.

## Map keys

Map keys become JSON keys only through `keys.json_keys`: keys that would share a
spelling (1 and "1", h'01' and "01") are each spelled with their type, and
`decode/key_collisions.py` reports the map as `json-key-collision`.

Map keys are equal by RFC 8949 section 5.6.1 (`decode/key_equivalence.py`): 1.0 at
any width is one key, -0.0 and 0.0 are one key, a chunked string equals the same
text unchunked, NaNs differ by payload, 1 and 1.0 differ. Equal keys are one entry
of `decodedValue` (the later value) and one `duplicate-map-key` finding at the entry
kept, whose `earlier` lists every earlier entry's offsets and key and value in EDN;
inside a value the decoded value drops, `kept` is null and the message says none is
kept (`duplicate-json-key` does the same).

A key `json_keys` spells with its type is written by `keys.qualified_key_text` and
read back only by `keys.read_json_key`, which the encoder uses for every object key
it writes: `"1" (text)`, `h'01' (bytes)`, `1.5 (float)`, `[1, 2] (array)`. A key
that looks typed (an EDN literal, then ` (<kind>)`) but whose kind is unknown, or
one a lenient decode could not read, is an error naming the key; anything else is
a text key, so `Temperature (C)` stays text. Two JSON keys that make equal CBOR
keys are refused, naming both.

## JSON input

JSON input is read by `decode/json_input.py`, which reports a key given twice in
one object as `duplicate-json-key` (the path, the value kept and the values
dropped; no offset, which the JSON reader cannot give); the encoder refuses such
input and points at EDN, which can express it. The encoder shows the JSON it was
given back with its keys as written (`keys.as_written` marks them `JsonLabel`), so
its own output can be pasted back in.

## The EDN view and EDN input

`decodedValue` is JSON, so it is lossy by nature: it cannot show a key's CBOR
type, a head's width, a chunked string, a float's width, a NaN's payload or a
duplicated key. `data.edn` is the lossless view beside it, the item in extended
diagnostic notation (RFC 8949 section 8, draft-ietf-cbor-edn-literals), written by
`decoder/edn/spell.py` with an encoding indicator only where the bytes differ from
preferred serialisation. It is given for CBOR readings (a plain item, a CTAP
message's item past its command or status byte, which stays in `data.ctap`, and
an attestation object), and only when it is exact: `decode/edn_view.py` reads the
text back and compares it with the item's bytes, so a tree the lenient parser
could not read whole gets no EDN rather than a wrong one (`spell` itself refuses a
node whose text would not span its bytes, which catches damage the lenient parser
leaves unmarked).

The encoder's EDN input (format `EDN`, also `edn (exact bytes)` and `cbor (edn)`)
is `decoder/edn/reader.py`: it writes exactly the bytes the text notates -- map
order, duplicate keys, head and float widths as written, never canonicalised --
and refuses, with the offset in the text as sent, reserved indicators, an
indicator too narrow for its value, a float not exact at its width or beyond a
double's range, `simple(24..31)`, a signed tag number, a `(_ ...)` chunk that is
not a byte or text string, a lone surrogate, items nested more than 64 deep (the
decoder's limit), a CBOR sequence and an integer beyond 64 bits. That last is a
deliberate departure from the EDN draft, which reads such an integer as a bignum:
write the tag, `2(h'...')`.

Decode then encode of `data.edn` gives back the input's bytes:
`tests/app/decoder/test_edn_round_trip.py` proves it with Hypothesis over
generated items (`tests/app/cbor_items.py`: every head width, chunked and
zero-chunk strings, duplicate keys, nested tags, raw-bit floats) and over every
CBOR input in the goldens and fixtures (`tests/app/codec_corpus.py`), at the
module and at the API. Hypothesis writes `.hypothesis/` in the working directory
whatever its `database` setting, so `tests/conftest.py` points
`HYPOTHESIS_STORAGE_DIRECTORY` at a temporary directory and loads a derandomized
profile with no example database.

## CTAP messages

A CTAP member label applies only to an integer key in a CTAP message; user
entities, credential descriptors and attestation objects are read by their text
keys.

The encoder never reads a plain map as a CTAP message. It encodes CTAP from
`ctapDecoded`, from `expandedJson` beside a `ctap` object, or from the
`ctap-webauthn` format; anything else in format `CBOR` is generic CBOR, so
`{"1": "a"}` is `a161316161`. A makeCredential or getAssertion view shows every
key of the map, spelling a non-integer key with its type, and
`decode/ctap_conformance.py` reports each as `ctap-non-integer-key`.

The encoder refuses a decoded-JSON member it cannot rebuild rather than dropping
it; that includes a CTAP member whose value is null.

## Encoder bytes

Encoder bytes come only from `decoder/cbor_canonical.py`, which writes
CTAP2-canonical CBOR, for JSON input, and from `edn` for EDN input; do not
serialise encoder output with cbor2. Every CBOR head either writes goes through
`decoder/cbor_head.py`.

## Where new code goes

`decode/ctap.py` and `decode/pipeline.py` are under the module size limit now;
keep them there by putting new code in a module named for what it does, as
`ctap_prefix.py` (the command or status byte), `findings.py` (collecting and
ordering findings), `ctap_responses.py` (makeCredential and getAssertion response
views), `authenticator_data.py`, `json_input.py`, `edn_view.py`,
`key_equivalence.py` and `ctap_conformance.py` are.
