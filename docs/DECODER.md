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
`data.getInfoDecoded` (`decode/get_info.py`, what an authenticatorGetInfo
response's members mean, CTAP 2.2 section 6.4). It shows, it does not verify:
every attestation view says so and lists what it did not check.

What a reading finds in a nested part is reported where the part is: a key
given twice in a SafetyNet JWS header or payload is a `duplicate-json-key`
finding at the attestation statement's `response` member, its path ending
`<JWS header>{"alg"}` and its `source` "SafetyNet JWS header" (or payload).

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

A byte or text string the lenient parser read past a skipped chunk is
`damaged`: it is no string it holds a part of, so as a map key it is equal only
to itself (`key_equivalence.identity` is its offset) and is spelled as a damaged
container key is, `invalid(bytes[1] at offset 1)`. Two such keys never merge
into one entry, and never merge with the string their surviving chunks spell.

## Readings

The decoder takes the first reading, in a fixed order, that reads its input, and
never picks silently: every later reading that also reads the input whole is
named in an `ambiguous-input` finding (`readAs`, `alsoValidAs`, a message).
`decode/ambiguous_input.py` holds the order and every pair of readings that can
both read one input, with an example of each; `decode/readings.py` is the binary
table itself, each reading with a strict "reads the whole input" test beside it.
"Whole" is strict whether or not the request asked for lenient decoding, so the
reading taken never depends on it.

Text, in order: JSON (RFC 8259, `null` too; text of hex digits that is also a
JSON number is hex when its bytes are one CTAP message, and the number
otherwise); PEM; hexadecimal (an even number of digits, `0x` only at the start,
`:` ignored); base64url, then base64. An odd number of hex digits
is no hexadecimal: `abc` is base64 (69 b7).

Bytes, in order: a lone CTAP command or status byte; PEM text; JSON text; a DER
certificate; an attestation object; one CTAP message or one CBOR item, whole;
authenticator data; CBOR, leniently when asked. One item comes before
authenticator data on purpose: about a quarter of all 37-byte items have a byte
32 without the AT and ED flags (a real 37-byte getInfo response is one), while
authenticator data that is also one item is a chance in tens of thousands.

What is the same item read for more is not named: an attestation object is one
CBOR item, client data is JSON text. What is named besides the bytes' readings:
the CTAP messages a map's shape fits (`ctap_classify.shape_findings`) and a
PublicKeyCredential that is also client data. `tests/app/decoder/test_edn_round_trip.py`
requires every input in the corpus that is not read as CBOR to carry the finding
naming the CBOR item.

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

`NaN`, `Infinity` and `-Infinity` are not JSON (RFC 8259), though Python's reader
takes them. Read strictly, input holding one is refused with a 422 naming the
offset and path of the first (`json_input.JsonConstantError`), and a nested field
holding one (client data inside a PublicKeyCredential) is that field's
`parse-error` finding; read leniently, each is a `json-nan-or-infinity` finding
(category `malformed`) and is shown as the decoder shows such a CBOR float,
`{"diagnostic": "NaN"}`. Every JSON read takes the request's leniency. The
encoder refuses such input the same way and points at EDN, which writes them;
the metadata upload refuses it. No answer may hold a bare `NaN`: Flask's JSON
provider would write it, and the answer would not be JSON.
`tests/app/core/test_codec_answers_are_json.py` parses every decoder and encoder
answer over the corpus with a reader that refuses them.

Every body is limited in size (`config/request_limits.py`: 8 MiB, the metadata
upload 16 MiB), and a larger one is answered 413 in JSON before the decoder
reads it.

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

A map read as a CTAP message (makeCredential or getAssertion, request or
response, or a getInfo response) is shown in `ctapDecoded` as
`{message: members}`, with its framing in `data.ctap`; `expandedJson` is the same
view, for makeCredential and getAssertion. The view is built once, from the
parser's nodes, by `decode/ctap_views.py`, and it shows every member as sent:
nothing added (no member the map did not hold, no wrapper around one it did),
nothing dropped (a null is null), nothing re-read (a byte string stays bytes).

- **Labels** (`decoder/ctap_message.py`): `"1 (fmt)"` for a member CTAP 2.2
  section 6 defines, the number alone for an integer it does not, any other key
  with its type, text too (`"rpId" (text)`). `decode/ctap_conformance.py` reports
  each key that is not an integer as `ctap-non-integer-key`, getInfo included.
- **Values** (`decoder/ctap_view.py`): a byte string is its lowercase hex; text
  is itself unless it would read as something else (an even number of hex digits,
  `""` too, or a typed spelling), when it is `"<text>" (text)` -- SafetyNet's
  `ver` "14574037" is `"14574037" (text)`; null, booleans and integers are JSON's;
  a float, a tag, a simple value and undefined are their EDN with their type,
  `"1.5 (float)"`, `"2(h'01') (tag)"`, `"simple(16) (simple value)"`. Inside a
  value a map's integer key is its number (`"1"`), unlike `decodedValue` and the
  encoder's plain JSON input, where `"1"` is the text "1"; text keys that look
  like integers, typed spellings or numbered labels (`"a #2"`) are typed.
  `ctap_view.read` reads that spelling back exactly and refuses, naming the JSON
  path, what it cannot read: a JSON number with a fraction or exponent, an
  integer beyond 64 bits, a key like `"01"`, a numbered or unknown spelling.
- **Interpreted in place**, carrying the bytes they were read from, which alone
  are read back (edits to the parsed fields are ignored): authenticator data,
  member 2 of both responses (`raw`, and `trailingBytesHex` for bytes past what
  its flags describe), and each x5c entry of a makeCredential response's
  attestation statement (`raw`, with `pem` and the certificate read, or why it
  would not read; an entry that is no certificate is kept).
- **getInfo** is shown as sent in `ctapDecoded.getInfoResponse`; what its
  members mean -- the aaguid as a GUID, each option with its default, algorithm
  names, uvModality bits, certification IDs -- is beside it in
  `data.getInfoDecoded`, labelled the same way, a member CTAP 2.2 does not define
  given as `{"value", "note"}`.
- **Framing** (`data.ctap`): `code`, the command or status byte sent before the
  message, or null when none was (a bare map); `message`, which view it is;
  `payloadLength`; `trailingBytesHex`, every byte after the message, padding too
  (all 0x00 or 0xff, counted in `paddingBytes`).
- **Self-check** (`decode/ctap_self_check.py`): the decoder rebuilds each view it
  shows with `ctap_message.rebuild`, the encoder's own writer, and compares. A
  message not in CTAP2 canonical form (a wide head, an indefinite length, keys
  out of order, a repeated key) or read past damage cannot come back from a JSON
  view; it is marked `data.ctap.notRebuildable`, saying why (the findings' codes
  and offsets, or the first offset that differs). Its `data.edn` is exact, and
  the EDN input gives its bytes back.

The encoder never reads a plain map as a CTAP message. `encode/ctap_views.py` is
its one path from a view back to bytes, for format `CBOR` and for the
CTAP/WebAuthn format alike: it takes `ctapDecoded`, or `expandedJson` beside a
`ctap` whose `message` names it, reads the members by the spelling above, writes
them in CTAP2 canonical form, and frames them exactly as `ctap` says -- the byte
if `code` is one and none if it is null, then `trailingBytesHex`. It refuses by
name a view without its `ctap`, a `ctapDecoded` whose message and `ctap.message`
disagree, a member given twice, a label that names no member, and a view marked
`notRebuildable` (pointing at `data.edn`). Anything else in format `CBOR` is
generic CBOR, so `{"1": "a"}` is `a161316161`. A `ctapDecoded` written by hand is
read by the same spelling: a base64 `clientDataHash` is text, not bytes.

The CTAP/WebAuthn format's other input, a numeric map written by hand without a
view, still goes through its own builders (`encode/ctap_numeric.py`,
`encode/ctap_encode.py`), which pick a message from the members present and add
a command or status byte.

Decode, view, encode gives back the input's bytes:
`tests/app/encoder/test_ctap_view_round_trip.py` proves it through `/api/codec`,
with both formats, over generated messages of every kind
(`tests/app/ctap_messages.py`, written by a canonical writer of the test's own,
with and without a CTAP byte and trailing bytes) and over every CTAP message the
repository holds (`codec_corpus.ctap_messages()`), where exactly the messages
not in canonical form or read past damage are refused.

The encoder refuses a decoded-JSON member it cannot rebuild rather than dropping
it.

## Encoder bytes

Encoder bytes come only from `decoder/cbor_canonical.py`, which writes
CTAP2-canonical CBOR, for JSON input, and from `edn` for EDN input; do not
serialise encoder output with cbor2. Every CBOR head either writes goes through
`decoder/cbor_head.py`.

## Where new code goes

`decode/ctap.py` and `decode/pipeline.py` are under the module size limit now;
keep them there by putting new code in a module named for what it does, as
`ctap_prefix.py` (the command or status byte), `ctap_classify.py` (a map's CTAP
shape), `ctap_views.py` (the views), `ctap_auth_data.py`, `ctap_self_check.py`,
`readings.py` (the binary readings), `findings.py` (collecting and ordering
findings), `authenticator_data.py`, `json_input.py`, `edn_view.py`,
`key_equivalence.py` and `ctap_conformance.py` are. Spelling shared by both
sides lives in `server/app/decoder/` itself (`ctap_view.py`, `ctap_message.py`,
`cbor_canonical.py`, `cbor_head.py`, `ctap2_order.py`), since `decode/` never
imports `encode/`.
