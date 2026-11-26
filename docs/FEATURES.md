# What the site does

## Simple Authentication

Register under a username and sign in, with fixed settings: a cross-platform authenticator (a
security key or a phone), and no user verification, attestation or resident key asked for. A
ceremony that does not hold (a bad signature, or a challenge, origin or RP ID that does not match)
is refused; every other finding is a warning beside the result.

## Advanced Authentication

A registration and an authentication, each a form beside the request's JSON, each following the
other. A registration sets the user, challenge, timeout, attachment, resident key, user
verification, attestation, algorithms, hints, credentials to exclude (fake ones too), and the
credProps, minPinLength, credProtect, largeBlob and prf extensions. An authentication sets the user
verification, challenge, timeout, hints, credentials to allow (every saved one, the Simple tab's
too; one; none; fake ones), largeBlob and prf, and the hash the server checks the client data
with. The JSON can name the RP ID. The result lists each failed check as an error and each warning
as a warning, and opens each part of the browser's response in the Codec.

## Saved credentials

Every registration is kept in the browser and listed in both tabs. A credential's details show its
properties, the attestation's checks (signature, root, RP ID hash, AAGUID match) and what FIDO's
metadata says of the authenticator; its user, AAGUID, attestation format, authenticator data,
extension outputs and public key; and its registration: the findings in words, each certificate,
and every part the Codec decodes. A credential whose AAGUID has an MDS entry links to it. Deleting
one removes it from the server, then the browser, and a browser with WebAuthn's Signal API is told
([STORAGE.md](STORAGE.md)).

## Codec

Decode reads a PublicKeyCredential or client data, an attestation object, a CTAP makeCredential,
getAssertion or getInfo message, authenticator data, or X.509 certificates, given as JSON, PEM,
hex, base64url or base64, and shows each value with what it means and what it found, as sent:
nothing is repaired. Encode writes JSON as CBOR, a CTAP message, a COSE key, DER, PEM or JSON
bytes, and EDN as exactly the CBOR it notates ([DECODER.md](DECODER.md)).

## FIDO MDS Authenticators

Every authenticator in the FIDO Metadata Service, from a snapshot of its BLOB verified against the
FIDO root and the chain's revocation lists, and checked twice a day for a newer one
([MDS_SNAPSHOT.md](MDS_SNAPSHOT.md)). Filter, sort and resize the table; open an entry's statement,
status reports, certificates, raw JSON and the credentials saved for its AAGUID. Try in Advanced
sets up a registration with what the statement says the authenticator takes. Manage Metadata
uploads statements of your own: listed in front of FIDO's, and registrations are checked against
them with a warning that they are not FIDO's.

## Analyze Browser

Which browser this is, and what it says about WebAuthn: a secure context, the API, passkey
autofill, the JSON methods, `getClientCapabilities()`, a built-in authenticator that verifies the
user, a phone or tablet over hybrid. Each answer says where it came from, or that it cannot be
known; the report can be copied.

## Algorithms

Registrations offer ML-DSA-44, ML-DSA-65 and ML-DSA-87 (FIPS 204; COSE -48, -49, -50), then EdDSA,
ES256, RS256 and ES384. The Simple tab offers these; the Advanced form ticks them by default and
lists further classical ones.
