# Storage

`server/app/storage/` keeps what the app persists: `credentials.py` (credential
records), `record_format.py` (the JSON envelope), `credential_artifacts.py`,
`session_metadata.py` (visitors' uploads), `cloud.py` (Cloud Storage), `common.py`, and
`github_mirror.py` (the copy of registrations and uploads kept on GitHub). These are its
rules. Read them before changing `server/app/storage`; `AGENTS.md` keeps only a summary.

## Compare-and-swap

Every read-modify-write of credential records (the signature counter, appending a
registration) goes through `read_for_update` / `save_if_unchanged`,
compare-and-swap: a GCS generation precondition, or locally an `flock` on the
file's `.lock` beside it (`common.file_lock`, with `common.replace_file` and
`common.file_digest`).

## What a read tells apart

A store read tells three cases apart. Nothing stored is fine. A copy or a listing
that cannot be read (an I/O or Cloud Storage error) raises `common.StorageReadError`,
never a shorter list; `routes/errors.py` answers 503. Content that does not decode
is logged by file or object name (never its content) and skipped.

## A copy that does not decode

`read_for_update` refuses a copy it cannot decode
(`credentials.CredentialsUndecodable`) rather than let the save replace it unread.

## The Simple record

A Simple registration keeps, in its username's list, only what the counter check
reads (`routes/simple/stored_sign_count.counter_record`): the credential's ID and
its signature counter, with its registration's time and user handle. The browser
keeps the registration itself; nothing on the server read the rest back, and it
made a record of 72 KB to 1 MB for one ML-DSA-87 registration, rewritten whole at
every registration and authentication. A record an earlier version stored whole
is read the same way and brought to that form the next time its list is written;
one whose credential ID cannot be read is kept as it is.

Deleting a saved Simple credential in the page deletes its record too
(`DELETE /api/simple/credentials/<credentialId>?email=<username>`,
`routes/simple/deletion.py`): by compare-and-swap on the list, the username read as
the store names the file (so a record saved before the begins' 64-byte rule can go
too), answering `deleted`, `absent` or `failed` as the artifact DELETE does.

## Credential artifacts

Credential artifacts (`server/app/storage/credential_artifacts.py`) are kept per session
on both backends (locally `<artifact dir>/<session>/`) and merge the same way:
conditional on the generation on GCS, under the record's `flock` locally. Their
reads keep the same three cases: an artifact that cannot be read raises
`StorageReadError` (503), one that does not decode is logged by name and treated
as absent. A merge that cannot read the record, or whose record does not decode,
refuses rather than overwrite it, and one whose write raised is re-read: it counts
as stored if the record holds every merged value.

## What a registration keeps

A registration's record (the Advanced artifact's `storedCredential`, and the Simple
answer's, which the browser keeps) holds each part once:

- The browser's response as it was sent, `registrationResponse`: its attestation
  object, its client data and, where the browser gives them, its authenticator data
  and public key. The record keeps no other copy of the attestation object and no
  attestation statement, and the relying party's view names neither; the page decodes
  the response's attestation object.
- The credential's public key, as `publicKey` (the COSE key in base64url, which the
  page sends back to authenticate), with `publicKeyAlgorithm` and `publicKeyType`.
- The attestation certificates, in `properties.attestationCertificates`; the Advanced
  answer's `relyingParty.attestationCertificates` names them for the page's result.
  Each keeps every value in one form (`webauthn/attestation/certificates._registration_view`):
  its DER as `derBase64`, its signature's hex, a public key's base64. The PEM, the
  summary and the lines of hex are left out, and the page writes them from those
  fields (`web/src/logic/credentials/certificates/text.js`, equal to the server's
  summary over every certificate the characterization reads). A registration snapshot
  the page uploads keeps the certificates without their DER.
- What FIDO's metadata said of the authenticator, beside the attestation's checks
  (`properties.attestationSummary.metadata`, and `attestationChecks.metadata`): its
  entry's latest status and highest certification, `latest_status` and
  `certification_level`, as the MDS explorer writes them (`mds/statement_fields.py`),
  each null when no entry matched. A record from an earlier release keeps neither, and
  the page shows nothing for them.

One ML-DSA-87 registration with a leaf, intermediate and root certificate stored a
992 KB artifact and answered 568 KB (Simple: 515 KB) when each part was kept in
several spellings, up to four times; it stores 160 KB and answers 109 KB (Simple:
176 KB). Artifacts and records stored before keep their copies as they are, and the
page still reads them.

## Quotas

What one visitor's namespace keeps is bounded; each limit is read from the
environment in `config/request_limits.py` (`deploy/README.md` lists them). A write
past one raises `common.StorageQuotaExceeded` before anything is written, and
`routes/errors.py` answers it with its sentence: 409 for a count, 413 for bytes.

- Credential artifacts: 1,000 in a namespace, and 256 MiB of them. A new artifact
  past the count is refused, and so is a write that would take the namespace's
  artifacts past the bytes; a write that shrinks an artifact never is. An Advanced
  registration's begin refuses a namespace they already fill, so the authenticator
  is not asked for a credential that could not be kept; its complete refuses one
  that filled meanwhile, with the challenge's trace.
- Uploaded metadata: 2,000 entries in a namespace (each entry is a file of its own,
  with an info file beside it that is not counted), and 64 MiB of them. An upload
  whose entries would pass either is refused whole, before any file is saved or
  copied to the device log (`mds/uploads.refuse_past_quota`).
- Simple credentials: 100 in one username's list. The registration's begin refuses
  a full list before the authenticator is asked, and its complete checks the list
  its compare-and-swap would replace, so that count is exact.

The counts and sizes come from a listing of the namespace's objects
(`cloud.list_blob_stats`; a scandir locally, which leaves `.lock` and `.tmp` files
out), and so do the times of the uploads a listing names (`session_metadata.file_stats`).
A store that cannot be listed raises `StorageReadError` (503). Two writes at
once in one namespace can both pass the check, so a namespace can go past a limit
by the writes in flight; each write is still compare-and-swap where it was.

## Listings

Listings stay inside what they need: `session_metadata.list_sessions` reads session
names as prefixes (`cloud.list_prefixes`), so a flat object is not a session.
`tests/app/storage/fake_gcs.py` records each listing's prefix and delimiter.

## Names

A name the store refuses raises `common.InvalidStorageIdentifier`, a `ValueError`
that `routes/errors.py` answers with 400 and no traceback.

A Simple username names its list's file as it is, once trimmed: "Alice" and
"alice" are two accounts. Cloud Storage keeps their lists apart; on a
case-insensitive disk (macOS's default) they share one local file, whose records are
still told apart by credential ID, and whose length the per-username quota counts
for both.

## The session and the namespace cookie

Two cookies, both signed with the app's secret, `HttpOnly`, `SameSite=Lax`, and
`Secure` as `SESSION_COOKIE_SECURE` says (on Cloud Run):

- Flask's session holds a ceremony's state from its begin to its complete, and no
  store reads or writes it. Only an answer that changed it sets the cookie
  (`SESSION_REFRESH_EACH_REQUEST` is off, `config/session_cookie.py`), so an answer
  that lands after a begin cannot undo it; it is accepted for
  `FIDO_SERVER_SESSION_LIFETIME_SECONDS` (30 minutes) after it was signed. A begin
  whose cookie would pass the browser's 4 KB is refused with a 400 and leaves the
  session as it was (`routes/ceremony_session.py`).
- `fido.mds.session` names the visitor's namespace, under which every store keeps
  their records: locally `<store dir>/<namespace>/`, on Cloud Storage
  `user-data/<namespace>/<store>/`. A route that stores something for the visitor
  mints it (`visitor_session.ensure_id`), and so does the Simple registration's
  begin, whose user handle is derived from it (`routes/simple/account.py`); a route
  that only reads mints none. A namespace holds nothing until a store writes in it,
  so one minted by a begin that goes no further stores nothing. It lasts a year and
  is signed again once a day old. A namespace idle for 14 days is
  removed whole, on both backends, by one sweep at most every 6 hours
  (`visitor_session.schedule_cleanup`). Its last access is its `.last-access`
  marker's time (the visitor's requests refresh it, at most every 30 minutes; the
  request that minted a namespace does not, the next one does), else, for one
  written but never marked, its newest object's or file's time. Locally the
  namespace is its folder in each store
  (`config/paths.LOCAL_STORES`): the sweep lists the namespaces of all three and
  removes all three folders. Deleting a visitor's last upload leaves the namespace,
  its marker with it, for the sweep.
