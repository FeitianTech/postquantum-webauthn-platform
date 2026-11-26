# Storage

`server/app/storage/` keeps what the app persists: `credentials.py` (credential
records), `record_format.py` (the JSON envelope), `credential_artifacts.py`,
`session_metadata.py` (visitors' uploads), `cloud.py` (Cloud Storage), `common.py`,
`github_mirror.py` (the copy of registrations and uploads kept on GitHub) and
`github_outbox.py` (what waits to be copied there). These are its rules. Read them before changing `server/app/storage`; `AGENTS.md` keeps only a summary.

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
  A map the authenticator keyed by byte strings, or by text beside integers, has its
  keys written as text in the Advanced artifact and answer, a byte string as base64url
  (`json_values.make_json_safe`'s `writable_keys`).
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
  with an info file beside it that is not counted: its names and time, and what the
  explorer and Manage Metadata list of it, at most about 20 KB, `mds/listed_uploads.py`),
  and 64 MiB of them. An upload
  whose entries would pass either is refused whole, before any file is saved or
  queued for the credential log (`mds/uploads.refuse_past_quota`). One entry larger
  than 1 MiB once stored is refused alone, in the upload's errors, and not counted.
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
  request that minted a namespace does not, the next one does; a metadata upload
  marks it once, before its entries are saved), else, for one
  written but never marked, its newest object's or file's time. Locally the
  namespace is its folder in each store
  (`config/paths.LOCAL_STORES`): the sweep lists the namespaces of all three and
  removes all three folders. Deleting a visitor's last upload leaves the namespace,
  its marker with it, for the sweep.

## The credential log

Each registration, and each uploaded metadata file, is copied to the owners' credential
log repository on GitHub (`GITHUB_LOG_REPO_OWNER`/`GITHUB_LOG_REPO_NAME`, by default
`rainzhang05/CredentialLogs`): a registration as `logs/<aaguid>/<time>_<random>.json` (its
time, RP ID, AAGUID, MDS device name, attestation object and the four checks), a metadata
file whole under `metadata/`, unless it is over 1 MiB (`MAX_LOGGED_METADATA_BYTES`: a file of
one statement fits, and a request without a cookie gets a namespace of its own, so the upload
quotas do not bound what the log keeps), which is not copied, with a warning naming it. At most
50 metadata files and 8 MiB of them are copied a day (UTC), counted when they are queued, and at
most 1,000 registrations and 64 MiB of them, counted when they are written (one found at its
path from an earlier delivery is not counted), each in one object beside the outbox
written by compare-and-swap (`github_outbox.take_metadata_budget`; `github_outbox._delivered`).
Past its budget, or while the budget cannot be read or written, an upload's files are not
queued, with one warning, and the upload goes on. Past its budget a registration's entry is
dropped from the outbox before GitHub is asked, with a warning naming it; while the budget
cannot be read, the entry stays queued, as one GitHub cannot take does, but never gets a failed
attempt (GitHub was not asked), and a delivery whose count cannot be written is warned about.
Each budget is one for all visitors, so
whoever spends it keeps that day's later uploads or registrations out of the log until 00:00 UTC;
what visitors save is unaffected. The log is on only with a
`GITHUB_TOKEN`, and `ENABLE_GITHUB_LOGGING=0` turns it off.

No request waits for GitHub. Once a registration's record is saved
(`record_registration_event`), or once an uploaded file has an entry saved
(`queue_uploaded_metadata_files`, from the upload route; a file none of whose entries saved is
not copied), the file is written to an **outbox** with the path it lands at, fixed then
(`github_outbox.enqueue`), and the request goes on: whatever fails there is a warning, never
the visitor's error.

- **Where entries wait.** On Cloud Storage under `github-outbox/` (`entries/<id>`, a `lease`
  object, the `metadata-budget` and the `registration-budget`), outside `user-data/`, so the idle
  sweep never removes them; locally in `FIDO_SERVER_GITHUB_OUTBOX_DIR`, else
  `instance/github-outbox` (`<id>.entry`, `.lease`, `.metadata-budget` and
  `.registration-budget`).
  An entry is a line of JSON (kind, path, commit message, and `attempts`, its failed attempts,
  once it has any: an entry without it has none) and the file's bytes. Ids begin with the time
  they were queued, so entries are delivered oldest first.
- **The bound.** 1,000 entries and 256 MiB (`MAX_ENTRIES`, `MAX_BYTES`), counted from one
  listing per request that queues. Past either an entry is dropped with a warning naming its
  path; a listing that fails is warned about and the entry written anyway. Two requests at
  once can both pass the bound, as with the quotas. Uploads queue at most the day's metadata
  budget, 50 entries and 8 MiB of file content, so while the outbox drains they cannot fill it
  ahead of registrations. Registrations are bounded only by this bound when they are queued, and
  past their budget dropped as their turn comes, without a GitHub call: a flood of registrations
  can keep the outbox full, and later entries out of it, while it lasts. The budgets let the log
  grow by about 1,050 files a day at most.
- **What delivers them.** `github_outbox.flush`, on a worker thread that requests start
  (`schedule_flush`): one before a request at most every 30 s per process, or every 10 minutes
  while its last run found the outbox empty (`github_mirror.init_app`), and one at once when a
  request has queued an entry, so entries another process queued and never delivered wait up to
  10 minutes for an idle one. On Cloud Run
  a run has CPU only while some request is being served, so it goes on through the requests
  that follow; one that stalls resumes at the next, and an instance that is stopped leaves its
  entries for the next instance's first request. A run delivers at most 20 entries; one that
  finds nothing queued stops at that listing and takes no lease.
- **One flusher at a time.** A run holds the outbox's lease for 300 s: on Cloud Storage the
  `lease` object, written only at the generation it was read at (as the stores write), so of
  two instances taking it one wins, and one past its time is taken over; locally an `flock` on
  `.lease`, which a stopped process gives up. A run starts no delivery with less than 60 s of
  its lease left, and gives it back at its own generation only, so a flusher that took over
  stays in charge. GitHub takes new files one at a time (its create-file endpoint refuses calls
  in parallel), and one holder makes "this content is there already" safe to check.
- **Delivery** (`github_mirror.deliver`). A file is created, never replaced. When GitHub says
  a file is at the path already, its blob SHA is read: the same content is an earlier delivery
  that landed: the entry is removed, but it is no sign that GitHub takes writes (below); so a
  delivery made twice (a run that stalled past its lease, a removal that failed after a landing)
  never becomes two files. The fixed path is the guarantee, not the lease. A metadata file whose
  content is anywhere in `metadata/` is not copied again, and is removed the same way: the
  folder is read through the git trees API (the root's listing names its tree), which lists all
  of it, where the contents API stops at 1,000 entries. A name holding
  other content is kept, and the new file goes beside it as `<name>-<first 12 of its blob
  SHA><extension>`.
- **Failures.** GitHub, the network or the token unable to take a file (401, 403, 404, 408,
  409, 429, a 5xx, a timeout, an answer that is not what the mirror reads) leaves the entry, and
  the run goes on to the next, stopping after 3 such in a row (`MAX_UNAVAILABLE_IN_A_ROW`). When
  a later entry in the same run is written (a file created now, not one found there already),
  GitHub was working: each entry passed over before it gets a failed attempt, rewritten into its
  entry under the lease (on Cloud Storage at the generation read), and one at 5 (`MAX_ATTEMPTS`)
  is dropped with a warning naming its path. It keeps its place, first in the next run. When no
  later entry is written, nothing is counted and every flusher leaves the outbox for 300 s: a
  full outage, a rate limit or a bad token costs 3 calls per 5 minutes and drops nothing. While
  GitHub fails only some calls, an entry can still reach the count; and three entries in a row
  that it never takes, at the front, hold the rest. A file GitHub refuses for good (another
  4xx), or that holds the only path left to it, is dropped with a warning; so is an entry that
  does not read.
