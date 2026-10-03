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

## Credential artifacts

Credential artifacts (`server/app/storage/credential_artifacts.py`) are kept per session
on both backends (locally `<artifact dir>/<session>/`) and merge the same way:
conditional on the generation on GCS, under the record's `flock` locally. Their
reads keep the same three cases: an artifact that cannot be read raises
`StorageReadError` (503), one that does not decode is logged by name and treated
as absent. A merge that cannot read the record, or whose record does not decode,
refuses rather than overwrite it, and one whose write raised is re-read: it counts
as stored if the record holds every merged value.

## Listings

Listings stay inside what they need: `session_metadata.list_sessions` reads session
names as prefixes (`cloud.list_prefixes`), so a flat object is not a session.
`tests/app/storage/fake_gcs.py` records each listing's prefix and delimiter.

## Names

A name the store refuses raises `common.InvalidStorageIdentifier`, a `ValueError`
that `routes/errors.py` answers with 400 and no traceback.

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
  mints it (`visitor_session.ensure_id`); a route that only reads mints none. It
  lasts a year and is signed again once a day old. A namespace idle for 14 days is
  removed whole, on both backends, by one sweep at most every 6 hours
  (`visitor_session.schedule_cleanup`). Deleting a visitor's last upload removes only
  the local uploads folder, never their credentials or artifacts.
