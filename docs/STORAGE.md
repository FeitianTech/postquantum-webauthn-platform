# Storage

`server/app/storage/` keeps what the app persists: `credentials.py` (credential
records), `record_format.py` (the JSON envelope and the restricted reader for
legacy `.pkl` copies), `session_metadata.py`, `cloud.py` (Cloud Storage) and
`common.py`. Credential artifacts live in `server/app/credential_artifacts.py`.
These are its rules. Read them before changing `server/app/storage` or
`credential_artifacts.py`; `AGENTS.md` keeps only a summary.

## Compare-and-swap

Every read-modify-write of credential records (the signature counter, appending a
registration) goes through `read_for_update` / `save_if_unchanged`,
compare-and-swap: a GCS generation precondition, or locally an `flock` on the
file's `.lock` beside it (`common.file_lock`, with `common.replace_file` and
`common.file_digest`).

`delkey` empties the current copy -- it leaves it in place, holding no records,
whenever any copy existed -- and removes every legacy copy, locally under that
lock. A save whose records came from a legacy copy holds "there is no current
copy" as its version; a removed current copy would make that true again and let
the save write deleted records back.

## What a read tells apart

A store read tells three cases apart. Nothing stored is fine. A copy or a listing
that cannot be read (an I/O or Cloud Storage error) raises `common.StorageReadError`,
never a shorter list; `routes/errors.py` answers 503. Content that does not decode
is logged by file or object name (never its content) and skipped, and
`iter_credentials` / `list_credentials` count it in their `undecodable` list.

## Legacy copies

The first copy that exists is the user's: an older one never stands in for it.
`read_for_update` refuses a current copy it cannot decode
(`credentials.CredentialsUndecodable`) rather than let the save replace it unread,
and with no current copy it refuses a first legacy copy that does not decode: the
save would shadow it, and delete a session `.pkl`, unread.

## Credential artifacts

Credential artifacts (`server/app/credential_artifacts.py`) are kept per session
on both backends (locally `<artifact dir>/<session>/`) and merge the same way:
conditional on the generation on GCS, under the record's `flock` locally. Their
reads keep the same three cases: an artifact that cannot be read raises
`StorageReadError` (503), one that does not decode is logged by name and treated
as absent. A merge that cannot read the record, or whose record does not decode,
refuses rather than overwrite it, and one whose write raised is re-read: it counts
as stored if the record holds every merged value.

## Listings

Listings stay inside what they need: the legacy pass lists `user-data/` with the
`/` delimiter, so it never walks every session's objects, and
`session_metadata.list_sessions` reads session names as prefixes
(`cloud.list_prefixes`), so a flat legacy object is not a session.
`tests/app/storage/fake_gcs.py` records each listing's prefix and delimiter.

## Names

A name the store refuses raises `common.InvalidStorageIdentifier`, a `ValueError`
that `routes/errors.py` answers with 400 and no traceback.
