# Metadata & Storage

This page describes how authenticator metadata and demo credentials are persisted.

## Metadata Bootstrapping

On startup the server ensures that the FIDO Metadata Service (MDS) cache is populated. `routes/general.py` coordinates the bootstrap using a process-wide lock, downloads the signed JWS blob, and stores the bytes on disk while recording cache metadata. Automatic refreshes log successes, rate limits, and unexpected failures without interrupting the Flask worker.【F:server/server/routes/general.py†L30-L195】 The rendered `index.html` template receives any cached JWS and metadata state so the frontend can initialize instantly without waiting for an additional request.【F:server/server/routes/general.py†L120-L138】

The configuration module centralizes constants such as the metadata URL, filenames, cache paths, and trust anchors used to validate authenticity. These values live alongside the Flask app and `Fido2Server` instance, keeping all metadata artifacts within the `server/server/static` tree.【F:server/server/config.py†L103-L234】

## Session Metadata Management

General routes expose JSON APIs for uploading and listing session-specific metadata snippets. Uploaded files are validated, decoded as UTF-8, parsed into JSON, and stored using helper utilities from `metadata.py`. Errors are aggregated so the UI can report invalid uploads without disrupting successful files.【F:server/server/routes/general.py†L198-L240】 Session metadata files are stored under `server/server/static/session-metadata`, matching the note in the README that highlights where user-supplied metadata is kept.【F:README.adoc†L251-L258】

## Credential Persistence

Credential data captured during registration ceremonies is serialized with `pickle` and written to the server module directory. `storage.py` exposes helpers to save, read, and delete credentials, as well as convert COSE public keys into JSON-friendly structures used by the UI. Stored entries can be revisited through the advanced credential viewer or removed from the filesystem when users clear credentials via the web interface.【F:server/server/storage.py†L1-L79】【F:README.adoc†L251-L258】
