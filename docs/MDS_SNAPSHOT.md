# The FIDO MDS snapshot

The MDS explorer is backed by a generated snapshot of the FIDO Alliance
metadata service: seven files totalling about 30 MB, produced together by
`tools/update_mds_snapshot.py`.

| File | Size | Read by |
| --- | --- | --- |
| `blob.jwt` | 10 MB | the updater, to tell whether the BLOB changed (the server does not read it) |
| `fido-mds3.verified.json` | 7.1 MB | the server, as the base metadata payload |
| `fido-mds3.explorer.json` | 5.5 MB | the server, for the explorer table |
| `fido-mds3.explorer.full.json` | 7.1 MB | the browser, as a cacheable static asset |
| `*.meta.json` (three files) | ~1 KB | the freshness check and the explorer banner |

All seven live in one directory: `frontend/static/`, unless
`FIDO_SERVER_MDS_SNAPSHOT_DIR` names another (see "Where the files are").
**None of them is tracked in git** and none is baked into the container image.

## Why they are not in git

They were rewritten daily by a bot that pushed straight to `main`. That added
about 30 MB of new blobs to history every day (`.git` reached 198 MB over ~79
such commits), invalidated the image layer that `COPY frontend` produces, and
changed `BUILD_ID` — which is a content hash over every static file — so each
refresh also expired every cached asset URL for every client.

Removing them from `HEAD` stops the growth. It does not shrink the existing
history: the old blobs stay reachable from the ~79 commits that introduced them.
Reclaiming that space needs a history rewrite, which is a separate, deliberate
decision because it changes every commit id.

## Where the files are

`server/app/mds_snapshot_dir.py` names the seven files once and says where they are:
`snapshot_dir()` reads `FIDO_SERVER_MDS_SNAPSHOT_DIR` whenever a path is needed, and
without it answers `frontend/static`. It is a leaf with no Flask import, so every
reader and writer follows the one setting: the server's metadata loaders
(`webauthn/metadata/blob.py`), `/api/mds/metadata/base`, the provisioning below,
`tools/update_mds_snapshot.py`, and the packaged snapshot browsers load
(`/assets/<build id>/fido-mds3.explorer.full.json`, served from that directory with its
`.gz` sibling). The page is given that URL as `snapshotUrl` only while the file is there
and its meta matches the verified snapshot; otherwise it asks the explorer API, which
answers from the verified snapshot either way. The URL ends in `?v=<serial>.<digest>`
(the digest of the snapshot's ETag and generation time), which the route ignores: the
file is cached as immutable for a year and changes at runtime without a deploy, so a
new snapshot has to be a new URL.

Flask's own static route still serves `frontend/static` at `/`, but never a snapshot
file: the seven names and the `.gz` sibling are refused there (a copy in
`frontend/static` may be another snapshot than the directory's), and the versioned
route serves only the browsers' copy, from the snapshot directory. Nothing the pages
use asks for any other snapshot file (the current UI's fallback request for
`fido-mds3.verified.json.meta.json` is gone: the page's info carries the timestamp
whenever there is a snapshot).

The tests use it to keep off a developer's real snapshot: `tests/conftest.py` points
every test at an empty directory of the run's, and a test that needs a snapshot
points it at a copy of `tests/fixtures/mds/snapshot` (a small synthetic snapshot
built by `tests/app/metadata/mds_fixture.py` with the updater's own code). The browser
tests' Flask (`web/e2e/serve-flask.mjs`) serves such a copy too. Phase 30 moves the
snapshot out of `frontend/static` by changing the default here.

## How the snapshot reaches the application

`server/app/mds_provisioning.py` materialises the files into the snapshot directory
on demand, trying three tiers in order. It runs once per process, from the
background warm-up on a Cloud Run cold start and from the metadata bootstrap
otherwise.

The routes that read the snapshot (`/api/mds/metadata/info`, `explorer`,
`explorer/full`, `resolve`, `base`, the upload and the delete, and the browsers'
copy at its versioned URL) call `ensure_snapshot_available()` first: on a cold
instance they wait for the provisioning under way (about 20 s from Cloud Storage)
instead of answering meanwhile as if there were no snapshot, and after the first
attempt they return at once. The index page `/` does not wait (unless it
bootstraps the metadata itself), so a cold instance's first page is not held: its
inline info then has no `snapshotUrl`, and the explorer asks the API, which waits.

1. **Local files.** Anything already on disk is used unchanged. No network.
2. **Cloud Storage.** With `FIDO_SERVER_GCS_ENABLED` set, missing files are
   downloaded from `gs://$FIDO_SERVER_GCS_BUCKET/mds/` (the prefix is
   `FIDO_SERVER_MDS_GCS_PREFIX`, default `mds`). This is the production path:
   the Cloud Run service account already has access to the `pqcwebauthn`
   bucket, so no new credentials are involved.
3. **Upstream refresh.** As a last resort the packaged updater downloads the
   BLOB from `https://mds3.fidoalliance.org/` and verifies it against the
   GlobalSign R46 trust root pinned in the source before writing anything. The
   result is then uploaded to Cloud Storage, so the next cold start stops at
   tier 2.

Tier 3 is controlled by `FIDO_SERVER_MDS_FETCH_UPSTREAM`. It defaults to the
Cloud Storage setting: **on** in a deployed service, which can repopulate its
own bucket, and **off** locally, so a first request never silently blocks on a
10 MB download.

The browser-facing `fido-mds3.explorer.full.json` is written with its
precompressed `.gz` sibling, which is what `tools/build_static_assets.py` would
have produced had the file been present at image build time.

### When no tier succeeds

The application still starts and serves. `/health` and `/` work; the explorer APIs
answer `200` with no entries (their `404` branch is not reached: the snapshot they
compose always has its counts), `/api/mds/metadata/base` answers `404` with
"Verified metadata snapshot is not available", the page is given no `snapshotUrl` (so
it requests no missing file), and the explorer shows no entries (`/beta` says the
packaged metadata is unavailable). This is the behaviour that already existed for a missing snapshot —
the relocation did not introduce a new failure mode.

## Working locally without Cloud Storage

Run the updater once. It fetches and verifies the BLOB and writes all seven
files into the snapshot directory (`frontend/static/`, where they are gitignored):

```bash
python tools/update_mds_snapshot.py
```

After that the application uses tier 1 and needs no network at all. To check
that upstream is reachable and the BLOB still verifies without writing anything:

```bash
python tools/update_mds_snapshot.py --verify-only
```

## Publishing a snapshot to Cloud Storage

With credentials for the bucket configured (`FIDO_SERVER_GCS_ENABLED=1`,
`FIDO_SERVER_GCS_BUCKET`, and either application-default credentials or
`FIDO_SERVER_GCS_CREDENTIALS_FILE`/`_JSON`):

```bash
FIDO_SERVER_GCS_ENABLED=1 FIDO_SERVER_GCS_BUCKET=pqcwebauthn python tools/update_mds_snapshot.py --gcs-upload
```

The upload is refused unless all seven files are present, so a partial
generation can never half-replace what the bucket serves.

## The container image

`.dockerignore` keeps the snapshot out of the build context, so the image is
identical whether or not the developer has a local snapshot, and a refresh
never invalidates a layer. The image does carry
`tools/update_mds_snapshot.py`, which is what tier 3 runs.
