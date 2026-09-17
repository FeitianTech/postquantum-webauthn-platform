# The FIDO MDS snapshot

The MDS explorer is backed by a generated snapshot of the FIDO Alliance
metadata service: seven files totalling about 30 MB, produced together by
`tools/update_mds_snapshot.py`.

| File | Size | Read by |
| --- | --- | --- |
| `blob.jwt` | 10 MB | the server, to re-verify the signed BLOB |
| `fido-mds3.verified.json` | 7.1 MB | the server, as the base metadata payload |
| `fido-mds3.explorer.json` | 5.5 MB | the server, for the explorer table |
| `fido-mds3.explorer.full.json` | 7.1 MB | the browser, as a cacheable static asset |
| `*.meta.json` (three files) | ~1 KB | the freshness check and the explorer banner |

All seven live under `frontend/static/`. **None of them is tracked in git** and
none is baked into the container image.

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

## How the snapshot reaches the application

`server/app/mds_provisioning.py` materialises the files into `frontend/static/`
on demand, trying three tiers in order. It runs once per process, from the
background warm-up on a Cloud Run cold start and from the metadata bootstrap
otherwise.

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

The application still starts and serves. `/health` and `/` work; the metadata
APIs return `404` with "Verified metadata snapshot is not available", and the
explorer shows no entries. This is the behaviour that already existed for a
missing snapshot — the relocation did not introduce a new failure mode.

## Working locally without Cloud Storage

Run the updater once. It fetches and verifies the BLOB and writes all seven
files into `frontend/static/`, where they are gitignored:

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
