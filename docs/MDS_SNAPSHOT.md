# The FIDO MDS snapshot

The MDS explorer is backed by a generated snapshot of the FIDO Alliance
metadata service: seven files totalling about 30 MB, produced together by
`tools/update_mds_snapshot.py`.

| File | Size | Read by |
| --- | --- | --- |
| `blob.jwt` | 10 MB | the updater, to tell whether the BLOB changed (the server does not read it) |
| `fido-mds3.verified.json` | 8.2 MB | the server, as the base metadata payload: the BLOB's payload as the BLOB has it, once verified |
| `fido-mds3.explorer.json` | 5.5 MB | the server, for the explorer table |
| `fido-mds3.explorer.full.json` | 7.1 MB | the browser, as a cacheable static asset |
| `*.meta.json` (three files) | ~1 KB | the freshness check and the explorer banner |

All seven live in one directory: `instance/mds-snapshot/`, unless
`FIDO_SERVER_MDS_SNAPSHOT_DIR` names another (see "Where the files are").
**None of them is tracked in git** and none is baked into the container image.

## Why they are not in git

The files change whenever the FIDO Alliance publishes a new BLOB. Tracked, each
refresh would add about 30 MB to the repository's history and invalidate an image
layer; so they are provisioned at runtime instead (below), and each snapshot is
served under a URL of its own.

## Where the files are

`server/app/mds_snapshot_dir.py` names the seven files once and says where they are:
`snapshot_dir()` reads `FIDO_SERVER_MDS_SNAPSHOT_DIR` whenever a path is needed, and
without it answers `instance/mds-snapshot` (in the image, `/app/instance/mds-snapshot`;
`docker compose` mounts `./instance`, so a local container keeps its copy there). It is a leaf with no Flask import, so every
reader and writer follows the one setting: the server's metadata loaders
(`webauthn/metadata/blob.py`), the provisioning below,
`tools/update_mds_snapshot.py`, and the packaged snapshot browsers load
(`/assets/mds/fido-mds3.explorer.full.json`, served from that directory with its `.gz`
sibling, `server/app/static_assets.py`). The page is given that URL as `snapshotUrl`
only while the file is there and its meta matches the verified snapshot; otherwise it
asks the explorer API, which answers from the verified snapshot either way. The URL ends
in `?v=<serial>.<digest>` (the digest of the snapshot's ETag and generation time,
`static_assets.snapshot_version`): the file changes at runtime without a deploy, so each
snapshot has a URL of its own. A request naming the current version is cached as
immutable for a year; any other revalidates.

No route serves a snapshot file at the site's root: the seven names and the `.gz`
sibling are refused there (the site's root is the UI's export), and the
versioned route serves only the browsers' copy, from the snapshot directory. Nothing the pages
use asks for any other snapshot file: the page's info carries the snapshot's timestamp
whenever there is a snapshot.

The tests use it to keep off a developer's real snapshot: `tests/conftest.py` points
every test at an empty directory of the run's, and a test that needs a snapshot
points it at a copy of `tests/fixtures/mds/snapshot` (a small synthetic snapshot
built by `tests/app/metadata/mds_fixture.py` with the updater's own code). The browser
tests' Flask (`web/e2e/serve-flask.mjs`) serves such a copy too.

## How the snapshot reaches the application

`server/app/mds_provisioning.py` materialises the files into the snapshot directory
on demand, trying three tiers in order. It runs once per process, from the
background warm-up on a Cloud Run cold start and from the first request that
needs the snapshot otherwise.

The routes that read the snapshot (`/api/mds/metadata/info`,
`explorer/full`, `resolve`, the upload and the delete, the browsers'
copy at its versioned URL, and both registrations' complete, which look the new
credential's AAGUID up and record what they found for good) call
`ensure_snapshot_available()` first (`mds_provisioning.waits_for_the_snapshot`): on a cold
instance they wait for the provisioning under way (about 20 s from Cloud Storage)
instead of answering meanwhile as if there were no snapshot, and after the first
attempt they return at once. The pages are static (the UI's export) and never wait,
so a cold instance's first page is not held; the explorer asks the info route, which
waits.

1. **Local files.** Anything already on disk is used unchanged. No network.
2. **Cloud Storage.** With `FIDO_SERVER_GCS_ENABLED` set, the set the bucket's
   pointer names (below) is downloaded from `gs://$FIDO_SERVER_GCS_BUCKET/mds/` (the
   prefix is `FIDO_SERVER_MDS_GCS_PREFIX`, default `mds`), each file checked against
   the pointer's SHA-256 and size. Without a usable pointer, or when its set cannot
   be read whole, the missing files come from the flat `mds/<file>` objects earlier
   releases wrote. This is the production path: the Cloud Run service account
   already has access to the `pqcwebauthn` bucket, so no new credentials are involved.
3. **Upstream refresh.** As a last resort the packaged updater downloads the
   BLOB from `https://mds3.fidoalliance.org/` and verifies it against the
   GlobalSign R46 trust root pinned in the source before writing anything. The
   result is then published to Cloud Storage as a set, so the next cold start
   stops at tier 2.

Tier 3 is controlled by `FIDO_SERVER_MDS_FETCH_UPSTREAM`. It defaults to the
Cloud Storage setting: **on** in a deployed service, which can repopulate its
own bucket, and **off** locally, so a first request never silently blocks on a
10 MB download.

Whatever writes the snapshot (the Cloud Storage tier, a running instance taking a
newer set, the updater) writes each file whole, through a temporary file renamed over
it, the payloads first and the three metas last (`mds_snapshot_dir.write_file`,
`WRITE_ORDER`). With the browser-facing `fido-mds3.explorer.full.json` goes its
precompressed `.gz` sibling, or the removal of a sibling left from an earlier file
when the new one does not compress smaller (`mds_snapshot_dir.write_gzip_sibling`),
so a gzip client is never sent an older snapshot. The server's metadata caches key on
every file they are built from (`blob._mtimes`): a request that reads a snapshot
halfway through its replacement may answer from the mix once, but never keeps it.

### A running instance

A Cloud Run instance lives as long as it has traffic, and would otherwise keep the
snapshot it started with. `/api/mds/metadata/info`, where the explorer starts, calls
`mds_provisioning.follow_newer_snapshot()`: at most once every
`FIDO_SERVER_MDS_POINTER_CHECK_SECONDS` (default 900) it reads the bucket's pointer,
with a 5 s timeout and no retry, inside the request (the service has CPU only while
serving one). When the pointer names a set with a higher serial than the local one,
that request downloads it, checks it and writes it; the instance's other requests go
on with the snapshot they have and never wait. Any failure keeps the local snapshot,
and the next check tries again.

### When no tier succeeds

The application still starts and serves. `/health` and `/` work; the explorer APIs
answer `200` with no entries (their `404` branch is not reached: the snapshot they
compose always has its counts), the page is given no `snapshotUrl` (so
it requests no missing file), and the explorer shows no entries (it says the
packaged metadata is unavailable). This is the behaviour that already existed for a missing snapshot —
the relocation did not introduce a new failure mode.

## Working locally without Cloud Storage

Run the updater once. It fetches and verifies the BLOB and writes all seven
files into the snapshot directory (`instance/mds-snapshot/`, which git and Docker ignore):

```bash
python tools/update_mds_snapshot.py
```

After that the application uses tier 1 and needs no network at all. To check
that upstream is reachable and the BLOB still verifies without writing anything:

```bash
python tools/update_mds_snapshot.py --verify-only
```

## Snapshot sets in Cloud Storage

`server/app/mds_snapshot_sets.py` (a leaf, like `mds_snapshot_dir`) keeps the bucket's
snapshot as immutable sets and a pointer:

- **A set** is the seven files under `mds/sets/1/<serial>-<random>/` (`1` is the
  format; a reader ignores a pointer of a format it does not know, and a writer does
  not replace one). Each file is uploaded only if no object has its name yet
  (`if_generation_match=0`), payloads first, metas last.
- **The pointer**, `mds/current.json`, names the current set with each file's SHA-256
  and size, the serial, ETag, generation time and `nextUpdate`, and the set it
  replaced (`previous`). It is written once its set is complete, only if it is still
  the object its writer read (its generation), and only forward: a snapshot whose
  serial is not above the pointer's is not published, so a run that finds no new
  BLOB writes nothing and the asset URL keeps its version.
- **Two writers at once** leave one pointer: the other's conditional write fails, it
  deletes the set it wrote, and the updater reads the pointer again (up to three
  times) in case the winner's snapshot is older than its own.
- **A failure** (the bucket unreachable, a set uploaded halfway) deletes what it
  uploaded and leaves the pointer where it was. A BLOB that fails verification, or a
  download the FIDO Alliance refuses (429, after the updater's backoff of 10 to
  80 s), never gets that far.
- **Pruning**: after a publish the set two back (the old pointer's `previous`) is
  deleted; the set it replaced stays, since an instance may still be reading it.
  Nothing needs to list the bucket.

The flat `mds/<file>` objects earlier releases published are left in place as the
fallback when there is no pointer; nothing writes them any more.

## Publishing a snapshot to Cloud Storage

With credentials for the bucket configured (`FIDO_SERVER_GCS_ENABLED=1`,
`FIDO_SERVER_GCS_BUCKET`, and application-default credentials):

```bash
FIDO_SERVER_GCS_ENABLED=1 FIDO_SERVER_GCS_BUCKET=pqcwebauthn python tools/update_mds_snapshot.py --publish
```

It downloads and verifies the BLOB, writes the local snapshot, and publishes that
verified snapshot as a set (`--gcs-upload` is the flag's earlier name). It exits
non-zero when the download, the verification or the bucket fails, having published
nothing.

The daily workflow (`.github/workflows/update-fido-mds.yml`) downloads and verifies
the BLOB; publishing from it waits on the owner's Workload Identity Federation set-up
for the workflow (no key is stored in GitHub).

## The container image

`.dockerignore` keeps the snapshot out of the build context, so the image is
identical whether or not the developer has a local snapshot, and a refresh
never invalidates a layer. The image does carry
`tools/update_mds_snapshot.py`, which is what tier 3 runs.
