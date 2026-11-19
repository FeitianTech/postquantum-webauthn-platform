# The FIDO MDS snapshot

The MDS explorer is backed by a generated snapshot of the FIDO Alliance
metadata service: seven files totalling about 34 MB (no. 302, 538 entries), produced
together by `tools/update_mds_snapshot.py`.

| File | Size | Read by |
| --- | --- | --- |
| `blob.jwt` | 11 MB | the server's provisioning, which verifies the copy it downloads and derives the other files from it and the verified meta (below); the updater, to tell whether the BLOB changed |
| `fido-mds3.verified.json` | 9.1 MB | the server, as the base metadata payload: the BLOB's payload as the BLOB has it, once verified |
| `fido-mds3.explorer.json` | 6.0 MB | the server, for the explorer's summary: its meta, and the whole file only when that meta does not describe the verified snapshot |
| `fido-mds3.explorer.full.json` | 7.8 MB | the server, which derives what browsers load from it (below) |
| `*.meta.json` (three files) | ~1 KB | the freshness check, the serial a running instance and the updater compare, and the explorer's status line |

All seven live in one directory: `instance/mds-snapshot/`, unless
`FIDO_SERVER_MDS_SNAPSHOT_DIR` names another (see "Where the files are").
**None of them is tracked in git** and none is baked into the container image.

## Why they are not in git

The files change whenever the FIDO Alliance publishes a new BLOB. Tracked, each
refresh would add about 34 MB to the repository's history and invalidate an image
layer; so they are provisioned at runtime instead (below), and each snapshot's entry
details are served under URLs of their own (the list keeps one URL, revalidated by its
ETag).

## Where the files are

`server/app/mds/files.py` names the seven files once and says where they are:
`snapshot_dir()` reads `FIDO_SERVER_MDS_SNAPSHOT_DIR` whenever a path is needed, and
without it answers `instance/mds-snapshot` (in the image,
`/app/instance/mds-snapshot`, which the image's unprivileged user owns; `docker compose`
keeps `/app/instance` in its `instance` volume, so a local container keeps its copy across
restarts). It is a leaf with no Flask import, so every reader
and writer follows the one setting: the server's metadata loaders (`mds/cache.py`),
the provisioning below, and `tools/update_mds_snapshot.py`.

## What browsers load

Browsers load no snapshot file. The server derives what they load from the full
explorer snapshot it already holds (`server/app/mds/explorer_files.py`; kept in
memory for each snapshot by `cache.load_explorer_files`, which the warm-up calls;
served by `server/app/routes/assets.py`), so the sets in Cloud Storage and their
seven files are exactly what they were:

- **The list**, `/assets/mds/fido-mds3.explorer.list.json`: every entry with what the
  table shows, filters and sorts by, without its detail or where it came from (about
  760 KB, 70 KB gzipped, for 538 entries). One URL, `no-cache`, with an ETag naming the
  version and the encoding, so the page fetches it without asking anything first (and
  without the session's cookie) and a revisit costs a 304. The page fetches it once its
  first view is interactive, and at once when the URL opens `#mds`.
- **The icons**, `/assets/mds/icons/<digest>.<png|svg|…>`: each distinct image once (129
  for 538 entries), named by its SHA-256 (the first 128 bits), so immutable; served
  with a sandboxing CSP of their own. The table loads them lazily, as rows scroll into
  view.
- **Each entry's detail**, `/assets/mds/entries/<entryId>?v=<version>`: the entry as the
  full snapshot holds it; the entry page reads it when it opens (and falls back to
  `/api/mds/metadata/resolve`). Immutable at the version its URL names, where the
  version is the snapshot's (`explorer_files.snapshot_version`: its serial and a digest
  of its ETag and generation time) and `DERIVED_FORMAT`, which changes with what the
  code derives. Requested without the current version, a detail revalidates with a weak
  ETag of its JSON bytes, which survives gzip, so an unchanged entry answers a
  conditional request with 304 in either content coding. Each entry has an id of its
  own: of entries sharing one (two statements of one AAGUID, AAID or key identifier) the
  last keeps it, as fido2 finds the last of them, and the earlier ones are listed as
  `<id>~2`, `~3`… counting back.

The page reads the list at its one URL, served from the verified snapshot whether or not
the full file is there, and, while the session has (or may have) uploads,
`/api/mds/metadata/explorer/custom`: the session's own rows and the counts. It shows the
uploads (of uploads with one AAGUID, the newest), then the packaged rows whose AAGUID no
upload has: an upload hides the packaged entry with its AAGUID. An upload and a delete
answer the session's rows as `custom`, which the page merges with the list it holds. An
upload's row has the list's shape, so these answers grow by a row for each upload, never
by its statement or its image: the entry page asks `/api/mds/metadata/resolve?entryId=`
for its detail, and its icon is at `/api/mds/metadata/custom/<stored name>/icon`, the
visitor's own, kept by the browser for good (an upload never changes), one URL for each
image (the oldest upload's that holds it). An icon no file is made of stays in its row, as
in the list. The server works out each upload's row, Manage Metadata's item and what a
registration's lookup reads of it once, when it is saved, and writes them into the info
file beside it, marked with their format and fido2's version (`mds/listed_uploads.py`). A
listing reads that info file, not the upload, and keeps what it read in memory by
namespace, stored name and version (within 20 MiB): one listing of the namespace says which
uploads were written since, and only those are read again. An upload whose info keeps
nothing of the current format (saved by an earlier release, or written again after its
info) is read and parsed instead, and nothing is rewritten. At the quota (2,000 uploads), a
listing with nothing in memory took about 3 s of CPU on a laptop, parsing every upload; it
takes about 0.1 s reading their info files, and an answer takes 30 ms once an instance has
listed them. A registration still reads the entry it finds from the upload itself. A page from an earlier release was sent to the list only by the info
answer's `snapshotUrl`, which is gone, and asked `/api/mds/metadata/explorer/full` for
every row: that answers `410` with a sentence telling it to reload.

No route serves a snapshot file, at `/assets/mds/` or at the site's root: the seven
names, and the `.gz` copy earlier releases wrote beside the full one, are refused there
(the site's root is the UI's export).

The tests use `FIDO_SERVER_MDS_SNAPSHOT_DIR` to keep off a developer's real snapshot:
`tests/conftest.py` points every test at an empty directory of the run's, and a test
that needs a snapshot points it at a copy of `tests/fixtures/mds/snapshot` (a small
synthetic snapshot built by `tests/app/metadata/mds_fixture.py` with the updater's own
code). The browser tests' Flask (`web/e2e/serve-flask.mjs`) serves such a copy too.

## How the snapshot reaches the application

`server/app/mds/provisioning.py` materialises the files into the snapshot directory
on demand, trying three tiers in order. It runs once per process, from the
background warm-up on a Cloud Run cold start and from the first request that
needs the snapshot otherwise. The warm-up then derives the explorer's files and
indexes the verified entries a registration looks its credential up in
(`server/app/mds/verifier.py`): their JSON is read once, and an entry is parsed into
fido2's dataclasses only when a lookup finds it, never the whole payload.

The routes that read the snapshot (`/api/mds/metadata/info`,
`explorer/custom`, `resolve`, the upload and the delete, the explorer's files
under `/assets/mds/`, and both registrations' complete, which look the new
credential's AAGUID up and record what they found for good) call
`ensure_snapshot_available()` first (`waits_for_the_snapshot` in `server/app/mds/provisioning.py`):
on a cold instance they wait for the provisioning under way instead of answering
meanwhile as if there were no snapshot, and after the first attempt they return at
once. From Cloud Storage that wait is the download of the BLOB and its meta (10.6 MB
for no. 288) and about 0.7 s of CPU to verify the BLOB and derive the other five files
(measured on no. 288 with the download taken out; Cloud Run's CPU may be slower). It
has no bound of its own: a request waits up to the service's request timeout (300 s,
`deploy/service.yaml`). The pages are static (the UI's export) and never wait,
so a cold instance's first page is not held; the explorer asks the info route, which
waits.

1. **Local files.** When all seven files are on disk they are used unchanged. No
   network. If one is missing, the tiers below write the whole set. The one
   exception is the explorer's full snapshot of another `derivedFormat` (its meta
   names the `explorer_files.DERIVED_FORMAT` of the code that derived it): an earlier
   release's rows would otherwise be served under this code's version, so the server
   derives them again from the verified payload, as it does for a full file whose meta
   does not describe the verified snapshot, until the updater, or a newer set from the
   bucket, rewrites the file. What it derives keeps the snapshot's generation time, and
   so the version the updater's file would have: every instance derives the same URLs.
2. **Cloud Storage.** With `FIDO_SERVER_GCS_ENABLED` set, the set the bucket's
   pointer names (below) is taken from `gs://$FIDO_SERVER_GCS_BUCKET/mds/` (the
   prefix is `FIDO_SERVER_MDS_GCS_PREFIX`, default `mds`): its BLOB and the verified
   payload's meta are downloaded at once, each checked against the pointer's SHA-256
   and size; the BLOB is verified against the pinned root at the time the meta says it
   was fetched (`mds/blob.py`), without its signing chain's CRLs (the updater checked
   them before it published the set: "Revocation" below), its signed `no` must be the
   meta's and the pointer's, and the other five files are derived from the two with the
   updater's own code
   (`mds/snapshot.py`'s `derive`), the payload derived being the file the pointer
   names. Without a usable pointer, or when its set cannot be read and verified,
   provisioning goes on to the upstream refresh. This is the production path: the
   Cloud Run service account already has access to the `pqcwebauthn` bucket, so no
   new credentials are involved.
3. **Upstream refresh.** As a last resort the packaged updater downloads the
   BLOB from `https://mds3.fidoalliance.org/` and verifies it against the
   GlobalSign R46 trust root pinned in the source, and its signing chain against the
   chain's CRLs, before writing anything: a CRL it cannot get fails the refresh, as
   it fails a run by hand (below). The result is then published to Cloud Storage as
   a set, so the next cold start stops at tier 2.

Tier 3 is controlled by `FIDO_SERVER_MDS_FETCH_UPSTREAM`. It defaults to the
Cloud Storage setting: **on** in a deployed service, which can repopulate its
own bucket, and **off** locally, so a first request never silently blocks on a
11 MB download.

Whatever writes the snapshot (the Cloud Storage tier, a running instance taking a
newer set, the updater) writes each file whole, through a temporary file renamed over
it, the payloads first and the three metas last (`mds/files.py`'s `write_file`,
`WRITE_ORDER`). The server's metadata caches, and the explorer's files derived from
them, key on every file they are built from (`cache._mtimes`): a request that reads a
snapshot halfway through its replacement may answer from the mix once, but never
keeps it.

### A running instance

A Cloud Run instance lives as long as it has traffic, and would otherwise keep the
snapshot it started with. `/api/mds/metadata/info`, where the explorer starts, calls
`follow_newer_snapshot()` (`server/app/mds/provisioning.py`): at most once every
`FIDO_SERVER_MDS_POINTER_CHECK_SECONDS` (default 900) it reads the bucket's pointer,
with a 5 s timeout and no retry, inside the request (the service has CPU only while
serving one). When the pointer names a set with a higher serial than the local one,
that request takes it as a cold start does (its BLOB and meta, the BLOB verified, the
rest derived) and writes it; the instance's other requests go
on with the snapshot they have and never wait. Any failure keeps the local snapshot,
and the next check tries again.

### When no tier succeeds

The application still starts and serves. `/health` and `/` work; `explorer/custom`
answers `200` with the session's uploads and no packaged entry, the list's URL answers
`404`, and the explorer shows the session's uploads alone, or no entries (it says the
packaged metadata is unavailable).
The updater (below) fills it.

## Working locally without Cloud Storage

Run the updater once. It fetches and verifies the BLOB and writes all seven
files into the snapshot directory (`instance/mds-snapshot/`, which git and Docker ignore):

```bash
python tools/update_mds_snapshot.py
```

After that the application uses tier 1 and needs no network at all. To check
that upstream is reachable and the BLOB still verifies (its signing chain unrevoked
too), and is no older than the local snapshot, without writing anything:

```bash
python tools/update_mds_snapshot.py --verify-only
```

`--help` lists the flags. A flag it does not take, or `--verify-only` beside `--publish`,
ends the run before anything is downloaded.

## Snapshot sets in Cloud Storage

`server/app/mds/sets.py` (over `storage/cloud.py` and `mds/files.py`, without Flask) keeps the bucket's
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
  BLOB publishes nothing and the explorer's files keep their version (one below the
  pointer's fails the run: the FIDO Alliance's serials only go up).
- **Two writers at once** leave one pointer: the other's conditional write fails, it
  deletes the set it wrote, and the updater tries again, three tries in all, in case
  the winner's snapshot is older than its own; after a third loss it publishes nothing
  and ends with a `::warning::` (exit 0). Tier 3's publish tries once.
- **A failure** (the bucket unreachable, a set uploaded halfway) deletes what it
  uploaded and leaves the pointer where it was. A BLOB that fails verification, or a
  download the FIDO Alliance refuses (429, 500, 502, 503 or 504 after five attempts,
  waiting 10 to 80 s between them, or what a 429's `Retry-After` asks, at most 120 s),
  never gets that far.
- **Pruning**: after a publish the set two back (the old pointer's `previous`) is
  deleted; the set it replaced stays, since an instance may still be reading it.
  Nothing needs to list the bucket.

## Publishing a snapshot to Cloud Storage

With credentials for the bucket configured (`FIDO_SERVER_GCS_ENABLED=1`,
`FIDO_SERVER_GCS_BUCKET`, and application-default credentials):

```bash
FIDO_SERVER_GCS_ENABLED=1 FIDO_SERVER_GCS_BUCKET=pqcwebauthn python tools/update_mds_snapshot.py --publish
```

It downloads and verifies the BLOB, writes the local snapshot, and publishes that
verified snapshot as a set (`--gcs-upload` is the flag's earlier name). It exits
non-zero, having published nothing, when the download, the verification or the bucket
fails, and when the BLOB's serial is below the local snapshot's (then nothing is written
either) or the bucket's: the FIDO Alliance's serials only go up, so an older BLOB is never
taken. A BLOB whose `nextUpdate` has passed (no newer one was published by then) is taken,
with a `::warning::` annotation on the run.

### Revocation

Verifying the BLOB includes its signing chain's revocation, as MDS3 asks
(`server/app/mds/revocation.py`, which `mds/blob.py`'s `verify_blob` runs when the
updater gives it its download, `_fetch_crl`). Each certificate on the path to the pinned
root but the root, which is the pin, names where its issuer publishes the CRL that
covers it: in the real chain, the signing certificate and its CA. The R3
cross-certificate the BLOB carries past the root is not on the path, so its CRL is never
fetched. The updater fetches each CRL there, over plain HTTP as CAs publish them (HTTPS
too, when a point names it; a CRL is signed), each read waiting at most 30 s, and at
most 16 MiB. The CRL must be the issuer's, signed with its key; current, its
`thisUpdate` passed and its `nextUpdate` not; and complete for the certificate: not a
delta CRL, nor one limited to some reasons, other kinds of certificate or another
distribution point. A certificate it lists fails the run (`::error::`, exit 1), with
nothing written or published.

The check fails closed. A certificate for which no such CRL can be had from any of its
points (each unreachable, unreadable, out of date or not such a CRL), or which names no
point to fetch one from, fails the run the same way, with an `::error::` line of its own.
A failed run costs only time: production keeps the snapshot it has, the next run tries
again twelve hours later, and `ci-scheduled-runs.yml` flags the failed workflow
meanwhile. A run that went on without the CRLs would let whoever can block or replay a
plain-HTTP fetch hide the very revocation the check is for.

A set taken from the bucket is not checked again: a cold start (tier 2) and a running
instance taking a newer set verify the BLOB's chain and signature at the time it was
fetched, not its revocation, which the updater checked before it published the set, so
they depend on no host but the bucket. Tier 3 runs the updater, and checks the CRLs as
any run does. A certificate revoked after a set was published fails the next run, which
publishes nothing, but does not withdraw that set: the pointer keeps naming it until a
newer BLOB, signed by a certificate no CRL lists, is published.

`.github/workflows/update-fido-mds.yml` runs this twice a day, so a new BLOB reaches
the bucket within about twelve hours of the FIDO Alliance publishing it, and running
instances within fifteen minutes after that. The workflow signs in to Google through
Workload Identity Federation (no key is stored in GitHub): the pool accepts only this
repository's `main` branch, and the `mds-publisher` account it acts as may write only
under `mds/` in the bucket (`deploy/README.md` has the set-up).

## The container image

`.dockerignore` keeps the snapshot out of the build context, so the image is
identical whether or not the developer has a local snapshot, and a refresh
never invalidates a layer. The image does carry
`tools/update_mds_snapshot.py`, which is what tier 3 runs.
