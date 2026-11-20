# Deploying pqcwebauthn on Cloud Run

The service runs in `feitian-project`, region `asia-northeast1`, on one vCPU, and keeps no instance warm (`minScale` 0): an idle instance costs nothing.

- **Code:** every push to `main` triggers Cloud Build ([cloudbuild.yaml](../cloudbuild.yaml)), which builds the image and updates only the service's image, through [deploy-revision.sh](deploy-revision.sh):
  - The new revision takes no traffic at first. It is tagged `candidate` and named for the commit and the build.
  - `/health`, `/` and `/api/mds/metadata/info` (with its `entryCount`) are checked at the tag's URL, `https://candidate---…`. Each is tried again, 15 s apart, while the revision starts and provisions its MDS snapshot, all within 8 minutes.
  - Only then does the revision get all the traffic (`update-traffic --to-revisions`).
  - Whatever fails leaves the traffic on the revision that had it. The failed revision keeps its tag, without traffic, until the next deploy moves the tag.
  - Builds can overlap, and one can be retried by hand, so the script reads main's tip from the public repository (git's ref advertisement, no token) before it deploys and again before it promotes. A build whose commit is no longer the tip stops there without error and leaves the traffic where it is; a tip it cannot read after a few tries fails the deploy. If the newer commit's own build then fails, nothing deploys until a later push's build passes. The read needs the repository public at the address `cloudbuild.yaml` gives the script.
  - The build's service account needs nothing more than the deploy did before. `services describe` and `update-traffic` need the same `run.services.get` and `run.services.update` as `services update`, and the tag's URL is public like the service's.
- **Settings:** concurrency, scaling, secrets and the runtime identity live in [service.yaml](service.yaml). Apply them with [apply-service-config.sh](apply-service-config.sh). The script keeps the image of the revision that serves the traffic. Its new revision takes all the traffic at once, without the deploy's checks.

## Rolling back

List the service's revisions and send all the traffic back to one that served well:

```bash
gcloud run revisions list --service pqcwebauthn --project feitian-project --region asia-northeast1
gcloud run services update-traffic pqcwebauthn --project feitian-project --region asia-northeast1 \
  --to-revisions=pqcwebauthn-<commit>-<build>=100
```

This holds until the next push to `main`, whose build deploys main's tip again: revert the bad commit on `main` next. A build of an older commit no longer takes the traffic by itself, so roll back with `update-traffic`, never by building an old commit again.

## One-time setup: secrets and runtime identity

Run these in your own terminal. Secret values are read from stdin and never appear in files or shell history.

```bash
PROJECT=feitian-project
REGION=asia-northeast1
PROJECT_NUMBER=277359456097
RUN_SA=pqcwebauthn-run@$PROJECT.iam.gserviceaccount.com
BUILD_SA=$PROJECT_NUMBER-compute@developer.gserviceaccount.com   # service account the Cloud Build trigger runs as

gcloud services enable secretmanager.googleapis.com --project $PROJECT

# Dedicated runtime identity with only the access the app needs.
gcloud iam service-accounts create pqcwebauthn-run --project $PROJECT \
  --display-name "pqcwebauthn Cloud Run runtime"
gcloud storage buckets add-iam-policy-binding gs://pqcwebauthn \
  --member serviceAccount:$RUN_SA --role roles/storage.objectAdmin

# Session signing key shared by all instances.
python3 -c 'import secrets, sys; sys.stdout.write(secrets.token_urlsafe(48))' | \
  gcloud secrets create pqcwebauthn-session-key --project $PROJECT \
    --replication-policy user-managed --locations $REGION --data-file=-

# GitHub token for credential logs: create a new fine-grained token with
# "Contents: read and write" on rainzhang05/CredentialLogs only, then paste it here.
read -rs NEW_TOKEN && printf %s "$NEW_TOKEN" | \
  gcloud secrets create pqcwebauthn-github-token --project $PROJECT \
    --replication-policy user-managed --locations $REGION --data-file=- ; unset NEW_TOKEN

for secret in pqcwebauthn-session-key pqcwebauthn-github-token; do
  gcloud secrets add-iam-policy-binding $secret --project $PROJECT \
    --member serviceAccount:$RUN_SA --role roles/secretmanager.secretAccessor
done

# Allow the build trigger to deploy revisions that run as the runtime identity.
gcloud iam service-accounts add-iam-policy-binding $RUN_SA --project $PROJECT \
  --member serviceAccount:$BUILD_SA --role roles/iam.serviceAccountUser
```

Then apply the service settings:

```bash
./deploy/apply-service-config.sh
```

## One-time setup: the MDS publisher

`.github/workflows/update-fido-mds.yml` publishes new MDS snapshot sets to the bucket
([MDS_SNAPSHOT.md](../docs/MDS_SNAPSHOT.md)). It signs in through Workload Identity
Federation, so no key is stored in GitHub: the pool accepts only this repository's `main`
branch, and the `mds-publisher` account it acts as may write only under `mds/`.

```bash
PROJECT=feitian-project
PROJECT_NUMBER=277359456097
REPO=FeitianTech/postquantum-webauthn-platform
PUBLISHER=mds-publisher@$PROJECT.iam.gserviceaccount.com

gcloud services enable sts.googleapis.com iamcredentials.googleapis.com --project $PROJECT

gcloud iam workload-identity-pools create github --project $PROJECT --location global \
  --display-name "GitHub Actions"
gcloud iam workload-identity-pools providers create-oidc postquantum-webauthn-platform \
  --project $PROJECT --location global --workload-identity-pool github \
  --display-name "postquantum-webauthn-platform" \
  --issuer-uri "https://token.actions.githubusercontent.com" \
  --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref" \
  --attribute-condition "assertion.repository == '$REPO' && assertion.ref == 'refs/heads/main'"

gcloud iam service-accounts create mds-publisher --project $PROJECT \
  --display-name "FIDO MDS snapshot publisher"
gcloud storage buckets add-iam-policy-binding gs://pqcwebauthn \
  --member serviceAccount:$PUBLISHER --role roles/storage.objectUser \
  --condition 'expression=resource.name.startsWith("projects/_/buckets/pqcwebauthn/objects/mds/"),title=mds-only'
gcloud iam service-accounts add-iam-policy-binding $PUBLISHER --project $PROJECT \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github/attribute.repository/$REPO"

# Where the workflow signs in (repository variables: identifiers, not secrets).
gh variable set GCP_WORKLOAD_IDENTITY_PROVIDER --repo $REPO \
  --body "projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github/providers/postquantum-webauthn-platform"
gh variable set GCP_MDS_PUBLISHER_SERVICE_ACCOUNT --repo $REPO --body "$PUBLISHER"
```

Once a conditional binding is on the bucket, `gcloud storage buckets remove-iam-policy-binding`
needs `--condition=None` to remove an unconditional one.

## Environment variables

Everything the server reads from its environment (`server/app`, `gunicorn.conf.py`).
`deploy/service.yaml` sets the ones production needs. A boolean takes `1`/`true`/`yes`/`on`
or `0`/`false`/`no`/`off`, and an empty value is off (`server/app/env_flags.py`); any other
value is ignored with a warning. "On Cloud Run" means `K_SERVICE` is set, which Cloud Run
does. The Dockerfile reads none: the image sets `PYTHONPATH=/app`, `PYTHONDONTWRITEBYTECODE`,
`PYTHONUNBUFFERED`, and glibc's `MALLOC_ARENA_MAX=1` and `MALLOC_MMAP_THRESHOLD_=131072` (so
the worker gives back the memory of a burst of large requests) for itself, and
`docker-compose.yml` sets `PORT` to `8000`.

| Variable | Default | What it does |
| --- | --- | --- |
| `K_SERVICE` | set by Cloud Run | Turns on the Cloud Run defaults below; the app then refuses to start without a secret key |
| `PORT` | `8080` | The port gunicorn listens on |
| `GUNICORN_THREADS` | `16` | Threads of the one gunicorn worker |
| `GUNICORN_LOG_LEVEL` | `warning` | gunicorn's log level |
| `FIDO_SERVER_SECRET_KEY` | none | The session signing key, shared by every instance |
| `FIDO_SERVER_SECRET_KEY_FILE` | none | A file holding the key, read when `FIDO_SERVER_SECRET_KEY` is unset; locally, without either, `instance/session-secret.key` is generated |
| `FIDO_SERVER_SESSION_LIFETIME_SECONDS` | `1800` | How long a session cookie is accepted |
| `FIDO_SERVER_SESSION_COOKIE_SECURE` | on on Cloud Run | The session and namespace cookies' `Secure` flag |
| `FIDO_SERVER_TRUST_PROXY` | on on Cloud Run | Believe `X-Forwarded-Proto` and the client address (never the forwarded host) |
| `FIDO_SERVER_RP_ID` | the request's host | The relying party ID; unset is a development fallback, logged as a warning |
| `FIDO_SERVER_ALLOWED_ORIGINS` | the request's own origin | The exact origins a ceremony may come from, separated by commas or new lines; an RP ID an Advanced request names must be one of their hosts or a registrable suffix of one; unset is a development fallback, which takes any RP ID named |
| `FIDO_SERVER_RP_NAME` | `FIDO2/WebAuthn PQC Developer Tools` | The relying party's name |
| `FIDO_SERVER_CHALLENGE_TTL_SECONDS` | `600` | How long an issued challenge can be used |
| `FIDO_SERVER_TRUSTED_ATTESTATION_CA_SUBJECTS` | none | Attestation roots the operator trusts, by subject (RFC 4514, as `CN=Root,O=Org`), one per line or separated by `;`: a subject's commas separate its attributes |
| `FIDO_SERVER_TRUSTED_ATTESTATION_CA_FINGERPRINTS` | none | The same by SHA-256 fingerprint (hex, 40 digits or more) |
| `FIDO_SERVER_CONTENT_SECURITY_POLICY` | the strict policy | Replaces the enforced Content-Security-Policy (`server/app/config/security_headers.py`) |
| `FIDO_SERVER_MAX_REQUEST_BYTES` | 8 MiB | The largest request body; larger answers 413. An instance works on two JSON bodies over 256 KiB at a time, and another that waits 2 s for its place answers 503 with `Retry-After` |
| `FIDO_SERVER_MAX_METADATA_UPLOAD_BYTES` | 16 MiB | The largest metadata upload; an instance reads one at a time, and another that waits 2 s for its place answers 503 with `Retry-After` |
| `FIDO_SERVER_MAX_METADATA_ENTRY_BYTES` | 1 MiB | The largest uploaded metadata entry once stored; a larger one is refused in the upload's errors |
| `FIDO_SERVER_MAX_CODEC_REQUEST_BYTES` | 1 MiB | The largest `/api/codec` request; larger answers 413 |
| `FIDO_SERVER_MAX_CODEC_ITEMS` | `20000` | The most items `/api/codec` reads for one request (`server/app/decoder/item_budget.py`); past it the input is refused, 422 |
| `FIDO_SERVER_MAX_REGISTRATION_RESPONSE_BYTES` | 256 KiB | The largest credential response a registration or a sign-in completes with (a Simple registration's whole body, a Simple sign-in's `credential`, an Advanced complete's `__credential_response` or `__assertion_response`; the saved credentials a sign-in sends beside it are not counted); larger answers 413 |
| `FIDO_SERVER_MAX_STORED_ARTIFACTS` | `1000` | The most credential artifacts one visitor's namespace keeps; a new one past it answers 409 |
| `FIDO_SERVER_MAX_STORED_ARTIFACT_BYTES` | 256 MiB | The most bytes of them; a write past it answers 413 |
| `FIDO_SERVER_MAX_STORED_METADATA_ENTRIES` | `2000` | The most uploaded metadata entries one visitor's namespace keeps; an upload past it answers 409 |
| `FIDO_SERVER_MAX_STORED_METADATA_BYTES` | 64 MiB | The most bytes of them; an upload past it answers 413 |
| `FIDO_SERVER_MAX_SIMPLE_CREDENTIALS_PER_USERNAME` | `100` | The most Simple credentials one username's list keeps; a registration past it answers 409 |
| `FIDO_SERVER_GCS_ENABLED` | off | Keep the stores and the MDS snapshot in Cloud Storage |
| `FIDO_SERVER_GCS_BUCKET` | none | The bucket; Cloud Storage is used only when it is set too |
| `FIDO_SERVER_GCS_PROJECT` | the credentials' | The Cloud Storage client's project |
| `FIDO_SERVER_CREDENTIAL_DIR` | `instance/session-credentials` | The local credential store |
| `FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR` | `instance/credential-artifacts` | The local credential artifact store |
| `FIDO_SERVER_SESSION_METADATA_DIR` | `instance/session-metadata` | The local store of visitors' metadata uploads |
| `FIDO_SERVER_MDS_SNAPSHOT_DIR` | `instance/mds-snapshot` | Where the MDS snapshot is ([MDS_SNAPSHOT.md](../docs/MDS_SNAPSHOT.md)) |
| `FIDO_SERVER_MDS_GCS_PREFIX` | `mds` | The snapshot's prefix in the bucket |
| `FIDO_SERVER_MDS_FETCH_UPSTREAM` | as `FIDO_SERVER_GCS_ENABLED` | Let provisioning fetch the BLOB from the FIDO Alliance as a last resort |
| `FIDO_SERVER_MDS_POINTER_CHECK_SECONDS` | `900` | How often a running instance looks for a newer snapshot set |
| `FIDO_SERVER_BACKGROUND_WARMUP` | on on Cloud Run | Provision the snapshot and fill the caches when a worker starts |
| `FIDO_SERVER_WEB_EXPORT_ROOT` | `web/out` (`/app/web/out` in the image) | The UI's static export, served at `/` |
| `ENABLE_GITHUB_LOGGING` | on when `GITHUB_TOKEN` is set | Log each registration and uploaded metadata file to the credential log repository; `0` turns it off |
| `GITHUB_TOKEN` | none | The token the log writes with; without it nothing is logged |
| `GITHUB_LOG_REPO_OWNER`, `GITHUB_LOG_REPO_NAME` | `rainzhang05`, `CredentialLogs` | The credential log repository |
| `GITHUB_HTTP_TIMEOUT_SECONDS` | `4` | Each GitHub request's timeout, in the worker that delivers the log's outbox (no request waits for GitHub) |
| `FIDO_SERVER_GITHUB_OUTBOX_DIR` | `instance/github-outbox` | Where the log's entries wait for delivery without Cloud Storage; with it they wait under `github-outbox/` in the bucket ([STORAGE.md](../docs/STORAGE.md#the-credential-log)) |

`FIDO_SERVER_CONTENT_SECURITY_POLICY_REPORT_ONLY` and `FIDO_SERVER_REPORTING_ENDPOINTS`
are no longer read: Trusted Types are part of the enforced policy, and the reporting
endpoint is the one the policy names. Nor is `GITHUB_LOG_ASYNC`: no request uploads to
GitHub, and the log's entries wait in an outbox that a worker delivers.

## Measuring cold starts

```bash
# Instances started and startup probe timing over the last day
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="pqcwebauthn" AND (textPayload:"Starting new instance" OR textPayload:"STARTUP TCP probe succeeded")' \
  --project feitian-project --freshness=1d --limit 50 --format='value(timestamp,textPayload)'

# Requests slower than one second
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="pqcwebauthn" AND httpRequest.latency>"1s"' \
  --project feitian-project --freshness=1d --limit 100 --format='table(timestamp,httpRequest.requestUrl,httpRequest.latency)'
```

With no instance kept warm, a visitor meets a cold start after a quiet spell, when traffic needs a second instance, or on a new revision's first request. A request's time to first byte:

```bash
curl -so /dev/null -w 'ttfb=%{time_starttransfer}s total=%{time_total}s\n' https://pqcwebauthn-277359456097.asia-northeast1.run.app/
```
