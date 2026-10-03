# Deploying pqcwebauthn on Cloud Run

The service runs in `feitian-project`, region `asia-northeast1`, and scales to zero.

- **Code:** every push to `main` triggers Cloud Build ([cloudbuild.yaml](../cloudbuild.yaml)), which builds the image and updates only the service's image.
- **Settings:** concurrency, scaling, secrets and the runtime identity live in [service.yaml](service.yaml). Apply them with [apply-service-config.sh](apply-service-config.sh). The script keeps the image that is currently deployed.

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

## Environment variables

Everything the server reads from its environment (`server/app`, `gunicorn.conf.py`).
`deploy/service.yaml` sets the ones production needs. A boolean takes `1`/`true`/`yes`/`on`
or `0`/`false`/`no`/`off` (`server/app/env_flags.py`); any other value is ignored with a
warning. "On Cloud Run" means `K_SERVICE` is set, which Cloud Run does.

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
| `FIDO_SERVER_ALLOWED_ORIGINS` | the request's own origin | The exact origins a ceremony may come from, separated by commas or new lines; unset is a development fallback |
| `FIDO_SERVER_RP_NAME` | `FIDO2/WebAuthn PQC Developer Tools` | The relying party's name |
| `FIDO_SERVER_CHALLENGE_TTL_SECONDS` | `600` | How long an issued challenge can be used |
| `FIDO_SERVER_TRUSTED_ATTESTATION_CA_SUBJECTS` | none | Attestation roots the operator trusts, by subject (RFC 4514), separated by `,`, `;` or new lines |
| `FIDO_SERVER_TRUSTED_ATTESTATION_CA_FINGERPRINTS` | none | The same by SHA-256 fingerprint (hex, 40 digits or more) |
| `FIDO_SERVER_CONTENT_SECURITY_POLICY` | the strict policy | Replaces the enforced Content-Security-Policy (`server/app/config/security_headers.py`) |
| `FIDO_SERVER_MAX_REQUEST_BYTES` | 8 MiB | The largest request body; larger answers 413 |
| `FIDO_SERVER_MAX_METADATA_UPLOAD_BYTES` | 16 MiB | The largest metadata upload |
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
| `ENABLE_GITHUB_LOGGING` | on | Log each registration to the credential log repository |
| `GITHUB_TOKEN` | none | The token the log writes with; without it each upload fails with a warning, and the registration goes on |
| `GITHUB_LOG_REPO_OWNER`, `GITHUB_LOG_REPO_NAME` | `rainzhang05`, `CredentialLogs` | The credential log repository |
| `GITHUB_HTTP_TIMEOUT_SECONDS` | `4` | Each GitHub request's timeout |
| `GITHUB_LOG_ASYNC` | off on Cloud Run, else on | Upload the log entry on a background thread |

`FIDO_SERVER_CONTENT_SECURITY_POLICY_REPORT_ONLY` and `FIDO_SERVER_REPORTING_ENDPOINTS`
are no longer read: Trusted Types are part of the enforced policy, and the reporting
endpoint is the one the policy names.

## Measuring cold starts

```bash
# Instances started and startup probe timing over the last day
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="pqcwebauthn" AND (textPayload:"Starting new instance" OR textPayload:"STARTUP TCP probe succeeded")' \
  --project feitian-project --freshness=1d --limit 50 --format='value(timestamp,textPayload)'

# Requests slower than one second
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="pqcwebauthn" AND httpRequest.latency>"1s"' \
  --project feitian-project --freshness=1d --limit 100 --format='table(timestamp,httpRequest.requestUrl,httpRequest.latency)'
```

After about 15–20 idle minutes the instance count reaches zero. A request after that measures a true cold start:

```bash
curl -so /dev/null -w 'ttfb=%{time_starttransfer}s total=%{time_total}s\n' https://pqcwebauthn-277359456097.asia-northeast1.run.app/
```
