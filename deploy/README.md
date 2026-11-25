# Deploying pqcwebauthn on Cloud Run

The service runs in `feitian-project`, region `asia-northeast1`, on one vCPU, and keeps no instance warm (`minScale` 0): an idle instance costs nothing.

- **Code:** every push to `main` triggers Cloud Build ([cloudbuild.yaml](../cloudbuild.yaml)), which builds the image and updates only the service's image, through [deploy-revision.sh](deploy-revision.sh):
  - Before anything is deployed, the `GitHub checks` step ([required_checks.py](../tools/required_checks.py)) reads the commit's check runs from GitHub's API, without a token (60 requests an hour for one address). It goes on only when GitHub Actions' latest runs of the browser tests (`Browser tests (Playwright, virtual authenticator)`) and the image check (`docker-build`) both succeeded. It waits up to 10 minutes for runs that have not ended. A run that failed, was cancelled or was skipped, a run never reported, and an answer it cannot read after three tries (GitHub's rate limit included) fail the build, and nothing is deployed. There is no bypass in the pipeline.
  - When a browser test failed for no fault of the commit, run the job again on GitHub, then retry the build in Cloud Build: it deploys, since its commit is still main's tip. A push made while the previous commit's GitHub runs are still going cancels them: that commit's build then fails this way, and the newer one deploys.
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

## When production misbehaves

The service's logs are in Cloud Logging (in the console: Cloud Run, `pqcwebauthn`, Logs). Cloud Run logs each request, a 5xx as `ERROR`; the app writes its own lines to stderr as `[time] LEVEL in module: message`: a refused ceremony is one `WARNING` line, the app's own failure a 500 with an `ERROR in app: Exception on <path> [<method>]` traceback, and where the MDS snapshot came from and the credential log's deliveries are `INFO` lines. A build's log prefixes each line with its step (`Step #5 - "Deploy"`); Deploy's lines say which check did not pass, or that main moved on.

```bash
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="pqcwebauthn" AND (httpRequest.status>=500 OR log_id("run.googleapis.com/stderr"))' \
  --project feitian-project --freshness=1h --limit 100 --format='value(timestamp,httpRequest.status,httpRequest.requestUrl,textPayload)'
gcloud builds list --project feitian-project --region global --limit 5
gcloud builds log <build> --project feitian-project --region global
```

To undo a bad deploy, see [Rolling back](#rolling-back). To run again what failed for no fault of the commit, rerun the GitHub job, then build main's tip again:

```bash
gh run list --repo FeitianTech/postquantum-webauthn-platform --commit <full sha>
gh run rerun <run> --repo FeitianTech/postquantum-webauthn-platform --failed
gcloud builds triggers run 340c8d13-cf47-4905-9acb-e85078ec7355 --project feitian-project --region global --branch main
```

Run these once, in your own terminal, so that an e-mail reaches the maintainer when the site is down or erroring, a build fails, or the month's spending passes half the budget, all of it, or is forecast to. By Google's pricing pages the three alert conditions cost at most about US$1.25 a month, and the uptime checks stay within their free allowance. Their two requests a minute keep an instance warm, so the cold starts [Measuring cold starts](#measuring-cold-starts) describes after a quiet spell become rare.

```bash
PROJECT=feitian-project
ALERT_EMAIL=maintainer@example.com   # set these two first
BUDGET=20                            # a month, in the billing account's currency
BILLING_ACCOUNT=$(gcloud billing projects describe $PROJECT --format 'value(billingAccountName)')

gcloud services enable monitoring.googleapis.com pubsub.googleapis.com billingbudgets.googleapis.com --project $PROJECT
CHANNEL=$(gcloud beta monitoring channels create --project $PROJECT --display-name "pqcwebauthn maintainer" \
  --type email --channel-labels email_address=$ALERT_EMAIL --format 'value(name)')

# Every 5 minutes from six regions; the MDS answer must list entries, as the deploy's check does.
gcloud monitoring uptime create "webauthndev.com /" --project $PROJECT --protocol https --validate-ssl true \
  --resource-labels host=webauthndev.com,project_id=$PROJECT --path / --period 5
gcloud monitoring uptime create "webauthndev.com MDS" --project $PROJECT --protocol https --validate-ssl true \
  --resource-labels host=webauthndev.com,project_id=$PROJECT --path /api/mds/metadata/info --period 5 \
  --matcher-type matches-regex --matcher-content '"entryCount": *[1-9]'

# Down: a check failing from more than one region for 10 minutes.
gcloud monitoring policies create --project $PROJECT --display-name "pqcwebauthn down" --notification-channels $CHANNEL \
  --condition-filter 'metric.type="monitoring.googleapis.com/uptime_check/check_passed" AND resource.type="uptime_url" AND resource.label.host="webauthndev.com"' \
  --aggregation '{"alignmentPeriod": "1200s", "perSeriesAligner": "ALIGN_NEXT_OLDER", "crossSeriesReducer": "REDUCE_COUNT_FALSE", "groupByFields": ["metric.label.check_id"]}' \
  --if '> 1' --duration 600s --combiner OR --condition-display-name "Uptime check failing"

# Erroring: five 5xx answers within 10 minutes (one stray 500 is not enough). Once they stop it
# closes by itself, which can take 45 minutes or more.
gcloud monitoring policies create --project $PROJECT --display-name "pqcwebauthn 5xx" --notification-channels $CHANNEL \
  --condition-filter 'metric.type="run.googleapis.com/request_count" AND resource.type="cloud_run_revision" AND resource.label.service_name="pqcwebauthn" AND metric.label.response_code_class="5xx"' \
  --aggregation '{"alignmentPeriod": "600s", "perSeriesAligner": "ALIGN_SUM", "crossSeriesReducer": "REDUCE_SUM"}' \
  --if '> 4' --duration 0s --combiner OR --condition-display-name "5xx answers" \
  --policy '{"alertStrategy": {"autoClose": "1800s"}}'

# A failed build: Cloud Build's documentation says it publishes each build's status to the topic
# cloud-builds, which must exist (if it does already, that command's error is harmless). The
# subscription holds a failure, unread, for 10 minutes, and the alert fires on it. A build whose
# GitHub runs a newer push cancelled fails at its GitHub checks step (see the first part), so it
# sends this notice too.
gcloud pubsub topics create cloud-builds --project $PROJECT
gcloud pubsub subscriptions create build-failures --project $PROJECT --topic cloud-builds \
  --message-filter 'attributes.status = "FAILURE" OR attributes.status = "INTERNAL_ERROR" OR attributes.status = "TIMEOUT"' \
  --message-retention-duration 10m --expiration-period never
gcloud monitoring policies create --project $PROJECT --display-name "pqcwebauthn build failed" --notification-channels $CHANNEL \
  --condition-filter 'metric.type="pubsub.googleapis.com/subscription/num_undelivered_messages" AND resource.type="pubsub_subscription" AND resource.label.subscription_id="build-failures"' \
  --aggregation '{"alignmentPeriod": "60s", "perSeriesAligner": "ALIGN_MAX"}' --if '> 0' --duration 0s \
  --combiner OR --condition-display-name "Failed build unread" --policy '{"alertStrategy": {"autoClose": "1800s"}}'

# Needs Billing Account Administrator or Billing Account Costs Manager on the billing account.
gcloud billing budgets create --billing-account $BILLING_ACCOUNT --display-name pqcwebauthn \
  --budget-amount $BUDGET --filter-projects projects/$PROJECT --notifications-rule-monitoring-notification-channels $CHANNEL \
  --threshold-rule percent=0.5 --threshold-rule percent=1.0 --threshold-rule percent=1.0,basis=forecasted-spend
```

`gcloud monitoring uptime list-configs --project $PROJECT` lists the checks, whose results the console shows after a few minutes, and `gcloud pubsub topics publish cloud-builds --project $PROJECT --attribute status=FAILURE --message test` should send the build alert's e-mail within about five minutes; the first real failed build shows that Cloud Build publishes there. Each has a `delete` command beside its `create` (`gcloud monitoring policies list` and `gcloud billing budgets list --billing-account $BILLING_ACCOUNT` give the names).

## One-time setup: secrets and runtime identity

Run these in your own terminal. Secret values are read from stdin and never appear in files or shell history.

```bash
PROJECT=feitian-project
REGION=asia-northeast1
RUN_SA=pqcwebauthn-run@$PROJECT.iam.gserviceaccount.com

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
```

Then apply the service settings:

```bash
./deploy/apply-service-config.sh
```

## One-time setup: the build's own account

The trigger (`postquantum-webauthn-platform`, a first-generation GitHub trigger in `global`) runs, until this is done, as the default compute account, which holds Editor on the project. Its first steps run `npm ci` with install scripts and both test suites: third-party code that can take the account's token. Give the build an account of its own, with only what its steps use:

- Artifact Registry Writer on the `cloud-run-source-deploy` repository: Push writes the image. The role reads and writes; it deletes no image.
- Cloud Run Developer on the `pqcwebauthn` service alone: Deploy's `services update`, `describe` and `update-traffic`. It cannot change the service's IAM policy, though it could change its other settings or delete it.
- Service Account User on the runtime account: a revision that runs as `pqcwebauthn-run` needs `iam.serviceAccounts.actAs` on it. This replaces the grant this setup used to give the compute account.
- Logs Writer on the project, the narrowest place it can be granted: the build logs to Cloud Logging only, one of the two places a build with its own account may log to.

The test steps and the GitHub checks use no Google Cloud right. Google's guide to user-specified accounts names no further role, for the source fetch or anything else, but does not say so outright for a first-generation GitHub trigger: the first build will tell. Setting the account on the trigger needs `iam.serviceAccounts.actAs` on it, which a project owner has. A grant can take a few minutes to apply.

```bash
PROJECT=feitian-project
REGION=asia-northeast1
TRIGGER=340c8d13-cf47-4905-9acb-e85078ec7355   # postquantum-webauthn-platform
RUN_SA=pqcwebauthn-run@$PROJECT.iam.gserviceaccount.com
BUILD_SA=pqcwebauthn-build@$PROJECT.iam.gserviceaccount.com
OLD_BUILD_SA=277359456097-compute@developer.gserviceaccount.com

gcloud iam service-accounts create pqcwebauthn-build --project $PROJECT \
  --display-name "pqcwebauthn Cloud Build"
gcloud artifacts repositories add-iam-policy-binding cloud-run-source-deploy \
  --project $PROJECT --location $REGION \
  --member serviceAccount:$BUILD_SA --role roles/artifactregistry.writer
gcloud run services add-iam-policy-binding pqcwebauthn --project $PROJECT --region $REGION \
  --member serviceAccount:$BUILD_SA --role roles/run.developer
gcloud iam service-accounts add-iam-policy-binding $RUN_SA --project $PROJECT \
  --member serviceAccount:$BUILD_SA --role roles/iam.serviceAccountUser
gcloud projects add-iam-policy-binding $PROJECT --condition=None \
  --member serviceAccount:$BUILD_SA --role roles/logging.logWriter

# Run the trigger as it: only the trigger's service account changes.
gcloud builds triggers update github $TRIGGER --project $PROJECT --region global \
  --service-account projects/$PROJECT/serviceAccounts/$BUILD_SA
gcloud builds triggers describe $TRIGGER --project $PROJECT --region global \
  --format 'value(serviceAccount)'
```

In the console: Cloud Build, Triggers (region `global`), the trigger, Edit, then pick `pqcwebauthn-build` under Service account and save.

The next push's build names `pqcwebauthn-build` as its service account in its details, and deploys as before. A missing right fails the step that needed it, with a permission-denied message naming the permission: Push for Artifact Registry, Deploy for Cloud Run or `iam.serviceAccounts.actAs`; a right this list lacks shows the same way, and one Cloud Build itself needs before any step fails the build as it starts. The traffic stays where it was. Grant what is named, on the resource above, and retry the build. To go back, run the trigger update with `--service-account projects/$PROJECT/serviceAccounts/$OLD_BUILD_SA`, or pick that account in the console.

Once a deploy has passed, remove the old account's grant on the runtime account, with the variables above (going back then needs it again):

```bash
gcloud iam service-accounts remove-iam-policy-binding $RUN_SA --project $PROJECT \
  --member serviceAccount:$OLD_BUILD_SA --role roles/iam.serviceAccountUser
```

The compute account keeps its roles in the project, since other things may use it. What changes is that this build no longer runs as it. Code in the build's steps can still deploy any image to this one service, change its other settings (not its IAM policy) and delete its revisions, and a revision it deploys runs with the runtime account's access to the bucket and the secrets. Beyond that it can only write images to the one repository and write logs.

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
