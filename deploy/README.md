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

Then apply the service settings. This replaces the plaintext `GITHUB_TOKEN` and `FIDO_SERVER_GCS_CREDENTIALS_JSON` environment variables with the secret references above.

```bash
./deploy/apply-service-config.sh
```

Once the new revision is serving:
1. Revoke the old GitHub token in GitHub settings.
2. Delete the old service-account key:

```bash
gcloud iam service-accounts keys list --iam-account 277359456097-compute@developer.gserviceaccount.com
gcloud iam service-accounts keys delete KEY_ID --iam-account 277359456097-compute@developer.gserviceaccount.com
```

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
