#!/usr/bin/env bash
# Apply deploy/service.yaml to the live Cloud Run service, keeping the image
# that serves its traffic. The new revision takes all the traffic at once, with
# none of the checks a deploy runs first (deploy/deploy-revision.sh).
set -euo pipefail

PROJECT="${PROJECT:-feitian-project}"
REGION="${REGION:-asia-northeast1}"
SERVICE="${SERVICE:-pqcwebauthn}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT

# The revision that serves the traffic, not the template's: after a deploy whose
# checks failed, the template holds that deploy's image, which must not go live.
serving="$(gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" \
  --format='value(status.traffic.filter("percent=100").map().extract(revisionName).flatten())')"
if [[ -z "$serving" || "$serving" == *,* ]]; then
  echo "No one revision of $SERVICE serves all its traffic; nothing applied." >&2
  exit 1
fi

image="$(gcloud run revisions describe "$serving" \
  --project "$PROJECT" --region "$REGION" \
  --format='value(spec.containers[0].image)')"

if [[ -z "$image" ]]; then
  echo "Could not determine the image of $serving." >&2
  exit 1
fi

sed "s|IMAGE_PLACEHOLDER|${image}|" "$SCRIPT_DIR/service.yaml" > "$rendered"

echo "Applying $SCRIPT_DIR/service.yaml to $SERVICE with $serving's image $image"
gcloud run services replace "$rendered" --project "$PROJECT" --region "$REGION"
