#!/usr/bin/env bash
# Apply deploy/service.yaml to the live Cloud Run service, keeping the image
# that is currently deployed.
set -euo pipefail

PROJECT="${PROJECT:-feitian-project}"
REGION="${REGION:-asia-northeast1}"
SERVICE="${SERVICE:-pqcwebauthn}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

image="$(gcloud run services describe "$SERVICE" \
  --project "$PROJECT" --region "$REGION" \
  --format='value(spec.template.spec.containers[0].image)')"

if [[ -z "$image" ]]; then
  echo "Could not determine the current image for $SERVICE." >&2
  exit 1
fi

rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT
sed "s|IMAGE_PLACEHOLDER|${image}|" "$SCRIPT_DIR/service.yaml" > "$rendered"

echo "Applying $SCRIPT_DIR/service.yaml to $SERVICE with image $image"
gcloud run services replace "$rendered" --project "$PROJECT" --region "$REGION"
