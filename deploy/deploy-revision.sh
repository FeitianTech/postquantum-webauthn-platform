#!/usr/bin/env bash
# Cloud Build's Deploy step (cloudbuild.yaml): roll IMAGE out to the Cloud Run
# service as a revision that takes no traffic, check that revision through its
# tag's URL, and only then send it all the traffic.
#
# Whatever fails ends the script, and the traffic stays where it was:
# --no-traffic leaves it, by name, on the revision that served it before. The
# checks wait out a cold start (minScale 0: the revision starts on its first
# request, and /api/mds/metadata/info waits for the MDS snapshot it provisions),
# trying each until it passes, PAUSE_SECONDS apart, within one deadline for all.
#
# Builds overlap, and one can be retried by hand: so before it deploys and again
# before it promotes, the script reads main's tip from REPOSITORY_URL. A build
# whose commit is no longer the tip ends there without error, the traffic left
# where it is; a tip it cannot read fails the deploy.
#
# Needs IMAGE, SERVICE, REGION, COMMIT_SHA, BUILD_ID and REPOSITORY_URL (the
# public repository on GitHub); LABELS is optional.
# It calls gcloud, curl and grep, all in the cloud-sdk:slim image (which has no
# python3 of its own): gcloud's projections read the service.
set -euo pipefail

: "${IMAGE:?}" "${SERVICE:?}" "${REGION:?}" "${COMMIT_SHA:?}" "${BUILD_ID:?}" "${REPOSITORY_URL:?}"
LABELS="${LABELS:-}"
TAG=candidate
DEADLINE_SECONDS=480
PAUSE_SECONDS=15
MAX_ATTEMPTS=40
MAX_REQUEST_SECONDS=120
TIP_ATTEMPTS=4
TIP_PAUSE_SECONDS=5

# The revision's own name, so the one checked is the one promoted, whatever
# another build deploys meanwhile. Cloud Run's names are lower-case.
suffix="$(printf '%s-%s' "${COMMIT_SHA:0:12}" "${BUILD_ID:0:8}" | tr '[:upper:]' '[:lower:]')"
revision="$SERVICE-$suffix"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The tag must name this build's revision: its URL is then the one to check.
tag_names_revision() {
  local found
  # "<url>,<revision>" of the traffic entry the tag names; nothing without it.
  found="$(gcloud run services describe "$SERVICE" --platform=managed --region="$REGION" \
    --format="value(status.traffic.filter(\"tag=$TAG\").map().extract(url,revisionName).flatten())")" || return 1
  url="${found%%,*}"
  if [ -z "$found" ] || [ "${found#*,}" != "$revision" ] || [ -z "$url" ]; then
    echo "The tag $TAG names '${found#*,}', not $revision." >&2
    return 1
  fi
}

# Ends the script unless COMMIT_SHA is main's tip. The tip is read from git's own
# ref advertisement, which needs no token and is not the REST API's rate limit;
# its line for main is "<4 hex digits of length><commit> refs/heads/main".
stop_unless_main_tip() {
  local attempt=0 tip commit
  commit="$(printf '%s' "$COMMIT_SHA" | tr '[:upper:]' '[:lower:]')"
  while :; do
    attempt=$((attempt + 1))
    if curl -fsS --max-time 30 -o "$work/refs" "$REPOSITORY_URL.git/info/refs?service=git-upload-pack" &&
      tip="$(grep -aEo '[0-9a-f]{40} refs/heads/main$' "$work/refs")"; then
      tip="${tip%% *}"
      [ "$tip" = "$commit" ] && return 0
      echo "main is now at $tip, not $commit: this build leaves the traffic where it is, and that commit's build deploys it."
      exit 0
    fi
    if [ "$attempt" -ge "$TIP_ATTEMPTS" ]; then
      echo "Could not read main's tip from $REPOSITORY_URL after $attempt attempts; the traffic stays where it was." >&2
      exit 1
    fi
    sleep "$TIP_PAUSE_SECONDS"
  done
}

body_is_ok() { [ "$(cat "$1")" = ok ]; }
body_is_html() { grep -qi '<html' "$1"; }
body_has_entries() { grep -Eq '"entryCount": *[1-9]' "$1"; }

deadline=0

# check PATH TEST: GET the revision's PATH until TEST passes on its body.
check() {
  local path="$1" test="$2" attempt=0 left
  while :; do
    attempt=$((attempt + 1))
    left=$((deadline - $(date +%s)))
    if [ "$left" -gt 0 ] && curl -fsS --max-time "$((left < MAX_REQUEST_SECONDS ? left : MAX_REQUEST_SECONDS))" \
      -o "$work/body" "$url$path" && "$test" "$work/body"; then
      echo "$path: passed on attempt $attempt"
      return 0
    fi
    if [ "$attempt" -ge "$MAX_ATTEMPTS" ] || [ "$((deadline - $(date +%s)))" -le "$PAUSE_SECONDS" ]; then
      echo "$path: not passed after $attempt attempts; the traffic stays where it was." >&2
      return 1
    fi
    sleep "$PAUSE_SECONDS"
  done
}

stop_unless_main_tip
echo "Deploying $IMAGE as $revision, tagged $TAG, with no traffic"
gcloud run services update "$SERVICE" --platform=managed --region="$REGION" --image="$IMAGE" \
  --revision-suffix="$suffix" --no-traffic --tag="$TAG" ${LABELS:+"--labels=$LABELS"} --quiet

tag_names_revision
echo "Checking $revision at $url"
deadline=$(($(date +%s) + DEADLINE_SECONDS))
check /health body_is_ok
check / body_is_html
check /api/mds/metadata/info body_has_entries

# Another build may have moved the tag, or main, while these ran: promote only this one.
tag_names_revision
stop_unless_main_tip
echo "Sending all traffic to $revision"
gcloud run services update-traffic "$SERVICE" --platform=managed --region="$REGION" \
  --to-revisions="$revision=100" --quiet
