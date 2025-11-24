#!/bin/bash

# Auto-update script for postquantum-webauthn-platform
# This script:
# 1. Checks for code updates from remote repository
# 2. Updates FIDO MDS locally
# 3. Redeploys if there are any changes

set -e

PROJECT_DIR="$HOME/postquantum-webauthn-platform"
LOG_FILE="$PROJECT_DIR/logs/auto-update.log"

# Ensure log directory exists
mkdir -p "$PROJECT_DIR/logs"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

cd "$PROJECT_DIR"

NEEDS_REBUILD=false

# --- Check for code updates ---
log "Checking for code updates..."

git fetch origin main

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" != "$REMOTE" ]; then
    log "Code updates found! Local: $LOCAL, Remote: $REMOTE"
    git reset --hard origin/main
    NEEDS_REBUILD=true
else
    log "No code updates. Current commit: $LOCAL"
fi

# --- Update FIDO MDS locally ---
log "Checking for FIDO MDS updates..."

# Store hash of current MDS file (if exists)
MDS_FILE="$PROJECT_DIR/server/server/static/fido-mds3.verified.json"
if [ -f "$MDS_FILE" ]; then
    OLD_MDS_HASH=$(md5sum "$MDS_FILE" | cut -d' ' -f1)
else
    OLD_MDS_HASH=""
fi

# Run MDS update script
python3 "$PROJECT_DIR/scripts/update_mds_snapshot.py" >> "$LOG_FILE" 2>&1 || {
    log "Warning: MDS update failed, continuing with existing MDS"
}

# Check if MDS was updated
if [ -f "$MDS_FILE" ]; then
    NEW_MDS_HASH=$(md5sum "$MDS_FILE" | cut -d' ' -f1)
    if [ "$OLD_MDS_HASH" != "$NEW_MDS_HASH" ]; then
        log "FIDO MDS updated!"
        NEEDS_REBUILD=true
    else
        log "FIDO MDS is already up to date"
    fi
fi

# --- Rebuild if needed ---
if [ "$NEEDS_REBUILD" = true ]; then
    log "Rebuilding and redeploying Docker containers..."
    docker compose up --build -d
    log "Deployment completed successfully!"

    # Clean up old Docker images
    docker image prune -f >> "$LOG_FILE" 2>&1
else
    log "No changes detected, skipping rebuild"
fi

log "Auto-update finished."
