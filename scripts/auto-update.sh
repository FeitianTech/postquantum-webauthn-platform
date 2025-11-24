#!/bin/bash

# Auto-update script for postquantum-webauthn-platform
# This script checks for updates from the remote repository and redeploys if there are changes

set -e

PROJECT_DIR="$HOME/postquantum-webauthn-platform"
LOG_FILE="$PROJECT_DIR/logs/auto-update.log"

# Ensure log directory exists
mkdir -p "$PROJECT_DIR/logs"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

cd "$PROJECT_DIR"

log "Checking for updates..."

# Fetch latest changes
git fetch origin main

# Check if there are new commits
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" = "$REMOTE" ]; then
    log "No updates available. Current commit: $LOCAL"
    exit 0
fi

log "Updates found! Local: $LOCAL, Remote: $REMOTE"

# Pull the latest changes
git pull origin main

log "Rebuilding and redeploying Docker containers..."

# Rebuild and restart containers
docker compose up --build -d

log "Deployment completed successfully!"

# Optional: Clean up old Docker images
docker image prune -f >> "$LOG_FILE" 2>&1

log "Auto-update finished."
