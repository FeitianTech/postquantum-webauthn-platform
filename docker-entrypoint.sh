#!/bin/bash
set -e

# Docker entrypoint script that handles volume permissions
# This script runs as root to fix permissions, then drops to the webauthn user

# Define storage directories that need to be created with proper permissions
STORAGE_DIRS=(
    "/app/storage"
    "/app/storage/user-data"
    "/app/storage/fido-mds"
    "/app/server/session-credentials"
    "/app/server/static/session-metadata"
    "/app/server/instance"
)

# Create directories and set proper ownership
for dir in "${STORAGE_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        echo "Created directory: $dir"
    fi
done

# Set ownership for all storage-related directories
chown -R webauthn:webauthn /app/storage
chown -R webauthn:webauthn /app/server/session-credentials
chown -R webauthn:webauthn /app/server/static/session-metadata
chown -R webauthn:webauthn /app/server/instance

echo "Permissions configured for webauthn user"

# Execute the main command as the webauthn user
exec gosu webauthn "$@"
