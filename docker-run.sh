#!/bin/bash

# Build and run the Docker container for WebAuthn FIDO2 test app

echo "Building Docker container..."
docker build -t webauthn-fido2-test .

echo "Running container on port 8080..."
echo "The application will be available at http://localhost:8080"
echo "Press Ctrl+C to stop the container"

docker run -p 8080:8080 \
  -e DOMAIN=${DOMAIN:-localhost:8080} \
  -e DOCKER_CONTAINER=true \
  --rm \
  webauthn-fido2-test