"""Gunicorn settings for the Cloud Run container."""

import os

bind = f"0.0.0.0:{os.environ.get('PORT', '8080')}"

# One process keeps a single copy of the in-memory MDS caches; threads let one
# instance serve a whole page load (HTML plus its static assets) concurrently.
workers = 1
worker_class = "gthread"
threads = int(os.environ.get("GUNICORN_THREADS", "16"))

# Cloud Run enforces the request timeout.
timeout = 0
graceful_timeout = 8
keepalive = 5
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "warning")


def post_worker_init(worker):
    # The image copies server/app to /app/server, so the module path differs
    # between the container and a repository checkout.
    try:
        from server.startup import start_background_warmup
    except ImportError:
        from server.app.startup import start_background_warmup

    start_background_warmup()
