"""An in-memory stand-in for a GCS bucket with object generations.

Conditional uploads (``if_generation_match``) are checked and applied under one
lock, as GCS does server-side, so threads racing them see exactly one winner.
``on_download`` hooks run after a download has read an object: a test uses one
to have "another instance" write between a request's read and its write.
``failing`` maps an object name to the error its downloads raise.
"""
from __future__ import annotations

import threading
import types
from collections.abc import Callable

from server.app.storage import cloud


# Stand-ins for google.api_core.exceptions. Other test modules replace that
# module in sys.modules with a stub that has no PreconditionFailed, so the fake
# bucket brings its own and the cloud module is pointed at them.
class NotFound(Exception):
    pass


class PreconditionFailed(Exception):
    pass


class ServiceUnavailable(Exception):
    """A GCS error the client does not retry here, so a failing read fails at once."""


class Bucket:
    def __init__(self) -> None:
        self.objects: dict[str, tuple[bytes, int]] = {}
        self.next_generation = 1
        self.upload_retries: list[object] = []
        self.on_download: list[Callable[[str], None]] = []
        self.failing: dict[str, Exception] = {}
        self.lock = threading.Lock()

    def blob(self, name: str) -> Blob:
        return Blob(self, name)

    def list_blobs(self, prefix: str = "", max_results: int | None = None) -> list[Blob]:
        with self.lock:
            names = sorted(name for name in self.objects if name.startswith(prefix))
        return [Blob(self, name) for name in names[:max_results]]

    def put(self, name: str, data: bytes) -> None:
        """Write ``name`` directly, as another server instance would."""

        with self.lock:
            self.objects[name] = (bytes(data), self.next_generation)
            self.next_generation += 1


class Blob:
    def __init__(self, bucket: Bucket, name: str) -> None:
        self.bucket = bucket
        self.name = name
        self.generation = None

    def download_as_bytes(self) -> bytes:
        if self.name in self.bucket.failing:
            raise self.bucket.failing[self.name]
        with self.bucket.lock:
            if self.name not in self.bucket.objects:
                raise NotFound(self.name)
            data, self.generation = self.bucket.objects[self.name]
        for hook in list(self.bucket.on_download):
            hook(self.name)
        return data

    def upload_from_string(self, data, content_type=None, if_generation_match=None, retry="default") -> None:
        with self.bucket.lock:
            self.bucket.upload_retries.append(retry)
            current = self.bucket.objects.get(self.name, (None, 0))[1]
            if if_generation_match is not None and if_generation_match != current:
                raise PreconditionFailed(f"{self.name} is at generation {current}")
            self.bucket.objects[self.name] = (bytes(data), self.bucket.next_generation)
            self.bucket.next_generation += 1

    def delete(self) -> None:
        with self.bucket.lock:
            if self.name not in self.bucket.objects:
                raise NotFound(self.name)
            del self.bucket.objects[self.name]

    def exists(self) -> bool:
        with self.bucket.lock:
            return self.name in self.bucket.objects


def install(monkeypatch, *stores) -> Bucket:
    """Point the cloud module at a fresh fake bucket and switch ``stores`` to GCS."""

    bucket = Bucket()
    exceptions = types.SimpleNamespace(
        NotFound=NotFound, PreconditionFailed=PreconditionFailed, GoogleAPICallError=OSError, RetryError=OSError
    )
    monkeypatch.setitem(vars(cloud), "gcs_exceptions", exceptions)
    # The retryable-error tuple is cached from whichever exceptions module is in
    # place when a retry is first considered; computed from these stand-ins, it
    # must not outlive the test and leave other modules' stubs unretried.
    monkeypatch.setattr(cloud, "_RETRYABLE_EXCEPTIONS_CACHE", None)
    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: bucket)
    for store in stores:
        monkeypatch.setattr(store, "_using_gcs", lambda: True)
    return bucket
