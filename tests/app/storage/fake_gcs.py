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
from server.app.storage import common as storage_common


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
        self.list_calls: list[tuple[str, str | None]] = []
        self.download_options: list[tuple[str, dict]] = []
        self.lock = threading.Lock()

    def blob(self, name: str) -> Blob:
        return Blob(self, name)

    def list_blobs(
        self, prefix: str = "", max_results: int | None = None, delimiter: str | None = None, retry: object = None
    ) -> Listing:
        """The objects under ``prefix``, as Cloud Storage lists them; every call is recorded.

        With ``delimiter``, a name with another delimiter after the prefix is not
        listed: its part up to that delimiter is one of the listing's ``prefixes``.
        """

        self.list_calls.append((prefix, delimiter))
        with self.lock:
            names = sorted(name for name in self.objects if name.startswith(prefix))
        blobs: list[Blob] = []
        prefixes: set[str] = set()
        for name in names:
            rest = name[len(prefix) :]
            if delimiter is not None and delimiter in rest:
                prefixes.add(prefix + rest[: rest.index(delimiter) + len(delimiter)])
            else:
                blobs.append(Blob(self, name))
        return Listing(blobs[:max_results], prefixes)

    def put(self, name: str, data: bytes) -> None:
        """Write ``name`` directly, as another server instance would."""

        with self.lock:
            self.objects[name] = (bytes(data), self.next_generation)
            self.next_generation += 1


class Listing:
    """A listing's iterator: ``prefixes`` fills in only as it is read, as the client's pages do."""

    def __init__(self, blobs: list[Blob], prefixes: set[str]) -> None:
        self._blobs = blobs
        self._prefixes = prefixes
        self.prefixes: set[str] = set()

    def __iter__(self):
        yield from self._blobs
        self.prefixes |= self._prefixes


class Blob:
    def __init__(self, bucket: Bucket, name: str) -> None:
        self.bucket = bucket
        self.name = name
        self.generation = None

    def download_as_bytes(self, **options) -> bytes:
        self.bucket.download_options.append((self.name, options))
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

    def delete(self, retry: object = None) -> None:
        with self.bucket.lock:
            if self.name not in self.bucket.objects:
                raise NotFound(self.name)
            del self.bucket.objects[self.name]

    def exists(self, retry: object = None) -> bool:
        with self.bucket.lock:
            return self.name in self.bucket.objects


def install(monkeypatch, *stores) -> Bucket:
    """Point the cloud module at a fresh fake bucket; with ``stores``, put the stores on it."""

    bucket = Bucket()
    exceptions = types.SimpleNamespace(
        NotFound=NotFound, PreconditionFailed=PreconditionFailed, GoogleAPICallError=OSError, RetryError=OSError
    )
    monkeypatch.setitem(vars(cloud), "gcs_exceptions", exceptions)
    # The client library's retry policy is what the calls are given; the fake
    # bucket records it and never needs the library.
    monkeypatch.setattr(cloud, "_retry", lambda: "the client's retry")
    monkeypatch.setattr(cloud, "_ensure_bucket", lambda: bucket)
    if stores:
        # One switch moves every store, as production's one environment switch does.
        monkeypatch.setattr(storage_common, "using_gcs", lambda: True)
    return bucket
