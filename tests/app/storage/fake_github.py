"""A stand-in for the credential log repository on GitHub, in place of ``github_mirror._request``.

The repository's default branch is ``files``, each path with its bytes. It answers the calls
the mirror makes as GitHub does:

- the contents API's GET: a file (with its blob SHA), or a folder's listing, at most 1,000
  entries as GitHub lists them; the root of an empty repository is a 404;
- its PUT: a new file is created (201); a file already there is replaced (200) only when the
  request names its SHA; without one GitHub answers 422 and says "sha" wasn't supplied, and
  with another SHA 409;
- the git trees API's GET of a folder's tree (``tree-<folder>`` here), every entry of it.

``fail`` queues errors the next calls raise; ``unseen`` names paths a GET does not find yet,
as a read from a replica behind the write would not.
"""
from __future__ import annotations

import base64
import io
import json
import threading
from urllib.error import HTTPError
from urllib.parse import unquote, urlsplit

from server.app.storage import github_mirror

_REPOSITORY = "/repos/rainzhang05/CredentialLogs/"
_CONTENTS_LISTED = 1_000
SHA_NOT_SUPPLIED = 'Invalid request.\n\n"sha" wasn\'t supplied.'


def http_error(code: int, message: str = "") -> HTTPError:
    """An error as urllib raises it for GitHub's answer: its JSON body carries the message."""

    body = json.dumps({"message": message or f"HTTP {code}"}).encode("utf-8")
    return HTTPError("https://api.github.com/", code, message or f"HTTP {code}", None, io.BytesIO(body))


class FakeGitHub:
    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.calls: list[tuple[str, str]] = []
        self.puts: list[tuple[str, dict]] = []
        self.fail: list[BaseException] = []
        self.unseen: set[str] = set()
        self.lock = threading.Lock()

    def request(self, method: str, url: str, body: dict | None = None) -> tuple[int, bytes]:
        path = unquote(urlsplit(url).path)
        assert path.startswith(_REPOSITORY), url
        path = path[len(_REPOSITORY) :]
        with self.lock:
            self.calls.append((method, path))
            if self.fail:
                raise self.fail.pop(0)
            if method == "PUT":
                return self._put(path.removeprefix("contents/"), body or {})
            assert method == "GET", method
            if path.startswith("git/trees/"):
                return self._tree(path.removeprefix("git/trees/tree-"))
            return self._get(path.removeprefix("contents").strip("/"))

    def _children(self, folder: str) -> dict[str, str]:
        """What is directly in ``folder``: each name, "blob" or "tree"."""

        prefix = f"{folder}/" if folder else ""
        children: dict[str, str] = {}
        for path in sorted(self.files):
            if path.startswith(prefix):
                name, _, rest = path[len(prefix) :].partition("/")
                children[name] = "tree" if rest else "blob"
        return children

    def _sha(self, path: str, kind: str) -> str:
        return github_mirror.git_blob_sha(self.files[path]) if kind == "blob" else f"tree-{path}"

    def _get(self, path: str) -> tuple[int, bytes]:
        if path in self.files and path not in self.unseen:
            item = {"type": "file", "name": path.rsplit("/", 1)[-1], "path": path, "sha": self._sha(path, "blob")}
            return 200, json.dumps(item).encode("utf-8")
        children = self._children(path)
        if not children or path in self.files:
            raise http_error(404, "Not Found")
        listing = []
        for name, kind in list(children.items())[:_CONTENTS_LISTED]:
            child = f"{path}/{name}" if path else name
            listing.append(
                {"type": "file" if kind == "blob" else "dir", "name": name, "path": child, "sha": self._sha(child, kind)}
            )
        return 200, json.dumps(listing).encode("utf-8")

    def _tree(self, folder: str) -> tuple[int, bytes]:
        children = self._children(folder)
        if not children:
            raise http_error(404, "Not Found")
        tree = [
            {"path": name, "type": kind, "sha": self._sha(f"{folder}/{name}", kind)} for name, kind in children.items()
        ]
        return 200, json.dumps({"sha": f"tree-{folder}", "tree": tree, "truncated": False}).encode("utf-8")

    def _put(self, path: str, body: dict) -> tuple[int, bytes]:
        data = base64.b64decode(body["content"], validate=True)
        current = self.files.get(path)
        sha = body.get("sha")
        if current is not None and sha is None:
            raise http_error(422, SHA_NOT_SUPPLIED)
        if sha is not None and (current is None or github_mirror.git_blob_sha(current) != sha):
            raise http_error(409, f"{path} does not match {sha}")
        self.files[path] = data
        self.puts.append((path, body))
        answer = {"content": {"path": path, "sha": github_mirror.git_blob_sha(data)}}
        return (201 if current is None else 200), json.dumps(answer).encode("utf-8")


def install(monkeypatch) -> FakeGitHub:
    """The log on, with a token, against a fresh fake repository at the default name."""

    github = FakeGitHub()
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "1")
    monkeypatch.delenv("GITHUB_LOG_REPO_OWNER", raising=False)
    monkeypatch.delenv("GITHUB_LOG_REPO_NAME", raising=False)
    monkeypatch.setattr(github_mirror, "_request", github.request)
    return github
