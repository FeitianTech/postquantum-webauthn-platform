#!/usr/bin/env python3
"""Cloud Build's GitHub checks step (cloudbuild.yaml): deploy a commit only once
GitHub Actions' browser tests and image check have passed on it.

The two pipelines are independent, so this reads the commit's check runs from
GitHub's REST API, without a token (60 requests an hour for one address), and
exits 0 only when the latest run of each REQUIRED job completed with success.
A run not reported yet, queued or in progress is read again PAUSE_SECONDS later,
until DEADLINE_SECONDS; a run that completed otherwise fails at once, and so does
an answer that could not be read READ_ATTEMPTS times in a row.

Needs COMMIT_SHA and REPOSITORY_URL (https://github.com/<owner>/<repo>). Uses
nothing but the standard library: it runs in the python:3.12-slim image.
"""

from __future__ import annotations

import json
import os
import sys
from http.client import HTTPException
from time import gmtime, monotonic, sleep, strftime
from urllib.error import HTTPError
from urllib.request import Request, urlopen

# The check runs' names: each job's name, or its id when it has none (ci-web.yml's
# e2e job, ci-docker.yml's docker-build; test_required_checks.py ties them).
REQUIRED = ("Browser tests (Playwright, virtual authenticator)", "docker-build")
APP = "github-actions"
DEADLINE_SECONDS = 600
PAUSE_SECONDS = 30
READ_ATTEMPTS = 3
REQUEST_SECONDS = 30


class Unreadable(Exception):
    """GitHub's answer could not be read; the message says why."""


def read_check_runs(repository: str, commit: str) -> list:
    # Ten or so check runs a commit, and a job run again replaces its run in the
    # default filter=latest: one page of 100 holds them all.
    request = Request(
        f"https://api.github.com/repos/{repository}/commits/{commit}/check-runs?per_page=100",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "postquantum-webauthn-platform-deploy"},
    )
    try:
        with urlopen(request, timeout=REQUEST_SECONDS) as answer:
            status, body = answer.status, answer.read()
    except HTTPError as error:
        if error.code in (403, 429):
            reset = error.headers.get("X-RateLimit-Reset", "")
            when = strftime(" until %H:%M UTC", gmtime(int(reset))) if reset.isdigit() else ""
            raise Unreadable(f"{error.code}: GitHub's rate limit for requests without a token is spent{when}") from None
        raise Unreadable(f"{error.code} from GitHub") from None
    except (OSError, HTTPException) as error:
        raise Unreadable(f"no answer from GitHub ({error})") from None
    if status != 200:
        raise Unreadable(f"{status} from GitHub")
    try:
        return json.loads(body)["check_runs"]
    except (ValueError, KeyError, TypeError):
        raise Unreadable("an answer that is not GitHub's check runs JSON") from None


def verdict(runs: list) -> tuple[str, str]:
    """"pass", "wait" or "fail", and what the required runs say."""

    waiting = []
    try:
        for name in REQUIRED:
            ours = [run for run in runs if run["name"] == name and run["app"]["slug"] == APP]
            # The latest started: a job run again starts after the run it replaces
            # (which filter=latest, the default, leaves out already); ids break a tie.
            run = max(ours, key=lambda run: (run["started_at"] or "", run["id"]), default=None)
            if run is None or run["status"] != "completed":
                waiting.append(f"{name}: {run['status'] if run else 'not reported'}")
            elif run["conclusion"] != "success":
                return "fail", f"{name} ended {run['conclusion']}"
    except (KeyError, TypeError) as error:
        raise Unreadable(f"a check run that is not GitHub's ({error!r})") from None
    return ("wait", "; ".join(waiting)) if waiting else ("pass", "")


def main() -> int:
    commit = os.environ["COMMIT_SHA"]
    repository = os.environ["REPOSITORY_URL"].removeprefix("https://github.com/")
    deadline = monotonic() + DEADLINE_SECONDS
    failed_reads = 0
    while True:
        try:
            state, said = verdict(read_check_runs(repository, commit))
            failed_reads = 0
        except Unreadable as error:
            failed_reads += 1
            if failed_reads >= READ_ATTEMPTS:
                print(f"Could not read {commit}'s check runs from GitHub in {failed_reads} tries (the last: "
                      f"{error}). Nothing is deployed; retry this build once GitHub answers.", file=sys.stderr)
                return 1
            state, said = "wait", str(error)
        if state == "pass":
            print(f"{' and '.join(REQUIRED)} passed on {commit}.")
            return 0
        if state == "fail":
            print(f"On {commit}, {said}: nothing is deployed. If it failed for no fault of the commit, "
                  "run the job again on GitHub, then retry this build.", file=sys.stderr)
            return 1
        if monotonic() + PAUSE_SECONDS > deadline:
            print(f"After {DEADLINE_SECONDS // 60} minutes, still waiting for {commit}'s checks ({said}): "
                  "nothing is deployed. Once both jobs have passed on GitHub, retry this build.", file=sys.stderr)
            return 1
        print(f"Waiting for GitHub ({said})")
        sleep(PAUSE_SECONDS)


if __name__ == "__main__":
    sys.exit(main())
