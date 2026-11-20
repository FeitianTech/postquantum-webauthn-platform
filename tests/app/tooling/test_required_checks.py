"""tools/required_checks.py, Cloud Build's GitHub checks step: a commit deploys only
once GitHub Actions' browser tests and image check succeeded on it.

GitHub's answers are stand-ins in the shape a real one has (read from this repository's
check runs); the clock is a stand-in too, whose sleep moves it on at once.
"""

from __future__ import annotations

import io
import json
import re
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

from tools import required_checks
from tools.required_checks import REQUIRED

ROOT = Path(__file__).resolve().parents[3]
COMMIT = "d7150ac61ad7845b865c5909d590f28f7ab89cc1"
REPOSITORY_URL = "https://github.com/FeitianTech/postquantum-webauthn-platform"
API_URL = (
    "https://api.github.com/repos/FeitianTech/postquantum-webauthn-platform"
    f"/commits/{COMMIT}/check-runs?per_page=100"
)
BROWSER, IMAGE = REQUIRED


def _run(name, status="completed", conclusion="success", started="2026-11-20T06:09:03Z", run_id=1, app="github-actions"):
    return {
        "id": run_id,
        "name": name,
        "head_sha": COMMIT,
        "status": status,
        "conclusion": conclusion if status == "completed" else None,
        "started_at": started,
        "app": {"slug": app},
    }


def _answer(*runs):
    return {"total_count": len(runs), "check_runs": list(runs)}


PASSED = _answer(_run("python-checks", run_id=3), _run(BROWSER, run_id=1), _run(IMAGE, run_id=2))


class _Response(io.BytesIO):
    def __init__(self, body: bytes, status: int = 200):
        super().__init__(body)
        self.status = status


class _GitHub:
    """Answers each request with the next answer: a JSON body, raw bytes, a status
    with its body, or an exception; the last one repeats."""

    def __init__(self, *answers):
        self.answers, self.requests = list(answers), []

    def urlopen(self, request, timeout):
        self.requests.append(request)
        answer = self.answers[min(len(self.requests), len(self.answers)) - 1]
        if isinstance(answer, BaseException):
            raise answer
        status, body = answer if isinstance(answer, tuple) else (200, answer)
        return _Response(body if isinstance(body, bytes) else json.dumps(body).encode(), status)


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _check(monkeypatch, *answers):
    github, clock = _GitHub(*answers), _Clock()
    monkeypatch.setenv("COMMIT_SHA", COMMIT)
    monkeypatch.setenv("REPOSITORY_URL", REPOSITORY_URL)
    monkeypatch.setattr(required_checks, "urlopen", github.urlopen)
    monkeypatch.setattr(required_checks, "monotonic", clock.monotonic)
    monkeypatch.setattr(required_checks, "sleep", clock.sleep)
    return required_checks.main(), github.requests


def _rate_limited(code):
    headers = Message()
    headers["X-RateLimit-Limit"] = "60"
    headers["X-RateLimit-Remaining"] = "0"
    headers["X-RateLimit-Reset"] = "1795157058"
    return HTTPError(API_URL, code, "rate limit exceeded", headers, io.BytesIO(b"{}"))


def test_a_commit_whose_two_jobs_succeeded_deploys_after_one_read(monkeypatch, capsys):
    code, requests = _check(monkeypatch, PASSED)

    assert code == 0
    assert [request.full_url for request in requests] == [API_URL]
    assert requests[0].get_header("Accept") == "application/vnd.github+json"
    assert requests[0].get_header("User-agent")
    assert requests[0].get_header("Authorization") is None
    assert COMMIT in capsys.readouterr().out


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "skipped", "timed_out", "neutral"])
@pytest.mark.parametrize("job", REQUIRED)
def test_a_job_that_ended_without_success_fails_at_once(monkeypatch, capsys, job, conclusion):
    other = IMAGE if job == BROWSER else BROWSER
    code, requests = _check(monkeypatch, _answer(_run(other, run_id=1), _run(job, conclusion=conclusion, run_id=2)))

    assert code == 1
    assert len(requests) == 1
    said = capsys.readouterr().err
    assert f"{job} ended {conclusion}" in said
    assert "nothing is deployed" in said


def test_a_failure_is_not_waited_out_behind_a_job_not_reported_yet(monkeypatch):
    code, requests = _check(monkeypatch, _answer(_run(IMAGE, conclusion="failure")))

    assert code == 1
    assert len(requests) == 1


@pytest.mark.parametrize("job", REQUIRED)
def test_a_job_never_reported_deploys_nothing(monkeypatch, capsys, job):
    reported = [run for run in PASSED["check_runs"] if run["name"] != job]
    code, requests = _check(monkeypatch, _answer(*reported))

    assert code == 1
    assert len(requests) > 1
    said = capsys.readouterr().err
    assert f"still waiting for {COMMIT}'s checks ({job}: not reported)" in said


def test_a_run_in_progress_is_read_again_until_it_succeeds(monkeypatch):
    running = _answer(_run(BROWSER, status="in_progress", run_id=1), _run(IMAGE, status="queued", run_id=2))

    code, requests = _check(monkeypatch, running, running, PASSED)

    assert code == 0
    assert len(requests) == 3


def test_a_run_still_in_progress_at_the_deadline_deploys_nothing(monkeypatch, capsys):
    code, requests = _check(monkeypatch, _answer(_run(BROWSER, status="in_progress"), _run(IMAGE, run_id=2)))

    assert code == 1
    assert 1 < len(requests) <= required_checks.DEADLINE_SECONDS // required_checks.PAUSE_SECONDS + 1
    assert f"({BROWSER}: in_progress)" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("first", "second", "code"),
    [("failure", "success", 0), ("success", "failure", 1)],
)
def test_a_job_run_again_counts_by_its_latest_run(monkeypatch, first, second, code):
    # Neither the first listed, the last listed nor the highest id is the latest started.
    earlier = _run(BROWSER, conclusion=first, started="2026-11-20T06:09:03Z", run_id=20)
    later = _run(BROWSER, conclusion=second, started="2026-11-20T06:30:41Z", run_id=10)
    earliest = _run(BROWSER, conclusion=first, started="2026-11-20T05:58:12Z", run_id=5)

    assert _check(monkeypatch, _answer(earlier, later, _run(IMAGE, run_id=7), earliest))[0] == code


def test_a_run_of_another_app_with_the_same_name_does_not_count(monkeypatch):
    stand_in = _run(BROWSER, run_id=9, started="2026-11-20T07:00:00Z", app="google-cloud-build")

    code, _ = _check(monkeypatch, _answer(stand_in, _run(IMAGE, run_id=2)))
    assert code == 1

    failed = _run(BROWSER, conclusion="failure", run_id=1)
    code, _ = _check(monkeypatch, _answer(failed, stand_in, _run(IMAGE, run_id=2)))
    assert code == 1


@pytest.mark.parametrize("status", [403, 429])
def test_the_rate_limit_is_named_and_deploys_nothing(monkeypatch, capsys, status):
    code, requests = _check(monkeypatch, _rate_limited(status))

    assert code == 1
    assert len(requests) == required_checks.READ_ATTEMPTS
    said = capsys.readouterr().err
    assert f"{status}: GitHub's rate limit for requests without a token is spent until 06:44 UTC" in said
    assert "retry this build" in said


def test_an_answer_read_after_a_failed_one_deploys(monkeypatch):
    error = HTTPError(API_URL, 500, "Internal Server Error", Message(), io.BytesIO(b""))

    code, requests = _check(monkeypatch, error, PASSED)

    assert code == 0
    assert len(requests) == 2


def test_only_failed_reads_in_a_row_deploy_nothing(monkeypatch):
    error = URLError("Connection reset by peer")
    running = _answer(_run(BROWSER, status="in_progress", run_id=1), _run(IMAGE, run_id=2))

    code, requests = _check(monkeypatch, error, running, error, error, PASSED)

    assert code == 0
    assert len(requests) == 5


@pytest.mark.parametrize(
    ("answer", "said"),
    [
        (HTTPError(API_URL, 500, "Internal Server Error", Message(), io.BytesIO(b"")), "500 from GitHub"),
        (HTTPError(API_URL, 404, "Not Found", Message(), io.BytesIO(b"")), "404 from GitHub"),
        (URLError("Name or service not known"), "no answer from GitHub"),
        (TimeoutError("timed out"), "no answer from GitHub"),
        ((202, PASSED), "202 from GitHub"),
        (b"<!DOCTYPE html><html><body>Unicorn!</body></html>", "not GitHub's check runs JSON"),
        (b"\xff\xfe", "not GitHub's check runs JSON"),
        ({"total_count": 0}, "not GitHub's check runs JSON"),
        ([], "not GitHub's check runs JSON"),
        ({"check_runs": {"name": BROWSER}}, "a check run that is not GitHub's"),
        ({"check_runs": [{"name": BROWSER}]}, "a check run that is not GitHub's"),
        ({"check_runs": None}, "a check run that is not GitHub's"),
    ],
)
def test_an_answer_that_cannot_be_read_deploys_nothing(monkeypatch, capsys, answer, said):
    code, requests = _check(monkeypatch, answer)

    assert code == 1
    assert len(requests) == required_checks.READ_ATTEMPTS
    assert said in capsys.readouterr().err


def _check_run_names(workflow: str) -> set[str]:
    """Each job's check run name: its ``name``, else its id (no job here has a matrix)."""

    jobs = (ROOT / ".github" / "workflows" / workflow).read_text().split("\njobs:\n", 1)[1]
    names = set()
    for block in re.split(r"\n(?=  [\w-]+:\n)", "\n" + jobs):
        job = re.match(r"\n?  ([\w-]+):\n", block)
        if job:
            name = re.search(r"^    name: (.+)$", block, re.MULTILINE)
            names.add(name.group(1).strip() if name else job.group(1))
    return names


def test_the_required_names_are_the_workflows_jobs():
    assert BROWSER in _check_run_names("ci-web.yml")
    assert IMAGE in _check_run_names("ci-docker.yml")


def test_the_name_reader_takes_a_jobs_name_else_its_id():
    assert _check_run_names("ci-web.yml") == {"Typecheck, unit tests, build and CSP scan", BROWSER}
    assert _check_run_names("ci-docker.yml") == {"docker-build"}


def _steps() -> list[str]:
    text = re.sub(r"(?m)^ *#.*\n", "", (ROOT / "cloudbuild.yaml").read_text())
    return text.split("\nsteps:\n", 1)[1].split("\nimages:\n", 1)[0].split("\n  - name: ")[1:]


def _step_id(step: str) -> str:
    return re.search(r"^    id: (.+)$", step, re.MULTILINE).group(1)


def test_cloud_build_reads_the_checks_before_it_deploys_and_after_nothing_that_deploys():
    steps = _steps()
    ids = [_step_id(step) for step in steps]
    checks, deploy = steps[ids.index("GitHub checks")], steps[ids.index("Deploy")]

    assert ids.index("GitHub checks") < ids.index("Deploy")
    assert checks.startswith("python:3.12-slim\n")
    assert "args: [tools/required_checks.py]" in checks
    assert "      - COMMIT_SHA=$COMMIT_SHA\n" in checks
    # Without waitFor a step waits for every step before it.
    assert "waitFor" not in checks
    assert "waitFor" not in deploy
    for step in steps[: ids.index("GitHub checks")]:
        assert not step.startswith("gcr.io/google.com/cloudsdktool/")
        assert "deploy-revision" not in step and "gcloud" not in step

    repository = re.compile(r"^      - REPOSITORY_URL=(.+)$", re.MULTILINE)
    assert repository.search(checks).group(1) == repository.search(deploy).group(1) == REPOSITORY_URL
