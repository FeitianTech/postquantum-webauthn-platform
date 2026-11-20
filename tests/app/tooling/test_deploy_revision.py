"""deploy/deploy-revision.sh, Cloud Build's Deploy step, run against stand-ins for gcloud,
curl and sleep: the traffic moves to the new revision only once every check passed.

The stand-ins log each call. gcloud answers as Cloud Run would: ``services update``
makes the revision ``<service>-<suffix>`` and tags it, and ``services describe`` gives
the tag's URL and revision, as the script's projection asks. ``FAIL_AT`` names the one step that fails; ``COLD_ATTEMPTS`` makes the
first requests fail as a revision that is still starting does. curl answers the repository's
ref advertisement as GitHub does; ``MAIN_TIPS`` gives, read by read, main's commit or an
answer that does not name it (the last one repeats), and by default main is the build's commit.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "deploy" / "deploy-revision.sh"
REVISION = "pqcwebauthn-0123456789ab-b1d2c3e4"
TAG_URL = "https://candidate---pqcwebauthn-example.a.run.app"
REPOSITORY_URL = "https://github.com/FeitianTech/postquantum-webauthn-platform"
REFS = f"curl {REPOSITORY_URL}.git/info/refs?service=git-upload-pack"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
NEWER = "fedcba9876543210fedcba9876543210fedcba98"

_GCLOUD = r'''
import json, os, sys
args = sys.argv[1:]
state = os.environ["STUB_STATE"]
with open(os.path.join(state, "calls.log"), "a") as log:
    log.write("gcloud " + " ".join(args) + "\n")
fail_at = os.environ.get("FAIL_AT", "")
command = " ".join(args[:3])
if command == "run services update":
    if fail_at == "update":
        sys.exit(1)
    suffix = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--revision-suffix="))
    with open(os.path.join(state, "revision"), "w") as revision:
        revision.write(f"{args[3]}-{suffix}")
elif command == "run services describe":
    if fail_at == "describe":
        sys.exit(1)
    path = os.path.join(state, "describes")
    count = int(open(path).read()) + 1 if os.path.exists(path) else 1
    open(path, "w").write(str(count))
    revision = open(os.path.join(state, "revision")).read()
    if fail_at == "moved-tag" and count > 1:
        revision = "pqcwebauthn-another-build"
    projection = 'value(status.traffic.filter("tag=candidate").map().extract(url,revisionName).flatten())'
    if f"--format={projection}" not in args:
        sys.exit(2)
    print("" if fail_at == "no-tag" else f"{os.environ['TAG_URL']},{revision}")
elif command == "run services update-traffic":
    if fail_at == "update-traffic":
        sys.exit(1)
    with open(os.path.join(state, "promoted"), "w") as promoted:
        promoted.write(next(arg.split("=", 1)[1] for arg in args if arg.startswith("--to-revisions=")))
'''

_CURL = r'''
import json, os, sys
args = sys.argv[1:]
state = os.environ["STUB_STATE"]
url = args[-1]
if url == os.environ["REPOSITORY_URL"] + ".git/info/refs?service=git-upload-pack":
    with open(os.path.join(state, "calls.log"), "a") as log:
        log.write("curl " + url + "\n")
    counter = os.path.join(state, "reads")
    count = int(open(counter).read()) + 1 if os.path.exists(counter) else 1
    open(counter, "w").write(str(count))
    tips = os.environ.get("MAIN_TIPS", os.environ["COMMIT_SHA"].lower()).split(",")
    tip = tips[min(count, len(tips)) - 1]
    if tip == "fail":
        sys.exit(22)
    pkt = lambda line: f"{len(line) + 5:04x}{line}\n"
    head = "4d09fa98ff22032f27085d7567aa4a7eb3d3c446 HEAD\0multi_ack symref=HEAD:refs/heads/main agent=git/github"
    answers = {
        "empty": "",
        "html": "<!DOCTYPE html><html><body>Service unavailable</body></html>",
        "no-main": pkt("# service=git-upload-pack") + "0000" + pkt(head) + pkt(f"{'a' * 40} refs/heads/maintenance") + "0000",
    }
    answer = answers.get(tip, pkt("# service=git-upload-pack") + "0000" + pkt(head) + pkt(f"{tip} refs/heads/main")
                         + pkt(f"{'b' * 40} refs/heads/release") + "0000")
    with open(args[args.index("-o") + 1], "w") as body:
        body.write(answer)
    sys.exit(0)
path = url[len(os.environ["TAG_URL"]):]
with open(os.path.join(state, "calls.log"), "a") as log:
    log.write("curl " + path + "\n")
counter = os.path.join(state, "requests")
count = int(open(counter).read()) + 1 if os.path.exists(counter) else 1
open(counter, "w").write(str(count))
if count <= int(os.environ.get("COLD_ATTEMPTS", "0")):
    sys.exit(28)
fail_at = os.environ.get("FAIL_AT", "")
if {"/health": "health", "/": "root", "/api/mds/metadata/info": "info"}.get(path) == fail_at:
    sys.exit(22)
bodies = {
    "/health": "ok",
    "/": "<!DOCTYPE html><html lang=\"en\"><head></head></html>",
    "/api/mds/metadata/info": json.dumps({"entryCount": 0 if fail_at == "no-entries" else 288, "no": 101}),
}
with open(args[args.index("-o") + 1], "w") as body:
    body.write(bodies[path])
'''


def _stand_in(directory: Path, name: str, source: str) -> None:
    path = directory / name
    path.write_text(f"#!{sys.executable}\n{source}")
    path.chmod(0o755)


def _deploy(tmp_path: Path, **env: str) -> tuple[subprocess.CompletedProcess, Path]:
    bin_dir, state = tmp_path / "bin", tmp_path / "state"
    bin_dir.mkdir()
    state.mkdir()
    _stand_in(bin_dir, "gcloud", _GCLOUD)
    _stand_in(bin_dir, "curl", _CURL)
    _stand_in(bin_dir, "sleep", "")
    environment = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "STUB_STATE": str(state),
        "TAG_URL": TAG_URL,
        "REPOSITORY_URL": REPOSITORY_URL,
        "IMAGE": "asia-northeast1-docker.pkg.dev/project/repository/pqcwebauthn:0123456789abcdef",
        "SERVICE": "pqcwebauthn",
        "REGION": "asia-northeast1",
        "COMMIT_SHA": "0123456789ABCDEF0123456789abcdef01234567",
        "BUILD_ID": "b1d2c3e4-5f60-4718-9a0b-1c2d3e4f5a6b",
        "LABELS": "managed-by=gcp-cloud-build-deploy-cloud-run,commit-sha=0123456789abcdef",
        **env,
    }
    result = subprocess.run(["bash", str(SCRIPT)], env=environment, capture_output=True, text=True, timeout=60)
    return result, state


def _calls(state: Path) -> list[str]:
    return (state / "calls.log").read_text().splitlines() if (state / "calls.log").exists() else []


def test_the_traffic_moves_to_the_checked_revision_once_every_check_passed(tmp_path):
    result, state = _deploy(tmp_path)

    assert result.returncode == 0, result.stderr
    calls = _calls(state)
    assert calls[0] == REFS
    assert calls[1].startswith("gcloud run services update pqcwebauthn ")
    assert "--no-traffic" in calls[1].split()
    assert "--tag=candidate" in calls[1].split()
    assert "--revision-suffix=0123456789ab-b1d2c3e4" in calls[1].split()
    assert [call for call in calls if call.startswith("curl /")] == [
        "curl /health",
        "curl /",
        "curl /api/mds/metadata/info",
    ]
    assert calls[-2:] == [REFS, calls[-1]]
    assert calls[-1].startswith("gcloud run services update-traffic pqcwebauthn ")
    assert calls.count(REFS) == 2
    assert (state / "promoted").read_text() == f"{REVISION}=100"


@pytest.mark.parametrize(
    ("fail_at", "said"),
    [
        ("update", ""),
        ("describe", ""),
        ("no-tag", "The tag candidate names '', not"),
        ("health", "/health: not passed after 40 attempts"),
        ("root", "/: not passed after 40 attempts"),
        ("info", "/api/mds/metadata/info: not passed after 40 attempts"),
        ("no-entries", "/api/mds/metadata/info: not passed after 40 attempts"),
        ("moved-tag", "The tag candidate names 'pqcwebauthn-another-build', not"),
        ("update-traffic", ""),
    ],
)
def test_a_step_that_fails_leaves_the_traffic_where_it_was(tmp_path, fail_at, said):
    result, state = _deploy(tmp_path, FAIL_AT=fail_at)

    assert result.returncode != 0
    assert said in result.stderr
    assert not (state / "promoted").exists()
    if fail_at != "update-traffic":
        assert not any(call.startswith("gcloud run services update-traffic") for call in _calls(state))


def test_a_revision_that_answers_only_once_started_is_promoted(tmp_path):
    result, state = _deploy(tmp_path, COLD_ATTEMPTS="3")

    assert result.returncode == 0, result.stderr
    assert [call for call in _calls(state) if call.startswith("curl /")][:4] == ["curl /health"] * 4
    assert "/health: passed on attempt 4" in result.stdout
    assert (state / "promoted").read_text() == f"{REVISION}=100"


def test_the_labels_and_image_reach_the_new_revision(tmp_path):
    result, state = _deploy(tmp_path)

    update = _calls(state)[1].split()
    assert result.returncode == 0, result.stderr
    assert "--image=asia-northeast1-docker.pkg.dev/project/repository/pqcwebauthn:0123456789abcdef" in update
    assert "--labels=managed-by=gcp-cloud-build-deploy-cloud-run,commit-sha=0123456789abcdef" in update
    assert json.loads((state / "revision").read_text().join('""')) == REVISION


def test_a_build_overtaken_before_it_deploys_creates_no_revision_and_moves_no_traffic(tmp_path):
    result, state = _deploy(tmp_path, MAIN_TIPS=NEWER)

    assert result.returncode == 0, result.stderr
    assert _calls(state) == [REFS]
    assert f"main is now at {NEWER}, not {COMMIT}: this build leaves the traffic where it is" in result.stdout
    assert not (state / "promoted").exists()


def test_a_build_overtaken_while_its_revision_is_checked_moves_no_traffic(tmp_path):
    result, state = _deploy(tmp_path, MAIN_TIPS=f"{COMMIT},{NEWER}")

    calls = _calls(state)
    assert result.returncode == 0, result.stderr
    assert calls[-1] == REFS
    assert "curl /api/mds/metadata/info" in calls
    assert f"main is now at {NEWER}, not {COMMIT}" in result.stdout
    assert not any(call.startswith("gcloud run services update-traffic") for call in calls)


@pytest.mark.parametrize("answer", ["fail", "empty", "no-main", "html"])
def test_a_tip_that_cannot_be_read_fails_the_deploy_and_leaves_the_traffic(tmp_path, answer):
    result, state = _deploy(tmp_path, MAIN_TIPS=answer)

    assert result.returncode != 0
    assert f"Could not read main's tip from {REPOSITORY_URL} after 4 attempts" in result.stderr
    assert _calls(state) == [REFS] * 4
    assert not (state / "promoted").exists()


def test_a_tip_read_after_failed_tries_lets_the_deploy_go_on(tmp_path):
    result, state = _deploy(tmp_path, MAIN_TIPS=f"fail,html,{COMMIT}")

    assert result.returncode == 0, result.stderr
    calls = _calls(state)
    assert calls[:3] == [REFS] * 3
    assert calls[3].startswith("gcloud run services update pqcwebauthn ")
    assert (state / "promoted").read_text() == f"{REVISION}=100"
