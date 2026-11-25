"""deploy/service.yaml keeps the live service's public access, and a liveness probe it passes.

`deploy/apply-service-config.sh` applies the file with `gcloud run services
replace`, which resets any annotation the file leaves out. The service has no IAM
bindings (not even allUsers): it is public only because the invoker IAM check is
off. A service.yaml without that annotation would answer 403 to every visitor.
"""
from __future__ import annotations

import re
from pathlib import Path

SERVICE_YAML = Path(__file__).resolve().parents[3] / "deploy" / "service.yaml"


def _service_metadata_block() -> str:
    text = SERVICE_YAML.read_text()
    # The service's own metadata comes before the first top-level `spec:`.
    return text.split("\nspec:", 1)[0]


def test_the_invoker_iam_check_stays_off():
    assert 'run.googleapis.com/invoker-iam-disabled: "true"' in _service_metadata_block()


def test_the_service_stays_reachable_from_the_internet():
    assert "run.googleapis.com/ingress: all" in _service_metadata_block()


def _liveness_probe() -> dict[str, str]:
    """The liveness probe's `key: value` lines, nested ones (httpGet's) included."""

    lines = SERVICE_YAML.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "livenessProbe:")
    indent = len(lines[start]) - len(lines[start].lstrip())
    fields = {}
    for line in lines[start + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        key, _, value = line.strip().partition(":")
        if value.strip():
            fields[key] = value.strip()
    return fields


# The probe is applied with no check before it (apply-service-config.sh): a path the app does not
# answer, or another port, would have Cloud Run kill every instance every two minutes.
def test_the_liveness_probe_asks_a_path_the_app_answers_on_its_port(client):
    probe = _liveness_probe()
    assert probe["port"] == re.search(r"containerPort: (\d+)", SERVICE_YAML.read_text()).group(1)
    assert 200 <= client.get(probe["path"]).status_code < 400


# Cloud Run's default timeout, 1 s, would fail an instance whose 16 threads are busy for a moment.
def test_the_liveness_probe_gives_a_busy_instance_time():
    probe = _liveness_probe()
    assert 1 < int(probe["timeoutSeconds"]) < int(probe["periodSeconds"])
    assert int(probe["failureThreshold"]) * int(probe["periodSeconds"]) >= 60
