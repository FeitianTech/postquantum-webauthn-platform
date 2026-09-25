"""deploy/service.yaml keeps the live service's public access.

`deploy/apply-service-config.sh` applies the file with `gcloud run services
replace`, which resets any annotation the file leaves out. The service has no IAM
bindings (not even allUsers): it is public only because the invoker IAM check is
off. A service.yaml without that annotation would answer 403 to every visitor.
"""
from __future__ import annotations

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
