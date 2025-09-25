"""Tests for algorithm handling in the advanced registration routes."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import List, Sequence

import sys
import types

import pytest


def _load_app():
    app_path = (
        Path(__file__).resolve().parents[1]
        / "examples"
        / "server"
        / "server"
        / "app.py"
    )
    spec = importlib.util.spec_from_file_location("advanced_server_app", app_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load advanced server application module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app



@pytest.fixture()
def client():
    app = _load_app()
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def _install_fake_oqs(monkeypatch, algorithms: Sequence[str]) -> None:
    signature = types.SimpleNamespace(algorithms=tuple(algorithms))
    module = types.SimpleNamespace(Signature=signature)
    monkeypatch.setitem(sys.modules, "oqs", module)


def _post_begin(client, pubkey_params: List[dict], expected_status: int = 200):
    payload = {
        "publicKey": {
            "rp": {"name": "Test RP", "id": "localhost"},
            "user": {
                "id": {"$hex": "0102030405060708090a0b0c0d0e0f10"},
                "name": "user",
                "displayName": "User",
            },
            "challenge": {"$hex": "11223344556677889900aabbccddeeff"},
            "pubKeyCredParams": pubkey_params,
            "timeout": 60000,
            "authenticatorSelection": {},
            "attestation": "none",
        }
    }

    response = client.post("/api/advanced/register/begin", json=payload)
    assert response.status_code == expected_status, response.get_data(as_text=True)
    return response.get_json()


def test_coerces_string_algorithm_identifiers(client, monkeypatch):
    _install_fake_oqs(monkeypatch, ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"))

    data = _post_begin(
        client,
        [
            {"type": "public-key", "alg": " -50 "},
            {"type": "public-key", "alg": -49},
            {"type": "public-key", "alg": "-48"},
        ],
    )

    params = data["publicKey"]["pubKeyCredParams"]
    algorithms = [entry["alg"] for entry in params]

    assert algorithms == [-50, -49, -48]
    assert all(isinstance(entry["alg"], int) for entry in params)


def test_ignores_invalid_algorithm_entries(client, monkeypatch):
    _install_fake_oqs(monkeypatch, ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"))

    data = _post_begin(
        client,
        [
            {"type": "public-key", "alg": "-50"},
            {"type": "public-key", "alg": "not-a-number"},
            {"type": "public-key", "alg": None},
        ],
    )

    params = data["publicKey"]["pubKeyCredParams"]
    algorithms = [entry["alg"] for entry in params]

    assert algorithms == [-50]
    assert all(isinstance(entry["alg"], int) for entry in params)


def test_translates_algorithm_names_to_cose_ids(client, monkeypatch):
    _install_fake_oqs(monkeypatch, ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"))

    data = _post_begin(
        client,
        [
            {"type": "public-key", "alg": "ML-DSA-44"},
            {"type": "public-key", "alg": "ml-dsa-65"},
            {"type": "public-key", "alg": "MLDSA87"},
            {"type": "public-key", "alg": "EdDSA"},
            {"type": "public-key", "alg": "es256"},
            {"type": "public-key", "alg": "RSA256"},
            {"type": "public-key", "alg": "PS256"},
            {"type": "public-key", "alg": "RS1"},
        ],
    )

    params = data["publicKey"]["pubKeyCredParams"]
    algorithms = [entry["alg"] for entry in params]

    assert algorithms == [-48, -49, -50, -8, -7, -257, -37, -65535]
    assert all(isinstance(entry["alg"], int) for entry in params)


def test_handles_prefixed_algorithm_name_aliases(client, monkeypatch):
    _install_fake_oqs(monkeypatch, ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"))

    data = _post_begin(
        client,
        [
            {"type": "public-key", "alg": "ML-DSA-44 (PQC) (-48)"},
            {"type": "public-key", "alg": "FIDOALG-MLDSA65"},
            {"type": "public-key", "alg": "COSE_ALG_MLDSA87"},
            {"type": "public-key", "alg": "COSE_ALG_RS256"},
        ],
    )

    params = data["publicKey"]["pubKeyCredParams"]
    algorithms = [entry["alg"] for entry in params]

    assert algorithms == [-48, -49, -50, -257]
    assert all(isinstance(entry["alg"], int) for entry in params)


def test_rejects_pqc_algorithms_when_oqs_missing(client):
    data = _post_begin(
        client,
        [
            {"type": "public-key", "alg": -48},
            {"type": "public-key", "alg": -49},
        ],
        expected_status=400,
    )

    assert "oqs" in data.get("error", "")


def test_reports_missing_specific_pqc_algorithms(client, monkeypatch):
    _install_fake_oqs(monkeypatch, ("ML-DSA-44", "ML-DSA-65"))

    data = _post_begin(
        client,
        [
            {"type": "public-key", "alg": -48},
            {"type": "public-key", "alg": -49},
            {"type": "public-key", "alg": -50},
        ],
        expected_status=400,
    )

    assert "ML-DSA-87" in data.get("error", "")


def test_filters_pqc_from_default_list_when_unsupported(client):
    data = _post_begin(client, [])

    params = data["publicKey"]["pubKeyCredParams"]
    algorithms = [entry["alg"] for entry in params]

    assert algorithms == [-7, -257]
