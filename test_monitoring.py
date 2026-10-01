import sys
import types

import pytest
from fastapi.testclient import TestClient

from core.config import settings

# The monitoring route does not exercise the optional vision/database modules.
vision_detector = types.ModuleType("core.vision_detector")
vision_detector.analyze_proctor_frame = lambda *args: {}
db_sync = types.ModuleType("core.db_sync")


async def _record_proctoring_violation(*args, **kwargs):
    return {}


db_sync.record_proctoring_violation = _record_proctoring_violation
sys.modules.setdefault("core.vision_detector", vision_detector)
sys.modules.setdefault("core.db_sync", db_sync)

from main import app


MONITORING_PATH = "/internal/monitor"
MONITORING_SECRET = "monitoring-test-secret"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "test")
    monkeypatch.setattr(settings, "MONITORING_ENDPOINT_SECRET", MONITORING_SECRET)
    return TestClient(app, base_url="http://localhost")


def test_monitoring_denies_when_secret_is_missing(client, monkeypatch):
    monkeypatch.setattr(settings, "MONITORING_ENDPOINT_SECRET", "")

    response = client.get(MONITORING_PATH, headers={"Authorization": f"Bearer {MONITORING_SECRET}"})

    assert response.status_code == 403


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Basic monitoring-test-secret"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer monitoring-test-secret extra"},
        {"Authorization": "Bearer wrong-secret"},
    ],
)
def test_monitoring_denies_missing_malformed_and_mismatched_authorization(client, headers):
    response = client.get(MONITORING_PATH, headers=headers)

    assert response.status_code == 403


def test_monitoring_does_not_accept_query_secret(client):
    response = client.get(f"{MONITORING_PATH}?secret={MONITORING_SECRET}")

    assert response.status_code == 403


def test_monitoring_accepts_matching_bearer_secret(client):
    response = client.get(
        MONITORING_PATH,
        headers={"Authorization": f"Bearer {MONITORING_SECRET}"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_monitoring_rejects_untrusted_origin_even_with_valid_secret(client):
    response = client.get(
        MONITORING_PATH,
        headers={
            "Authorization": f"Bearer {MONITORING_SECRET}",
            "Origin": "https://attacker.example",
        },
    )

    assert response.status_code == 403


def test_monitoring_uses_framework_method_not_allowed(client):
    response = client.post(
        MONITORING_PATH,
        headers={"Authorization": f"Bearer {MONITORING_SECRET}"},
    )

    assert response.status_code == 405
