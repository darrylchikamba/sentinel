"""Phase 13 incident-router tests with MongoDB and BONA mocked."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import sys
from types import SimpleNamespace

from bson import ObjectId
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))
os.environ.setdefault("MONGO_URI", "mongodb://unused-test-host:27017/sentinel")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-for-tests")

from middleware.auth import get_current_user  # noqa: E402
from models.user import UserInDB  # noqa: E402
from routers import incident  # noqa: E402


USER_ID = ObjectId()
OTHER_USER_ID = ObjectId()
INVESTIGATION_ID = ObjectId()
CREATED_AT = datetime(2026, 8, 20, 21, 20, tzinfo=timezone.utc)


def fake_user() -> UserInDB:
    return UserInDB.model_validate({
        "_id": USER_ID,
        "username": "analyst",
        "email": "analyst@example.co.za",
        "hashed_password": "unused",
        "is_admin": False,
        "created_at": datetime.now(timezone.utc),
    })


def investigation_document(
    *,
    user_id: ObjectId = USER_ID,
) -> dict:
    return {
        "_id": INVESTIGATION_ID,
        "user_id": str(user_id),
        "filename": "sample.csv",
        "upload_source": "csv",
        "event_count": 2,
        "anomaly_count": 2,
        "high_threat_count": 1,
        "threat_distribution": {
            "critical": 0,
            "high": 1,
            "medium": 1,
            "low": 0,
            "none": 0,
        },
        "graph_nodes": 4,
        "graph_edges": 2,
        "attack_clusters": 1,
        "mitre_techniques": ["T1110.004 (Credential Stuffing)"],
        "popia_flags": ["POPIA_SECTION_22"],
        "cybercrimes_flags": ["CYBERCRIMES_ACT_REPORTABLE"],
        "sa_patterns_matched": ["GOVPORTAL_CREDENTIAL_STUFFING"],
        "incident_summary": "Original summary",
        "incident_next_steps": ["A", "B", "C", "D"],
        "rag_sources_used": ["MITRE ATT&CK"],
        "events": [
            {
                "event_type": "login_failed",
                "src_ip": "1.1.1.1",
                "dst_ip": "10.0.0.1",
                "threat_score": 85,
                "threat_level": "High",
                "threat_signals": ["Credential stuffing"],
                "anomaly_reasons": ["BRUTE_FORCE"],
                "timestamp": "2026-08-20T20:00:00+00:00",
            },
            {
                "event_type": "port_scan",
                "src_ip": "1.1.1.1",
                "dst_ip": "10.0.0.2",
                "threat_score": 45,
                "threat_level": "Medium",
                "threat_signals": ["Port scan"],
                "anomaly_reasons": ["PORT_SCAN"],
                "timestamp": "2026-08-20T20:01:00+00:00",
            },
        ],
        "created_at": CREATED_AT,
    }


NEW_REPORT = {
    "incident_summary": "Regenerated evidence-grounded summary",
    "mitre_techniques": ["T1110.004 (Credential Stuffing)"],
    "confidence_level": "High",
    "incident_next_steps": ["N1", "N2", "N3", "N4"],
    "popia_flags": ["POPIA_SECTION_22"],
    "cybercrimes_flags": ["CYBERCRIMES_ACT_REPORTABLE"],
    "sa_patterns_matched": ["GOVPORTAL_CREDENTIAL_STUFFING"],
    "rag_sources_used": [],
    "generated_by": "BONA",
    "mock": False,
}


class FakeCollection:
    def __init__(self, document: dict | None) -> None:
        self.document = document
        self.find_queries: list[dict] = []
        self.update_calls: list[tuple[dict, dict]] = []

    def find_one(self, query: dict):
        self.find_queries.append(query)
        if self.document is None:
            return None
        if all(self.document.get(key) == value for key, value in query.items()):
            return dict(self.document)
        return None

    def update_one(self, query: dict, update: dict):
        self.update_calls.append((query, update))
        if self.document is None:
            return SimpleNamespace(matched_count=0, modified_count=0)
        if not all(
            self.document.get(key) == value for key, value in query.items()
        ):
            return SimpleNamespace(matched_count=0, modified_count=0)
        self.document.update(update["$set"])
        return SimpleNamespace(matched_count=1, modified_count=1)


class FakeDatabase:
    def __init__(self, collection: FakeCollection) -> None:
        self.collection = collection

    def __getitem__(self, name: str):
        assert name == "investigations"
        return self.collection


def build_app(*, authenticated: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(incident.router, prefix="/api/incident")
    if authenticated:
        app.dependency_overrides[get_current_user] = fake_user
    return app


def install_database(
    monkeypatch: pytest.MonkeyPatch,
    document: dict | None,
) -> FakeCollection:
    collection = FakeCollection(document)
    database = FakeDatabase(collection)
    monkeypatch.setattr(incident, "get_database", lambda: database)
    return collection


def test_get_returns_correct_incident_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = install_database(monkeypatch, investigation_document())

    response = TestClient(build_app()).get(
        f"/api/incident/{INVESTIGATION_ID}"
    )

    body = response.json()
    assert response.status_code == 200
    assert body["investigation_id"] == str(INVESTIGATION_ID)
    assert body["incident_summary"] == "Original summary"
    assert body["incident_next_steps"] == ["A", "B", "C", "D"]
    assert body["mitre_techniques"] == ["T1110.004 (Credential Stuffing)"]
    assert body["created_at"] == CREATED_AT.isoformat()
    assert set(body) == {
        "investigation_id",
        "incident_summary",
        "incident_next_steps",
        "mitre_techniques",
        "popia_flags",
        "cybercrimes_flags",
        "sa_patterns_matched",
        "rag_sources_used",
        "attack_clusters",
        "high_threat_count",
        "event_count",
        "created_at",
    }
    assert collection.find_queries[0] == {
        "_id": INVESTIGATION_ID,
        "user_id": str(USER_ID),
    }


def test_get_for_other_user_returns_404(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_database(
        monkeypatch,
        investigation_document(user_id=OTHER_USER_ID),
    )

    response = TestClient(build_app()).get(
        f"/api/incident/{INVESTIGATION_ID}"
    )

    assert response.status_code == 404


def test_unauthenticated_returns_401() -> None:
    response = TestClient(build_app(authenticated=False)).get(
        f"/api/incident/{INVESTIGATION_ID}"
    )
    assert response.status_code == 401


def test_invalid_investigation_id_returns_422() -> None:
    response = TestClient(build_app()).get("/api/incident/not-valid")
    assert response.status_code == 422


def test_regenerate_calls_bona_with_stored_data_and_empty_rag_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_database(monkeypatch, investigation_document())
    seen = {}

    def fake_generate(data: dict) -> dict:
        seen["data"] = data
        return NEW_REPORT

    monkeypatch.setattr(incident, "generate_incident_report", fake_generate)

    response = TestClient(build_app()).post(
        f"/api/incident/{INVESTIGATION_ID}/regenerate"
    )

    assert response.status_code == 200
    data = seen["data"]
    assert data["threat_summary"]["event_count"] == 2
    assert data["threat_summary"]["max_threat_score"] == 85
    assert data["graph_summary"]["total_nodes"] == 4
    assert data["sa_result"]["popia_flags"] == ["POPIA_SECTION_22"]
    assert data["rag_context"] == {
        "retrieved_context": [],
        "query_used": "",
        "collections_queried": [],
        "total_retrieved": 0,
        "rag_available": False,
    }


def test_regenerate_updates_mongodb_with_new_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = install_database(monkeypatch, investigation_document())
    monkeypatch.setattr(
        incident,
        "generate_incident_report",
        lambda data: NEW_REPORT,
    )

    response = TestClient(build_app()).post(
        f"/api/incident/{INVESTIGATION_ID}/regenerate"
    )

    assert response.status_code == 200
    assert len(collection.update_calls) == 1
    query, update = collection.update_calls[0]
    assert query == {
        "_id": INVESTIGATION_ID,
        "user_id": str(USER_ID),
    }
    values = update["$set"]
    assert values["incident_summary"] == NEW_REPORT["incident_summary"]
    assert values["incident_next_steps"] == NEW_REPORT[
        "incident_next_steps"
    ]
    assert values["mitre_techniques"] == NEW_REPORT["mitre_techniques"]
    assert values["rag_sources_used"] == []
    assert isinstance(values["regenerated_at"], datetime)


def test_regenerate_for_other_user_returns_404(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = install_database(
        monkeypatch,
        investigation_document(user_id=OTHER_USER_ID),
    )
    called = False

    def fake_generate(data: dict) -> dict:
        nonlocal called
        called = True
        return NEW_REPORT

    monkeypatch.setattr(incident, "generate_incident_report", fake_generate)

    response = TestClient(build_app()).post(
        f"/api/incident/{INVESTIGATION_ID}/regenerate"
    )

    assert response.status_code == 404
    assert called is False
    assert collection.update_calls == []


def test_bona_exception_returns_500_and_does_not_update(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = install_database(monkeypatch, investigation_document())

    def fail(data: dict):
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(incident, "generate_incident_report", fail)

    response = TestClient(build_app()).post(
        f"/api/incident/{INVESTIGATION_ID}/regenerate"
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Incident report regeneration failed"
    }
    assert collection.update_calls == []


def test_bona_error_result_returns_500_and_does_not_update(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = install_database(monkeypatch, investigation_document())
    failure = dict(NEW_REPORT)
    failure["mock"] = True
    failure["bona_error"] = "Ollama generation error — mock used"

    monkeypatch.setattr(
        incident,
        "generate_incident_report",
        lambda data: failure,
    )

    response = TestClient(build_app()).post(
        f"/api/incident/{INVESTIGATION_ID}/regenerate"
    )

    assert response.status_code == 500
    assert collection.update_calls == []


def test_valid_mock_mode_without_error_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = install_database(monkeypatch, investigation_document())
    valid_mock = dict(NEW_REPORT)
    valid_mock["mock"] = True

    monkeypatch.setattr(
        incident,
        "generate_incident_report",
        lambda data: valid_mock,
    )

    response = TestClient(build_app()).post(
        f"/api/incident/{INVESTIGATION_ID}/regenerate"
    )

    assert response.status_code == 200
    assert len(collection.update_calls) == 1


def test_regenerated_response_contains_updated_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_database(monkeypatch, investigation_document())
    monkeypatch.setattr(
        incident,
        "generate_incident_report",
        lambda data: NEW_REPORT,
    )

    response = TestClient(build_app()).post(
        f"/api/incident/{INVESTIGATION_ID}/regenerate"
    )

    assert response.status_code == 200
    assert (
        response.json()["incident_summary"]
        == "Regenerated evidence-grounded summary"
    )