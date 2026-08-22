"""Phase 13 investigation-router tests with MongoDB mocked."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import sys
from types import SimpleNamespace

from bson import ObjectId
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pymongo import ASCENDING, DESCENDING
import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))
os.environ.setdefault("MONGO_URI", "mongodb://unused-test-host:27017/sentinel")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-for-tests")

from middleware.auth import get_current_user  # noqa: E402
from models.user import UserInDB  # noqa: E402
from routers import analysis  # noqa: E402


USER_ID = ObjectId()
OTHER_USER_ID = ObjectId()
INVESTIGATION_ID = ObjectId()


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
    object_id: ObjectId | None = None,
    user_id: ObjectId = USER_ID,
    event_count: int = 6,
    high_threat_count: int = 1,
    created_at: datetime | None = None,
) -> dict:
    return {
        "_id": object_id or ObjectId(),
        "user_id": str(user_id),
        "filename": "sample.csv",
        "upload_source": "csv",
        "event_count": event_count,
        "anomaly_count": 4,
        "high_threat_count": high_threat_count,
        "threat_distribution": {
            "critical": 0,
            "high": high_threat_count,
            "medium": 2,
            "low": 0,
            "none": 3,
        },
        "graph_nodes": 7,
        "graph_edges": 2,
        "attack_clusters": 1,
        "mitre_techniques": ["T1110.004 (Credential Stuffing)"],
        "popia_flags": ["POPIA_SECTION_22"],
        "cybercrimes_flags": [],
        "sa_patterns_matched": [],
        "incident_summary": "Summary",
        "incident_next_steps": ["A", "B", "C", "D"],
        "rag_sources_used": ["MITRE ATT&CK"],
        "events": [{"event_type": "login_failed", "threat_score": 85}],
        "created_at": created_at or datetime.now(timezone.utc),
    }


class FakeCursor:
    def __init__(self, documents: list[dict]) -> None:
        self.documents = list(documents)
        self.sort_args = None
        self.skip_value = 0
        self.limit_value = None

    def sort(self, field: str, order: int):
        self.sort_args = (field, order)
        reverse = order == DESCENDING
        self.documents.sort(
            key=lambda item: item.get(field),
            reverse=reverse,
        )
        return self

    def skip(self, value: int):
        self.skip_value = value
        return self

    def limit(self, value: int):
        self.limit_value = value
        return self

    def __iter__(self):
        start = self.skip_value
        stop = None
        if self.limit_value is not None:
            stop = start + self.limit_value
        return iter(self.documents[start:stop])


class FakeCollection:
    def __init__(self, documents: list[dict] | None = None) -> None:
        self.documents = list(documents or [])
        self.count_queries: list[dict] = []
        self.find_calls: list[tuple[dict, dict | None]] = []
        self.find_one_queries: list[dict] = []
        self.delete_queries: list[dict] = []
        self.last_cursor: FakeCursor | None = None

    def count_documents(self, query: dict) -> int:
        self.count_queries.append(query)
        return sum(
            1 for doc in self.documents
            if all(doc.get(key) == value for key, value in query.items())
        )

    def find(self, query: dict, projection: dict | None = None) -> FakeCursor:
        self.find_calls.append((query, projection))
        matching = [
            dict(doc) for doc in self.documents
            if all(doc.get(key) == value for key, value in query.items())
        ]
        if projection and projection.get("events") == 0:
            for doc in matching:
                doc.pop("events", None)
        self.last_cursor = FakeCursor(matching)
        return self.last_cursor

    def find_one(self, query: dict):
        self.find_one_queries.append(query)
        for doc in self.documents:
            if all(doc.get(key) == value for key, value in query.items()):
                return dict(doc)
        return None

    def delete_one(self, query: dict):
        self.delete_queries.append(query)
        for index, doc in enumerate(self.documents):
            if all(doc.get(key) == value for key, value in query.items()):
                self.documents.pop(index)
                return SimpleNamespace(deleted_count=1)
        return SimpleNamespace(deleted_count=0)


class FakeDatabase:
    def __init__(self, collection: FakeCollection) -> None:
        self.collection = collection

    def __getitem__(self, name: str):
        assert name == "investigations"
        return self.collection


def build_app(*, authenticated: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(analysis.router, prefix="/api/investigations")
    if authenticated:
        app.dependency_overrides[get_current_user] = fake_user
    return app


def install_database(
    monkeypatch: pytest.MonkeyPatch,
    documents: list[dict],
) -> FakeCollection:
    collection = FakeCollection(documents)
    database = FakeDatabase(collection)
    monkeypatch.setattr(analysis, "get_database", lambda: database)
    return collection


def test_list_returns_only_current_users_investigations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = install_database(
        monkeypatch,
        [
            investigation_document(user_id=USER_ID),
            investigation_document(user_id=OTHER_USER_ID),
        ],
    )

    response = TestClient(build_app()).get("/api/investigations")

    assert response.status_code == 200
    assert len(response.json()["investigations"]) == 1
    ownership = {"user_id": str(USER_ID)}
    assert collection.count_queries == [ownership]
    assert collection.find_calls[0][0] == ownership


def test_list_excludes_events_at_projection_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = install_database(
        monkeypatch,
        [investigation_document()],
    )

    response = TestClient(build_app()).get("/api/investigations")

    assert response.status_code == 200
    assert "events" not in response.json()["investigations"][0]
    assert collection.find_calls[0][1] == {"events": 0}


def test_pagination_calculates_page_size_and_total_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docs = [investigation_document(event_count=i) for i in range(12)]
    collection = install_database(monkeypatch, docs)

    response = TestClient(build_app()).get(
        "/api/investigations?page=2&page_size=5"
    )

    body = response.json()
    assert response.status_code == 200
    assert body["total"] == 12
    assert body["page"] == 2
    assert body["page_size"] == 5
    assert body["total_pages"] == 3
    assert len(body["investigations"]) == 5
    assert collection.last_cursor.skip_value == 5
    assert collection.last_cursor.limit_value == 5


def test_default_sort_is_created_at_desc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_database(
        monkeypatch,
        [
            investigation_document(
                created_at=datetime(2026, 1, 1, tzinfo=timezone.utc)
            ),
            investigation_document(
                created_at=datetime(2026, 2, 1, tzinfo=timezone.utc)
            ),
        ],
    )
    response = TestClient(build_app()).get("/api/investigations")
    assert response.status_code == 200

    collection = analysis.get_database()["investigations"]
    assert collection.last_cursor.sort_args == ("created_at", DESCENDING)


def test_sort_by_high_threat_count_asc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = install_database(
        monkeypatch,
        [
            investigation_document(high_threat_count=5),
            investigation_document(high_threat_count=1),
        ],
    )

    response = TestClient(build_app()).get(
        "/api/investigations?sort_by=high_threat_count&sort_order=asc"
    )

    assert response.status_code == 200
    assert collection.last_cursor.sort_args == (
        "high_threat_count",
        ASCENDING,
    )
    assert response.json()["investigations"][0]["high_threat_count"] == 1


def test_invalid_sort_by_returns_422() -> None:
    response = TestClient(build_app()).get(
        "/api/investigations?sort_by=filename"
    )
    assert response.status_code == 422


def test_page_less_than_one_returns_422() -> None:
    response = TestClient(build_app()).get("/api/investigations?page=0")
    assert response.status_code == 422


def test_page_size_over_fifty_returns_422() -> None:
    response = TestClient(build_app()).get(
        "/api/investigations?page_size=51"
    )
    assert response.status_code == 422


def test_get_detail_returns_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = investigation_document(object_id=INVESTIGATION_ID)
    collection = install_database(monkeypatch, [document])

    response = TestClient(build_app()).get(
        f"/api/investigations/{INVESTIGATION_ID}"
    )

    assert response.status_code == 200
    assert response.json()["events"] == document["events"]
    assert collection.find_one_queries[0] == {
        "_id": INVESTIGATION_ID,
        "user_id": str(USER_ID),
    }


def test_invalid_object_id_returns_422() -> None:
    response = TestClient(build_app()).get(
        "/api/investigations/not-an-object-id"
    )
    assert response.status_code == 422


def test_get_detail_for_other_user_returns_404(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_database(
        monkeypatch,
        [
            investigation_document(
                object_id=INVESTIGATION_ID,
                user_id=OTHER_USER_ID,
            )
        ],
    )

    response = TestClient(build_app()).get(
        f"/api/investigations/{INVESTIGATION_ID}"
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Investigation not found"}


def test_delete_removes_document_and_query_enforces_ownership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = install_database(
        monkeypatch,
        [investigation_document(object_id=INVESTIGATION_ID)],
    )

    response = TestClient(build_app()).delete(
        f"/api/investigations/{INVESTIGATION_ID}"
    )

    assert response.status_code == 200
    assert response.json() == {"message": "Investigation deleted"}
    assert collection.delete_queries == [{
        "_id": INVESTIGATION_ID,
        "user_id": str(USER_ID),
    }]
    assert collection.documents == []


def test_delete_other_users_investigation_returns_404(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = install_database(
        monkeypatch,
        [
            investigation_document(
                object_id=INVESTIGATION_ID,
                user_id=OTHER_USER_ID,
            )
        ],
    )

    response = TestClient(build_app()).delete(
        f"/api/investigations/{INVESTIGATION_ID}"
    )

    assert response.status_code == 404
    assert len(collection.documents) == 1


def test_unauthenticated_requests_return_401() -> None:
    response = TestClient(build_app(authenticated=False)).get(
        "/api/investigations"
    )
    assert response.status_code == 401