"""Phase 14 knowledge-base router tests with external systems mocked."""

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

from middleware.auth import get_admin_user  # noqa: E402
from models.user import UserInDB  # noqa: E402
from routers import kb  # noqa: E402


def make_user(*, is_admin: bool) -> UserInDB:
    return UserInDB.model_validate({
        "_id": ObjectId(),
        "username": "kb_admin" if is_admin else "analyst",
        "email": "kb@example.co.za",
        "hashed_password": "unused",
        "is_admin": is_admin,
        "created_at": datetime.now(timezone.utc),
    })


def admin_user() -> UserInDB:
    return make_user(is_admin=True)


def forbidden_admin_dependency() -> None:
    from fastapi import HTTPException
    raise HTTPException(
        status_code=403,
        detail="Administrator access required",
    )


def build_app(*, mode: str = "admin") -> FastAPI:
    app = FastAPI()
    app.include_router(kb.router, prefix="/api/kb")

    if mode == "admin":
        app.dependency_overrides[get_admin_user] = admin_user
    elif mode == "non_admin":
        app.dependency_overrides[get_admin_user] = forbidden_admin_dependency

    return app


class FakeBackgroundTasks:
    def __init__(self) -> None:
        self.tasks: list[tuple[object, tuple, dict]] = []

    def add_task(self, func, *args, **kwargs) -> None:
        self.tasks.append((func, args, kwargs))


class FakeCollection:
    def __init__(self, count: int) -> None:
        self._count = count

    def count(self) -> int:
        return self._count


class FakeChromaClient:
    def __init__(
        self,
        counts: dict[str, int] | None = None,
        *,
        heartbeat_error: Exception | None = None,
        missing: set[str] | None = None,
    ) -> None:
        self.counts = counts or {}
        self.heartbeat_error = heartbeat_error
        self.missing = missing or set()
        self.requested: list[str] = []

    def heartbeat(self):
        if self.heartbeat_error:
            raise self.heartbeat_error
        return 1

    def get_collection(self, name: str):
        self.requested.append(name)
        if name in self.missing or name not in self.counts:
            raise RuntimeError("collection not found")
        return FakeCollection(self.counts[name])


def test_non_admin_returns_403_on_setup() -> None:
    response = TestClient(build_app(mode="non_admin")).post(
        "/api/kb/setup",
        json={"embedding_provider": "ollama"},
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "Administrator access required"}


def test_admin_setup_registers_background_task_without_running_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def fake_ingestion() -> int:
        nonlocal called
        called = True
        return 0

    monkeypatch.setattr(kb, "run_ingestion", fake_ingestion)

    tasks = FakeBackgroundTasks()
    response = kb.setup_knowledge_base(
        tasks,
        kb.KnowledgeBaseSetupRequest(embedding_provider="ollama"),
        admin_user(),
    )

    assert response["message"] == "Knowledge base ingestion started"
    assert response["embedding_provider"] == "ollama"
    assert len(tasks.tasks) == 1
    func, args, kwargs = tasks.tasks[0]
    assert func is kb._run_ingestion_background
    assert args == ("ollama",)
    assert kwargs == {}
    assert called is False


def test_invalid_embedding_provider_returns_422() -> None:
    response = TestClient(build_app()).post(
        "/api/kb/setup",
        json={"embedding_provider": "openai"},
    )
    assert response.status_code == 422


def test_valid_provider_returns_immediate_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Starlette executes BackgroundTasks during TestClient response completion.
    # Replace add_task so this test verifies only the HTTP registration path.
    registered = []

    def fake_add_task(self, func, *args, **kwargs):
        registered.append((func, args, kwargs))

    from fastapi import BackgroundTasks
    monkeypatch.setattr(BackgroundTasks, "add_task", fake_add_task)

    response = TestClient(build_app()).post(
        "/api/kb/setup",
        json={"embedding_provider": "gemini"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "message": "Knowledge base ingestion started",
        "embedding_provider": "gemini",
        "note": (
            "Ingestion runs in the background. "
            "Check /api/kb/status for progress."
        ),
    }
    assert len(registered) == 1


def test_omitted_provider_uses_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AI_EMBEDDING_PROVIDER", "ollama")
    registered = []

    def fake_add_task(self, func, *args, **kwargs):
        registered.append((func, args, kwargs))

    from fastapi import BackgroundTasks
    monkeypatch.setattr(BackgroundTasks, "add_task", fake_add_task)

    response = TestClient(build_app()).post("/api/kb/setup")

    assert response.status_code == 200
    assert response.json()["embedding_provider"] == "ollama"
    assert registered[0][1] == ("ollama",)


def test_invalid_environment_provider_returns_422(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AI_EMBEDDING_PROVIDER", "none")
    response = TestClient(build_app()).post("/api/kb/setup")
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("provider", "dimension"),
    [("ollama", "768"), ("gemini", "3072")],
)
def test_background_callback_sets_provider_dimension_and_calls_ingestion(
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
    dimension: str,
) -> None:
    calls = 0

    def fake_ingestion() -> int:
        nonlocal calls
        calls += 1
        return 0

    monkeypatch.setattr(kb, "run_ingestion", fake_ingestion)
    monkeypatch.delenv("AI_EMBEDDING_PROVIDER", raising=False)
    monkeypatch.delenv("SENTINEL_EMBEDDING_DIM", raising=False)

    kb._run_ingestion_background(provider)

    assert calls == 1
    assert os.environ["AI_EMBEDDING_PROVIDER"] == provider
    assert os.environ["SENTINEL_EMBEDDING_DIM"] == dimension


def test_background_callback_handles_nonzero_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kb, "run_ingestion", lambda: 1)
    kb._run_ingestion_background("ollama")


def test_status_returns_correct_collection_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeChromaClient({
        "mitre_attack": 526,
        "sa_threat_intel": 5,
        "sa_compliance": 5,
    })
    monkeypatch.setattr(kb, "_create_chroma_client", lambda: client)
    monkeypatch.setenv("AI_EMBEDDING_PROVIDER", "ollama")

    response = TestClient(build_app()).get("/api/kb/status")

    assert response.status_code == 200
    assert response.json() == {
        "collections": {
            "mitre_attack": {
                "exists": True,
                "document_count": 526,
            },
            "sa_threat_intel": {
                "exists": True,
                "document_count": 5,
            },
            "sa_compliance": {
                "exists": True,
                "document_count": 5,
            },
        },
        "chromadb_available": True,
        "embedding_provider": "ollama",
        "total_documents": 536,
    }


def test_status_represents_missing_collection_independently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeChromaClient(
        {
            "mitre_attack": 526,
            "sa_threat_intel": 5,
            "sa_compliance": 5,
        },
        missing={"sa_compliance"},
    )
    monkeypatch.setattr(kb, "_create_chroma_client", lambda: client)

    response = TestClient(build_app()).get("/api/kb/status")

    body = response.json()
    assert response.status_code == 200
    assert body["chromadb_available"] is True
    assert body["collections"]["sa_compliance"] == {
        "exists": False,
        "document_count": 0,
    }
    assert body["total_documents"] == 531


def test_status_handles_chromadb_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeChromaClient(
        heartbeat_error=RuntimeError("Chroma unavailable")
    )
    monkeypatch.setattr(kb, "_create_chroma_client", lambda: client)
    monkeypatch.setenv("AI_EMBEDDING_PROVIDER", "ollama")

    response = TestClient(build_app()).get("/api/kb/status")

    body = response.json()
    assert response.status_code == 200
    assert body["chromadb_available"] is False
    assert body["total_documents"] == 0
    assert all(
        item == {"exists": False, "document_count": 0}
        for item in body["collections"].values()
    )


def test_non_admin_returns_403_on_status() -> None:
    response = TestClient(build_app(mode="non_admin")).get("/api/kb/status")
    assert response.status_code == 403


def test_unauthenticated_returns_401() -> None:
    response = TestClient(build_app(mode="unauthenticated")).get(
        "/api/kb/status"
    )
    assert response.status_code == 401