"""Phase 12 upload-router integration tests with external boundaries mocked."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import sys
from types import SimpleNamespace

from bson import ObjectId
from fastapi import FastAPI
from fastapi.testclient import TestClient
import numpy as np
import pandas as pd
import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))
os.environ.setdefault("MONGO_URI", "mongodb://unused-test-host:27017/sentinel")
os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-for-tests")

from middleware.auth import get_current_user  # noqa: E402
from models.user import UserInDB  # noqa: E402
from routers import upload  # noqa: E402


USER_ID = ObjectId()


def fake_user() -> UserInDB:
    return UserInDB.model_validate({
        "_id": USER_ID,
        "username": "soc_analyst",
        "email": "analyst@example.co.za",
        "hashed_password": "unused",
        "is_admin": False,
        "created_at": datetime.now(timezone.utc),
    })


def parsed_df() -> pd.DataFrame:
    return pd.DataFrame([
        {
            "timestamp": pd.Timestamp("2026-08-18T18:00:00Z"),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "event_type": "login_failed",
            "user_account": "analyst",
            "device_id": "dev-1",
            "bytes_transferred": 100.0,
        },
        {
            "timestamp": pd.Timestamp("2026-08-18T18:01:00Z"),
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.3",
            "event_type": "port_scan",
            "user_account": "analyst",
            "device_id": "dev-1",
            "bytes_transferred": 250.0,
        },
    ])


def anomaly_df() -> pd.DataFrame:
    df = parsed_df()
    df["is_anomaly"] = [np.bool_(True), np.bool_(False)]
    df["ml_is_anomaly"] = [np.bool_(True), np.bool_(False)]
    df["anomaly_reasons"] = [["BRUTE_FORCE"], ["PORT_SCAN"]]
    return df


def scored_df() -> pd.DataFrame:
    df = anomaly_df()
    df["threat_score"] = [np.int64(85), np.int64(45)]
    df["threat_level"] = ["Critical", "Medium"]
    df["threat_signals"] = [
        ["Repeated authentication failures"],
        ["Port scan detected"],
    ]
    return df


GRAPH_RESULT = {
    "nodes": [],
    "edges": [],
    "attack_clusters": [{"cluster_id": "CLUSTER-001"}],
    "graph_summary": {
        "total_nodes": 3,
        "total_edges": 2,
        "suspicious_nodes": 2,
        "attack_clusters_detected": 1,
        "max_threat_score_in_graph": 85,
    },
}

SA_RESULT = {
    "popia_flags": ["POPIA_SECTION_22"],
    "cybercrimes_flags": ["CYBERCRIMES_ACT_REPORTABLE"],
    "sa_patterns_matched": ["GOVPORTAL_CREDENTIAL_STUFFING"],
    "compliance_summary": {},
    "reporting_obligations": [],
}

RAG_RESULT = {
    "retrieved_context": [{
        "source": "MITRE ATT&CK",
        "id": "T1110.004",
        "content": "Credential Stuffing",
        "relevance_score": -1.0,
        "metadata": {},
    }],
    "query_used": "credential stuffing",
    "collections_queried": ["mitre_attack"],
    "total_retrieved": 1,
    "rag_available": True,
}

BONA_REPORT = {
    "incident_summary": "Detected credential-stuffing activity.",
    "mitre_techniques": ["T1110.004 (Credential Stuffing)"],
    "confidence_level": "High",
    "incident_next_steps": [
        "Isolate affected accounts.",
        "Reset exposed credentials.",
        "Review authentication telemetry.",
        "Assess reporting obligations.",
    ],
    "popia_flags": ["POPIA_SECTION_22"],
    "cybercrimes_flags": ["CYBERCRIMES_ACT_REPORTABLE"],
    "sa_patterns_matched": ["GOVPORTAL_CREDENTIAL_STUFFING"],
    "rag_sources_used": ["MITRE ATT&CK"],
    "generated_by": "BONA",
    "mock": False,
}


class FakeInvestigationsCollection:
    def __init__(self) -> None:
        self.documents: list[dict] = []

    def insert_one(self, document: dict):
        self.documents.append(document)
        return SimpleNamespace(inserted_id=ObjectId())


class FakeDatabase:
    def __init__(self) -> None:
        self.investigations = FakeInvestigationsCollection()

    def __getitem__(self, name: str):
        assert name == "investigations"
        return self.investigations


def build_app(*, authenticated: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(upload.router, prefix="/api/upload")
    if authenticated:
        app.dependency_overrides[get_current_user] = fake_user
    return app


def install_success_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    *,
    order: list[str] | None = None,
) -> FakeDatabase:
    calls = order if order is not None else []

    def parse_file(data: bytes, filename: str) -> pd.DataFrame:
        calls.append("parse")
        return parsed_df()

    def parse_text(text: str) -> pd.DataFrame:
        calls.append("parse")
        return parsed_df()

    def anomaly(data: pd.DataFrame) -> pd.DataFrame:
        calls.append("anomaly")
        return anomaly_df()

    def score(data: pd.DataFrame) -> pd.DataFrame:
        calls.append("score")
        return scored_df()

    def graph(data: pd.DataFrame) -> dict:
        calls.append("graph")
        return GRAPH_RESULT

    def sa(data: pd.DataFrame, graph_result: dict) -> dict:
        calls.append("sa")
        return SA_RESULT

    def rag(summary: dict, sa_result: dict) -> dict:
        calls.append("rag")
        return RAG_RESULT

    def bona(data: dict) -> dict:
        calls.append("bona")
        assert data["rag_context"] is RAG_RESULT
        return BONA_REPORT

    database = FakeDatabase()
    monkeypatch.setattr(upload, "parse_log_file", parse_file)
    monkeypatch.setattr(upload, "parse_log_text", parse_text)
    monkeypatch.setattr(upload, "detect_anomalies", anomaly)
    monkeypatch.setattr(upload, "score_threats", score)
    monkeypatch.setattr(upload, "build_attack_graph", graph)
    monkeypatch.setattr(upload, "classify_sa_intelligence", sa)
    monkeypatch.setattr(upload, "retrieve_threat_context", rag)
    monkeypatch.setattr(upload, "generate_incident_report", bona)
    monkeypatch.setattr(upload, "get_database", lambda: database)
    return database


def test_valid_csv_upload_triggers_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    database = install_success_pipeline(monkeypatch, order=order)
    client = TestClient(build_app())
    response = client.post(
        "/api/upload",
        files={"file": ("events.csv", b"a,b\n1,2\n", "text/csv")},
    )
    assert response.status_code == 200
    assert order == ["parse", "anomaly", "score", "graph", "sa", "rag", "bona"]
    assert len(database.investigations.documents) == 1
    assert response.json()["upload_source"] == "csv"


def test_raw_text_upload_triggers_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    install_success_pipeline(monkeypatch, order=order)
    client = TestClient(build_app())
    response = client.post(
        "/api/upload",
        json={"raw_text": "timestamp,src_ip,dst_ip,event_type\nx,a,b,c"},
    )
    assert response.status_code == 200
    assert order[0] == "parse"
    assert response.json()["upload_source"] == "text"


def test_missing_file_and_text_returns_422() -> None:
    response = TestClient(build_app()).post("/api/upload", json={})
    assert response.status_code == 422
    assert response.json() == {
        "detail": "Provide either a file upload or raw_text"
    }


def test_file_too_large_returns_422(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parse_called = False

    def parse_file(*args, **kwargs):
        nonlocal parse_called
        parse_called = True
        return parsed_df()

    monkeypatch.setattr(upload, "parse_log_file", parse_file)
    response = TestClient(build_app()).post(
        "/api/upload",
        files={"file": (
            "events.csv",
            b"x" * (upload.MAX_FILE_BYTES + 1),
            "text/csv",
        )},
    )
    assert response.status_code == 422
    assert "10 MB" in response.json()["detail"]
    assert parse_called is False


def test_unsupported_extension_returns_422() -> None:
    response = TestClient(build_app()).post(
        "/api/upload",
        files={"file": ("events.json", b"{}", "application/json")},
    )
    assert response.status_code == 422
    assert "Unsupported file type" in response.json()["detail"]


def test_parser_value_error_returns_422(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_parser(*args, **kwargs):
        raise ValueError("Missing required columns: dst_ip")

    monkeypatch.setattr(upload, "parse_log_file", fail_parser)
    response = TestClient(build_app()).post(
        "/api/upload",
        files={"file": ("events.csv", b"x", "text/csv")},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Missing required columns: dst_ip"


def test_stage_two_failure_returns_500_and_never_inserts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    monkeypatch.setattr(upload, "parse_log_file", lambda *args: parsed_df())

    def fail_anomaly(df: pd.DataFrame):
        raise RuntimeError("model exploded")

    monkeypatch.setattr(upload, "detect_anomalies", fail_anomaly)
    monkeypatch.setattr(upload, "get_database", lambda: database)
    response = TestClient(build_app()).post(
        "/api/upload",
        files={"file": ("events.csv", b"x", "text/csv")},
    )
    assert response.status_code == 500
    assert response.json() == {"detail": "Anomaly detection failed"}
    assert database.investigations.documents == []


def test_rag_exception_does_not_block_investigation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = install_success_pipeline(monkeypatch)

    def fail_rag(*args, **kwargs):
        raise RuntimeError("chroma offline")

    seen: dict = {}

    def bona(data: dict) -> dict:
        seen["rag_context"] = data["rag_context"]
        return BONA_REPORT

    monkeypatch.setattr(upload, "retrieve_threat_context", fail_rag)
    monkeypatch.setattr(upload, "generate_incident_report", bona)
    response = TestClient(build_app()).post(
        "/api/upload",
        files={"file": ("events.csv", b"x", "text/csv")},
    )
    assert response.status_code == 200
    assert seen["rag_context"]["rag_available"] is False
    assert seen["rag_context"]["retrieved_context"] == []
    assert len(database.investigations.documents) == 1


def test_bona_exception_uses_mock_and_does_not_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = install_success_pipeline(monkeypatch)

    def fail_bona(data: dict):
        raise RuntimeError("provider offline")

    monkeypatch.setattr(upload, "generate_incident_report", fail_bona)
    mock_report = dict(BONA_REPORT)
    mock_report["mock"] = True
    mock_report["incident_summary"] = "Mock fallback report."

    class FakeMockProvider:
        def generate_incident_report(self, data: dict) -> dict:
            return mock_report

    monkeypatch.setattr(upload, "MockGenerationProvider", FakeMockProvider)
    response = TestClient(build_app()).post(
        "/api/upload",
        files={"file": ("events.csv", b"x", "text/csv")},
    )
    assert response.status_code == 200
    assert len(database.investigations.documents) == 1
    assert (
        database.investigations.documents[0]["incident_summary"]
        == "Mock fallback report."
    )


def test_successful_upload_returns_investigation_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_success_pipeline(monkeypatch)
    response = TestClient(build_app()).post(
        "/api/upload",
        files={"file": ("events.csv", b"x", "text/csv")},
    )
    body = response.json()
    assert response.status_code == 200
    assert ObjectId.is_valid(body["investigation_id"])
    assert body["message"] == "Investigation complete"
    assert body["event_count"] == 2
    assert body["anomaly_count"] == 1
    assert body["high_threat_count"] == 1
    assert body["attack_clusters_detected"] == 1


def test_unauthenticated_request_returns_401() -> None:
    response = TestClient(build_app(authenticated=False)).post(
        "/api/upload",
        json={"raw_text": "anything"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


def test_insert_uses_authenticated_user_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = install_success_pipeline(monkeypatch)
    response = TestClient(build_app()).post(
        "/api/upload",
        files={"file": ("events.csv", b"x", "text/csv")},
    )
    assert response.status_code == 200
    assert database.investigations.documents[0]["user_id"] == str(USER_ID)


def test_insert_persists_complete_graph_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = install_success_pipeline(monkeypatch)

    response = TestClient(build_app()).post(
        "/api/upload",
        files={"file": ("events.csv", b"x", "text/csv")},
    )

    assert response.status_code == 200

    document = database.investigations.documents[0]
    assert document["graph_result"] == GRAPH_RESULT
    assert document["graph_result"]["nodes"] == GRAPH_RESULT["nodes"]
    assert document["graph_result"]["edges"] == GRAPH_RESULT["edges"]
    assert document["graph_result"]["attack_clusters"] == GRAPH_RESULT[
        "attack_clusters"
    ]
    assert document["graph_result"]["graph_summary"] == GRAPH_RESULT[
        "graph_summary"
    ]


def test_inserted_events_are_bson_safe_and_timestamp_is_iso(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = install_success_pipeline(monkeypatch)
    response = TestClient(build_app()).post(
        "/api/upload",
        files={"file": ("events.csv", b"x", "text/csv")},
    )
    assert response.status_code == 200
    events = database.investigations.documents[0]["events"]
    assert isinstance(events[0]["timestamp"], str)
    assert type(events[0]["threat_score"]) is int
    assert type(events[0]["is_anomaly"]) is bool


def test_top_threats_are_sorted_and_limited_to_ten() -> None:
    rows = [{
        "timestamp": pd.Timestamp("2026-08-18T18:00:00Z"),
        "event_type": f"event-{score}",
        "src_ip": "a",
        "dst_ip": "b",
        "threat_score": np.int64(score),
        "threat_level": "High",
        "threat_signals": [],
        "anomaly_reasons": [],
        "is_anomaly": False,
    } for score in range(12)]
    summary = upload._build_threat_summary(pd.DataFrame(rows), GRAPH_RESULT)
    assert len(summary["top_threats"]) == 10
    assert summary["top_threats"][0]["threat_score"] == 11
    assert summary["top_threats"][-1]["threat_score"] == 2


def test_raw_text_over_limit_returns_422() -> None:
    response = TestClient(build_app()).post(
        "/api/upload",
        json={"raw_text": "x" * (upload.MAX_RAW_TEXT_CHARS + 1)},
    )
    assert response.status_code == 422
    assert "50,000" in response.json()["detail"]


def test_filename_path_components_are_stripped_before_parsing_and_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, str] = {}

    database = install_success_pipeline(monkeypatch)

    def parse_file(data: bytes, filename: str) -> pd.DataFrame:
        seen["filename"] = filename
        return parsed_df()

    monkeypatch.setattr(upload, "parse_log_file", parse_file)

    response = TestClient(build_app()).post(
        "/api/upload",
        files={
            "file": (
                "../../windows\\path\\events.csv",
                b"a,b\n1,2\n",
                "text/csv",
            )
        },
    )

    assert response.status_code == 200
    assert seen["filename"] == "events.csv"
    assert database.investigations.documents[0]["filename"] == "events.csv"


def test_obvious_binary_content_with_csv_suffix_is_rejected_before_parser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parse_called = False

    def parse_file(*args, **kwargs):
        nonlocal parse_called
        parse_called = True
        return parsed_df()

    monkeypatch.setattr(upload, "parse_log_file", parse_file)

    response = TestClient(build_app()).post(
        "/api/upload",
        files={
            "file": (
                "events.csv",
                b"MZ\x00\x00this-is-not-csv",
                "text/csv",
            )
        },
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "CSV upload contains unsupported binary content"
    }
    assert parse_called is False
