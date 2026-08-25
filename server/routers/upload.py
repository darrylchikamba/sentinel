"""Protected upload endpoint and full SENTINEL investigation orchestration."""

import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, Request, status
from starlette.datastructures import UploadFile

from config.database import get_database
from config.rate_limit import RATE_LIMITS, get_user_id_key, limiter
from middleware.auth import get_current_user
from models.investigation import InvestigationCreate
from models.user import UserInDB
from services.ai_providers.mock_provider import MockGenerationProvider
from services.anomaly import detect_anomalies
from services.bona import generate_incident_report
from services.graph_builder import build_attack_graph
from services.log_parser import parse_log_file, parse_log_text
from services.rag import retrieve_threat_context
from services.sa_intelligence import classify_sa_intelligence
from services.threat_scorer import score_threats
from utils.dataframe_serialiser import serialise_dataframe


logger = logging.getLogger(__name__)
router = APIRouter()

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_RAW_TEXT_CHARS = 50_000
SUPPORTED_EXTENSIONS = {".csv", ".xlsx", ".xls"}


def _empty_rag_result() -> dict[str, Any]:
    return {
        "retrieved_context": [],
        "query_used": "",
        "collections_queried": [],
        "total_retrieved": 0,
        "rag_available": False,
    }


def _determine_upload_source(filename: str) -> str:
    extension = Path(filename).suffix.lower()
    if extension == ".csv":
        return "csv"
    if extension in {".xlsx", ".xls"}:
        return "excel"
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="Unsupported file type. Supported types are .csv, .xlsx and .xls",
    )


def _count_level(df: pd.DataFrame, level: str) -> int:
    if "threat_level" not in df.columns:
        return 0
    values = df["threat_level"].fillna("None").astype(str).str.lower()
    return int(values.eq(level.lower()).sum())


def _serialise_top_threats(df: pd.DataFrame) -> list[dict[str, Any]]:
    fields = [
        "event_type",
        "src_ip",
        "dst_ip",
        "threat_score",
        "threat_level",
        "threat_signals",
        "anomaly_reasons",
        "timestamp",
    ]
    working = df.copy(deep=True)
    for field in fields:
        if field not in working.columns:
            if field in {"threat_signals", "anomaly_reasons"}:
                working[field] = [[] for _ in range(len(working))]
            elif field == "threat_score":
                working[field] = 0
            else:
                working[field] = None

    working["_sort_score"] = pd.to_numeric(
        working["threat_score"],
        errors="coerce",
    ).fillna(0)
    top = (
        working.sort_values("_sort_score", ascending=False, kind="stable")
        .head(10)
        .loc[:, fields]
    )
    return serialise_dataframe(top)


def _build_threat_summary(
    df: pd.DataFrame,
    graph_result: dict[str, Any],
) -> dict[str, Any]:
    anomaly_count = 0
    if "is_anomaly" in df.columns:
        anomaly_count = int(df["is_anomaly"].fillna(False).astype(bool).sum())

    critical = _count_level(df, "critical")
    high = _count_level(df, "high")
    medium = _count_level(df, "medium")
    low = _count_level(df, "low")
    none = _count_level(df, "none")

    max_score = 0
    if not df.empty and "threat_score" in df.columns:
        scores = pd.to_numeric(df["threat_score"], errors="coerce").fillna(0)
        max_score = int(scores.max())

    graph_summary = graph_result.get("graph_summary", {})
    attack_clusters = int(
        graph_summary.get("attack_clusters_detected", 0) or 0
    )

    return {
        "event_count": int(len(df)),
        "anomaly_count": anomaly_count,
        "high_threat_count": int(critical + high),
        "threat_distribution": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "none": none,
        },
        "top_threats": _serialise_top_threats(df),
        "attack_clusters_detected": attack_clusters,
        "max_threat_score": max_score,
    }


def _pipeline_failure(stage: str, exc: Exception) -> HTTPException:
    logger.exception("%s failed during upload pipeline", stage, exc_info=exc)
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"{stage} failed",
    )


async def _parse_request_input(
    request: Request,
) -> tuple[pd.DataFrame, str, str]:
    content_type = request.headers.get("content-type", "").lower()

    if content_type.startswith("multipart/form-data"):
        try:
            form = await request.form()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Unable to read multipart upload",
            ) from exc

        uploaded = form.get("file")
        if uploaded is None or not isinstance(uploaded, UploadFile):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Provide either a file upload or raw_text",
            )

        filename = (uploaded.filename or "").strip()
        if not filename:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="A filename is required",
            )

        upload_source = _determine_upload_source(filename)
        file_bytes = await uploaded.read()
        if len(file_bytes) > MAX_FILE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="File exceeds the 10 MB upload limit",
            )

        try:
            dataframe = parse_log_file(file_bytes, filename)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        return dataframe, filename, upload_source

    if content_type.startswith("application/json"):
        try:
            payload = await request.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Request body must be valid JSON",
            ) from exc

        if not isinstance(payload, dict):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Request body must be a JSON object",
            )

        raw_text = payload.get("raw_text")
        if raw_text is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Provide either a file upload or raw_text",
            )
        if not isinstance(raw_text, str):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="raw_text must be a string",
            )
        if len(raw_text) > MAX_RAW_TEXT_CHARS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="raw_text exceeds the 50,000 character limit",
            )

        try:
            dataframe = parse_log_text(raw_text)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        return dataframe, "pasted-text", "text"

    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=(
            "Content-Type must be multipart/form-data for file uploads "
            "or application/json for raw_text"
        ),
    )


@router.post("")
@limiter.limit(RATE_LIMITS["upload"], key_func=get_user_id_key)
async def upload_logs(
    request: Request,
    current_user: UserInDB = Depends(get_current_user),
) -> dict[str, Any]:
    """Run the full investigation pipeline and persist its result."""
    dataframe, filename, upload_source = await _parse_request_input(request)

    try:
        anomaly_df = detect_anomalies(dataframe)
    except Exception as exc:
        raise _pipeline_failure("Anomaly detection", exc) from exc

    try:
        scored_df = score_threats(anomaly_df)
    except Exception as exc:
        raise _pipeline_failure("Threat scoring", exc) from exc

    try:
        graph_result = build_attack_graph(scored_df)
    except Exception as exc:
        raise _pipeline_failure("Graph building", exc) from exc

    try:
        sa_result = classify_sa_intelligence(scored_df, graph_result)
    except Exception as exc:
        raise _pipeline_failure("SA intelligence", exc) from exc

    threat_summary = _build_threat_summary(scored_df, graph_result)

    try:
        rag_result = retrieve_threat_context(threat_summary, sa_result)
    except Exception:
        logger.exception(
            "RAG retrieval failed during upload pipeline; continuing without RAG"
        )
        rag_result = _empty_rag_result()

    # EP-016: preserve the Phase 11 contract by passing the complete RAG result.
    investigation_data = {
        "threat_summary": threat_summary,
        "graph_summary": graph_result.get("graph_summary", {}),
        "sa_result": sa_result,
        "rag_context": rag_result,
    }

    try:
        bona_report = generate_incident_report(investigation_data)
    except Exception:
        logger.exception(
            "BONA generation failed during upload pipeline; using mock fallback"
        )
        bona_report = MockGenerationProvider().generate_incident_report(
            investigation_data
        )

    graph_summary = graph_result.get("graph_summary", {})
    investigation = InvestigationCreate(
        user_id=str(current_user.id),
        filename=filename,
        upload_source=upload_source,
        event_count=threat_summary["event_count"],
        anomaly_count=threat_summary["anomaly_count"],
        high_threat_count=threat_summary["high_threat_count"],
        threat_distribution=threat_summary["threat_distribution"],
        graph_nodes=int(graph_summary.get("total_nodes", 0) or 0),
        graph_edges=int(graph_summary.get("total_edges", 0) or 0),
        attack_clusters=int(
            graph_summary.get("attack_clusters_detected", 0) or 0
        ),
        graph_result=graph_result,
        mitre_techniques=list(bona_report.get("mitre_techniques", [])),
        popia_flags=list(sa_result.get("popia_flags", [])),
        cybercrimes_flags=list(sa_result.get("cybercrimes_flags", [])),
        sa_patterns_matched=list(sa_result.get("sa_patterns_matched", [])),
        incident_summary=str(bona_report.get("incident_summary", "")),
        incident_next_steps=list(
            bona_report.get("incident_next_steps", [])
        ),
        rag_sources_used=list(bona_report.get("rag_sources_used", [])),
        events=serialise_dataframe(scored_df),
    )

    document = investigation.model_dump(mode="python")
    try:
        result = get_database()["investigations"].insert_one(document)
    except Exception as exc:
        logger.exception("Failed to persist completed investigation")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to store investigation",
        ) from exc

    return {
        "investigation_id": str(result.inserted_id),
        "message": "Investigation complete",
        "event_count": threat_summary["event_count"],
        "anomaly_count": threat_summary["anomaly_count"],
        "high_threat_count": threat_summary["high_threat_count"],
        "attack_clusters_detected": threat_summary[
            "attack_clusters_detected"
        ],
        "threat_distribution": threat_summary["threat_distribution"],
        "upload_source": upload_source,
    }
