"""Incident-report retrieval and regeneration routes."""

from datetime import datetime, timezone
from typing import Any

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Request, status

from config.database import get_database
from config.rate_limit import RATE_LIMITS, get_ip_key, get_user_id_key, limiter
from middleware.auth import get_current_user
from models.user import UserInDB
from services.bona import generate_incident_report


router = APIRouter()


def _validate_object_id(investigation_id: str) -> ObjectId:
    if not ObjectId.is_valid(investigation_id):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid investigation ID format",
        )
    return ObjectId(investigation_id)


def _get_owned_investigation(
    investigation_id: str,
    current_user: UserInDB,
) -> dict[str, Any]:
    object_id = _validate_object_id(investigation_id)
    document = get_database()["investigations"].find_one(
        {
            "_id": object_id,
            "user_id": str(current_user.id),
        }
    )
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )
    return document


def _incident_response(document: dict[str, Any]) -> dict[str, Any]:
    created_at = document.get("created_at")
    if isinstance(created_at, datetime):
        created_at_value = created_at.isoformat()
    else:
        created_at_value = str(created_at or "")

    return {
        "investigation_id": str(document["_id"]),
        "incident_summary": str(document.get("incident_summary", "")),
        "incident_next_steps": list(document.get("incident_next_steps", [])),
        "mitre_techniques": list(document.get("mitre_techniques", [])),
        "popia_flags": list(document.get("popia_flags", [])),
        "cybercrimes_flags": list(document.get("cybercrimes_flags", [])),
        "sa_patterns_matched": list(document.get("sa_patterns_matched", [])),
        "rag_sources_used": list(document.get("rag_sources_used", [])),
        "attack_clusters": int(document.get("attack_clusters", 0) or 0),
        "high_threat_count": int(document.get("high_threat_count", 0) or 0),
        "event_count": int(document.get("event_count", 0) or 0),
        "created_at": created_at_value,
    }


def _stored_top_threats(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    allowed_fields = (
        "event_type",
        "src_ip",
        "dst_ip",
        "threat_score",
        "threat_level",
        "threat_signals",
        "anomaly_reasons",
        "timestamp",
    )

    def numeric_score(event: dict[str, Any]) -> float:
        try:
            return float(event.get("threat_score", 0) or 0)
        except (TypeError, ValueError):
            return 0.0

    ranked = sorted(
        (event for event in events if isinstance(event, dict)),
        key=numeric_score,
        reverse=True,
    )[:10]

    return [
        {field: event.get(field) for field in allowed_fields}
        for event in ranked
    ]


def _max_stored_threat_score(events: list[dict[str, Any]]) -> int:
    values: list[float] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        try:
            values.append(float(event.get("threat_score", 0) or 0))
        except (TypeError, ValueError):
            continue
    return int(max(values)) if values else 0


def _build_regeneration_data(document: dict[str, Any]) -> dict[str, Any]:
    events = document.get("events", [])
    if not isinstance(events, list):
        events = []

    max_threat_score = _max_stored_threat_score(events)

    threat_summary = {
        "event_count": int(document.get("event_count", len(events)) or 0),
        "anomaly_count": int(document.get("anomaly_count", 0) or 0),
        "high_threat_count": int(document.get("high_threat_count", 0) or 0),
        "threat_distribution": dict(document.get("threat_distribution", {})),
        "top_threats": _stored_top_threats(events),
        "attack_clusters_detected": int(
            document.get("attack_clusters", 0) or 0
        ),
        "max_threat_score": max_threat_score,
    }

    graph_summary = {
        "total_nodes": int(document.get("graph_nodes", 0) or 0),
        "total_edges": int(document.get("graph_edges", 0) or 0),
        "suspicious_nodes": int(document.get("high_threat_count", 0) or 0),
        "attack_clusters_detected": int(
            document.get("attack_clusters", 0) or 0
        ),
        "max_threat_score_in_graph": max_threat_score,
    }

    sa_result = {
        "popia_flags": list(document.get("popia_flags", [])),
        "cybercrimes_flags": list(document.get("cybercrimes_flags", [])),
        "sa_patterns_matched": list(document.get("sa_patterns_matched", [])),
        "compliance_summary": "",
        "reporting_obligations": [],
    }

    # EP-018: canonical Phase 11 RAG shape, intentionally empty.
    rag_context = {
        "retrieved_context": [],
        "query_used": "",
        "collections_queried": [],
        "total_retrieved": 0,
        "rag_available": False,
    }

    return {
        "threat_summary": threat_summary,
        "graph_summary": graph_summary,
        "sa_result": sa_result,
        "rag_context": rag_context,
    }


@router.get("/{investigation_id}")
@limiter.limit(RATE_LIMITS["incident_get"], key_func=get_ip_key)
def get_incident_report(
    request: Request,
    investigation_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict[str, Any]:
    document = _get_owned_investigation(investigation_id, current_user)
    return _incident_response(document)


@router.post("/{investigation_id}/regenerate")
@limiter.limit(RATE_LIMITS["incident_regenerate"], key_func=get_user_id_key)
def regenerate_incident_report(
    request: Request,
    investigation_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict[str, Any]:
    document = _get_owned_investigation(investigation_id, current_user)
    investigation_data = _build_regeneration_data(document)

    try:
        report = generate_incident_report(investigation_data)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Incident report regeneration failed",
        ) from exc

    if report.get("bona_error"):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Incident report regeneration failed",
        )

    regenerated_at = datetime.now(timezone.utc)
    update_fields = {
        "incident_summary": str(report.get("incident_summary", "")),
        "incident_next_steps": list(report.get("incident_next_steps", [])),
        "mitre_techniques": list(report.get("mitre_techniques", [])),
        "rag_sources_used": list(report.get("rag_sources_used", [])),
        "regenerated_at": regenerated_at,
    }

    result = get_database()["investigations"].update_one(
        {
            "_id": document["_id"],
            "user_id": str(current_user.id),
        },
        {"$set": update_fields},
    )
    if result.matched_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    updated_document = dict(document)
    updated_document.update(update_fields)
    return _incident_response(updated_document)