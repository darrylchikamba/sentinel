"""Pydantic contracts for persisted SENTINEL investigations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

UploadSource = Literal["csv", "excel", "text"]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class InvestigationCreate(BaseModel):
    """Internal document shape written to MongoDB."""

    user_id: str
    filename: str
    upload_source: UploadSource
    event_count: int
    anomaly_count: int
    high_threat_count: int
    threat_distribution: dict[str, int]
    graph_nodes: int
    graph_edges: int
    attack_clusters: int
    mitre_techniques: list[str]
    popia_flags: list[str]
    cybercrimes_flags: list[str]
    sa_patterns_matched: list[str]
    incident_summary: str
    incident_next_steps: list[str]
    rag_sources_used: list[str]
    events: list[dict[str, Any]]
    created_at: datetime = Field(default_factory=_utc_now)


class InvestigationResponse(BaseModel):
    """Investigation summary returned by list endpoints."""

    investigation_id: str
    user_id: str
    filename: str
    upload_source: UploadSource
    event_count: int
    anomaly_count: int
    high_threat_count: int
    threat_distribution: dict[str, int]
    graph_nodes: int
    graph_edges: int
    attack_clusters: int
    mitre_techniques: list[str]
    popia_flags: list[str]
    cybercrimes_flags: list[str]
    sa_patterns_matched: list[str]
    incident_summary: str
    incident_next_steps: list[str]
    rag_sources_used: list[str]
    created_at: datetime


class InvestigationDetailResponse(InvestigationResponse):
    """Full investigation response including scored event records."""

    events: list[dict[str, Any]]