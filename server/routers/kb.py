"""Administrator-only knowledge-base setup and status routes."""

import logging
import os
from typing import Literal

import chromadb
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel

from config.rate_limit import RATE_LIMITS, get_ip_key, limiter
from knowledge_base.setup import run_ingestion
from middleware.auth import get_admin_user
from models.user import UserInDB


logger = logging.getLogger(__name__)
router = APIRouter()

COLLECTION_NAMES = (
    "mitre_attack",
    "sa_threat_intel",
    "sa_compliance",
)

PROVIDER_DIMENSIONS = {
    "ollama": 768,
    "gemini": 3072,
}


class KnowledgeBaseSetupRequest(BaseModel):
    """Optional provider override for a knowledge-base rebuild."""

    embedding_provider: Literal["ollama", "gemini"] | None = None


def _resolve_embedding_provider(
    payload: KnowledgeBaseSetupRequest | None,
) -> str:
    """Resolve a valid ingestion provider from request or environment."""
    requested = payload.embedding_provider if payload else None
    provider = (
        requested
        or os.getenv("AI_EMBEDDING_PROVIDER", "").strip().lower()
    )

    if provider not in PROVIDER_DIMENSIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "embedding_provider must be 'ollama' or 'gemini', "
                "or AI_EMBEDDING_PROVIDER must be configured accordingly"
            ),
        )

    return provider


def _run_ingestion_background(provider: str) -> None:
    """Configure and run knowledge-base ingestion after the HTTP response."""
    dimension = PROVIDER_DIMENSIONS[provider]
    os.environ["AI_EMBEDDING_PROVIDER"] = provider
    os.environ["SENTINEL_EMBEDDING_DIM"] = str(dimension)

    logger.info(
        "Knowledge-base ingestion background task started | "
        "embedding_provider=%s dimension=%s",
        provider,
        dimension,
    )

    try:
        exit_code = run_ingestion()
    except Exception:
        logger.exception(
            "Knowledge-base ingestion background task crashed | "
            "embedding_provider=%s",
            provider,
        )
        return

    if exit_code == 0:
        logger.info(
            "Knowledge-base ingestion background task completed | "
            "embedding_provider=%s",
            provider,
        )
    else:
        logger.error(
            "Knowledge-base ingestion background task failed | "
            "embedding_provider=%s exit_code=%s",
            provider,
            exit_code,
        )


def _create_chroma_client():
    """Create the Docker-network ChromaDB HTTP client."""
    host = os.getenv("CHROMA_HOST", "chromadb").strip() or "chromadb"
    try:
        port = int(os.getenv("CHROMA_PORT", "8000"))
    except ValueError:
        port = 8000
    return chromadb.HttpClient(host=host, port=port)


def _empty_collection_status() -> dict[str, dict[str, int | bool]]:
    return {
        name: {
            "exists": False,
            "document_count": 0,
        }
        for name in COLLECTION_NAMES
    }


def setup_knowledge_base(
    background_tasks: BackgroundTasks,
    payload: KnowledgeBaseSetupRequest | None = None,
    admin_user: UserInDB = Depends(get_admin_user),
) -> dict:
    """Start a provider-aware knowledge-base rebuild in the background."""
    del admin_user  # dependency enforces administrator access
    provider = _resolve_embedding_provider(payload)

    background_tasks.add_task(_run_ingestion_background, provider)

    return {
        "message": "Knowledge base ingestion started",
        "embedding_provider": provider,
        "note": (
            "Ingestion runs in the background. "
            "Check /api/kb/status for progress."
        ),
    }


@router.post("/setup")
@limiter.limit(RATE_LIMITS["kb_setup"], key_func=get_ip_key)
def setup_knowledge_base_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: KnowledgeBaseSetupRequest | None = None,
    admin_user: UserInDB = Depends(get_admin_user),
) -> dict:
    """HTTP wrapper preserving the tested Phase 14 setup helper."""
    return setup_knowledge_base(background_tasks, payload, admin_user)


@router.get("/status")
@limiter.limit(RATE_LIMITS["kb_status"], key_func=get_ip_key)
def knowledge_base_status(
    request: Request,

    admin_user: UserInDB = Depends(get_admin_user),
) -> dict:
    """Return live ChromaDB collection state without raising on outage."""
    del admin_user  # dependency enforces administrator access

    provider = os.getenv("AI_EMBEDDING_PROVIDER", "none").strip().lower()
    collections = _empty_collection_status()

    try:
        client = _create_chroma_client()
        # HttpClient creation can be lazy; heartbeat proves the service is reachable.
        client.heartbeat()
    except Exception:
        logger.exception("ChromaDB unavailable while reading knowledge-base status")
        return {
            "collections": collections,
            "chromadb_available": False,
            "embedding_provider": provider,
            "total_documents": 0,
        }

    total_documents = 0
    for name in COLLECTION_NAMES:
        try:
            collection = client.get_collection(name)
            count = int(collection.count())
            collections[name] = {
                "exists": True,
                "document_count": count,
            }
            total_documents += count
        except Exception:
            # Chroma is reachable, so an individual lookup failure is represented
            # as that collection being unavailable/missing rather than a full outage.
            logger.warning(
                "Knowledge-base collection unavailable | collection=%s",
                name,
                exc_info=True,
            )

    return {
        "collections": collections,
        "chromadb_available": True,
        "embedding_provider": provider,
        "total_documents": total_documents,
    }