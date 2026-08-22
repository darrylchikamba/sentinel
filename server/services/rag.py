"""Retrieve relevant threat intelligence context from ChromaDB."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import chromadb

from services.ai_providers.base import EmbeddingProviderError
from services.ai_providers.provider_factory import get_embedding_provider


logger = logging.getLogger(__name__)

COLLECTIONS: tuple[tuple[str, str], ...] = (
    ("mitre_attack", "MITRE ATT&CK"),
    ("sa_threat_intel", "SA Threat Intelligence"),
    ("sa_compliance", "SA Compliance"),
)

# Verified provider contracts. Vectors from these models are not
# interchangeable; changing embedding provider requires re-ingestion.
GEMINI_EMBEDDING_DIM = 3072
OLLAMA_EMBEDDING_DIM = 768


def _normalise_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def _append_unique(
    values: list[str],
    seen: set[str],
    candidate: object,
) -> None:
    for item in _normalise_list(candidate):
        key = item.casefold()
        if key not in seen:
            seen.add(key)
            values.append(item)


def _build_query(
    threat_summary: dict[str, Any],
    sa_result: dict[str, Any],
) -> str:
    terms: list[str] = []
    seen: set[str] = set()

    for threat in threat_summary.get("top_threats", []) or []:
        if not isinstance(threat, dict):
            continue
        _append_unique(terms, seen, threat.get("threat_signals"))
        _append_unique(terms, seen, threat.get("anomaly_reasons"))
        _append_unique(terms, seen, threat.get("event_type"))

    _append_unique(terms, seen, sa_result.get("sa_patterns_matched"))
    _append_unique(terms, seen, sa_result.get("popia_flags"))
    _append_unique(terms, seen, sa_result.get("cybercrimes_flags"))

    return ", ".join(terms) if terms else "Cybersecurity incident investigation"


def _json_safe(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "item"):
        try:
            return _json_safe(value.item())
        except Exception:
            pass
    return str(value)


def _empty_result(query: str) -> dict[str, Any]:
    return {
        "retrieved_context": [],
        "query_used": query,
        "collections_queried": [],
        "total_retrieved": 0,
        "rag_available": False,
    }


def _configured_embedding_dim(provider_dim: int) -> int:
    raw = os.getenv("SENTINEL_EMBEDDING_DIM", str(provider_dim)).strip()
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(
            "SENTINEL_EMBEDDING_DIM must be a valid integer"
        ) from exc


def _create_chroma_client() -> Any:
    host = os.getenv("CHROMA_HOST", "chromadb").strip() or "chromadb"
    try:
        port = int(os.getenv("CHROMA_PORT", "8000"))
    except ValueError as exc:
        raise ValueError("CHROMA_PORT must be a valid integer") from exc

    # Containers use the Chroma service's internal port. Port 8001 is
    # only the host-machine mapping in the current Docker Compose setup.
    return chromadb.HttpClient(host=host, port=port)


def _first_group(value: object) -> list[Any]:
    if isinstance(value, list) and value:
        first = value[0]
        return first if isinstance(first, list) else value
    return []


def _query_collection(
    client: Any,
    name: str,
    label: str,
    query_embedding: list[float],
    top_k: int,
) -> tuple[list[dict[str, Any]], bool]:
    try:
        collection = client.get_collection(name=name)
        count = int(collection.count())
        if count <= 0:
            return [], False

        response = collection.query(
            query_embeddings=[query_embedding],
            n_results=min(top_k, count),
            include=["documents", "metadatas", "distances"],
        )
    except Exception as exc:
        logger.warning(
            "RAG collection query failed | collection=%s error=%s",
            name,
            type(exc).__name__,
        )
        return [], False

    ids = _first_group(response.get("ids", []))
    documents = _first_group(response.get("documents", []))
    metadatas = _first_group(response.get("metadatas", []))
    distances = _first_group(response.get("distances", []))

    results: list[dict[str, Any]] = []
    for index, document_id in enumerate(ids):
        try:
            distance = float(distances[index])
        except (IndexError, TypeError, ValueError):
            distance = 1.0

        content = documents[index] if index < len(documents) else ""
        metadata = metadatas[index] if index < len(metadatas) else {}

        # Retain the Phase 10 contract: L2 distance is exposed as 1 - distance.
        # This can be negative for sufficiently distant results and is
        # intentionally not clamped until real retrieval data justifies it.
        results.append(
            {
                "source": label,
                "id": str(document_id),
                "content": "" if content is None else str(content),
                "relevance_score": float(1.0 - distance),
                "metadata": _json_safe(metadata or {}),
            }
        )

    return results, True


def retrieve_threat_context(
    threat_summary: dict[str, Any],
    sa_result: dict[str, Any],
    top_k: int = 5,
) -> dict[str, Any]:
    """Retrieve context without allowing RAG failure to stop the pipeline."""
    if not isinstance(threat_summary, dict):
        raise TypeError("threat_summary must be a dictionary")
    if not isinstance(sa_result, dict):
        raise TypeError("sa_result must be a dictionary")
    if not isinstance(top_k, int) or isinstance(top_k, bool):
        raise TypeError("top_k must be an integer")
    if not 1 <= top_k <= 10:
        raise ValueError("top_k must be between 1 and 10")

    query = _build_query(threat_summary, sa_result)
    embedding_provider = get_embedding_provider()

    # Mock/recruiter mode deliberately has no embedding dependency.
    if embedding_provider is None:
        return _empty_result(query)

    provider_dim = embedding_provider.embedding_dim()
    try:
        configured_dim = _configured_embedding_dim(provider_dim)
    except ValueError as exc:
        logger.error(
            "RAG embedding configuration invalid | provider=%s error=%s",
            embedding_provider.provider_name(),
            str(exc),
        )
        return _empty_result(query)

    if configured_dim != provider_dim:
        logger.error(
            "RAG embedding dimension mismatch | provider=%s "
            "configured=%s provider_expected=%s. "
            "Update SENTINEL_EMBEDDING_DIM and re-run knowledge-base ingestion.",
            embedding_provider.provider_name(),
            configured_dim,
            provider_dim,
        )
        return _empty_result(query)

    try:
        # Generate the investigation query vector exactly once and reuse it
        # across all knowledge-base collections.
        query_embedding = embedding_provider.embed(query)
    except EmbeddingProviderError as exc:
        logger.error(
            "RAG embedding generation failed | provider=%s error=%s",
            embedding_provider.provider_name(),
            str(exc),
        )
        return _empty_result(query)
    except Exception as exc:
        logger.error(
            "Unexpected RAG embedding failure | provider=%s error=%s",
            embedding_provider.provider_name(),
            type(exc).__name__,
        )
        return _empty_result(query)

    actual_dim = len(query_embedding)
    if actual_dim != configured_dim:
        logger.error(
            "RAG embedding dimension mismatch | provider=%s "
            "configured=%s actual=%s. "
            "Re-run knowledge-base ingestion with the configured provider.",
            embedding_provider.provider_name(),
            configured_dim,
            actual_dim,
        )
        return _empty_result(query)

    try:
        client = _create_chroma_client()
    except Exception as exc:
        logger.error(
            "ChromaDB unavailable; continuing without RAG context | error=%s",
            type(exc).__name__,
        )
        return _empty_result(query)

    retrieved: list[dict[str, Any]] = []
    queried: list[str] = []

    for name, label in COLLECTIONS:
        results, was_queried = _query_collection(
            client,
            name,
            label,
            query_embedding,
            top_k,
        )
        if was_queried:
            queried.append(name)
        retrieved.extend(results)

    retrieved.sort(
        key=lambda item: (
            -float(item["relevance_score"]),
            str(item["source"]),
            str(item["id"]),
        )
    )

    result = {
        "retrieved_context": retrieved,
        "query_used": query,
        "collections_queried": queried,
        "total_retrieved": int(len(retrieved)),
        "rag_available": bool(retrieved),
    }
    json.dumps(result)
    return result