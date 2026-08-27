"""Local Ollama embedding and BONA generation providers."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from .base import (
    BaseEmbeddingProvider,
    BaseGenerationProvider,
    EmbeddingProviderError,
)
from .mock_provider import BONA_MOCK_INCIDENT_REPORT
from .reporting import (
    BONA_REPORT_JSON_SCHEMA,
    build_incident_report_prompt,
    mock_fallback,
    parse_and_validate_report,
)

logger = logging.getLogger(__name__)

OLLAMA_EMBEDDING_MODEL = "nomic-embed-text"
OLLAMA_GENERATION_MODEL = "llama3.2:1b"
OLLAMA_EMBEDDING_DIM = 768
DEFAULT_OLLAMA_TIMEOUT_SECONDS = 180.0
DEFAULT_OLLAMA_NUM_CTX = 2048
DEFAULT_OLLAMA_NUM_PREDICT = 700
OLLAMA_MAX_RAG_ENTRIES = 5
OLLAMA_RAG_CONTENT_CHARS = 200


def _ollama_base_url() -> str:
    host = os.getenv("OLLAMA_HOST", "localhost").strip() or "localhost"
    port = os.getenv("OLLAMA_PORT", "11434").strip() or "11434"
    return f"http://{host}:{port}"


def _positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Invalid %s='%s'; using default %s", name, raw, default)
        return default
    if value <= 0:
        logger.warning("Non-positive %s='%s'; using default %s", name, raw, default)
        return default
    return value


class OllamaEmbeddingProvider(BaseEmbeddingProvider):
    """Generate embeddings locally through Ollama's HTTP API."""

    def embed(self, text: str) -> list[float]:
        if not isinstance(text, str) or not text.strip():
            raise EmbeddingProviderError("Embedding text must be non-empty")
        try:
            response = httpx.post(
                f"{_ollama_base_url()}/api/embeddings",
                json={"model": OLLAMA_EMBEDDING_MODEL, "prompt": text},
                timeout=DEFAULT_OLLAMA_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            raise EmbeddingProviderError(
                f"Ollama embedding request failed: {type(exc).__name__}"
            ) from exc

        raw_embedding = payload.get("embedding")
        if not isinstance(raw_embedding, list) or not raw_embedding:
            raise EmbeddingProviderError("Ollama returned no embedding vector")
        try:
            embedding = [float(value) for value in raw_embedding]
        except (TypeError, ValueError) as exc:
            raise EmbeddingProviderError(
                "Ollama returned a non-numeric embedding vector"
            ) from exc
        if len(embedding) != OLLAMA_EMBEDDING_DIM:
            raise EmbeddingProviderError(
                "Ollama embedding dimension mismatch: "
                f"expected {OLLAMA_EMBEDDING_DIM}, got {len(embedding)}"
            )
        return embedding

    def embedding_dim(self) -> int:
        return OLLAMA_EMBEDDING_DIM

    def provider_name(self) -> str:
        return "ollama"


class OllamaGenerationProvider(BaseGenerationProvider):
    """Generate structured BONA reports locally through Ollama."""

    def generate_incident_report(
        self,
        investigation_data: dict[str, Any],
    ) -> dict[str, Any]:
        prompt = build_incident_report_prompt(
            investigation_data,
            max_rag_entries=OLLAMA_MAX_RAG_ENTRIES,
            rag_content_chars=OLLAMA_RAG_CONTENT_CHARS,
        )
        num_ctx = _positive_int_env("OLLAMA_NUM_CTX", DEFAULT_OLLAMA_NUM_CTX)
        num_predict = _positive_int_env(
            "OLLAMA_NUM_PREDICT", DEFAULT_OLLAMA_NUM_PREDICT
        )
        try:
            response = httpx.post(
                f"{_ollama_base_url()}/api/generate",
                json={
                    "model": OLLAMA_GENERATION_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "format": BONA_REPORT_JSON_SCHEMA,
                    "options": {
                        "num_ctx": num_ctx,
                        "num_predict": num_predict,
                    },
                },
                timeout=DEFAULT_OLLAMA_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            payload = response.json()
            raw = payload.get("response", "")
            if not isinstance(raw, str) or not raw.strip():
                raise ValueError("Ollama returned an empty response")
            return parse_and_validate_report(
                raw,
                rag_context=investigation_data.get("rag_context"),
            )
        except Exception as exc:
            logger.error(
                "Ollama BONA generation failed; using mock fallback | error=%s",
                type(exc).__name__,
            )
            return mock_fallback(
                BONA_MOCK_INCIDENT_REPORT,
                "Ollama generation error — mock used",
            )

    def provider_name(self) -> str:
        return "ollama"
