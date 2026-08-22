"""Gemini cloud embedding and BONA generation providers."""

from __future__ import annotations

import logging
import os
from typing import Any

from google import genai

from .base import (
    BaseEmbeddingProvider,
    BaseGenerationProvider,
    EmbeddingProviderError,
)
from .mock_provider import BONA_MOCK_INCIDENT_REPORT
from .reporting import (
    build_incident_report_prompt,
    mock_fallback,
    parse_and_validate_report,
)


logger = logging.getLogger(__name__)

GEMINI_EMBEDDING_MODEL = "gemini-embedding-2"
GEMINI_GENERATION_MODEL = "gemini-2.5-flash"

# Verified against the live Gemini API during SENTINEL Phase 11 compatibility
# testing. Ingestion and query vectors must always use the same 3072-D model.
GEMINI_EMBEDDING_DIM = 3072


def _gemini_client() -> genai.Client:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key or api_key.lower() in {
        "your-gemini-api-key-here",
        "your_gemini_api_key_here",
    }:
        raise ValueError("GEMINI_API_KEY is missing or still a placeholder")
    return genai.Client(api_key=api_key)


class GeminiEmbeddingProvider(BaseEmbeddingProvider):
    """Generate cloud embeddings using Gemini."""

    def embed(self, text: str) -> list[float]:
        if not isinstance(text, str) or not text.strip():
            raise EmbeddingProviderError("Embedding text must be non-empty")
        try:
            result = _gemini_client().models.embed_content(
                model=GEMINI_EMBEDDING_MODEL,
                contents=text,
            )
            embedding = [float(value) for value in result.embeddings[0].values]
        except Exception as exc:
            raise EmbeddingProviderError(
                f"Gemini embedding request failed: {type(exc).__name__}"
            ) from exc

        if len(embedding) != GEMINI_EMBEDDING_DIM:
            raise EmbeddingProviderError(
                "Gemini embedding dimension mismatch: "
                f"expected {GEMINI_EMBEDDING_DIM}, got {len(embedding)}"
            )
        return embedding

    def embedding_dim(self) -> int:
        return GEMINI_EMBEDDING_DIM

    def provider_name(self) -> str:
        return "gemini"


class GeminiGenerationProvider(BaseGenerationProvider):
    """Generate structured BONA reports using Gemini 2.5 Flash."""

    def generate_incident_report(
        self,
        investigation_data: dict[str, Any],
    ) -> dict[str, Any]:
        prompt = build_incident_report_prompt(investigation_data)
        try:
            response = _gemini_client().models.generate_content(
                model=GEMINI_GENERATION_MODEL,
                contents=prompt,
            )
            raw = response.text
            if not isinstance(raw, str) or not raw.strip():
                raise ValueError("Gemini returned an empty response")
            return parse_and_validate_report(raw)
        except Exception as exc:
            logger.error(
                "Gemini BONA generation failed; using mock fallback | error=%s",
                type(exc).__name__,
            )
            return mock_fallback(
                BONA_MOCK_INCIDENT_REPORT,
                "Gemini API error — mock used",
            )

    def provider_name(self) -> str:
        return "gemini"
