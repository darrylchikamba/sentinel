"""Resolve configured SENTINEL AI providers."""

from __future__ import annotations

import logging
import os

from .base import BaseEmbeddingProvider, BaseGenerationProvider
from .gemini_provider import GeminiEmbeddingProvider, GeminiGenerationProvider
from .mock_provider import MockGenerationProvider
from .ollama_provider import OllamaEmbeddingProvider, OllamaGenerationProvider


logger = logging.getLogger(__name__)


def get_embedding_provider() -> BaseEmbeddingProvider | None:
    """Resolve the configured embedding provider."""
    value = os.getenv("AI_EMBEDDING_PROVIDER", "none").strip().lower()
    if value in {"", "none"}:
        return None
    if value == "ollama":
        return OllamaEmbeddingProvider()
    if value == "gemini":
        return GeminiEmbeddingProvider()

    logger.warning(
        "Unknown AI_EMBEDDING_PROVIDER '%s'; retrieval disabled",
        value,
    )
    return None


def get_generation_provider() -> BaseGenerationProvider:
    """Resolve generation provider, always falling back safely to mock."""
    value = os.getenv("AI_GENERATION_PROVIDER", "mock").strip().lower()
    if value == "ollama":
        return OllamaGenerationProvider()
    if value == "gemini":
        return GeminiGenerationProvider()
    if value not in {"", "mock"}:
        logger.warning(
            "Unknown AI_GENERATION_PROVIDER '%s'; using mock provider",
            value,
        )
    return MockGenerationProvider()
