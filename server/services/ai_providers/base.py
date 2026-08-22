"""Provider contracts and provider-specific error types for SENTINEL AI."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class EmbeddingProviderError(RuntimeError):
    """Raised when an embedding provider cannot return a valid vector."""


class GenerationProviderError(RuntimeError):
    """Raised when a generation provider cannot return a valid response."""


class BaseEmbeddingProvider(ABC):
    """Contract implemented by every SENTINEL embedding provider."""

    @abstractmethod
    def embed(self, text: str) -> list[float]:
        """Return an embedding vector for text."""

    @abstractmethod
    def embedding_dim(self) -> int:
        """Return the provider's expected embedding dimensionality."""

    @abstractmethod
    def provider_name(self) -> str:
        """Return the stable provider identifier."""


class BaseGenerationProvider(ABC):
    """Contract implemented by every SENTINEL report-generation provider."""

    @abstractmethod
    def generate_incident_report(
        self,
        investigation_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate or fall back to a structured BONA incident report."""

    @abstractmethod
    def provider_name(self) -> str:
        """Return the stable provider identifier."""
