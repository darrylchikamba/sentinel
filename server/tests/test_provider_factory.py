"""Unit tests for SENTINEL AI provider resolution."""

from pathlib import Path
import sys

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from services.ai_providers import provider_factory
from services.ai_providers.gemini_provider import (
    GeminiEmbeddingProvider,
    GeminiGenerationProvider,
)
from services.ai_providers.mock_provider import MockGenerationProvider
from services.ai_providers.ollama_provider import (
    OllamaEmbeddingProvider,
    OllamaGenerationProvider,
)


def test_generation_defaults_to_mock(monkeypatch):
    monkeypatch.delenv("AI_GENERATION_PROVIDER", raising=False)
    assert isinstance(
        provider_factory.get_generation_provider(),
        MockGenerationProvider,
    )


def test_generation_mock(monkeypatch):
    monkeypatch.setenv("AI_GENERATION_PROVIDER", "mock")
    assert isinstance(
        provider_factory.get_generation_provider(),
        MockGenerationProvider,
    )


def test_generation_ollama(monkeypatch):
    monkeypatch.setenv("AI_GENERATION_PROVIDER", "ollama")
    assert isinstance(
        provider_factory.get_generation_provider(),
        OllamaGenerationProvider,
    )


def test_generation_gemini(monkeypatch):
    monkeypatch.setenv("AI_GENERATION_PROVIDER", "gemini")
    assert isinstance(
        provider_factory.get_generation_provider(),
        GeminiGenerationProvider,
    )


def test_unknown_generation_falls_back_to_mock(monkeypatch):
    monkeypatch.setenv("AI_GENERATION_PROVIDER", "unknown")
    assert isinstance(
        provider_factory.get_generation_provider(),
        MockGenerationProvider,
    )


def test_embedding_defaults_to_none(monkeypatch):
    monkeypatch.delenv("AI_EMBEDDING_PROVIDER", raising=False)
    assert provider_factory.get_embedding_provider() is None


def test_embedding_none(monkeypatch):
    monkeypatch.setenv("AI_EMBEDDING_PROVIDER", "none")
    assert provider_factory.get_embedding_provider() is None


def test_embedding_ollama(monkeypatch):
    monkeypatch.setenv("AI_EMBEDDING_PROVIDER", "ollama")
    assert isinstance(
        provider_factory.get_embedding_provider(),
        OllamaEmbeddingProvider,
    )


def test_embedding_gemini(monkeypatch):
    monkeypatch.setenv("AI_EMBEDDING_PROVIDER", "gemini")
    assert isinstance(
        provider_factory.get_embedding_provider(),
        GeminiEmbeddingProvider,
    )


def test_unknown_embedding_disables_retrieval(monkeypatch):
    monkeypatch.setenv("AI_EMBEDDING_PROVIDER", "unknown")
    assert provider_factory.get_embedding_provider() is None
