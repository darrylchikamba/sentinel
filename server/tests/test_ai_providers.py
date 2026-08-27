"""Unit tests for concrete SENTINEL AI providers."""

import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from services.ai_providers.base import EmbeddingProviderError
from services.ai_providers import gemini_provider, ollama_provider
from services.ai_providers.mock_provider import (
    BONA_MOCK_INCIDENT_REPORT,
    MockGenerationProvider,
)
from services.ai_providers.reporting import (
    BONA_REPORT_JSON_SCHEMA,
    build_incident_report_prompt,
    parse_and_validate_report,
)


VALID_REPORT = {
    "incident_summary": "Paragraph one.\n\nParagraph two.",
    "mitre_techniques": ["T1110.001 (Password Guessing)"],
    "confidence_level": "High",
    "incident_next_steps": [
        "Isolate the host.",
        "Reset credentials.",
        "Review telemetry.",
        "Assess reporting obligations.",
    ],
    "popia_flags": ["POPIA_SECTION_22"],
    "cybercrimes_flags": ["CYBERCRIMES_ACT_REPORTABLE"],
    "sa_patterns_matched": ["GOVPORTAL_CREDENTIAL_STUFFING"],
    "rag_sources_used": ["MITRE ATT&CK"],
    "generated_by": "WRONG",
    "mock": True,
}


class FakeHttpxResponse:
    def __init__(self, payload, *, error=None):
        self.payload = payload
        self.error = error

    def raise_for_status(self):
        if self.error:
            raise self.error

    def json(self):
        return self.payload


def test_mock_provider_returns_deep_copy():
    provider = MockGenerationProvider()

    first = provider.generate_incident_report({})
    first["popia_flags"].append("MUTATED")
    second = provider.generate_incident_report({})

    assert first is not second
    assert "MUTATED" not in second["popia_flags"]


def test_report_validation_overrides_provenance():
    result = parse_and_validate_report(json.dumps(VALID_REPORT))

    assert result["generated_by"] == "BONA"
    assert result["mock"] is False


def test_report_validation_strips_json_fence():
    raw = "```json\n" + json.dumps(VALID_REPORT) + "\n```"
    result = parse_and_validate_report(raw)

    assert result["confidence_level"] == "High"




def test_bona_json_schema_requires_all_contract_fields():
    assert set(BONA_REPORT_JSON_SCHEMA["required"]) == {
        "incident_summary", "mitre_techniques", "confidence_level",
        "incident_next_steps", "popia_flags", "cybercrimes_flags",
        "sa_patterns_matched", "rag_sources_used", "generated_by", "mock",
    }
    next_steps = BONA_REPORT_JSON_SCHEMA["properties"]["incident_next_steps"]
    assert next_steps["minItems"] == 4
    assert next_steps["maxItems"] == 4


def test_ollama_prompt_trims_local_rag_context():
    data = {
        "rag_context": {
            "retrieved_context": [
                {
                    "source": "MITRE ATT&CK",
                    "id": f"T{i}",
                    "content": "x" * 300,
                    "relevance_score": 0.1,
                }
                for i in range(8)
            ]
        }
    }
    prompt = build_incident_report_prompt(
        data, max_rag_entries=5, rag_content_chars=200
    )
    context = json.loads(prompt.split("INVESTIGATION CONTEXT:\n", 1)[1])
    assert context["rag_context"]["rag_available"] is False
    assert len(context["rag_context"]["retrieved_context"]) == 5
    assert all(
        len(item["content"]) == 200
        for item in context["rag_context"]["retrieved_context"]
    )


def test_ollama_embedding_success(monkeypatch):
    monkeypatch.setattr(
        ollama_provider.httpx,
        "post",
        lambda *args, **kwargs: FakeHttpxResponse(
            {"embedding": [0.25] * 768}
        ),
    )
    provider = ollama_provider.OllamaEmbeddingProvider()

    vector = provider.embed("SENTINEL")

    assert len(vector) == 768
    assert vector[0] == pytest.approx(0.25)
    assert provider.provider_name() == "ollama"


def test_ollama_embedding_dimension_mismatch(monkeypatch):
    monkeypatch.setattr(
        ollama_provider.httpx,
        "post",
        lambda *args, **kwargs: FakeHttpxResponse(
            {"embedding": [0.25] * 10}
        ),
    )

    with pytest.raises(EmbeddingProviderError):
        ollama_provider.OllamaEmbeddingProvider().embed("SENTINEL")


def test_ollama_embedding_connection_failure(monkeypatch):
    def fail(*args, **kwargs):
        raise ConnectionError("offline")

    monkeypatch.setattr(ollama_provider.httpx, "post", fail)

    with pytest.raises(EmbeddingProviderError):
        ollama_provider.OllamaEmbeddingProvider().embed("SENTINEL")


def test_ollama_generation_success(monkeypatch):
    calls = []

    def fake_post(*args, **kwargs):
        calls.append(kwargs)
        return FakeHttpxResponse({"response": json.dumps(VALID_REPORT)})

    monkeypatch.setattr(ollama_provider.httpx, "post", fake_post)
    monkeypatch.setenv("OLLAMA_NUM_CTX", "2048")
    monkeypatch.setenv("OLLAMA_NUM_PREDICT", "700")
    result = ollama_provider.OllamaGenerationProvider().generate_incident_report(
        {"threat_summary": {}}
    )

    payload = calls[0]["json"]
    assert payload["model"] == "llama3.2:1b"
    assert payload["format"] == BONA_REPORT_JSON_SCHEMA
    assert payload["options"] == {"num_ctx": 2048, "num_predict": 700}
    assert result["generated_by"] == "BONA"
    assert result["mock"] is False


def test_ollama_generation_invalid_json_falls_back(monkeypatch):
    monkeypatch.setattr(
        ollama_provider.httpx,
        "post",
        lambda *args, **kwargs: FakeHttpxResponse(
            {"response": "not-json"}
        ),
    )
    result = ollama_provider.OllamaGenerationProvider().generate_incident_report(
        {}
    )

    assert result["mock"] is True
    assert result["bona_error"] == "Ollama generation error — mock used"


def test_gemini_embedding_success(monkeypatch):
    fake_models = SimpleNamespace(
        embed_content=lambda **kwargs: SimpleNamespace(
            embeddings=[
                SimpleNamespace(values=[0.5] * 3072)
            ]
        )
    )
    monkeypatch.setattr(
        gemini_provider,
        "_gemini_client",
        lambda: SimpleNamespace(models=fake_models),
    )

    vector = gemini_provider.GeminiEmbeddingProvider().embed("SENTINEL")

    assert len(vector) == 3072
    assert vector[0] == pytest.approx(0.5)
    assert gemini_provider.GeminiEmbeddingProvider().provider_name() == "gemini"


def test_gemini_embedding_dimension_mismatch(monkeypatch):
    fake_models = SimpleNamespace(
        embed_content=lambda **kwargs: SimpleNamespace(
            embeddings=[SimpleNamespace(values=[0.5] * 10)]
        )
    )
    monkeypatch.setattr(
        gemini_provider,
        "_gemini_client",
        lambda: SimpleNamespace(models=fake_models),
    )

    with pytest.raises(EmbeddingProviderError):
        gemini_provider.GeminiEmbeddingProvider().embed("SENTINEL")


def test_gemini_embedding_api_failure(monkeypatch):
    class BrokenModels:
        def embed_content(self, **kwargs):
            raise RuntimeError("quota")

    monkeypatch.setattr(
        gemini_provider,
        "_gemini_client",
        lambda: SimpleNamespace(models=BrokenModels()),
    )

    with pytest.raises(EmbeddingProviderError):
        gemini_provider.GeminiEmbeddingProvider().embed("SENTINEL")


def test_gemini_generation_success(monkeypatch):
    fake_models = SimpleNamespace(
        generate_content=lambda **kwargs: SimpleNamespace(
            text=json.dumps(VALID_REPORT)
        )
    )
    monkeypatch.setattr(
        gemini_provider,
        "_gemini_client",
        lambda: SimpleNamespace(models=fake_models),
    )

    result = gemini_provider.GeminiGenerationProvider().generate_incident_report(
        {"threat_summary": {}}
    )

    assert result["generated_by"] == "BONA"
    assert result["mock"] is False


def test_gemini_generation_failure_falls_back(monkeypatch):
    class BrokenModels:
        def generate_content(self, **kwargs):
            raise RuntimeError("quota")

    monkeypatch.setattr(
        gemini_provider,
        "_gemini_client",
        lambda: SimpleNamespace(models=BrokenModels()),
    )

    result = gemini_provider.GeminiGenerationProvider().generate_incident_report(
        {}
    )

    assert result["mock"] is True
    assert result["bona_error"] == "Gemini API error — mock used"
    assert result["incident_summary"] == BONA_MOCK_INCIDENT_REPORT[
        "incident_summary"
    ]