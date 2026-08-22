"""Unit tests for the SENTINEL RAG service."""

from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from services import rag
from services.ai_providers.base import EmbeddingProviderError


class FakeEmbeddingProvider:
    def __init__(
        self,
        *,
        name: str = "ollama",
        dimension: int = 768,
        vector: list[float] | None = None,
        error: Exception | None = None,
    ):
        self._name = name
        self._dimension = dimension
        self._vector = vector if vector is not None else [0.1] * dimension
        self._error = error
        self.embed_calls: list[str] = []

    def embed(self, text: str) -> list[float]:
        self.embed_calls.append(text)
        if self._error:
            raise self._error
        return list(self._vector)

    def embedding_dim(self) -> int:
        return self._dimension

    def provider_name(self) -> str:
        return self._name


class FakeCollection:
    def __init__(self, count, response=None, error=None):
        self._count = count
        self.response = response or {
            "ids": [[]],
            "documents": [[]],
            "metadatas": [[]],
            "distances": [[]],
        }
        self.error = error
        self.query_calls = []

    def count(self):
        return self._count

    def query(self, **kwargs):
        self.query_calls.append(kwargs)
        if self.error:
            raise self.error
        return self.response


class FakeClient:
    def __init__(self, collections):
        self.collections = collections
        self.requested = []

    def get_collection(self, name):
        self.requested.append(name)
        if name not in self.collections:
            raise RuntimeError("missing")
        return self.collections[name]


def summary():
    return {
        "top_threats": [
            {
                "threat_signals": [
                    "Brute force authentication attempt",
                    "Port scanning detected",
                ],
                "anomaly_reasons": ["BRUTE_FORCE", "PORT_SCAN"],
                "event_type": "login failed",
            }
        ]
    }


def sa():
    return {
        "popia_flags": ["POPIA_SECTION_22"],
        "cybercrimes_flags": ["CYBERCRIMES_ACT_REPORTABLE"],
        "sa_patterns_matched": ["GOVPORTAL_CREDENTIAL_STUFFING"],
    }


def enable_fake_embedding(
    monkeypatch,
    provider: FakeEmbeddingProvider | None = None,
):
    provider = provider or FakeEmbeddingProvider()
    monkeypatch.setattr(rag, "get_embedding_provider", lambda: provider)
    monkeypatch.setenv(
        "SENTINEL_EMBEDDING_DIM",
        str(provider.embedding_dim()),
    )
    return provider


def test_none_provider_returns_empty_without_chroma(monkeypatch):
    monkeypatch.setattr(rag, "get_embedding_provider", lambda: None)

    def fail_if_called():
        raise AssertionError("ChromaDB must not be touched in none mode")

    monkeypatch.setattr(rag, "_create_chroma_client", fail_if_called)

    result = rag.retrieve_threat_context(summary(), sa())

    assert result["rag_available"] is False
    assert result["total_retrieved"] == 0
    assert result["collections_queried"] == []


def test_unreachable_returns_empty(monkeypatch):
    enable_fake_embedding(monkeypatch)
    monkeypatch.setattr(
        rag,
        "_create_chroma_client",
        lambda: (_ for _ in ()).throw(ConnectionError()),
    )
    result = rag.retrieve_threat_context(summary(), sa())

    assert result["rag_available"] is False
    assert result["total_retrieved"] == 0


def test_empty_collections(monkeypatch):
    provider = enable_fake_embedding(monkeypatch)
    collections = {name: FakeCollection(0) for name, _ in rag.COLLECTIONS}
    monkeypatch.setattr(
        rag,
        "_create_chroma_client",
        lambda: FakeClient(collections),
    )

    result = rag.retrieve_threat_context(summary(), sa())

    assert result["collections_queried"] == []
    assert all(not collection.query_calls for collection in collections.values())
    assert len(provider.embed_calls) == 1


def test_results_sorted_and_relevance(monkeypatch):
    provider = enable_fake_embedding(monkeypatch)
    c1 = FakeCollection(
        2,
        {
            "ids": [["T1", "T2"]],
            "documents": [["D1", "D2"]],
            "metadatas": [[{}, {}]],
            "distances": [[0.2, 0.6]],
        },
    )
    c2 = FakeCollection(
        1,
        {
            "ids": [["C1"]],
            "documents": [["C"]],
            "metadatas": [[{}]],
            "distances": [[0.1]],
        },
    )
    monkeypatch.setattr(
        rag,
        "_create_chroma_client",
        lambda: FakeClient(
            {
                "mitre_attack": c1,
                "sa_threat_intel": FakeCollection(0),
                "sa_compliance": c2,
            }
        ),
    )

    result = rag.retrieve_threat_context(summary(), sa())

    assert [item["id"] for item in result["retrieved_context"]] == [
        "C1",
        "T1",
        "T2",
    ]
    assert result["retrieved_context"][1]["relevance_score"] == pytest.approx(0.8)
    assert result["total_retrieved"] == 3
    assert provider.embed_calls == [result["query_used"]]


def test_query_contains_signals(monkeypatch):
    enable_fake_embedding(monkeypatch)
    monkeypatch.setattr(
        rag,
        "_create_chroma_client",
        lambda: FakeClient({}),
    )

    query = rag.retrieve_threat_context(summary(), sa())["query_used"]

    for value in [
        "Brute force authentication attempt",
        "BRUTE_FORCE",
        "login failed",
        "GOVPORTAL_CREDENTIAL_STUFFING",
        "POPIA_SECTION_22",
        "CYBERCRIMES_ACT_REPORTABLE",
    ]:
        assert value in query


def test_query_embedding_is_generated_once(monkeypatch):
    provider = enable_fake_embedding(monkeypatch)
    collections = {
        name: FakeCollection(
            1,
            {
                "ids": [[name]],
                "documents": [["D"]],
                "metadatas": [[{}]],
                "distances": [[0.5]],
            },
        )
        for name, _ in rag.COLLECTIONS
    }
    monkeypatch.setattr(
        rag,
        "_create_chroma_client",
        lambda: FakeClient(collections),
    )

    rag.retrieve_threat_context(summary(), sa())

    assert len(provider.embed_calls) == 1


def test_query_embeddings_used_not_query_texts(monkeypatch):
    provider = enable_fake_embedding(monkeypatch)
    collection = FakeCollection(
        1,
        {
            "ids": [["A"]],
            "documents": [["D"]],
            "metadatas": [[{}]],
            "distances": [[0.5]],
        },
    )
    monkeypatch.setattr(
        rag,
        "_create_chroma_client",
        lambda: FakeClient({"mitre_attack": collection}),
    )

    rag.retrieve_threat_context(summary(), sa())

    call = collection.query_calls[0]
    assert call["query_embeddings"] == [[0.1] * 768]
    assert "query_texts" not in call


def test_top_k_passed(monkeypatch):
    enable_fake_embedding(monkeypatch)
    collection = FakeCollection(
        9,
        {
            "ids": [["A"]],
            "documents": [["D"]],
            "metadatas": [[{}]],
            "distances": [[0.5]],
        },
    )
    monkeypatch.setattr(
        rag,
        "_create_chroma_client",
        lambda: FakeClient({"mitre_attack": collection}),
    )

    rag.retrieve_threat_context(summary(), sa(), 7)

    assert collection.query_calls[0]["n_results"] == 7


def test_top_k_reduced_to_collection_count(monkeypatch):
    enable_fake_embedding(monkeypatch)
    collection = FakeCollection(
        2,
        {
            "ids": [["A"]],
            "documents": [["D"]],
            "metadatas": [[{}]],
            "distances": [[0.5]],
        },
    )
    monkeypatch.setattr(
        rag,
        "_create_chroma_client",
        lambda: FakeClient({"mitre_attack": collection}),
    )

    rag.retrieve_threat_context(summary(), sa(), 5)

    assert collection.query_calls[0]["n_results"] == 2


@pytest.mark.parametrize("value", [0, 11])
def test_invalid_top_k(value):
    with pytest.raises(ValueError):
        rag.retrieve_threat_context({}, {}, value)


def test_partial_failure(monkeypatch):
    enable_fake_embedding(monkeypatch)
    bad = FakeCollection(1, error=RuntimeError())
    good = FakeCollection(
        1,
        {
            "ids": [["SA1"]],
            "documents": [["D"]],
            "metadatas": [[{}]],
            "distances": [[0.3]],
        },
    )
    monkeypatch.setattr(
        rag,
        "_create_chroma_client",
        lambda: FakeClient(
            {
                "mitre_attack": bad,
                "sa_threat_intel": good,
            }
        ),
    )

    result = rag.retrieve_threat_context(summary(), sa())

    assert result["rag_available"] is True
    assert result["collections_queried"] == ["sa_threat_intel"]


def test_embedding_provider_failure_returns_empty(monkeypatch):
    provider = FakeEmbeddingProvider(
        error=EmbeddingProviderError("offline")
    )
    enable_fake_embedding(monkeypatch, provider)

    result = rag.retrieve_threat_context(summary(), sa())

    assert result["rag_available"] is False
    assert result["collections_queried"] == []


def test_configured_dimension_mismatch_returns_empty(monkeypatch):
    provider = FakeEmbeddingProvider(dimension=768)
    monkeypatch.setattr(rag, "get_embedding_provider", lambda: provider)
    monkeypatch.setenv("SENTINEL_EMBEDDING_DIM", "3072")

    result = rag.retrieve_threat_context(summary(), sa())

    assert result["rag_available"] is False
    assert provider.embed_calls == []


def test_actual_dimension_mismatch_returns_empty(monkeypatch):
    provider = FakeEmbeddingProvider(
        dimension=768,
        vector=[0.1] * 767,
    )
    enable_fake_embedding(monkeypatch, provider)

    result = rag.retrieve_threat_context(summary(), sa())

    assert result["rag_available"] is False
    assert len(provider.embed_calls) == 1


def test_json_and_immutability(monkeypatch):
    enable_fake_embedding(monkeypatch)
    threat_summary = summary()
    sa_result = sa()
    original_summary = deepcopy(threat_summary)
    original_sa = deepcopy(sa_result)
    monkeypatch.setattr(
        rag,
        "_create_chroma_client",
        lambda: FakeClient({}),
    )

    json.dumps(rag.retrieve_threat_context(threat_summary, sa_result))

    assert threat_summary == original_summary
    assert sa_result == original_sa


def test_internal_port(monkeypatch):
    calls = []

    class Dummy:
        @staticmethod
        def HttpClient(**kwargs):
            calls.append(kwargs)
            return object()

    monkeypatch.setattr(rag, "chromadb", Dummy)
    monkeypatch.delenv("CHROMA_HOST", raising=False)
    monkeypatch.delenv("CHROMA_PORT", raising=False)

    rag._create_chroma_client()

    assert calls == [{"host": "chromadb", "port": 8000}]