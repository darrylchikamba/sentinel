"""Build SENTINEL's provider-specific knowledge base inside Docker.

Run only inside Docker:

    docker compose exec api python knowledge_base/setup.py

The configured embedding provider is used for both ingestion and RAG. Changing
embedding provider requires rebuilding the ChromaDB collections because vectors
from different embedding models are not interchangeable.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Sequence

# When this file is executed directly as ``python knowledge_base/setup.py``,
# Python places /app/knowledge_base on sys.path. Add the server root so the
# shared services package remains importable without changing the run command.
SERVER_DIR = Path(__file__).resolve().parent.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import chromadb
import httpx
from dotenv import load_dotenv

from services.ai_providers.base import (
    BaseEmbeddingProvider,
    EmbeddingProviderError,
)
from services.ai_providers.gemini_provider import (
    GEMINI_EMBEDDING_DIM,
    GEMINI_EMBEDDING_MODEL,
)
from services.ai_providers.ollama_provider import (
    OLLAMA_EMBEDDING_DIM,
    OLLAMA_EMBEDDING_MODEL,
)
from services.ai_providers.provider_factory import get_embedding_provider


KNOWLEDGE_BASE_DIR = Path(__file__).resolve().parent
SOURCES_DIR = KNOWLEDGE_BASE_DIR / "sources"
ENV_FILE = SERVER_DIR / ".env"

LOCAL_MITRE_BUNDLE = SOURCES_DIR / "enterprise-attack.json"

MITRE_TAXII_BASE_URL = "https://attack-taxii.mitre.org"
MITRE_TAXII_DISCOVERY_URL = f"{MITRE_TAXII_BASE_URL}/taxii2/"
MITRE_TAXII_ACCEPT = "application/taxii+json;version=2.1"
MITRE_TAXII_PAGE_LIMIT = 200

MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
MITRE_ATTACK_FALLBACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
MITRE_FETCH_ATTEMPTS = 3
MITRE_RETRY_STATUS_CODES = {429, 500, 502, 503, 504}
BATCH_SIZE = 50
EXPECTED_CHROMA_CLIENT_VERSION = "0.5.10"
CONNECTIVITY_TEST_TEXT = "SENTINEL connectivity test"

COLLECTION_NAMES = (
    "mitre_attack",
    "sa_threat_intel",
    "sa_compliance",
)

# Verified during Phase 11 compatibility testing:
# - Ollama nomic-embed-text -> 768 dimensions
# - Gemini gemini-embedding-2 -> 3072 dimensions
VERIFIED_EMBEDDING_DIMS = {
    "ollama": OLLAMA_EMBEDDING_DIM,
    "gemini": GEMINI_EMBEDDING_DIM,
}

EMBEDDING_MODELS = {
    "ollama": OLLAMA_EMBEDDING_MODEL,
    "gemini": GEMINI_EMBEDDING_MODEL,
}


class IngestionError(RuntimeError):
    """Raised when a knowledge-base ingestion stage cannot complete."""


def load_configuration() -> tuple[str, int, int]:
    """Load Docker Chroma and embedding-dimension configuration."""
    load_dotenv(ENV_FILE)

    host = os.getenv("CHROMA_HOST", "chromadb").strip() or "chromadb"

    try:
        port = int(os.getenv("CHROMA_PORT", "8000"))
    except ValueError as exc:
        raise IngestionError("CHROMA_PORT must be a valid integer.") from exc

    raw_dim = os.getenv("SENTINEL_EMBEDDING_DIM", "").strip()
    if not raw_dim:
        raise IngestionError(
            "SENTINEL_EMBEDDING_DIM is required for knowledge-base ingestion."
        )

    try:
        configured_dim = int(raw_dim)
    except ValueError as exc:
        raise IngestionError(
            "SENTINEL_EMBEDDING_DIM must be a valid integer."
        ) from exc

    return host, port, configured_dim


def normalise_text(value: str) -> str:
    """Collapse repeated whitespace in source descriptions."""
    return " ".join(value.replace("\u00a0", " ").split())


def batched(
    items: Sequence[dict[str, Any]],
    size: int,
) -> Iterable[Sequence[dict[str, Any]]]:
    """Yield deterministic slices of a sequence."""
    for index in range(0, len(items), size):
        yield items[index : index + size]


def embedding_model_name(provider: BaseEmbeddingProvider) -> str:
    """Return the fixed model identity associated with the provider."""
    name = provider.provider_name()
    model = EMBEDDING_MODELS.get(name)
    if not model:
        raise IngestionError(
            f"No approved embedding model is registered for provider '{name}'."
        )
    return model


def validate_embedding_configuration(
    provider: BaseEmbeddingProvider,
    configured_dim: int,
) -> None:
    """Require provider, installation and verified dimensionality to agree."""
    provider_name = provider.provider_name()
    provider_dim = provider.embedding_dim()
    verified_dim = VERIFIED_EMBEDDING_DIMS.get(provider_name)

    if verified_dim is None:
        raise IngestionError(
            f"Embedding provider '{provider_name}' has no verified dimension."
        )

    if provider_dim != verified_dim:
        raise IngestionError(
            "Embedding provider contract mismatch: "
            f"provider '{provider_name}' reports {provider_dim} dimensions "
            f"but SENTINEL verifies {verified_dim}."
        )

    if configured_dim != provider_dim:
        raise IngestionError(
            "Embedding configuration mismatch: "
            f"SENTINEL_EMBEDDING_DIM={configured_dim}, "
            f"provider '{provider_name}' requires {provider_dim}. "
            "Update the environment and re-run ingestion."
        )


def verify_chroma_client_version() -> str:
    """Report thin-client version and warn if it differs from the server pin."""
    try:
        version = importlib.metadata.version("chromadb-client")
    except importlib.metadata.PackageNotFoundError as exc:
        raise IngestionError(
            "chromadb-client is not installed in the API container."
        ) from exc

    if version != EXPECTED_CHROMA_CLIENT_VERSION:
        print(
            "WARNING: chromadb-client version mismatch: "
            f"expected {EXPECTED_CHROMA_CLIENT_VERSION}, found {version}. "
            "Client and server should remain aligned.",
            file=sys.stderr,
        )

    return version


def create_chroma_client(host: str, port: int) -> Any:
    """Connect to the dedicated ChromaDB service over the Docker network."""
    try:
        client = chromadb.HttpClient(host=host, port=port)
        client.heartbeat()
        return client
    except Exception as exc:
        raise IngestionError(
            f"Unable to reach ChromaDB at {host}:{port}: {type(exc).__name__}"
        ) from exc


def verify_test_embedding(
    provider: BaseEmbeddingProvider,
    configured_dim: int,
) -> None:
    """Make one real provider call before any source download or writes."""
    try:
        vector = provider.embed(CONNECTIVITY_TEST_TEXT)
    except EmbeddingProviderError as exc:
        raise IngestionError(
            f"Embedding provider preflight failed: {exc}"
        ) from exc
    except Exception as exc:
        raise IngestionError(
            "Unexpected embedding-provider preflight failure: "
            f"{type(exc).__name__}"
        ) from exc

    actual_dim = len(vector)
    if actual_dim != configured_dim:
        raise IngestionError(
            "Embedding preflight dimension mismatch: "
            f"configured {configured_dim}, returned {actual_dim}."
        )


def collection_metadata(
    provider: BaseEmbeddingProvider,
    configured_dim: int,
) -> dict[str, Any]:
    """Build metadata that binds a collection to one embedding vector space."""
    return {
        "sentinel_embedding_provider": provider.provider_name(),
        "sentinel_embedding_model": embedding_model_name(provider),
        "sentinel_embedding_dim": configured_dim,
    }


def prepare_collection(
    client: Any,
    name: str,
    provider: BaseEmbeddingProvider,
    configured_dim: int,
) -> Any:
    """Create or validate a collection without silently mixing embeddings."""
    expected = collection_metadata(provider, configured_dim)
    collection = client.get_or_create_collection(
        name=name,
        metadata=expected,
    )
    count = int(collection.count())
    current = collection.metadata or {}

    if count > 0:
        current_provider = current.get("sentinel_embedding_provider")
        current_model = current.get("sentinel_embedding_model")
        current_dim = current.get("sentinel_embedding_dim")

        if (
            current_provider != expected["sentinel_embedding_provider"]
            or current_model != expected["sentinel_embedding_model"]
            or int(current_dim or 0) != configured_dim
        ):
            raise IngestionError(
                f"Collection '{name}' already contains {count} documents "
                "from a different or undocumented embedding configuration. "
                "Do not mix embedding vector spaces. Reset the existing "
                "knowledge-base collections explicitly, then re-run ingestion."
            )
        return collection

    # Existing empty collections may pre-date provider metadata. It is safe to
    # bind them now because no vectors need to be preserved.
    if current != expected:
        try:
            collection.modify(metadata=expected)
        except Exception as exc:
            raise IngestionError(
                f"Unable to bind embedding metadata to empty collection '{name}'."
            ) from exc

    return collection


def embed_texts(
    provider: BaseEmbeddingProvider,
    texts: Sequence[str],
) -> list[list[float]]:
    """Generate one validated embedding per document via the shared provider."""
    embeddings: list[list[float]] = []
    for text in texts:
        try:
            embeddings.append(provider.embed(text))
        except EmbeddingProviderError as exc:
            raise IngestionError(
                f"Embedding generation failed during ingestion: {exc}"
            ) from exc

    return embeddings


def _http_get_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], httpx.Headers]:
    """GET JSON with bounded retry for transient upstream failures."""
    last_error: Exception | None = None

    for attempt in range(1, MITRE_FETCH_ATTEMPTS + 1):
        try:
            with httpx.Client(timeout=60.0, follow_redirects=True) as client:
                response = client.get(
                    url,
                    headers=headers,
                    params=params,
                )

                if (
                    response.status_code in MITRE_RETRY_STATUS_CODES
                    and attempt < MITRE_FETCH_ATTEMPTS
                ):
                    delay = 2 ** (attempt - 1)
                    print(
                        "MITRE ATT&CK fetch returned "
                        f"HTTP {response.status_code}; retrying in {delay}s "
                        f"({attempt}/{MITRE_FETCH_ATTEMPTS})."
                    )
                    time.sleep(delay)
                    continue

                response.raise_for_status()
                payload = response.json()

            if not isinstance(payload, dict):
                raise IngestionError(
                    f"MITRE ATT&CK returned an unexpected payload from {url}."
                )
            return payload, response.headers

        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < MITRE_FETCH_ATTEMPTS:
                delay = 2 ** (attempt - 1)
                print(
                    "MITRE ATT&CK fetch failed; retrying in "
                    f"{delay}s ({attempt}/{MITRE_FETCH_ATTEMPTS}) | "
                    f"error={type(exc).__name__}"
                )
                time.sleep(delay)
                continue

    raise IngestionError(
        f"Unable to fetch MITRE ATT&CK data from {url}: {last_error}"
    )


def _load_local_mitre_bundle() -> dict[str, Any] | None:
    """Use a local official Enterprise ATT&CK bundle when one is available."""
    if not LOCAL_MITRE_BUNDLE.exists():
        return None

    try:
        with LOCAL_MITRE_BUNDLE.open("r", encoding="utf-8") as source_file:
            payload = json.load(source_file)
    except (OSError, json.JSONDecodeError) as exc:
        raise IngestionError(
            f"Local MITRE ATT&CK bundle is unreadable: {LOCAL_MITRE_BUNDLE}"
        ) from exc

    if not isinstance(payload, dict) or not isinstance(
        payload.get("objects"),
        list,
    ):
        raise IngestionError(
            "Local MITRE ATT&CK bundle does not contain an objects array."
        )

    print(f"MITRE ATT&CK source: local bundle {LOCAL_MITRE_BUNDLE}.")
    return payload


def _latest_taxii_attack_root(api_roots: list[object]) -> str:
    """Choose the highest non-beta versioned ATT&CK TAXII API root."""
    candidates: list[tuple[tuple[int, int], str]] = []

    for raw_root in api_roots:
        if not isinstance(raw_root, str) or "beta" in raw_root.lower():
            continue

        match = re.fullmatch(r"/api/v21/attack-(\d+)\.(\d+)", raw_root)
        if match:
            candidates.append(
                ((int(match.group(1)), int(match.group(2))), raw_root)
            )

    if not candidates:
        raise IngestionError(
            "MITRE TAXII discovery returned no versioned ATT&CK API roots."
        )

    return max(candidates, key=lambda item: item[0])[1]


def _fetch_mitre_from_taxii() -> dict[str, Any]:
    """Retrieve Enterprise ATT&CK attack-patterns through official TAXII 2.1."""
    headers = {"Accept": MITRE_TAXII_ACCEPT}

    discovery, _ = _http_get_json(
        MITRE_TAXII_DISCOVERY_URL,
        headers=headers,
    )
    api_roots = discovery.get("api_roots", [])
    if not isinstance(api_roots, list):
        raise IngestionError(
            "MITRE TAXII discovery did not return an api_roots array."
        )

    api_root = _latest_taxii_attack_root(api_roots)
    collections_url = f"{MITRE_TAXII_BASE_URL}{api_root}/collections/"
    collections_payload, _ = _http_get_json(
        collections_url,
        headers=headers,
    )

    collections = collections_payload.get("collections", [])
    if not isinstance(collections, list):
        raise IngestionError(
            "MITRE TAXII collections response was malformed."
        )

    enterprise = next(
        (
            item
            for item in collections
            if isinstance(item, dict)
            and item.get("title") == "Enterprise ATT&CK"
            and item.get("can_read") is True
        ),
        None,
    )
    if enterprise is None or not isinstance(enterprise.get("id"), str):
        raise IngestionError(
            "MITRE TAXII Enterprise ATT&CK collection was not found."
        )

    collection_id = enterprise["id"]
    objects_url = (
        f"{MITRE_TAXII_BASE_URL}{api_root}/collections/"
        f"{collection_id}/objects/"
    )

    params: dict[str, Any] = {
        "limit": MITRE_TAXII_PAGE_LIMIT,
        "match[type]": "attack-pattern",
    }
    all_objects: list[dict[str, Any]] = []
    seen_continuations: set[str] = set()
    page_number = 0

    while True:
        page_number += 1
        envelope, response_headers = _http_get_json(
            objects_url,
            headers=headers,
            params=params,
        )

        page_objects = envelope.get("objects", [])
        if not isinstance(page_objects, list):
            raise IngestionError(
                "MITRE TAXII envelope contained an invalid objects field."
            )

        all_objects.extend(
            item for item in page_objects if isinstance(item, dict)
        )
        print(
            "MITRE TAXII progress: "
            f"page {page_number}, {len(all_objects)} attack-pattern objects received."
        )

        if envelope.get("more") is not True:
            break

        next_token = envelope.get("next")
        if isinstance(next_token, str) and next_token:
            continuation_key = f"next:{next_token}"
            if continuation_key in seen_continuations:
                raise IngestionError(
                    "MITRE TAXII returned a repeated pagination token."
                )
            seen_continuations.add(continuation_key)
            params["next"] = next_token
            params.pop("added_after", None)
            continue

        added_after = response_headers.get("X-TAXII-Date-Added-Last")
        if not added_after:
            raise IngestionError(
                "MITRE TAXII indicated more data but supplied neither a next "
                "token nor X-TAXII-Date-Added-Last."
            )

        continuation_key = f"added_after:{added_after}"
        if continuation_key in seen_continuations:
            raise IngestionError(
                "MITRE TAXII returned a repeated pagination timestamp."
            )
        seen_continuations.add(continuation_key)
        params["added_after"] = added_after
        params.pop("next", None)

    print(
        "MITRE ATT&CK source: official TAXII 2.1 "
        f"({api_root}, Enterprise ATT&CK)."
    )
    return {"objects": all_objects}


def _fetch_mitre_bundle(url: str) -> dict[str, Any]:
    """Fetch one complete MITRE bundle from an official GitHub source."""
    payload, _ = _http_get_json(url)
    return payload


def _deduplicate_attack_patterns(
    techniques: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep the newest STIX version of each attack-pattern object."""
    newest: dict[str, dict[str, Any]] = {}

    for technique in techniques:
        stix_id = str(technique.get("id", "")).strip()
        if not stix_id:
            continue

        existing = newest.get(stix_id)
        if existing is None:
            newest[stix_id] = technique
            continue

        candidate_modified = str(technique.get("modified", ""))
        existing_modified = str(existing.get("modified", ""))
        if candidate_modified > existing_modified:
            newest[stix_id] = technique

    return list(newest.values())


def fetch_mitre_attack_patterns() -> list[dict[str, Any]]:
    """Load active Enterprise ATT&CK techniques from resilient official sources."""
    payload = _load_local_mitre_bundle()

    if payload is None:
        try:
            payload = _fetch_mitre_from_taxii()
        except IngestionError as taxii_error:
            print(
                "MITRE TAXII source unavailable; trying official GitHub sources.",
                file=sys.stderr,
            )
            try:
                payload = _fetch_mitre_bundle(MITRE_ATTACK_URL)
                print("MITRE ATT&CK source: primary CTI repository.")
            except IngestionError as primary_error:
                print(
                    "Primary MITRE CTI source unavailable after retries; "
                    "trying official attack-stix-data fallback.",
                    file=sys.stderr,
                )
                try:
                    payload = _fetch_mitre_bundle(
                        MITRE_ATTACK_FALLBACK_URL
                    )
                    print(
                        "MITRE ATT&CK source: official attack-stix-data fallback."
                    )
                except IngestionError as fallback_error:
                    raise IngestionError(
                        "All official MITRE ATT&CK sources were unavailable. "
                        f"TAXII error: {taxii_error} "
                        f"Primary GitHub error: {primary_error} "
                        f"Fallback GitHub error: {fallback_error}"
                    ) from fallback_error

    objects = payload.get("objects")
    if not isinstance(objects, list):
        raise IngestionError(
            "MITRE ATT&CK payload does not contain an objects array."
        )

    techniques = [
        item
        for item in objects
        if isinstance(item, dict)
        and item.get("type") == "attack-pattern"
        and not item.get("revoked", False)
        and not item.get("x_mitre_deprecated", False)
    ]
    techniques = _deduplicate_attack_patterns(techniques)
    techniques.sort(
        key=lambda item: extract_technique_id(item) or item.get("name", "")
    )
    return techniques


def extract_technique_id(technique: dict[str, Any]) -> str | None:
    """Return the public ATT&CK technique ID from MITRE external references."""
    for reference in technique.get("external_references", []):
        if (
            reference.get("source_name") == "mitre-attack"
            and isinstance(reference.get("external_id"), str)
        ):
            return reference["external_id"]
    return None


def extract_tactics(technique: dict[str, Any]) -> list[str]:
    """Return sorted tactic names from STIX kill-chain phases."""
    tactics = {
        phase.get("phase_name", "").strip()
        for phase in technique.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
        and phase.get("phase_name")
    }
    return sorted(tactics)


def build_mitre_record(
    technique: dict[str, Any],
) -> dict[str, Any] | None:
    """Transform one MITRE STIX technique into a Chroma-ready record."""
    technique_id = extract_technique_id(technique)
    name = normalise_text(str(technique.get("name", "")))
    if not technique_id or not name:
        return None

    description = normalise_text(str(technique.get("description", "")))
    platforms = sorted(
        {
            normalise_text(str(platform))
            for platform in technique.get("x_mitre_platforms", [])
            if platform
        }
    )
    tactics = extract_tactics(technique)

    text = (
        f"Technique: {technique_id} - {name}. "
        f"{description}. "
        f"Platforms: {', '.join(platforms) or 'Not specified'}. "
        f"Tactics: {', '.join(tactics) or 'Not specified'}"
    )

    return {
        "id": technique_id,
        "document": text,
        "metadata": {
            "technique_id": technique_id,
            "name": name,
            "tactics": ", ".join(tactics),
            "platforms": ", ".join(platforms),
        },
    }


def upsert_mitre(
    collection: Any,
    provider: BaseEmbeddingProvider,
) -> int:
    """Embed and upsert MITRE ATT&CK techniques in groups of 50."""
    techniques = fetch_mitre_attack_patterns()
    records = [
        record
        for technique in techniques
        if (record := build_mitre_record(technique)) is not None
    ]

    total = len(records)
    for batch_number, batch in enumerate(
        batched(records, BATCH_SIZE),
        start=1,
    ):
        documents = [item["document"] for item in batch]
        embeddings = embed_texts(provider, documents)

        collection.upsert(
            ids=[item["id"] for item in batch],
            documents=documents,
            embeddings=embeddings,
            metadatas=[item["metadata"] for item in batch],
        )

        processed = min(batch_number * BATCH_SIZE, total)
        print(f"MITRE ATT&CK progress: {processed}/{total} techniques")

    return total


def load_json_array(path: Path) -> list[dict[str, Any]]:
    """Load a JSON source file and require an array of objects."""
    try:
        with path.open("r", encoding="utf-8") as source_file:
            data = json.load(source_file)
    except FileNotFoundError as exc:
        raise IngestionError(
            f"Required source file was not found: {path}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise IngestionError(
            f"Source file contains invalid JSON: {path}"
        ) from exc

    if not isinstance(data, list) or not all(
        isinstance(item, dict) for item in data
    ):
        raise IngestionError(
            f"Source file must contain a JSON array of objects: {path}"
        )

    return data


def build_pattern_text(pattern: dict[str, Any]) -> str:
    """Build retrieval text from every threat-pattern field."""
    return (
        f"South African threat pattern: {pattern['name']} ({pattern['id']}). "
        f"Description: {pattern['description']} "
        f"Indicators: {'; '.join(pattern['indicators'])}. "
        f"Affected sectors: {', '.join(pattern['sector'])}. "
        f"MITRE ATT&CK techniques: "
        f"{', '.join(pattern['mitre_technique_ids'])}. "
        f"Source: {pattern['source']}."
    )


def build_compliance_text(rule: dict[str, Any]) -> str:
    """Build retrieval text from every compliance-rule field."""
    return (
        f"Compliance rule: {rule['legislation']}, "
        f"{rule['section']} - {rule['title']}. "
        f"Summary: {rule['summary']} "
        f"Trigger conditions: {'; '.join(rule['trigger_conditions'])}. "
        f"Required action: {rule['required_action']} "
        f"Reporting body: {rule['reporting_body']}. "
        f"Deadline: {rule['deadline']}."
    )


def upsert_sa_patterns(
    collection: Any,
    provider: BaseEmbeddingProvider,
) -> int:
    """Embed and upsert the SENTINEL South African threat library."""
    patterns = load_json_array(SOURCES_DIR / "sa_patterns.json")
    documents = [build_pattern_text(pattern) for pattern in patterns]
    embeddings = embed_texts(provider, documents)

    collection.upsert(
        ids=[pattern["id"] for pattern in patterns],
        documents=documents,
        embeddings=embeddings,
        metadatas=[
            {
                "pattern_id": pattern["id"],
                "name": pattern["name"],
                "sectors": ", ".join(pattern["sector"]),
                "mitre_technique_ids": ", ".join(
                    pattern["mitre_technique_ids"]
                ),
                "source": pattern["source"],
            }
            for pattern in patterns
        ],
    )
    return len(patterns)


def upsert_sa_compliance(
    collection: Any,
    provider: BaseEmbeddingProvider,
) -> int:
    """Embed and upsert the SENTINEL South African compliance library."""
    rules = load_json_array(SOURCES_DIR / "sa_compliance.json")
    documents = [build_compliance_text(rule) for rule in rules]
    embeddings = embed_texts(provider, documents)

    collection.upsert(
        ids=[rule["id"] for rule in rules],
        documents=documents,
        embeddings=embeddings,
        metadatas=[
            {
                "compliance_id": rule["id"],
                "legislation": rule["legislation"],
                "section": rule["section"],
                "reporting_body": rule["reporting_body"],
                "deadline": rule["deadline"],
            }
            for rule in rules
        ],
    )
    return len(rules)


def run_ingestion() -> int:
    """Run provider-aware knowledge-base ingestion after compatibility checks."""
    started_at = time.monotonic()

    try:
        load_dotenv(ENV_FILE)
        host, port, configured_dim = load_configuration()

        provider = get_embedding_provider()
        if provider is None:
            raise IngestionError(
                "AI_EMBEDDING_PROVIDER is 'none'. Configure 'ollama' or "
                "'gemini' before running knowledge-base ingestion."
            )

        validate_embedding_configuration(provider, configured_dim)
        client_version = verify_chroma_client_version()
        client = create_chroma_client(host, port)

        # Fail before downloading MITRE or writing vectors if the selected
        # provider cannot produce the exact vector contract for this install.
        verify_test_embedding(provider, configured_dim)

        print("SENTINEL knowledge-base preflight passed.")
        print(f"- embedding provider: {provider.provider_name()}")
        print(f"- embedding model: {embedding_model_name(provider)}")
        print(f"- configured dimension: {configured_dim}")
        print(f"- verified vector dimension: {provider.embedding_dim()}")
        print(f"- chromadb-client: {client_version}")
        print(f"- ChromaDB endpoint: {host}:{port}")

        collections = {
            name: prepare_collection(
                client,
                name,
                provider,
                configured_dim,
            )
            for name in COLLECTION_NAMES
        }

        print("Starting SENTINEL knowledge-base ingestion.")
        print(
            "MITRE ATT&CK techniques are embedded individually and "
            "upserted in groups of 50."
        )

        mitre_count = upsert_mitre(
            collections["mitre_attack"],
            provider,
        )
        threat_count = upsert_sa_patterns(
            collections["sa_threat_intel"],
            provider,
        )
        compliance_count = upsert_sa_compliance(
            collections["sa_compliance"],
            provider,
        )

        elapsed_seconds = time.monotonic() - started_at
        print("\nIngestion summary")
        print(
            "- mitre_attack: "
            f"{collections['mitre_attack'].count()} documents "
            f"({mitre_count} processed)"
        )
        print(
            "- sa_threat_intel: "
            f"{collections['sa_threat_intel'].count()} documents "
            f"({threat_count} processed)"
        )
        print(
            "- sa_compliance: "
            f"{collections['sa_compliance'].count()} documents "
            f"({compliance_count} processed)"
        )
        print(f"- total runtime: {elapsed_seconds:.1f} seconds")
        print(
            "SENTINEL knowledge-base ingestion completed successfully."
        )
        return 0

    except IngestionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(
            f"ERROR: Unexpected ingestion failure: {exc}",
            file=sys.stderr,
        )
        return 1


def main() -> int:
    """CLI wrapper for the shared knowledge-base ingestion routine."""
    return run_ingestion()


if __name__ == "__main__":
    raise SystemExit(main())