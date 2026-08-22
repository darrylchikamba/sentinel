"""Shared BONA persona, prompt construction and response validation."""

from __future__ import annotations

from copy import deepcopy
import json
from typing import Any


BONA_PERSONA = """
You are BONA, SENTINEL's intelligence layer.

Produce formal SOC-style incident reports in UK English.
Write in the third person and past tense using precise technical language.
Every claim must be grounded in a detected signal, a MITRE ATT&CK technique,
retrieved threat intelligence, or a South African compliance rule supplied in
the investigation context.
Do not speculate beyond the supplied evidence.
Do not name a threat actor unless the supplied evidence explicitly matches
SABRIC-published intelligence.
When referring to MITRE ATT&CK techniques, include their technique IDs.
Confidence must be exactly High, Medium, or Low.
""".strip()

_REQUIRED_KEYS = {
    "incident_summary",
    "mitre_techniques",
    "confidence_level",
    "incident_next_steps",
    "popia_flags",
    "cybercrimes_flags",
    "sa_patterns_matched",
    "rag_sources_used",
}
_LIST_FIELDS = {
    "mitre_techniques",
    "incident_next_steps",
    "popia_flags",
    "cybercrimes_flags",
    "sa_patterns_matched",
    "rag_sources_used",
}
_CONFIDENCE_LEVELS = {"High", "Medium", "Low"}

# Ollama accepts a JSON Schema object in its ``format`` field. This gives
# smaller local models a hard output contract instead of prompt-only guidance.
BONA_REPORT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "incident_summary": {"type": "string"},
        "mitre_techniques": {"type": "array", "items": {"type": "string"}},
        "confidence_level": {"type": "string", "enum": ["High", "Medium", "Low"]},
        "incident_next_steps": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 4,
            "maxItems": 4,
        },
        "popia_flags": {"type": "array", "items": {"type": "string"}},
        "cybercrimes_flags": {"type": "array", "items": {"type": "string"}},
        "sa_patterns_matched": {"type": "array", "items": {"type": "string"}},
        "rag_sources_used": {"type": "array", "items": {"type": "string"}},
        "generated_by": {"type": "string"},
        "mock": {"type": "boolean"},
    },
    "required": [
        "incident_summary", "mitre_techniques", "confidence_level",
        "incident_next_steps", "popia_flags", "cybercrimes_flags",
        "sa_patterns_matched", "rag_sources_used", "generated_by", "mock",
    ],
    "additionalProperties": False,
}


def build_incident_report_prompt(
    investigation_data: dict[str, Any],
    *,
    max_rag_entries: int | None = None,
    rag_content_chars: int | None = None,
) -> str:
    """Build one provider-neutral prompt with optional provider context limits."""
    context = {
        "threat_summary": investigation_data.get("threat_summary", {}),
        "graph_summary": investigation_data.get("graph_summary", {}),
        "sa_result": investigation_data.get("sa_result", {}),
        "rag_context": _rag_context_for_prompt(
            investigation_data.get("rag_context", {}),
            max_entries=max_rag_entries,
            content_chars=rag_content_chars,
        ),
    }
    schema = {
        "incident_summary": "string; exactly 2 formal SOC narrative paragraphs",
        "mitre_techniques": ["T####.### (Technique name)"],
        "confidence_level": "High | Medium | Low",
        "incident_next_steps": ["exactly four formal imperative actions"],
        "popia_flags": ["string"],
        "cybercrimes_flags": ["string"],
        "sa_patterns_matched": ["string"],
        "rag_sources_used": ["string"],
        "generated_by": "BONA",
        "mock": False,
    }
    return (
        f"{BONA_PERSONA}\n\n"
        "OUTPUT REQUIREMENTS:\n"
        "Respond with raw JSON only. Do not use markdown fences, a preamble, "
        "or any explanation outside the JSON.\n"
        "Use real MITRE ATT&CK technique IDs from the supplied evidence; "
        "never substitute placeholder labels such as 'Technique'.\n"
        "The incident_summary must contain exactly two concise formal "
        "paragraphs separated by a blank line.\n"
        "rag_sources_used must name only sources actually present in the "
        "retrieved context.\n"
        "Return exactly this structure:\n"
        f"{json.dumps(schema, ensure_ascii=False, indent=2)}\n\n"
        "INVESTIGATION CONTEXT:\n"
        f"{json.dumps(context, ensure_ascii=False, default=str, indent=2)}"
    )


def strip_json_fences(raw: str) -> str:
    """Remove only a simple accidental Markdown JSON fence."""
    text = raw.strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def parse_and_validate_report(raw: str) -> dict[str, Any]:
    """Parse a BONA response and enforce the provider-independent contract."""
    parsed = json.loads(strip_json_fences(raw))
    if not isinstance(parsed, dict):
        raise ValueError("BONA response must be a JSON object")

    missing = sorted(_REQUIRED_KEYS - parsed.keys())
    if missing:
        raise ValueError(
            f"BONA response missing required keys: {', '.join(missing)}"
        )

    if not isinstance(parsed["incident_summary"], str):
        raise ValueError("incident_summary must be a string")

    for field in _LIST_FIELDS:
        if not isinstance(parsed[field], list):
            raise ValueError(f"{field} must be a list")

    if parsed["confidence_level"] not in _CONFIDENCE_LEVELS:
        raise ValueError("confidence_level must be High, Medium, or Low")

    if len(parsed["incident_next_steps"]) != 4:
        raise ValueError("incident_next_steps must contain exactly four items")

    parsed["generated_by"] = "BONA"
    parsed["mock"] = False
    return parsed


def mock_fallback(
    mock_report: dict[str, Any],
    error_message: str,
) -> dict[str, Any]:
    """Return an isolated mock report annotated with the provider failure."""
    fallback = deepcopy(mock_report)
    fallback["bona_error"] = error_message
    return fallback


def _rag_context_for_prompt(
    value: object,
    *,
    max_entries: int | None = None,
    content_chars: int | None = None,
) -> list[dict[str, Any]]:
    """Keep only retrieval fields BONA needs, with optional local-model limits."""
    if not isinstance(value, dict):
        return []
    entries = value.get("retrieved_context", [])
    if not isinstance(entries, list):
        return []
    if max_entries is not None:
        entries = entries[:max_entries]

    cleaned: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        content = str(entry.get("content", ""))
        if content_chars is not None:
            content = content[:content_chars]
        cleaned.append(
            {
                "source": str(entry.get("source", "")),
                "id": str(entry.get("id", "")),
                "content": content,
                "relevance_score": entry.get("relevance_score", 0.0),
            }
        )
    return cleaned