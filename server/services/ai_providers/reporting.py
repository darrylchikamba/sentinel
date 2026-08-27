"""Shared BONA persona, prompt construction and response validation."""

from __future__ import annotations

from copy import deepcopy
import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

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
    "incident_summary", "mitre_techniques", "confidence_level",
    "incident_next_steps", "popia_flags", "cybercrimes_flags",
    "sa_patterns_matched", "rag_sources_used",
}
_LIST_FIELDS = {
    "mitre_techniques", "incident_next_steps", "popia_flags",
    "cybercrimes_flags", "sa_patterns_matched", "rag_sources_used",
}
_CONFIDENCE_LEVELS = {"High", "Medium", "Low"}
_MITRE_TECHNIQUE_PREFIX = re.compile(
    r"^T\d{4}(?:\.\d{3})?(?=\s|\(|$)"
)
_NEXT_STEP_PAD_VALUE = "No further action identified."

BONA_REPORT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "incident_summary": {"type": "string"},
        "mitre_techniques": {"type": "array", "items": {"type": "string"}},
        "confidence_level": {"type": "string", "enum": ["High", "Medium", "Low"]},
        "incident_next_steps": {
            "type": "array", "items": {"type": "string"},
            "minItems": 4, "maxItems": 4,
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
        "If rag_context.rag_available is false, set rag_sources_used to an empty list.\n"
        "Only cite intelligence sources that appear in the supplied "
        "rag_context.retrieved_context.\n"
        "Only include MITRE technique IDs in the format T####.### that are "
        "directly supported by the supplied evidence.\n"
        "Do not invent attack techniques, threat actor names, or intelligence "
        "sources not present in the supplied context.\n"
        "The incident_summary must contain exactly two concise formal "
        "paragraphs separated by a blank line.\n"
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


def parse_and_validate_report(
    raw: str,
    *,
    rag_context: object | None = None,
) -> dict[str, Any]:
    """Parse and deterministically ground a provider-independent BONA report."""
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

    _clean_mitre_techniques(parsed)
    _clean_rag_provenance(parsed, rag_context)
    _enforce_next_steps(parsed)

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


def _clean_mitre_techniques(report: dict[str, Any]) -> None:
    """Keep valid MITRE ID-prefixed entries without changing their text shape."""
    techniques = report["mitre_techniques"]
    cleaned = [
        entry for entry in techniques
        if isinstance(entry, str)
        and _MITRE_TECHNIQUE_PREFIX.match(entry.strip())
    ]
    removed = len(techniques) - len(cleaned)
    report["mitre_techniques"] = cleaned
    if removed:
        logger.info("BONA grounding removed %s invalid MITRE technique entries", removed)


def _clean_rag_provenance(
    report: dict[str, Any],
    rag_context: object | None,
) -> None:
    """Clear generated provenance when retrieval supplied no usable context."""
    if not isinstance(rag_context, dict):
        return
    if rag_context.get("rag_available") is False:
        if report["rag_sources_used"]:
            logger.info(
                "BONA grounding cleared RAG provenance because rag_available=false"
            )
        report["rag_sources_used"] = []


def _enforce_next_steps(report: dict[str, Any]) -> None:
    """Normalise incident_next_steps to the stable four-item UI contract."""
    steps = report["incident_next_steps"]
    original_count = len(steps)
    if original_count < 4:
        report["incident_next_steps"] = steps + (
            [_NEXT_STEP_PAD_VALUE] * (4 - original_count)
        )
        logger.info(
            "BONA grounding padded incident_next_steps from %s to 4",
            original_count,
        )
    elif original_count > 4:
        report["incident_next_steps"] = steps[:4]
        logger.info(
            "BONA grounding truncated incident_next_steps from %s to 4",
            original_count,
        )


def _rag_context_for_prompt(
    value: object,
    *,
    max_entries: int | None = None,
    content_chars: int | None = None,
) -> dict[str, Any]:
    """Keep RAG availability plus only fields BONA needs for grounding."""
    if not isinstance(value, dict):
        return {"rag_available": False, "retrieved_context": []}

    entries = value.get("retrieved_context", [])
    if not isinstance(entries, list):
        entries = []
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

    return {
        "rag_available": bool(value.get("rag_available", False)),
        "retrieved_context": cleaned,
    }
