"""Phase 21 Workstream D BONA grounding tests."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest


SERVER_ROOT = Path(__file__).resolve().parents[1]

if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))


from services.ai_providers.reporting import (
    build_incident_report_prompt,
    parse_and_validate_report,
)

BASE_REPORT = {
    "incident_summary": "Paragraph one.\n\nParagraph two.",
    "mitre_techniques": ["T1110.001 (Password Guessing)"],
    "confidence_level": "High",
    "incident_next_steps": [
        "Isolate the host.",
        "Reset credentials.",
        "Review telemetry.",
        "Assess reporting obligations.",
    ],
    "popia_flags": [],
    "cybercrimes_flags": [],
    "sa_patterns_matched": [],
    "rag_sources_used": ["MITRE ATT&CK T1110.001"],
    "generated_by": "BONA",
    "mock": False,
}


def parse(report=None, rag_context=None):
    return parse_and_validate_report(
        json.dumps(report or BASE_REPORT),
        rag_context=rag_context,
    )


@pytest.mark.parametrize(
    "technique",
    [
        "T1110",
        "T1110.001",
        "T1110.001 (Brute Force: Password Guessing)",
    ],
)
def test_valid_mitre_id_prefixes_are_kept_without_shape_change(technique):
    report = deepcopy(BASE_REPORT)
    report["mitre_techniques"] = [technique]
    assert parse(report)["mitre_techniques"] == [technique]


def test_invalid_mitre_ids_are_removed():
    report = deepcopy(BASE_REPORT)
    report["mitre_techniques"] = [
    "Technique",
    "TA0001",
    "T111.001",
    "T1110.01",
    "T1110.0001",
    "Not T1110.001",
    ]
    assert parse(report)["mitre_techniques"] == []


def test_mixed_mitre_list_keeps_only_valid_entries():
    report = deepcopy(BASE_REPORT)
    report["mitre_techniques"] = [
        "Technique",
        "T1021.002 (Remote Services: SMB/Windows Admin Shares)",
        "T1074.001 (Data Staged: Local Data Staging)",
        "invalid",
    ]
    assert parse(report)["mitre_techniques"] == [
        "T1021.002 (Remote Services: SMB/Windows Admin Shares)",
        "T1074.001 (Data Staged: Local Data Staging)",
    ]


def test_empty_mitre_list_stays_empty():
    report = deepcopy(BASE_REPORT)
    report["mitre_techniques"] = []
    assert parse(report)["mitre_techniques"] == []


def test_rag_sources_are_cleared_when_rag_unavailable():
    result = parse(
        rag_context={"rag_available": False, "retrieved_context": []}
    )
    assert result["rag_sources_used"] == []


def test_rag_sources_are_preserved_when_rag_available():
    result = parse(
        rag_context={
            "rag_available": True,
            "retrieved_context": [
                {
                    "source": "MITRE ATT&CK",
                    "id": "T1110.001",
                    "content": "Grounded technique context.",
                    "relevance_score": 0.92,
                }
            ],
        }
    )
    assert result["rag_sources_used"] == ["MITRE ATT&CK T1110.001"]


def test_next_steps_are_padded_to_four():
    report = deepcopy(BASE_REPORT)
    report["incident_next_steps"] = [
        "Isolate the affected host.",
        "Reset exposed credentials.",
    ]
    assert parse(report)["incident_next_steps"] == [
        "Isolate the affected host.",
        "Reset exposed credentials.",
        "No further action identified.",
        "No further action identified.",
    ]


def test_next_steps_are_truncated_to_four():
    report = deepcopy(BASE_REPORT)
    report["incident_next_steps"] = [
        "One.", "Two.", "Three.", "Four.", "Five.", "Six."
    ]
    assert parse(report)["incident_next_steps"] == [
        "One.", "Two.", "Three.", "Four."
    ]


def test_prompt_contains_grounding_rules_and_rag_availability():
    prompt = build_incident_report_prompt(
        {"rag_context": {"rag_available": False, "retrieved_context": []}}
    )
    assert (
        "If rag_context.rag_available is false, set rag_sources_used "
        "to an empty list." in prompt
    )
    assert (
        "Only cite intelligence sources that appear in the supplied "
        "rag_context.retrieved_context." in prompt
    )
    assert (
        "Do not invent attack techniques, threat actor names, or "
        "intelligence sources not present in the supplied context." in prompt
    )
    context = json.loads(prompt.split("INVESTIGATION CONTEXT:\n", 1)[1])
    assert context["rag_context"] == {
        "rag_available": False,
        "retrieved_context": [],
    }
