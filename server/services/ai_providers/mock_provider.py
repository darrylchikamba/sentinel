"""Deterministic zero-dependency BONA provider."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from .base import BaseGenerationProvider


BONA_MOCK_INCIDENT_REPORT: dict[str, Any] = {
    "incident_summary": (
        "SENTINEL identified a coordinated sequence of repeated failed SSH "
        "authentication attempts followed by SMB-based lateral movement and "
        "subsequent data staging on an internal host. The authentication "
        "activity aligned with MITRE ATT&CK T1110.001 (Brute Force: Password "
        "Guessing), the SMB movement aligned with T1021.002 (Remote Services: "
        "SMB/Windows Admin Shares), and the staging behaviour aligned with "
        "T1074.001 (Data Staged: Local Data Staging). The report reflected "
        "only signals supplied by SENTINEL's deterministic investigation "
        "pipeline.\n\n"
        "The investigation also contained indicators associated with personal "
        "data and coordinated unauthorised access. POPIA Section 22 "
        "notification to the Information Regulator may therefore be required "
        "where a security compromise of personal information is confirmed. "
        "Potential Cybercrimes Act 2021 reportable activity was also detected; "
        "the Section 54 reporting obligation remains subject to the "
        "organisation falling within the applicable statutory entity scope."
    ),
    "mitre_techniques": [
        "T1110.001 (Brute Force: Password Guessing)",
        "T1021.002 (Remote Services: SMB/Windows Admin Shares)",
        "T1074.001 (Data Staged: Local Data Staging)",
    ],
    "confidence_level": "High",
    "incident_next_steps": [
        "Isolate the affected internal host and preserve volatile evidence.",
        "Reset exposed credentials and review authentication telemetry for additional compromise.",
        "Review SMB activity and restrict unnecessary administrative share access.",
        "Assess the confirmed incident against POPIA and Cybercrimes Act reporting obligations.",
    ],
    "popia_flags": ["POPIA_PERSONAL_DATA", "POPIA_SECTION_22"],
    "cybercrimes_flags": ["CYBERCRIMES_ACT_REPORTABLE", "SAPS_REFERRAL"],
    "sa_patterns_matched": ["GOVPORTAL_CREDENTIAL_STUFFING"],
    "rag_sources_used": [
        "MITRE ATT&CK T1110.001",
        "MITRE ATT&CK T1021.002",
        "POPIA Section 22(1)",
    ],
    "generated_by": "BONA",
    "mock": True,
}


class MockGenerationProvider(BaseGenerationProvider):
    """Return a realistic report when no live generation provider is enabled."""

    def generate_incident_report(
        self,
        investigation_data: dict[str, Any],
    ) -> dict[str, Any]:
        del investigation_data
        return deepcopy(BONA_MOCK_INCIDENT_REPORT)

    def provider_name(self) -> str:
        return "mock"
