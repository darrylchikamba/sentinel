"""Apply South African threat and compliance intelligence."""
from __future__ import annotations

from typing import Any
import pandas as pd

PERSONAL_DATA_TERMS = (
    "login", "authentication", "user", "account", "email", "identity",
    "credential", "profile", "personal", "record", "customer",
)
SERVICE_ACCOUNT_TERMS = (
    "svc_", "sys_", "admin", "service", "operator", "batch", "daemon",
)
BANKING_TERMS = ("bank", "payment", "transfer", "swift", "transaction")
ESKOM_TERMS = (
    "eskom", "loadshedding", "load_shedding", "prepaid", "meter", "outage",
)
GOVERNMENT_TERMS = (".gov.za", "gov_portal", "government")
MOBILE_MONEY_TERMS = ("ussd", "ewallet", "momo", "mobile_money")
RANSOMWARE_TERMS = ("ransomware", "encrypt")
MUNICIPAL_TERMS = ("municipality", "municipal")
FICA_TERMS = ("fica", "kyc", "onboard", "identity_verification")


def _text(value: object) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return str(value).strip().lower()


def _values(value: object) -> list[str]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip().lower() for item in value]
    return [str(value).strip().lower()]


def _contains(text: str, terms: tuple[str, ...]) -> bool:
    return any(term in text for term in terms)


def _reasons(row: pd.Series) -> set[str]:
    return {value.upper() for value in _values(row.get("anomaly_reasons"))}


def _cluster_count(graph_result: dict[str, Any]) -> int:
    try:
        return int(
            graph_result.get("graph_summary", {})
            .get("attack_clusters_detected", 0) or 0
        )
    except (TypeError, ValueError):
        return 0


def classify_sa_intelligence(
    df: pd.DataFrame,
    graph_result: dict[str, Any],
) -> dict[str, Any]:
    """Return SA-specific flags, matched patterns and obligations."""
    if not isinstance(df, pd.DataFrame):
        raise TypeError("df must be a pandas DataFrame")
    if not isinstance(graph_result, dict):
        raise TypeError("graph_result must be a dictionary")

    personal = cross_border = operator = reportable = sarb = False
    eskom = government = mobile = municipal = fica = False

    for _, row in df.iterrows():
        event_type = _text(row.get("event_type"))
        signal_text = " ".join(_values(row.get("threat_signals")))
        combined = f"{event_type} {signal_text}".strip()
        reasons = _reasons(row)
        level = str(row.get("threat_level", "None")).strip()
        score = int(row.get("threat_score", 0) or 0)
        account = _text(row.get("user_account"))
        destination = _text(row.get("dst_ip"))

        row_personal = _contains(combined, PERSONAL_DATA_TERMS)
        personal = personal or row_personal

        if row_personal and "CROSS_BORDER" in reasons:
            cross_border = True
        if level in {"High", "Critical"} and _contains(
            account, SERVICE_ACCOUNT_TERMS
        ):
            operator = True
        if (
            level == "Critical"
            or "BRUTE_FORCE" in reasons
            or "PORT_SCAN" in reasons
        ):
            reportable = True

        # Same-row evidence avoids combining unrelated events.
        if level == "Critical" and _contains(event_type, BANKING_TERMS):
            sarb = True

        eskom = eskom or _contains(combined, ESKOM_TERMS)
        if "BRUTE_FORCE" in reasons and (
            _contains(destination, GOVERNMENT_TERMS)
            or _contains(event_type, GOVERNMENT_TERMS)
        ):
            government = True
        mobile = mobile or _contains(event_type, MOBILE_MONEY_TERMS)
        if _contains(event_type, RANSOMWARE_TERMS) and (
            _contains(destination, MUNICIPAL_TERMS)
            or _contains(event_type, MUNICIPAL_TERMS)
        ):
            municipal = True
        if score >= 50 and _contains(event_type, FICA_TERMS):
            fica = True

    popia_flags = []
    if personal:
        popia_flags.append("POPIA_PERSONAL_DATA")

    section_22 = bool(
        personal
        and not df.empty
        and pd.to_numeric(
            df.get("threat_score", pd.Series(dtype=float)),
            errors="coerce",
        ).fillna(0).ge(50).any()
    )
    if section_22:
        popia_flags.append("POPIA_SECTION_22")
    if cross_border:
        popia_flags.append("POPIA_CROSS_BORDER")
    if operator:
        popia_flags.append("POPIA_OPERATOR")

    cyber_flags = []
    if reportable:
        cyber_flags.append("CYBERCRIMES_ACT_REPORTABLE")
    saps = reportable and _cluster_count(graph_result) > 0
    if saps:
        cyber_flags.append("SAPS_REFERRAL")
    if sarb:
        cyber_flags.append("SARB_REPORTABLE")

    patterns = []
    if eskom:
        patterns.append("ESKOM_SOCIAL_ENG")
    if government:
        patterns.append("GOVPORTAL_CREDENTIAL_STUFFING")
    if mobile:
        patterns.append("MOBILE_MONEY_FRAUD")
    if municipal:
        patterns.append("MUNICIPALITY_RANSOMWARE")
    if fica:
        patterns.append("FICA_BYPASS_ATTEMPT")

    summary = []
    obligations = []
    if section_22:
        summary.append(
            "POPIA Section 22 notification to the Information Regulator may be required."
        )
        obligations.append(
            "Notify Information Regulator as soon as reasonably possible (POPIA Section 22)"
        )
    if reportable:
        summary.append(
            "Potential Cybercrimes Act 2021 reportable activity detected."
        )
        # Section 54's 72-hour duty is conditional on the specified entity scope.
        obligations.append(
            "Report to SAPS within 72 hours if electronic communications service provider or financial institution (Cybercrimes Act Section 54)"
        )
    if saps:
        summary.append(
            "SAPS referral recommended for coordinated attack pattern."
        )
        obligations.append(
            "Refer coordinated attack evidence to SAPS Cybercrime Unit"
        )
    if sarb:
        summary.append(
            "SARB Directive 1 of 2021 notification may apply for affected banking systems."
        )
        obligations.append(
            "Notify SARB under Directive 1 of 2021 operational resilience requirements"
        )

    return {
        "popia_flags": popia_flags,
        "cybercrimes_flags": cyber_flags,
        "sa_patterns_matched": patterns,
        "compliance_summary": (
            " ".join(summary)
            if summary
            else "No immediate compliance obligations identified."
        ),
        "reporting_obligations": obligations,
    }