"""In-memory tests for the SA intelligence layer."""
from copy import deepcopy
import json
from pathlib import Path
import sys

import pandas as pd

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from services.sa_intelligence import classify_sa_intelligence


def row(**overrides):
    value = {
        "event_type": "connection",
        "threat_signals": [],
        "anomaly_reasons": [],
        "user_account": "analyst",
        "dst_ip": "10.0.0.2",
        "threat_score": 0,
        "threat_level": "None",
    }
    value.update(overrides)
    return value


def graph(clusters=0):
    return {"graph_summary": {"attack_clusters_detected": clusters}}


def test_clean_input():
    result = classify_sa_intelligence(pd.DataFrame([row()]), graph())
    assert result["popia_flags"] == []
    assert result["cybercrimes_flags"] == []
    assert result["sa_patterns_matched"] == []
    assert result["reporting_obligations"] == []
    assert result["compliance_summary"] == (
        "No immediate compliance obligations identified."
    )


def test_personal_data_from_event_and_signal():
    event_result = classify_sa_intelligence(
        pd.DataFrame([row(event_type="user login")]), graph()
    )
    signal_result = classify_sa_intelligence(
        pd.DataFrame([row(threat_signals=["Credential exposure"])]), graph()
    )
    assert "POPIA_PERSONAL_DATA" in event_result["popia_flags"]
    assert "POPIA_PERSONAL_DATA" in signal_result["popia_flags"]


def test_section_22_threshold():
    high = classify_sa_intelligence(
        pd.DataFrame([row(event_type="account login", threat_score=50)]), graph()
    )
    low = classify_sa_intelligence(
        pd.DataFrame([row(event_type="account login", threat_score=49)]), graph()
    )
    assert "POPIA_SECTION_22" in high["popia_flags"]
    assert "POPIA_SECTION_22" not in low["popia_flags"]


def test_cross_border_personal_data():
    result = classify_sa_intelligence(
        pd.DataFrame([
            row(event_type="customer account", anomaly_reasons=["CROSS_BORDER"])
        ]),
        graph(),
    )
    assert "POPIA_CROSS_BORDER" in result["popia_flags"]


def test_operator_requires_high_or_critical():
    result = classify_sa_intelligence(
        pd.DataFrame([
            row(user_account="svc_batch", threat_level="High"),
            row(user_account="admin", threat_level="Medium"),
        ]),
        graph(),
    )
    assert "POPIA_OPERATOR" in result["popia_flags"]


def test_cybercrimes_flags_and_saps_boundary():
    reportable = row(anomaly_reasons=["BRUTE_FORCE"])
    with_cluster = classify_sa_intelligence(
        pd.DataFrame([reportable]), graph(1)
    )
    without_cluster = classify_sa_intelligence(
        pd.DataFrame([reportable]), graph(0)
    )
    assert "CYBERCRIMES_ACT_REPORTABLE" in with_cluster["cybercrimes_flags"]
    assert "SAPS_REFERRAL" in with_cluster["cybercrimes_flags"]
    assert "SAPS_REFERRAL" not in without_cluster["cybercrimes_flags"]


def test_critical_is_reportable():
    result = classify_sa_intelligence(
        pd.DataFrame([row(threat_level="Critical")]), graph()
    )
    assert "CYBERCRIMES_ACT_REPORTABLE" in result["cybercrimes_flags"]


def test_sarb_requires_same_row():
    positive = classify_sa_intelligence(
        pd.DataFrame([row(threat_level="Critical", event_type="swift payment")]),
        graph(),
    )
    negative = classify_sa_intelligence(
        pd.DataFrame([
            row(threat_level="Critical", event_type="malware"),
            row(threat_level="Low", event_type="bank transfer"),
        ]),
        graph(),
    )
    assert "SARB_REPORTABLE" in positive["cybercrimes_flags"]
    assert "SARB_REPORTABLE" not in negative["cybercrimes_flags"]


def test_eskom_pattern():
    result = classify_sa_intelligence(
        pd.DataFrame([row(event_type="Eskom prepaid meter outage")]), graph()
    )
    assert "ESKOM_SOCIAL_ENG" in result["sa_patterns_matched"]


def test_government_credential_stuffing():
    result = classify_sa_intelligence(
        pd.DataFrame([
            row(
                event_type="government login failed",
                dst_ip="services.gov.za",
                anomaly_reasons=["BRUTE_FORCE"],
            )
        ]),
        graph(),
    )
    assert "GOVPORTAL_CREDENTIAL_STUFFING" in result["sa_patterns_matched"]


def test_other_sa_patterns():
    result = classify_sa_intelligence(
        pd.DataFrame([
            row(event_type="USSD eWallet fraud"),
            row(event_type="municipality ransomware encryption", threat_score=70),
            row(event_type="FICA identity_verification onboarding", threat_score=60),
        ]),
        graph(),
    )
    assert "MOBILE_MONEY_FRAUD" in result["sa_patterns_matched"]
    assert "MUNICIPALITY_RANSOMWARE" in result["sa_patterns_matched"]
    assert "FICA_BYPASS_ATTEMPT" in result["sa_patterns_matched"]


def test_summary_and_obligations():
    result = classify_sa_intelligence(
        pd.DataFrame([
            row(
                event_type="critical customer bank transfer",
                threat_score=80,
                threat_level="Critical",
                anomaly_reasons=["BRUTE_FORCE"],
            )
        ]),
        graph(1),
    )
    assert "POPIA Section 22 notification" in result["compliance_summary"]
    assert "Potential Cybercrimes Act 2021" in result["compliance_summary"]
    assert "SAPS referral recommended" in result["compliance_summary"]
    assert "SARB Directive 1 of 2021" in result["compliance_summary"]
    assert result["reporting_obligations"] == [
        "Notify Information Regulator as soon as reasonably possible (POPIA Section 22)",
        "Report to SAPS within 72 hours if electronic communications service provider or financial institution (Cybercrimes Act Section 54)",
        "Refer coordinated attack evidence to SAPS Cybercrime Unit",
        "Notify SARB under Directive 1 of 2021 operational resilience requirements",
    ]


def test_inputs_unchanged_and_json_serialisable():
    df = pd.DataFrame([row()])
    graph_result = graph()
    original_df = df.copy(deep=True)
    original_graph = deepcopy(graph_result)

    result = classify_sa_intelligence(df, graph_result)

    pd.testing.assert_frame_equal(df, original_df)
    assert graph_result == original_graph
    json.dumps(result)