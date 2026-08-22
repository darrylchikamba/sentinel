"""In-memory tests for the SENTINEL graph builder."""
import json
from pathlib import Path
import sys

import numpy as np
import pandas as pd

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from services.graph_builder import build_attack_graph


def row(**overrides):
    value = {
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "user_account": "analyst",
        "device_id": "endpoint-1",
        "threat_score": 10,
        "threat_level": "Low",
        "bytes_transferred": 1000.0,
        "event_type": "connection",
    }
    value.update(overrides)
    return value


def test_empty_graph():
    result = build_attack_graph(pd.DataFrame())
    assert result["nodes"] == []
    assert result["edges"] == []
    assert result["attack_clusters"] == []
    assert all(value == 0 for value in result["graph_summary"].values())


def test_single_edge_and_nodes():
    result = build_attack_graph(pd.DataFrame([row()]))
    assert {node["id"] for node in result["nodes"]} == {
        "ip:10.0.0.1", "ip:10.0.0.2",
        "user_account:analyst", "device_id:endpoint-1",
    }
    assert result["edges"][0]["event_count"] == 1


def test_suspicious_and_non_suspicious_nodes():
    result = build_attack_graph(pd.DataFrame([
        row(src_ip="10.0.0.10", threat_score=80, threat_level="Critical"),
        row(
            src_ip="10.0.0.20", dst_ip="10.0.0.21",
            user_account="user", device_id="endpoint-2",
            threat_score=40, threat_level="Medium",
        ),
    ]))
    nodes = {node["id"]: node for node in result["nodes"]}
    assert nodes["ip:10.0.0.10"]["is_suspicious"] is True
    assert nodes["ip:10.0.0.20"]["is_suspicious"] is False


def test_edge_aggregation_and_dominant_event():
    result = build_attack_graph(pd.DataFrame([
        row(event_type="login", bytes_transferred=100),
        row(event_type="login", bytes_transferred=200),
        row(event_type="alert", bytes_transferred=300),
    ]))
    edge = result["edges"][0]
    assert edge["event_count"] == 3
    assert edge["total_bytes"] == 600.0
    assert edge["dominant_event_type"] == "login"


def test_attack_cluster_detected():
    result = build_attack_graph(pd.DataFrame([
        row(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            user_account="admin", device_id=None,
            threat_score=90, threat_level="Critical",
        ),
        row(
            src_ip="10.0.0.2", dst_ip="10.0.0.3",
            user_account=None, device_id=None,
            threat_score=70, threat_level="High",
        ),
    ]))
    assert result["graph_summary"]["attack_clusters_detected"] == 1
    assert result["attack_clusters"][0]["cluster_id"] == "CLUSTER-001"


def test_no_cluster_with_two_suspicious_nodes():
    result = build_attack_graph(pd.DataFrame([
        row(
            user_account=None, device_id=None,
            threat_score=80, threat_level="Critical",
        )
    ]))
    assert result["attack_clusters"] == []


def test_cluster_ordering_by_score():
    result = build_attack_graph(pd.DataFrame([
        row(
            src_ip="10.0.1.1", dst_ip="10.0.1.2",
            user_account=None, device_id=None,
            threat_score=60, threat_level="High",
        ),
        row(
            src_ip="10.0.1.2", dst_ip="10.0.1.3",
            user_account=None, device_id=None,
            threat_score=60, threat_level="High",
        ),
        row(
            src_ip="10.0.2.1", dst_ip="10.0.2.2",
            user_account=None, device_id=None,
            threat_score=95, threat_level="Critical",
        ),
        row(
            src_ip="10.0.2.2", dst_ip="10.0.2.3",
            user_account=None, device_id=None,
            threat_score=95, threat_level="Critical",
        ),
    ]))
    assert [c["max_threat_score"] for c in result["attack_clusters"]] == [95, 60]


def test_json_serialisable_with_numpy_values():
    result = build_attack_graph(pd.DataFrame([
        row(threat_score=np.int64(75), bytes_transferred=np.float64(1234.5))
    ]))
    json.dumps(result)


def test_input_not_mutated():
    df = pd.DataFrame([row()])
    original = df.copy(deep=True)
    build_attack_graph(df)
    pd.testing.assert_frame_equal(df, original)


def test_null_values_skipped():
    result = build_attack_graph(pd.DataFrame([
        row(user_account=None, device_id=np.nan),
        row(
            src_ip=" ", dst_ip="10.0.0.3",
            user_account="", device_id="device-2",
        ),
    ]))
    ids = {node["id"] for node in result["nodes"]}
    assert "device_id:nan" not in ids
    assert "user_account:" not in ids
    assert "ip:" not in ids


def test_summary_counts():
    result = build_attack_graph(pd.DataFrame([
        row(threat_score=80, threat_level="Critical")
    ]))
    summary = result["graph_summary"]
    assert summary["total_nodes"] == 4
    assert summary["total_edges"] == 1
    assert summary["suspicious_nodes"] == 4
    assert summary["max_threat_score_in_graph"] == 80
