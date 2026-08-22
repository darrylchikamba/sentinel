"""Build a JSON-serialisable attack graph from scored SENTINEL events."""
from __future__ import annotations

from collections import Counter
from typing import Any
import json

import networkx as nx
import pandas as pd

REQUIRED_COLUMNS = (
    "src_ip", "dst_ip", "user_account", "device_id",
    "threat_score", "threat_level", "bytes_transferred", "event_type",
)
THREAT_RANK = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _empty_result() -> dict[str, Any]:
    return {
        "nodes": [],
        "edges": [],
        "attack_clusters": [],
        "graph_summary": {
            "total_nodes": 0,
            "total_edges": 0,
            "suspicious_nodes": 0,
            "attack_clusters_detected": 0,
            "max_threat_score_in_graph": 0,
        },
    }


def _clean(value: object) -> str | None:
    if value is None or pd.isna(value):
        return None
    text = str(value).strip()
    return text or None


def _node_id(node_type: str, value: str) -> str:
    # Source and destination appearances of the same IP must resolve to one
    # node so lateral movement forms a connected path. Accounts and devices
    # remain namespaced to prevent unrelated entity-type collisions.
    if node_type in {"src_ip", "dst_ip"}:
        return f"ip:{value}"
    return f"{node_type}:{value}"


def _level(value: object) -> str:
    level = str(value).strip() if value is not None else "None"
    return level if level in THREAT_RANK else "None"


def _higher(current: str, candidate: str) -> str:
    return candidate if THREAT_RANK[candidate] > THREAT_RANK[current] else current


def _dominant(counter: Counter[str]) -> str:
    if not counter:
        return ""
    highest = max(counter.values())
    return sorted(k for k, v in counter.items() if v == highest)[0]


def build_attack_graph(df: pd.DataFrame) -> dict[str, Any]:
    """Return plain-Python graph data with no NetworkX objects."""
    if not isinstance(df, pd.DataFrame):
        raise TypeError("df must be a pandas DataFrame")
    if df.empty:
        return _empty_result()

    missing = [column for column in REQUIRED_COLUMNS if column not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")

    data = df.copy(deep=True)
    graph = nx.DiGraph()
    entities = (
        ("src_ip", "src_ip"),
        ("dst_ip", "dst_ip"),
        ("user_account", "user_account"),
        ("device_id", "device_id"),
    )

    for row in data.to_dict(orient="records"):
        score = int(row.get("threat_score", 0) or 0)
        level = _level(row.get("threat_level"))
        suspicious = level in {"High", "Critical"}

        for column, node_type in entities:
            value = _clean(row.get(column))
            if value is None:
                continue
            identifier = _node_id(node_type, value)
            if not graph.has_node(identifier):
                graph.add_node(
                    identifier,
                    type=node_type,
                    is_suspicious=False,
                    max_threat_score=0,
                    max_threat_level="None",
                    event_count=0,
                )
            attrs = graph.nodes[identifier]
            if node_type == "src_ip":
                attrs["type"] = "src_ip"
            attrs["event_count"] += 1
            attrs["max_threat_score"] = max(int(attrs["max_threat_score"]), score)
            attrs["max_threat_level"] = _higher(
                str(attrs["max_threat_level"]), level
            )
            attrs["is_suspicious"] = bool(attrs["is_suspicious"] or suspicious)

        source = _clean(row.get("src_ip"))
        target = _clean(row.get("dst_ip"))
        if source is None or target is None:
            continue
        source_id = _node_id("src_ip", source)
        target_id = _node_id("dst_ip", target)
        transferred = float(row.get("bytes_transferred", 0.0) or 0.0)
        event_type = _clean(row.get("event_type")) or ""

        if not graph.has_edge(source_id, target_id):
            graph.add_edge(
                source_id,
                target_id,
                event_count=0,
                total_bytes=0.0,
                max_threat_score=0,
                event_type_counts=Counter(),
            )
        edge = graph.edges[source_id, target_id]
        edge["event_count"] += 1
        edge["total_bytes"] += transferred
        edge["max_threat_score"] = max(int(edge["max_threat_score"]), score)
        if event_type:
            edge["event_type_counts"][event_type] += 1

    nodes = [
        {
            "id": str(identifier),
            "type": str(attrs["type"]),
            "is_suspicious": bool(attrs["is_suspicious"]),
            "max_threat_score": int(attrs["max_threat_score"]),
            "max_threat_level": str(attrs["max_threat_level"]),
            "event_count": int(attrs["event_count"]),
        }
        for identifier, attrs in sorted(graph.nodes(data=True))
    ]
    edges = [
        {
            "source": str(source),
            "target": str(target),
            "event_count": int(attrs["event_count"]),
            "total_bytes": float(attrs["total_bytes"]),
            "max_threat_score": int(attrs["max_threat_score"]),
            "dominant_event_type": _dominant(attrs["event_type_counts"]),
        }
        for source, target, attrs in sorted(graph.edges(data=True))
    ]

    candidates = []
    for component in nx.connected_components(graph.to_undirected()):
        suspicious_nodes = [
            node for node in component if graph.nodes[node]["is_suspicious"]
        ]
        if len(suspicious_nodes) < 3:
            continue

        internal_edges = [
            (source, target, attrs)
            for source, target, attrs in graph.edges(data=True)
            if source in component and target in component
        ]
        max_score = max(
            int(graph.nodes[node]["max_threat_score"]) for node in component
        )
        highest_level = max(
            (str(graph.nodes[node]["max_threat_level"]) for node in component),
            key=lambda value: THREAT_RANK.get(value, 0),
        )
        event_types = sorted({
            event_type
            for _, _, attrs in internal_edges
            for event_type in attrs["event_type_counts"]
        })
        candidates.append({
            "nodes": sorted(str(node) for node in component),
            "edge_count": int(len(internal_edges)),
            "total_bytes": float(sum(
                float(attrs["total_bytes"]) for _, _, attrs in internal_edges
            )),
            "max_threat_score": int(max_score),
            "dominant_threat_level": str(highest_level),
            "event_types": event_types,
            "_suspicious_count": len(suspicious_nodes),
        })

    candidates.sort(key=lambda cluster: (
        -cluster["max_threat_score"],
        -cluster["_suspicious_count"],
        cluster["nodes"][0] if cluster["nodes"] else "",
    ))
    clusters = [
        {
            "cluster_id": f"CLUSTER-{index:03d}",
            "nodes": cluster["nodes"],
            "edge_count": int(cluster["edge_count"]),
            "total_bytes": float(cluster["total_bytes"]),
            "max_threat_score": int(cluster["max_threat_score"]),
            "dominant_threat_level": str(cluster["dominant_threat_level"]),
            "event_types": list(cluster["event_types"]),
        }
        for index, cluster in enumerate(candidates, start=1)
    ]

    result = {
        "nodes": nodes,
        "edges": edges,
        "attack_clusters": clusters,
        "graph_summary": {
            "total_nodes": int(graph.number_of_nodes()),
            "total_edges": int(graph.number_of_edges()),
            "suspicious_nodes": int(sum(
                1 for _, attrs in graph.nodes(data=True)
                if bool(attrs["is_suspicious"])
            )),
            "attack_clusters_detected": int(len(clusters)),
            "max_threat_score_in_graph": int(max(
                (
                    int(attrs["max_threat_score"])
                    for _, attrs in graph.nodes(data=True)
                ),
                default=0,
            )),
        },
    }
    # Catch NumPy or NetworkX scalar leakage at the service boundary.
    json.dumps(result)
    return result