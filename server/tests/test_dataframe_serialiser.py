"""Tests for recursive pandas/NumPy to BSON-safe serialisation."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import numpy as np
import pandas as pd

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from utils.dataframe_serialiser import serialise_dataframe  # noqa: E402


def test_serialise_dataframe_converts_numpy_and_timestamp_types() -> None:
    df = pd.DataFrame([{
        "score": np.int64(85),
        "ratio": np.float64(1.25),
        "flag": np.bool_(True),
        "timestamp": pd.Timestamp("2026-08-18T20:00:00Z"),
    }])
    row = serialise_dataframe(df)[0]
    assert type(row["score"]) is int
    assert type(row["ratio"]) is float
    assert type(row["flag"]) is bool
    assert row["timestamp"] == "2026-08-18T20:00:00+00:00"
    json.dumps(row)


def test_serialise_dataframe_converts_missing_values_to_none() -> None:
    df = pd.DataFrame([{"a": np.nan, "b": pd.NaT, "c": pd.NA}], dtype=object)
    assert serialise_dataframe(df) == [{"a": None, "b": None, "c": None}]


def test_serialise_dataframe_recurses_through_nested_collections() -> None:
    nested = [{
        "signal": "PORT_SCAN",
        "evidence": [
            {"port_count": np.int64(32)},
            {"confidence": np.float64(0.91)},
        ],
    }]
    df = pd.DataFrame([{
        "anomaly_reasons": ["PORT_SCAN"],
        "threat_signals": nested,
        "metadata": {
            "flags": [np.bool_(True)],
            "counts": {"events": np.int64(7)},
        },
    }])

    result = serialise_dataframe(df)
    row = result[0]
    assert type(
        row["threat_signals"][0]["evidence"][0]["port_count"]
    ) is int
    assert type(
        row["threat_signals"][0]["evidence"][1]["confidence"]
    ) is float
    assert type(row["metadata"]["flags"][0]) is bool
    assert type(row["metadata"]["counts"]["events"]) is int
    json.dumps(result)


def test_serialise_dataframe_does_not_mutate_input() -> None:
    df = pd.DataFrame([{
        "timestamp": pd.Timestamp("2026-08-18T20:00:00Z"),
        "score": np.int64(5),
    }])
    original = df.copy(deep=True)
    serialise_dataframe(df)
    pd.testing.assert_frame_equal(df, original)


def test_datetime_is_iso_serialised() -> None:
    value = datetime(2026, 8, 18, 20, 0, tzinfo=timezone.utc)
    df = pd.DataFrame([{"created": value}])
    assert serialise_dataframe(df)[0]["created"] == "2026-08-18T20:00:00+00:00"