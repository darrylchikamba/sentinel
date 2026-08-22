"""BSON-safe serialisation helpers for pandas investigation data."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

import numpy as np
import pandas as pd


def _serialise_value(value: Any) -> Any:
    """Recursively convert pandas/NumPy values to plain Python/BSON-safe values."""
    if value is None:
        return None

    # Handle pandas scalar missing sentinels before datetime conversion.
    # pd.NaT behaves like a datetime object and isoformat() would return "NaT".
    if value is pd.NaT or value is pd.NA:
        return None

    if isinstance(value, pd.Timestamp):
        return None if pd.isna(value) else value.isoformat()

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, date):
        return value.isoformat()

    if isinstance(value, np.ndarray):
        return [_serialise_value(item) for item in value.tolist()]

    if isinstance(value, np.generic):
        return _serialise_value(value.item())

    if isinstance(value, dict):
        return {
            str(key): _serialise_value(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [_serialise_value(item) for item in value]

    try:
        missing = pd.isna(value)
    except (TypeError, ValueError):
        missing = False

    if isinstance(missing, (bool, np.bool_)) and bool(missing):
        return None

    return value


def serialise_dataframe(df: pd.DataFrame) -> list[dict[str, Any]]:
    """Return DataFrame rows containing only plain Python/BSON-safe values."""
    if not isinstance(df, pd.DataFrame):
        raise TypeError("df must be a pandas DataFrame")

    return [
        {
            str(key): _serialise_value(value)
            for key, value in record.items()
        }
        for record in df.to_dict(orient="records")
    ]