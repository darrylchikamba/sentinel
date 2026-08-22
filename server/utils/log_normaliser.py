"""Normalise heterogeneous cybersecurity log DataFrames."""

from __future__ import annotations

from collections.abc import Iterable

import pandas as pd


COLUMN_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "time", "datetime", "date"),
    "src_ip": ("src_ip", "source_ip", "src", "from_ip"),
    "dst_ip": ("dst_ip", "dest_ip", "destination", "dst"),
    "event_type": ("event_type", "type", "action", "alert", "event"),
    "severity": ("severity", "priority", "level", "risk"),
    "user_account": ("user", "username", "account", "user_id"),
    "device_id": ("device", "host", "hostname", "machine", "endpoint"),
    "protocol": ("protocol", "proto"),
    "dst_port": ("port", "dst_port", "destination_port", "dport"),
    "bytes_transferred": ("bytes", "data_size", "payload", "size"),
}
REQUIRED_COLUMNS = ("timestamp", "src_ip", "dst_ip", "event_type")


def _normalised_column_name(column: object) -> str:
    return str(column).strip().lower()


def _build_rename_map(columns: Iterable[object]) -> dict[object, str]:
    """Map aliases without creating duplicate canonical columns."""
    original_columns = list(columns)
    lookup: dict[str, list[object]] = {}
    for column in original_columns:
        lookup.setdefault(_normalised_column_name(column), []).append(column)

    rename_map: dict[object, str] = {}
    claimed_sources: set[object] = set()

    for canonical, aliases in COLUMN_ALIASES.items():
        selected = None

        # Prefer an existing canonical column over any alias.
        for candidate in lookup.get(canonical, []):
            if candidate not in claimed_sources:
                selected = candidate
                break

        if selected is None:
            for alias in aliases:
                for candidate in lookup.get(alias, []):
                    if candidate not in claimed_sources:
                        selected = candidate
                        break
                if selected is not None:
                    break

        if selected is not None:
            rename_map[selected] = canonical
            claimed_sources.add(selected)

    return rename_map


def _strip_string_columns(dataframe: pd.DataFrame) -> None:
    for column in dataframe.columns:
        if pd.api.types.is_object_dtype(dataframe[column]) or pd.api.types.is_string_dtype(
            dataframe[column]
        ):
            dataframe[column] = dataframe[column].map(
                lambda value: value.strip() if isinstance(value, str) else value
            )


def _parse_timestamps(series: pd.Series) -> pd.Series:
    source = series.copy()
    stripped = source.map(
        lambda value: value.strip() if isinstance(value, str) else value
    )
    non_empty = stripped.notna() & stripped.ne("")

    parsed = pd.to_datetime(stripped, errors="coerce", format="mixed", dayfirst=False)

    # Retry remaining values using day-first parsing for common SA date formats.
    failed = non_empty & parsed.isna()
    if failed.any():
        parsed.loc[failed] = pd.to_datetime(
            stripped.loc[failed],
            errors="coerce",
            dayfirst=True,
        )

    if (non_empty & parsed.isna()).any():
        raise ValueError("Unable to parse one or more timestamp values")

    return parsed


def normalise_logs(df: pd.DataFrame) -> pd.DataFrame:
    """Return a cleaned copy with SENTINEL's canonical log schema."""
    if not isinstance(df, pd.DataFrame):
        raise TypeError("df must be a pandas DataFrame")

    cleaned = df.copy(deep=True)
    cleaned = cleaned.rename(columns=_build_rename_map(cleaned.columns))

    missing = [column for column in REQUIRED_COLUMNS if column not in cleaned.columns]
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")

    _strip_string_columns(cleaned)
    cleaned["timestamp"] = _parse_timestamps(cleaned["timestamp"])

    if "bytes_transferred" not in cleaned.columns:
        cleaned["bytes_transferred"] = 0.0
    cleaned["bytes_transferred"] = (
        pd.to_numeric(cleaned["bytes_transferred"], errors="coerce")
        .fillna(0.0)
        .astype(float)
    )

    if "dst_port" not in cleaned.columns:
        cleaned["dst_port"] = 0
    cleaned["dst_port"] = (
        pd.to_numeric(cleaned["dst_port"], errors="coerce")
        .fillna(0)
        .astype(int)
    )

    return cleaned