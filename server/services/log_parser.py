"""Pure pandas log-file and pasted-text parsing."""

from __future__ import annotations

from io import BytesIO, StringIO
from pathlib import Path

import pandas as pd

from utils.log_normaliser import normalise_logs


SUPPORTED_EXTENSIONS = {".csv", ".xlsx", ".xls"}


def parse_log_file(file_bytes: bytes, filename: str) -> pd.DataFrame:
    """Parse an uploaded CSV or Excel log into SENTINEL's standard schema."""
    if not isinstance(file_bytes, bytes):
        raise TypeError("file_bytes must be bytes")
    if not filename or not filename.strip():
        raise ValueError("A filename is required")

    extension = Path(filename.strip()).suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            "Unsupported file type. Supported types are .csv, .xlsx and .xls"
        )

    buffer = BytesIO(file_bytes)
    try:
        if extension == ".csv":
            dataframe = pd.read_csv(buffer)
        else:
            dataframe = pd.read_excel(buffer, engine="openpyxl")
    except Exception as exc:
        if extension == ".xls":
            raise ValueError(
                "Unable to read the .xls file with the configured Excel engine"
            ) from exc
        raise ValueError(f"Unable to read {extension} log file") from exc

    return normalise_logs(dataframe)


def parse_log_text(raw_text: str) -> pd.DataFrame:
    """Parse pasted CSV text into SENTINEL's standard schema."""
    if not isinstance(raw_text, str):
        raise TypeError("raw_text must be a string")
    if not raw_text.strip():
        raise ValueError("Log text must not be empty")

    try:
        dataframe = pd.read_csv(StringIO(raw_text))
    except Exception as exc:
        raise ValueError("Unable to parse pasted CSV log text") from exc

    return normalise_logs(dataframe)