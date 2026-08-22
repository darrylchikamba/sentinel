"""In-memory tests for the SENTINEL log parser."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
import sys

import pandas as pd
import pytest


SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from services.log_parser import parse_log_file, parse_log_text  # noqa: E402
from utils.log_normaliser import normalise_logs  # noqa: E402


def canonical_dataframe() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "timestamp": ["2026-07-30 10:15:00"],
            "src_ip": ["10.0.0.10"],
            "dst_ip": ["10.0.0.20"],
            "event_type": ["login"],
            "dst_port": ["443"],
            "bytes_transferred": ["1024.5"],
        }
    )


def test_csv_parsing_with_standard_columns() -> None:
    csv_bytes = canonical_dataframe().to_csv(index=False).encode("utf-8")

    result = parse_log_file(csv_bytes, "security.csv")

    assert list(result["src_ip"]) == ["10.0.0.10"]
    assert pd.api.types.is_datetime64_any_dtype(result["timestamp"])
    assert result.loc[0, "dst_port"] == 443
    assert result.loc[0, "bytes_transferred"] == 1024.5


def test_csv_parsing_with_case_insensitive_variant_columns() -> None:
    data = pd.DataFrame(
        {
            " Time ": ["2026-07-30T10:15:00Z"],
            "SOURCE_IP": [" 10.0.0.10 "],
            "Destination": [" 10.0.0.20 "],
            "Action": [" blocked "],
        }
    )

    result = parse_log_file(data.to_csv(index=False).encode(), "events.CSV")

    assert result.loc[0, "src_ip"] == "10.0.0.10"
    assert result.loc[0, "dst_ip"] == "10.0.0.20"
    assert result.loc[0, "event_type"] == "blocked"


def test_excel_xlsx_parsing_in_memory() -> None:
    buffer = BytesIO()
    canonical_dataframe().to_excel(buffer, index=False, engine="openpyxl")

    result = parse_log_file(buffer.getvalue(), "events.xlsx")

    assert len(result) == 1
    assert result.loc[0, "dst_port"] == 443


def test_pasted_text_parsing() -> None:
    raw_text = (
        "date,from_ip,dst,type\n"
        "30/07/2026 14:20:00,192.168.1.5,192.168.1.8,authentication_failure\n"
    )

    result = parse_log_text(raw_text)

    assert result.loc[0, "src_ip"] == "192.168.1.5"
    assert result.loc[0, "event_type"] == "authentication_failure"


def test_missing_required_columns_lists_exact_names() -> None:
    dataframe = pd.DataFrame(
        {
            "timestamp": ["2026-07-30"],
            "source_ip": ["10.0.0.1"],
        }
    )

    with pytest.raises(
        ValueError,
        match=r"^Missing required columns: dst_ip, event_type$",
    ):
        normalise_logs(dataframe)


def test_unparseable_timestamp_raises_value_error() -> None:
    dataframe = canonical_dataframe()
    dataframe.loc[0, "timestamp"] = "not-a-date"

    with pytest.raises(
        ValueError,
        match=r"^Unable to parse one or more timestamp values$",
    ):
        normalise_logs(dataframe)


def test_whitespace_is_stripped_from_all_string_columns() -> None:
    dataframe = canonical_dataframe()
    dataframe["severity"] = [" high "]
    dataframe.loc[0, "src_ip"] = " 10.0.0.10 "
    dataframe.loc[0, "event_type"] = " login "

    result = normalise_logs(dataframe)

    assert result.loc[0, "src_ip"] == "10.0.0.10"
    assert result.loc[0, "event_type"] == "login"
    assert result.loc[0, "severity"] == "high"


def test_bytes_transferred_coercion_and_defaults() -> None:
    dataframe = pd.concat(
        [canonical_dataframe(), canonical_dataframe(), canonical_dataframe()],
        ignore_index=True,
    )
    dataframe["bytes_transferred"] = ["500", "invalid", None]

    result = normalise_logs(dataframe)

    assert result["bytes_transferred"].tolist() == [500.0, 0.0, 0.0]


def test_normaliser_does_not_mutate_input_dataframe() -> None:
    dataframe = canonical_dataframe()
    original = dataframe.copy(deep=True)

    normalise_logs(dataframe)

    pd.testing.assert_frame_equal(dataframe, original)


def test_unsupported_extension_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Unsupported file type"):
        parse_log_file(b"{}", "events.json")


def test_empty_pasted_text_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Log text must not be empty"):
        parse_log_text("   ")