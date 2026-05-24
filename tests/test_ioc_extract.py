"""
Tests for edr_workbook_builder.ioc_extract:
  - extract_iocs
  - _classify_hash
"""

from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd
import pytest

from edr_workbook_builder.ioc_extract import _classify_hash, extract_iocs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(df, name="test.csv", error=None):
    r = MagicMock()
    r.dataframe = df
    r.error = error
    r.path = Path(name)
    return r


# ---------------------------------------------------------------------------
# _classify_hash
# ---------------------------------------------------------------------------


class TestClassifyHash:
    def test_sha256(self):
        assert _classify_hash("a" * 64) == "SHA256"

    def test_sha1(self):
        assert _classify_hash("b" * 40) == "SHA1"

    def test_md5(self):
        assert _classify_hash("c" * 32) == "MD5"

    def test_uppercase_accepted(self):
        assert _classify_hash("A" * 64) == "SHA256"

    def test_mixed_case_accepted(self):
        assert _classify_hash("aAbB" * 8) == "MD5"

    def test_wrong_length_returns_none(self):
        assert _classify_hash("a" * 63) is None
        assert _classify_hash("a" * 65) is None

    def test_non_hex_returns_none(self):
        assert _classify_hash("g" * 64) is None

    def test_empty_returns_none(self):
        assert _classify_hash("") is None


# ---------------------------------------------------------------------------
# extract_iocs
# ---------------------------------------------------------------------------


class TestExtractIocs:
    def test_sha256_extracted(self):
        df = pd.DataFrame({"SHA256": ["a" * 64]})
        r = _make_result(df)
        out = extract_iocs([r], ["s1"])
        assert not out.empty
        assert "SHA256" in out["Type"].values
        assert ("a" * 64).upper() in out["Value"].values

    def test_md5_extracted(self):
        df = pd.DataFrame({"MD5": ["b" * 32]})
        r = _make_result(df)
        out = extract_iocs([r], ["s1"])
        assert "MD5" in out["Type"].values

    def test_sha1_extracted(self):
        df = pd.DataFrame({"SHA1": ["c" * 40]})
        r = _make_result(df)
        out = extract_iocs([r], ["s1"])
        assert "SHA1" in out["Type"].values

    def test_ipv4_extracted(self):
        df = pd.DataFrame({"RemoteIP": ["1.2.3.4"]})
        r = _make_result(df)
        out = extract_iocs([r], ["s1"])
        assert "IPv4" in out["Type"].values
        assert "1.2.3.4" in out["Value"].values

    def test_loopback_excluded(self):
        df = pd.DataFrame({"RemoteIP": ["127.0.0.1"]})
        r = _make_result(df)
        out = extract_iocs([r], ["s1"])
        assert out.empty

    def test_unspecified_ip_excluded(self):
        df = pd.DataFrame({"RemoteIP": ["0.0.0.0"]})
        r = _make_result(df)
        out = extract_iocs([r], ["s1"])
        assert out.empty

    def test_no_ioc_columns_returns_empty(self):
        df = pd.DataFrame({"SomeProp": ["value"]})
        r = _make_result(df)
        out = extract_iocs([r], ["s1"])
        assert out.empty
        assert list(out.columns) == ["Type", "Value", "SourceSheets", "Count"]

    def test_deduplication_across_sheets(self):
        hash_val = "a" * 64
        df1 = pd.DataFrame({"SHA256": [hash_val]})
        df2 = pd.DataFrame({"SHA256": [hash_val]})
        r1 = _make_result(df1, "s1.csv")
        r2 = _make_result(df2, "s2.csv")
        out = extract_iocs([r1, r2], ["s1", "s2"])
        sha256_rows = out[out["Type"] == "SHA256"]
        assert len(sha256_rows) == 1
        assert sha256_rows.iloc[0]["Count"] == 2

    def test_source_sheets_column_populated(self):
        df = pd.DataFrame({"SHA256": ["a" * 64]})
        r = _make_result(df, "test.csv")
        out = extract_iocs([r], ["mysheet"])
        assert out.iloc[0]["SourceSheets"] == "mysheet"

    def test_errored_results_skipped(self):
        r = _make_result(None, error="parse error")
        out = extract_iocs([r], ["s1"])
        assert out.empty

    def test_multiple_types_per_sheet(self):
        df = pd.DataFrame({
            "SHA256":   ["a" * 64],
            "RemoteIP": ["10.0.0.1"],
        })
        r = _make_result(df)
        out = extract_iocs([r], ["s1"])
        types = set(out["Type"])
        assert "SHA256" in types
        assert "IPv4" in types

    def test_output_columns_correct(self):
        df = pd.DataFrame({"SHA256": ["a" * 64]})
        r = _make_result(df)
        out = extract_iocs([r], ["s1"])
        assert list(out.columns) == ["Type", "Value", "SourceSheets", "Count"]

    def test_hash_column_name_case_insensitive(self):
        df = pd.DataFrame({"sha256": ["a" * 64]})
        r = _make_result(df)
        out = extract_iocs([r], ["s1"])
        assert "SHA256" in out["Type"].values

    def test_nan_values_skipped(self):
        df = pd.DataFrame({"SHA256": [None, "a" * 64, "nan"]})
        r = _make_result(df)
        out = extract_iocs([r], ["s1"])
        assert len(out) == 1

    def test_invalid_ip_format_skipped(self):
        df = pd.DataFrame({"RemoteIP": ["999.0.0.1", "not-an-ip", "1.2.3.4"]})
        r = _make_result(df)
        out = extract_iocs([r], ["s1"])
        ip_rows = out[out["Type"] == "IPv4"]
        assert len(ip_rows) == 1
        assert ip_rows.iloc[0]["Value"] == "1.2.3.4"
