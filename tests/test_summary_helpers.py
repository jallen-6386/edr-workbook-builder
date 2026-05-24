"""
Tests for v0.2 summary helper functions:
  - get_key_column_presence
  - extract_relationships
"""

from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd
import pytest

from edr_workbook_builder.summary import extract_relationships, get_key_column_presence


# ---------------------------------------------------------------------------
# get_key_column_presence
# ---------------------------------------------------------------------------


class TestGetKeyColumnPresence:
    def test_timestamp_detected(self):
        result = get_key_column_presence(["Timestamp", "ProcessId"])
        assert result["Timestamp"] is True

    def test_timestamp_variant_detected(self):
        result = get_key_column_presence(["EventTimeUTC"])
        assert result["Timestamp"] is True

    def test_case_insensitive(self):
        result = get_key_column_presence(["imagefilename"])
        assert result["ImageFileName"] is True

    def test_missing_group_is_false(self):
        result = get_key_column_presence(["SomeOtherColumn"])
        assert result["CommandLine"] is False

    def test_network_detected_via_remote_port(self):
        result = get_key_column_presence(["RemotePort", "LocalPort"])
        assert result["Network"] is True

    def test_hash_detected(self):
        result = get_key_column_presence(["SHA256HashData"])
        assert result["Hash"] is True

    def test_all_groups_present(self):
        columns = [
            "Timestamp", "ProcessId", "ImageFileName", "CommandLine",
            "ParentProcessId", "ParentBaseFileName", "RemoteAddressIP4",
            "TargetFileName", "SHA256HashData", "TargetObjectName",
        ]
        result = get_key_column_presence(columns)
        assert all(result.values())

    def test_empty_columns_all_false(self):
        result = get_key_column_presence([])
        assert not any(result.values())


# ---------------------------------------------------------------------------
# extract_relationships
# ---------------------------------------------------------------------------


def _make_result(df, sheet_name="test"):
    result = MagicMock()
    result.dataframe = df
    result.error = None
    result.path = Path(f"{sheet_name}.csv")
    return result


class TestExtractRelationships:
    def test_basic_relationship_extracted(self):
        df = pd.DataFrame({
            "ParentProcessId": ["1000"],
            "ProcessId": ["2000"],
            "ParentBaseFileName": [r"C:\Windows\explorer.exe"],
            "ImageFileName": [r"C:\Windows\System32\cmd.exe"],
        })
        result = _make_result(df, "cmd")
        rels = extract_relationships([result], ["cmd"])
        assert len(rels) == 1
        assert rels[0]["parent_name"] == "explorer"
        assert rels[0]["child_name"] == "cmd"
        assert rels[0]["parent_pid"] == "1000"
        assert rels[0]["child_pid"] == "2000"
        assert rels[0]["source_sheet"] == "cmd"

    def test_no_pid_columns_returns_empty(self):
        df = pd.DataFrame({"ImageFileName": [r"C:\Windows\cmd.exe"]})
        result = _make_result(df)
        assert extract_relationships([result], ["cmd"]) == []

    def test_deduplicates_by_pid_pair(self):
        df = pd.DataFrame({
            "ParentProcessId": ["1000", "1000", "1000"],
            "ProcessId": ["2000", "2000", "2000"],
        })
        result = _make_result(df)
        rels = extract_relationships([result], ["cmd"])
        assert len(rels) == 1

    def test_multiple_unique_pairs(self):
        df = pd.DataFrame({
            "ParentProcessId": ["1000", "1000", "2000"],
            "ProcessId": ["2000", "3000", "4000"],
        })
        result = _make_result(df)
        rels = extract_relationships([result], ["test"])
        assert len(rels) == 3

    def test_skips_empty_pids(self):
        df = pd.DataFrame({
            "ParentProcessId": ["", None, "1000"],
            "ProcessId": ["2000", "3000", ""],
        })
        result = _make_result(df)
        rels = extract_relationships([result], ["test"])
        assert len(rels) == 0

    def test_skips_nan_pids(self):
        df = pd.DataFrame({
            "ParentProcessId": ["nan", "1000"],
            "ProcessId": ["2000", "nan"],
        })
        result = _make_result(df)
        rels = extract_relationships([result], ["test"])
        assert len(rels) == 0

    def test_skips_errored_results(self):
        result = MagicMock()
        result.error = "parse error"
        result.dataframe = None
        rels = extract_relationships([result], ["test"])
        assert rels == []

    def test_multiple_sheets(self):
        df1 = pd.DataFrame({"ParentProcessId": ["1000"], "ProcessId": ["2000"]})
        df2 = pd.DataFrame({"ParentProcessId": ["3000"], "ProcessId": ["4000"]})
        r1 = _make_result(df1, "sheet1")
        r2 = _make_result(df2, "sheet2")
        rels = extract_relationships([r1, r2], ["sheet1", "sheet2"])
        assert len(rels) == 2
        sources = {r["source_sheet"] for r in rels}
        assert sources == {"sheet1", "sheet2"}

    def test_deduplication_across_sheets(self):
        # Same parent/child PID in two different sheets — should appear only once
        df1 = pd.DataFrame({"ParentProcessId": ["1000"], "ProcessId": ["2000"]})
        df2 = pd.DataFrame({"ParentProcessId": ["1000"], "ProcessId": ["2000"]})
        r1 = _make_result(df1, "sheet1")
        r2 = _make_result(df2, "sheet2")
        rels = extract_relationships([r1, r2], ["sheet1", "sheet2"])
        assert len(rels) == 1

    def test_parent_name_unknown_when_no_name_column(self):
        df = pd.DataFrame({"ParentProcessId": ["1000"], "ProcessId": ["2000"]})
        result = _make_result(df)
        rels = extract_relationships([result], ["test"])
        assert rels[0]["parent_name"] == "unknown"
        assert rels[0]["child_name"] == "unknown"
