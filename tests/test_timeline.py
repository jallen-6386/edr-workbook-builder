"""
Tests for edr_workbook_builder.timeline:
  - find_best_timestamp_column
  - _parse_ts
  - build_timeline_df
"""

from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd
import pytest

from edr_workbook_builder.timeline import (
    TIMESTAMP_COLS,
    _parse_ts,
    build_timeline_df,
    find_best_timestamp_column,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(df, name="test", error=None):
    r = MagicMock()
    r.dataframe = df
    r.error = error
    r.path = Path(f"{name}.csv")
    return r


# ---------------------------------------------------------------------------
# find_best_timestamp_column
# ---------------------------------------------------------------------------


class TestFindBestTimestampColumn:
    def test_finds_timestamp_column(self):
        df = pd.DataFrame({"Timestamp": ["2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z"]})
        result = _make_result(df)
        assert find_best_timestamp_column([result], ["sheet1"]) == "Timestamp"

    def test_finds_eventtimeutc_when_no_timestamp(self):
        df = pd.DataFrame({"EventTimeUTC": ["2024-01-01T00:00:00Z"]})
        result = _make_result(df)
        assert find_best_timestamp_column([result], ["sheet1"]) == "EventTimeUTC"

    def test_priority_timestamp_over_eventtime(self):
        df = pd.DataFrame({
            "EventTime": ["2024-01-01"],
            "Timestamp": ["2024-01-02"],
        })
        result = _make_result(df)
        # Timestamp is earlier in TIMESTAMP_COLS, should win
        assert find_best_timestamp_column([result], ["sheet1"]) == "Timestamp"

    def test_case_insensitive_match(self):
        df = pd.DataFrame({"timestamp": ["2024-01-01"]})
        result = _make_result(df)
        assert find_best_timestamp_column([result], ["sheet1"]) == "Timestamp"

    def test_returns_none_when_no_column_found(self):
        df = pd.DataFrame({"SomeOtherColumn": ["value"]})
        result = _make_result(df)
        assert find_best_timestamp_column([result], ["sheet1"]) is None

    def test_skips_errored_results(self):
        r = _make_result(None, error="parse error")
        assert find_best_timestamp_column([r], ["sheet1"]) is None

    def test_skips_all_null_column(self):
        df = pd.DataFrame({"Timestamp": [None, None, None]})
        result = _make_result(df)
        assert find_best_timestamp_column([result], ["sheet1"]) is None

    def test_multiple_sheets_first_match_wins(self):
        df1 = pd.DataFrame({"EventTimeUTC": ["2024-01-01"]})
        df2 = pd.DataFrame({"Timestamp": ["2024-01-02"]})
        r1 = _make_result(df1, "s1")
        r2 = _make_result(df2, "s2")
        # Timestamp has higher priority (earlier in list) even though it's in the second sheet
        assert find_best_timestamp_column([r1, r2], ["s1", "s2"]) == "Timestamp"

    def test_timestamp_cols_list_is_nonempty(self):
        assert len(TIMESTAMP_COLS) > 0


# ---------------------------------------------------------------------------
# _parse_ts
# ---------------------------------------------------------------------------


class TestParseTs:
    def test_iso8601_string(self):
        s = pd.Series(["2024-01-15T14:32:00Z", "2024-01-16T08:00:00Z"])
        result = _parse_ts(s)
        assert result.notna().all()
        assert result.iloc[0] < result.iloc[1]

    def test_epoch_milliseconds(self):
        # 2024-01-15 00:00:00 UTC in epoch ms
        ms = 1705276800000
        s = pd.Series([str(ms), str(ms + 1000)])
        result = _parse_ts(s)
        assert result.notna().all()
        assert result.iloc[0] < result.iloc[1]

    def test_epoch_seconds(self):
        s = pd.Series(["1705276800", "1705363200"])
        result = _parse_ts(s)
        assert result.notna().all()
        assert result.iloc[0] < result.iloc[1]

    def test_invalid_values_become_nat(self):
        s = pd.Series(["not-a-date", "also-not-a-date"])
        result = _parse_ts(s)
        assert result.isna().all()

    def test_mixed_valid_and_invalid(self):
        s = pd.Series(["2024-01-15T00:00:00Z", "not-a-date"])
        result = _parse_ts(s)
        assert result.iloc[0] is not pd.NaT
        assert pd.isna(result.iloc[1])

    def test_empty_series(self):
        s = pd.Series([], dtype=str)
        result = _parse_ts(s)
        assert len(result) == 0


# ---------------------------------------------------------------------------
# build_timeline_df
# ---------------------------------------------------------------------------


class TestBuildTimelineDf:
    def test_basic_merge_and_sort(self):
        df1 = pd.DataFrame({
            "Timestamp": ["2024-01-15T12:00:00Z", "2024-01-15T10:00:00Z"],
            "Event": ["B", "A"],
        })
        df2 = pd.DataFrame({
            "Timestamp": ["2024-01-15T11:00:00Z"],
            "Event": ["C"],
        })
        r1 = _make_result(df1, "sheet1")
        r2 = _make_result(df2, "sheet2")
        tl, included, excluded = build_timeline_df([r1, r2], ["sheet1", "sheet2"], "Timestamp")

        assert tl is not None
        assert len(tl) == 3
        assert list(tl["Event"]) == ["A", "C", "B"]  # chronological order
        assert excluded == []
        assert set(included) == {"sheet1", "sheet2"}

    def test_source_sheet_column_prepended(self):
        df = pd.DataFrame({"Timestamp": ["2024-01-01T00:00:00Z"]})
        r = _make_result(df, "mysheet")
        tl, _, _ = build_timeline_df([r], ["mysheet"], "Timestamp")
        assert "SourceSheet" in tl.columns
        assert tl.columns[0] == "SourceSheet"
        assert tl["SourceSheet"].iloc[0] == "mysheet"

    def test_timestamp_column_second(self):
        df = pd.DataFrame({"Timestamp": ["2024-01-01T00:00:00Z"], "Other": ["x"]})
        r = _make_result(df, "s1")
        tl, _, _ = build_timeline_df([r], ["s1"], "Timestamp")
        assert tl.columns[1] == "Timestamp"

    def test_excluded_sheet_missing_column(self):
        df1 = pd.DataFrame({"Timestamp": ["2024-01-01T00:00:00Z"]})
        df2 = pd.DataFrame({"OtherCol": ["value"]})
        r1 = _make_result(df1, "s1")
        r2 = _make_result(df2, "s2")
        tl, included, excluded = build_timeline_df([r1, r2], ["s1", "s2"], "Timestamp")
        assert "s2" in excluded
        assert "s1" in included

    def test_all_sheets_excluded_returns_none(self):
        df = pd.DataFrame({"WrongColumn": ["value"]})
        r = _make_result(df)
        tl, _, _ = build_timeline_df([r], ["test"], "Timestamp")
        assert tl is None

    def test_errored_results_excluded(self):
        r = _make_result(None, error="bad file")
        tl, included, excluded = build_timeline_df([r], ["test"], "Timestamp")
        assert tl is None
        assert "test" in excluded

    def test_unparseable_timestamps_sorted_last(self):
        df = pd.DataFrame({
            "Timestamp": ["2024-01-15T10:00:00Z", "not-a-date", "2024-01-15T08:00:00Z"],
            "Order": ["B", "bad", "A"],
        })
        r = _make_result(df, "s1")
        tl, _, _ = build_timeline_df([r], ["s1"], "Timestamp")
        assert tl is not None
        assert list(tl["Order"]) == ["A", "B", "bad"]

    def test_union_columns_across_sheets(self):
        df1 = pd.DataFrame({"Timestamp": ["2024-01-01"], "ColA": ["a"]})
        df2 = pd.DataFrame({"Timestamp": ["2024-01-02"], "ColB": ["b"]})
        r1 = _make_result(df1, "s1")
        r2 = _make_result(df2, "s2")
        tl, _, _ = build_timeline_df([r1, r2], ["s1", "s2"], "Timestamp")
        assert "ColA" in tl.columns
        assert "ColB" in tl.columns

    def test_case_insensitive_column_match(self):
        df = pd.DataFrame({"timestamp": ["2024-01-01T00:00:00Z"]})
        r = _make_result(df, "s1")
        tl, included, excluded = build_timeline_df([r], ["s1"], "Timestamp")
        assert tl is not None
        assert "s1" in included

    def test_source_sheet_renamed_if_conflict(self):
        df = pd.DataFrame({
            "Timestamp": ["2024-01-01T00:00:00Z"],
            "SourceSheet": ["existing_value"],
        })
        r = _make_result(df, "mysheet")
        tl, _, _ = build_timeline_df([r], ["mysheet"], "Timestamp")
        assert tl is not None
        assert tl["SourceSheet"].iloc[0] == "mysheet"
        assert "SourceSheet_orig" in tl.columns
