"""
Timeline sheet builder.

Merges rows from all loaded CSVs on a shared timestamp column and produces
a single chronologically sorted DataFrame, with a SourceSheet column prepended
so analysts can trace every event back to its origin sheet.

Timestamp column candidates (checked in priority order):
  Timestamp, EventTimeUTC, ContextTimeStamp, EventTime,
  StartTime, EndTime, CreationTime

Parsing strategy (applied to the best candidate column):
  1. Numeric string → epoch milliseconds if median value > 1e12
  2. Numeric string → epoch seconds if median value > 1e9
  3. General datetime string via pd.to_datetime (handles ISO 8601 and common variants)

Rows whose timestamps cannot be parsed are included in the output but sorted
last so they don't discard data.
"""

import logging
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

# Candidate timestamp column names, checked in priority order.
TIMESTAMP_COLS = [
    "Timestamp",
    "EventTimeUTC",
    "ContextTimeStamp",
    "EventTime",
    "StartTime",
    "EndTime",
    "CreationTime",
]

# Internal sort column — dropped before the sheet is written.
_SORT_COL = "__timeline_sort_ts__"

# Column inserted first in every timeline row.
_SOURCE_COL = "SourceSheet"


def find_best_timestamp_column(load_results: list, sheet_names: list[str]) -> Optional[str]:
    """
    Return the highest-priority timestamp column name found across the loaded CSVs.

    Iterates through TIMESTAMP_COLS in order and returns the first candidate
    that has at least one non-null value in any loaded sheet.
    Returns None if no candidate is found.
    """
    for candidate in TIMESTAMP_COLS:
        for result in load_results:
            if result.dataframe is None or result.error is not None:
                continue
            cols_lower = {c.lower(): c for c in result.dataframe.columns}
            actual = cols_lower.get(candidate.lower())
            if actual is not None and result.dataframe[actual].notna().any():
                return candidate
    return None


def _parse_ts(series: pd.Series) -> pd.Series:
    """
    Parse a string Series to UTC-aware datetime. Returns NaT for unparseable values.

    Tries numeric epoch (ms then s) first, then general datetime string parsing.
    """
    if series.empty:
        return pd.Series([], dtype="datetime64[ns, UTC]")

    # Attempt numeric interpretation (some EDR platforms export epoch ms as strings).
    numeric = pd.to_numeric(series, errors="coerce")
    n_numeric = int(numeric.notna().sum())

    if n_numeric > 0 and n_numeric >= len(series) * 0.5:
        median = float(numeric.dropna().median())
        if median > 1e12:
            try:
                return pd.to_datetime(numeric, unit="ms", utc=True, errors="coerce")
            except Exception:
                pass
        elif median > 1e9:
            try:
                return pd.to_datetime(numeric, unit="s", utc=True, errors="coerce")
            except Exception:
                pass

    # Fall back to string-based datetime parsing.
    try:
        parsed = pd.to_datetime(series, errors="coerce", utc=True)
        return parsed
    except Exception:
        return pd.Series([pd.NaT] * len(series), index=series.index, dtype="datetime64[ns, UTC]")


def build_timeline_df(
    load_results: list,
    sheet_names: list[str],
    timestamp_col: str,
) -> tuple[Optional[pd.DataFrame], list[str], list[str]]:
    """
    Merge all loaded CSVs into a single chronologically sorted DataFrame.

    Only sheets that contain timestamp_col (case-insensitive) are included.
    A SourceSheet column is prepended; the timestamp column is moved to position 2.

    Returns:
        (merged_df, included_sheet_names, excluded_sheet_names)
        merged_df is None if no sheets contained the timestamp column.
    """
    parts: list[pd.DataFrame] = []
    included: list[str] = []
    excluded: list[str] = []

    # Track all column names in encounter order (for final column ordering).
    seen_cols: dict[str, None] = {_SOURCE_COL: None, timestamp_col: None}

    for result, sheet_name in zip(load_results, sheet_names):
        if result.dataframe is None or result.error is not None:
            excluded.append(sheet_name)
            continue

        df = result.dataframe
        cols_lower = {c.lower(): c for c in df.columns}
        actual_col = cols_lower.get(timestamp_col.lower())

        if actual_col is None:
            excluded.append(sheet_name)
            logger.debug("Timeline: sheet '%s' has no '%s' column — excluded", sheet_name, timestamp_col)
            continue

        # Parse timestamps for the sort key.
        parsed = _parse_ts(df[actual_col])
        n_parsed = int(parsed.notna().sum())
        logger.debug(
            "Timeline: sheet '%s' — %d/%d timestamps parsed",
            sheet_name, n_parsed, len(df),
        )

        part = df.copy()

        # Rename timestamp column to canonical name if the case differs.
        if actual_col != timestamp_col:
            part = part.rename(columns={actual_col: timestamp_col})

        # Guard against a sheet already having a SourceSheet column.
        if _SOURCE_COL in part.columns:
            part = part.rename(columns={_SOURCE_COL: f"{_SOURCE_COL}_orig"})

        part.insert(0, _SOURCE_COL, sheet_name)
        part[_SORT_COL] = parsed.values

        # Record column names (preserving encounter order for the final layout).
        for col in part.columns:
            if col != _SORT_COL:
                seen_cols.setdefault(col, None)

        parts.append(part)
        included.append(sheet_name)

    if not parts:
        return None, included, excluded

    merged = pd.concat(parts, ignore_index=True, sort=False)

    # Sort: rows with parseable timestamps first (ascending), unparseable rows last.
    has_ts = merged[_SORT_COL].notna()
    sorted_df = pd.concat([
        merged[has_ts].sort_values(_SORT_COL, kind="stable"),
        merged[~has_ts],
    ]).reset_index(drop=True)

    sorted_df = sorted_df.drop(columns=[_SORT_COL])

    # Apply the column order established by encounter sequence.
    ordered = [c for c in seen_cols if c in sorted_df.columns]
    remainder = [c for c in sorted_df.columns if c not in seen_cols]
    sorted_df = sorted_df[ordered + remainder]

    sorted_df = sorted_df.fillna("")

    return sorted_df, included, excluded
