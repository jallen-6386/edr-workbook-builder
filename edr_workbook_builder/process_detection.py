"""
Detect the primary process name from an EDR CSV DataFrame.

Checks known EDR column names in priority order. Extracts the executable
stem from paths and command lines (handles Windows and Unix paths, quoted
paths, and command lines with arguments).
"""

import logging
import re
from pathlib import Path
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

# Checked in priority order — most specific/reliable column first
_PROCESS_COLUMNS = [
    "ImageFileName",
    "FileName",
    "ProcessName",
    "TargetProcessName",
    "ParentBaseFileName",
    "CommandLine",
]

_PATH_SEP = re.compile(r"[/\\]")


def extract_exe_name(value: str) -> Optional[str]:
    """Return the executable stem from a file path or command-line string."""
    if not value or not isinstance(value, str):
        return None

    value = value.strip()
    if not value:
        return None

    # Quoted path: "C:\Program Files\app.exe" --args  →  C:\Program Files\app.exe
    if value.startswith('"'):
        end = value.find('"', 1)
        value = value[1:end] if end > 1 else value[1:]
    else:
        # Unquoted: grab everything up to the first space.
        # Handles bare paths and command lines: C:\foo\bar.exe /c whoami
        value = value.split()[0]

    if not value:
        return None

    parts = _PATH_SEP.split(value)
    exe = parts[-1] if parts else value
    stem = Path(exe).stem
    return stem if stem else None


def detect_process_name(df: pd.DataFrame) -> Optional[str]:
    """
    Return the most common executable name from the first matching EDR column.

    Returns None if no known process column is found or all values are empty.
    """
    if df.empty and len(df.columns) == 0:
        return None

    columns_lower = {col.lower(): col for col in df.columns}

    for target in _PROCESS_COLUMNS:
        actual = columns_lower.get(target.lower())
        if actual is None:
            continue

        series = df[actual].dropna()
        non_empty = series[series.str.strip() != ""]
        if non_empty.empty:
            continue

        top_value = non_empty.mode().iloc[0]
        name = extract_exe_name(str(top_value))
        if name:
            logger.debug("Process name '%s' detected from column '%s'", name, actual)
            return name

    return None
