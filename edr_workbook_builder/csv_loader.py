"""
CSV discovery and loading with multi-encoding fallback.

Reads all files as raw strings (dtype=str) to preserve exact EDR values
without pandas type coercion changing timestamps, hashes, or PID values.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pandas as pd
from pandas.errors import EmptyDataError

logger = logging.getLogger(__name__)

# Tried in order — CrowdStrike exports are usually UTF-8 with BOM
_ENCODINGS = ["utf-8-sig", "utf-8", "windows-1252", "latin-1"]


@dataclass
class CSVLoadResult:
    path: Path
    dataframe: Optional[pd.DataFrame]
    encoding_used: Optional[str]
    error: Optional[str]
    row_count: int = 0
    col_count: int = 0


def find_csv_files(folder: Path, recursive: bool = False) -> list[Path]:
    pattern = "**/*.csv" if recursive else "*.csv"
    return sorted(f for f in folder.glob(pattern) if f.is_file())


def load_csv(path: Path) -> CSVLoadResult:
    for encoding in _ENCODINGS:
        try:
            df = pd.read_csv(path, encoding=encoding, dtype=str, low_memory=False)
            return CSVLoadResult(
                path=path,
                dataframe=df,
                encoding_used=encoding,
                error=None,
                row_count=len(df),
                col_count=len(df.columns),
            )
        except EmptyDataError:
            return CSVLoadResult(
                path=path,
                dataframe=pd.DataFrame(),
                encoding_used=encoding,
                error="Empty file — no data or header row",
                row_count=0,
                col_count=0,
            )
        except UnicodeDecodeError:
            continue
        except Exception as exc:
            return CSVLoadResult(
                path=path,
                dataframe=None,
                encoding_used=None,
                error=str(exc),
            )

    return CSVLoadResult(
        path=path,
        dataframe=None,
        encoding_used=None,
        error=(
            "Could not decode file with any supported encoding "
            "(tried: utf-8-sig, utf-8, windows-1252, latin-1)"
        ),
    )


def load_all_csvs(paths: list[Path]) -> list[CSVLoadResult]:
    results = []
    for path in paths:
        logger.debug("Loading: %s", path.name)
        result = load_csv(path)
        if result.error:
            logger.warning("Could not load %s: %s", path.name, result.error)
        else:
            logger.debug(
                "Loaded %s — %d rows, %d columns (encoding: %s)",
                path.name, result.row_count, result.col_count, result.encoding_used,
            )
        results.append(result)
    return results
