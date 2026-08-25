"""
CSV discovery and loading with multi-encoding fallback.

Reads all files as raw strings (dtype=str) to preserve exact EDR values
without pandas type coercion changing timestamps, hashes, or PID values.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pandas as pd
from pandas.errors import EmptyDataError

logger = logging.getLogger(__name__)

# Tried in order — EDR exports are commonly UTF-8 with or without BOM
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


def _load_and_log(path: Path) -> CSVLoadResult:
    logger.debug("Loading: %s", path.name)
    result = load_csv(path)
    if result.error:
        logger.warning("Could not load %s: %s", path.name, result.error)
    else:
        logger.debug(
            "Loaded %s — %d rows, %d columns (encoding: %s)",
            path.name, result.row_count, result.col_count, result.encoding_used,
        )
    return result


def load_all_csvs(paths: list[Path], max_workers: int = 8) -> list[CSVLoadResult]:
    """Load all CSVs, in parallel when there are multiple files.

    Results are returned in the same order as *paths* regardless of
    which file finishes first.  The worker cap prevents thread storms
    on very large file lists.
    """
    if not paths:
        return []
    if len(paths) == 1:
        return [_load_and_log(paths[0])]

    results: list[Optional[CSVLoadResult]] = [None] * len(paths)
    workers = min(max_workers, len(paths))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_idx = {pool.submit(_load_and_log, p): i for i, p in enumerate(paths)}
        for future in as_completed(future_to_idx):
            results[future_to_idx[future]] = future.result()
    return results  # type: ignore[return-value]
