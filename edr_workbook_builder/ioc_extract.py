"""
IOC (Indicator of Compromise) extraction from EDR DataFrames.

Scans known hash and IP columns across all loaded CSVs and writes a
deduplicated IOC_Extract sheet with columns: Type, Value, SourceSheets, Count.

Supported IOC types:
  - SHA256  (64 hex chars)
  - SHA1    (40 hex chars)
  - MD5     (32 hex chars)
  - IPv4    (dotted-decimal, excluding loopback and unspecified)

Column detection uses both name-based hints (e.g. 'SHA256', 'RemoteIP') and,
for hash columns, value-pattern validation so mis-named columns are still caught.
"""

import re
import logging
from typing import Optional

import pandas as pd

logger = logging.getLogger(__name__)

# --- Value validators -------------------------------------------------------

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SHA1_RE   = re.compile(r"^[0-9a-fA-F]{40}$")
_MD5_RE    = re.compile(r"^[0-9a-fA-F]{32}$")
_IPV4_RE   = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# IPv4 addresses to ignore — these carry no intelligence value.
_IPV4_IGNORE = frozenset({"0.0.0.0", "127.0.0.1", "255.255.255.255", "::", "::1"})

# --- Column name hints -------------------------------------------------------

# Substrings that indicate a column likely contains hash values.
_HASH_COL_HINTS = frozenset({
    "sha256", "sha1", "md5", "hash", "filehash",
    "sha256hashdata", "md5hashdata", "targetfilehash", "imagefilehash",
})

# Substrings that indicate a column likely contains IP addresses.
_IP_COL_HINTS = frozenset({
    "remoteip", "localip", "destinationip", "sourceip",
    "remoteaddress", "localaddress",
    "networkdestinationip", "networkremoteip",
    "localaddressip4", "remoteaddressip4",
})


def _classify_hash(value: str) -> Optional[str]:
    v = value.strip().upper()
    if _SHA256_RE.match(v):
        return "SHA256"
    if _SHA1_RE.match(v):
        return "SHA1"
    if _MD5_RE.match(v):
        return "MD5"
    return None


def _col_matches_hint(col_lower: str, hints: frozenset[str]) -> bool:
    return any(h in col_lower for h in hints)


def extract_iocs(load_results: list, sheet_names: list[str]) -> pd.DataFrame:
    """
    Extract unique IOCs from all loaded CSVs.

    Returns a DataFrame with columns: Type, Value, SourceSheets, Count.
    Sorted by type, then descending hit count, then value.
    Returns an empty DataFrame (with those columns) when nothing is found.
    """
    # (type, normalised_value) → set of sheet names that contained it
    hits: dict[tuple[str, str], set[str]] = {}

    for result, sheet_name in zip(load_results, sheet_names):
        if result.error or result.dataframe is None:
            continue

        df = result.dataframe
        cols_lower = {c.lower(): c for c in df.columns}

        for col_lower, actual_col in cols_lower.items():
            is_hash_hint = _col_matches_hint(col_lower, _HASH_COL_HINTS)
            is_ip_hint   = _col_matches_hint(col_lower, _IP_COL_HINTS)

            if not is_hash_hint and not is_ip_hint:
                continue

            series = df[actual_col].dropna()
            for raw_val in series:
                v = str(raw_val).strip()
                if not v or v.lower() in ("nan", "none", ""):
                    continue

                if is_hash_hint:
                    h_type = _classify_hash(v)
                    if h_type:
                        key = (h_type, v.upper())
                        hits.setdefault(key, set()).add(sheet_name)

                if is_ip_hint and _IPV4_RE.match(v) and v not in _IPV4_IGNORE:
                    key = ("IPv4", v)
                    hits.setdefault(key, set()).add(sheet_name)

    _EMPTY = pd.DataFrame(columns=["Type", "Value", "SourceSheets", "Count"])
    if not hits:
        return _EMPTY

    rows = []
    for (ioc_type, ioc_val), sheets in hits.items():
        rows.append({
            "Type":         ioc_type,
            "Value":        ioc_val,
            "SourceSheets": ", ".join(sorted(sheets)),
            "Count":        len(sheets),
        })

    df_out = pd.DataFrame(rows)
    df_out = df_out.sort_values(
        ["Type", "Count", "Value"],
        ascending=[True, False, True],
    ).reset_index(drop=True)

    logger.debug("IOC_Extract: %d unique indicator(s) found", len(df_out))
    return df_out
