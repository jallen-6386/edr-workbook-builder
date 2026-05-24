"""
Suspicious pattern detection for CrowdStrike EDR data rows.

Detects:
  - LOLBin (Living-off-the-Land Binary) process names
  - PowerShell -EncodedCommand patterns
  - Long base64-encoded argument blobs
  - Long hex-encoded argument blobs

Used by workbook.py to highlight suspicious rows and by summary.py to
populate the Suspicious Activity section.
"""

import base64
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import pandas as pd

from edr_workbook_builder.process_detection import extract_exe_name

logger = logging.getLogger(__name__)

# Known LOLBins — exe stems, lowercase.
# Core set sourced from LOLBAS project (lolbas-project.github.io).
LOLBINS: frozenset[str] = frozenset({
    "bash", "bitsadmin", "certutil", "cmd", "cmstp",
    "csc", "cscript", "desktopimgdownldr", "diskshadow", "dnscmd",
    "esentutl", "expand", "extrac32", "findstr", "forfiles",
    "ftp", "hh", "ieexec", "infdefaultinstall", "installutil",
    "makecab", "mavinject", "msbuild", "msdeploy", "msdt",
    "mshta", "msiexec", "odbcconf", "pcalua", "powershell",
    "powershell_ise", "presentationhost", "pubprn", "regasm",
    "regsvcs", "regsvr32", "replace", "rundll32", "runscripthelper",
    "schtasks", "scriptrunner", "syncappvpublishingserver",
    "wmic", "wscript", "xwizard",
})

# Process-name columns checked for LOLBin matches, in priority order.
_PROC_COLS = [
    "imagefilename", "filename", "processname",
    "targetprocessname", "parentbasefilename",
]

# CommandLine columns.
_CMD_COLS = ["commandline"]

# PowerShell -EncodedCommand and common abbreviations (-Enc, -En, -E).
# Requires at least 16 base64 chars following the flag (16 chars → 12 decoded bytes,
# the smallest meaningful PS payload).
_PS_ENCODE_RE = re.compile(
    r"-e(?:nc(?:odedcommand)?)?(?:\s+|:)([A-Za-z0-9+/]{16,}={0,2})",
    re.IGNORECASE,
)

# Standalone base64 blob of 80+ chars, not adjacent to other base64 chars.
_BASE64_BLOB_RE = re.compile(
    r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{80,}={0,2})(?![A-Za-z0-9+/=])"
)

# Hex blob of 100+ contiguous hex characters.
_HEX_BLOB_RE = re.compile(r"[0-9A-Fa-f]{100,}")

# Cell values starting with these characters may trigger Excel formula execution.
FORMULA_PFXS: frozenset[str] = frozenset("=+-@")


@dataclass
class SuspiciousMatch:
    reason: str
    severity: int         # 1 = LOLBin, 2 = obfuscation, 3 = encoded command
    column: Optional[str] = None
    process_exe: Optional[str] = None   # exe stem, set for LOLBin matches only


@dataclass
class RowFinding:
    sheet_name: str
    data_row: int          # 1-indexed row number in the data (excludes header)
    process_name: str      # exe stem from a LOLBin match, or ""
    reasons: list[str]     # human-readable match descriptions
    severity: int          # highest severity across all matches for this row


# Runtime-configurable set — starts as the baseline LOLBINS and can be
# extended at startup via configure_lolbins() without changing the source.
_effective_lolbins: frozenset[str] = LOLBINS


def configure_lolbins(extra: list[str]) -> None:
    """
    Extend the LOLBin detection set with additional exe stems.

    Call once at startup (e.g. from cli.py after reading config).
    Stems are lower-cased and stripped before being added.
    """
    global _effective_lolbins
    cleaned = frozenset(e.strip().lower() for e in extra if e.strip())
    _effective_lolbins = LOLBINS | cleaned
    if cleaned:
        logger.debug("Extra LOLBins configured: %s", ", ".join(sorted(cleaned)))


def is_lolbin(process_name: str) -> bool:
    """Return True if the exe stem is in the effective LOLBin set."""
    return process_name.lower() in _effective_lolbins


def check_commandline(value: str) -> Optional[SuspiciousMatch]:
    """Return the highest-severity obfuscation match for a CommandLine value, or None."""
    if not value or not isinstance(value, str):
        return None
    v = value.strip()
    if not v or v == "nan":
        return None
    if _PS_ENCODE_RE.search(v):
        return SuspiciousMatch(reason="Encoded PowerShell (-EncodedCommand)", severity=3)
    if _BASE64_BLOB_RE.search(v):
        return SuspiciousMatch(reason="Possible base64-encoded argument (80+ chars)", severity=2)
    if _HEX_BLOB_RE.search(v):
        return SuspiciousMatch(reason="Possible hex-encoded argument (100+ chars)", severity=2)
    return None


def check_row(row_data: pd.Series) -> list[SuspiciousMatch]:
    """
    Return suspicious pattern matches for a single DataFrame row.

    Checks process-name columns for LOLBin matches (severity 1) and CommandLine
    for obfuscation patterns (severity 2-3). Returns matches sorted by
    descending severity so the most critical finding is always first.
    """
    matches: list[SuspiciousMatch] = []
    cols_lower = {str(c).lower(): c for c in row_data.index}

    # LOLBin check — first matching process column wins.
    for proc_key in _PROC_COLS:
        if proc_key in cols_lower:
            col = cols_lower[proc_key]
            raw = str(row_data[col]).strip()
            if raw and raw != "nan":
                exe = extract_exe_name(raw)
                if exe and is_lolbin(exe):
                    matches.append(SuspiciousMatch(
                        reason=f"LOLBin: {exe.lower()}",
                        severity=1,
                        column=str(col),
                        process_exe=exe.lower(),
                    ))
            break

    # CommandLine obfuscation check — first matching column wins.
    for cmd_key in _CMD_COLS:
        if cmd_key in cols_lower:
            col = cols_lower[cmd_key]
            raw = str(row_data[col]).strip()
            m = check_commandline(raw)
            if m:
                m.column = str(col)
                matches.append(m)
            break

    matches.sort(key=lambda m: m.severity, reverse=True)
    return matches


def max_severity(matches: list[SuspiciousMatch]) -> int:
    """Return the highest severity across a list of matches, or 0 if empty."""
    return max((m.severity for m in matches), default=0)


def decode_ps_commandline(value: str) -> Optional[str]:
    """
    Decode a PowerShell -EncodedCommand base64 blob to plain text.

    Returns the decoded UTF-16-LE string when a match is found, or None.
    Non-printable characters other than tabs and newlines are replaced with
    a Unicode replacement character so the result is always safe to write
    to a cell.
    """
    if not value or not isinstance(value, str):
        return None
    m = _PS_ENCODE_RE.search(value)
    if not m:
        return None
    b64 = m.group(1)
    # Pad to a multiple of 4 if needed.
    remainder = len(b64) % 4
    if remainder:
        b64 += "=" * (4 - remainder)
    try:
        raw = base64.b64decode(b64)
        text = raw.decode("utf-16-le", errors="replace").strip("\x00").strip()
        return text if text else None
    except Exception:
        return None


def add_decoded_column(df: pd.DataFrame) -> pd.DataFrame:
    """
    Return a copy of *df* with a 'DecodedCommand' column inserted after
    the CommandLine column when at least one row contains an encoded command.

    Rows without an encoded command get an empty string.  The column is
    omitted entirely when no encoded commands are found in the sheet.
    """
    df = df.copy()
    cols_lower = {c.lower(): c for c in df.columns}
    cmd_col = cols_lower.get("commandline")
    if cmd_col is None:
        return df

    decoded = df[cmd_col].apply(lambda v: decode_ps_commandline(str(v)) or "")

    if not decoded.any():
        return df

    insert_at = df.columns.get_loc(cmd_col) + 1
    df.insert(insert_at, "DecodedCommand", decoded)
    return df
