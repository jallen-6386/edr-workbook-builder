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

import re
from dataclasses import dataclass, field
from typing import Optional

import pandas as pd

from edr_workbook_builder.process_detection import extract_exe_name

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


def is_lolbin(process_name: str) -> bool:
    """Return True if the exe stem is a known LOLBin."""
    return process_name.lower() in LOLBINS


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
