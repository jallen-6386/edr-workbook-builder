"""
MITRE ATT&CK technique tagging for EDR rows.

Maps process executable names and command-line patterns to ATT&CK technique IDs.
Used by build_workbook() when --attck is passed to insert an 'ATT&CK' column
into each data sheet alongside the detected process column.
"""

import re
from typing import Optional

import pandas as pd

# Process exe stem (lowercase) → ATT&CK technique IDs.
PROCESS_TECHNIQUES: dict[str, list[str]] = {
    # Scripting / shell interpreters (T1059.*)
    "powershell":           ["T1059.001"],
    "pwsh":                 ["T1059.001"],
    "cmd":                  ["T1059.003"],
    "wscript":              ["T1059.005"],
    "cscript":              ["T1059.005"],
    "bash":                 ["T1059.004"],
    "sh":                   ["T1059.004"],
    "python":               ["T1059.006"],
    "python3":              ["T1059.006"],
    "perl":                 ["T1059.006"],
    "ruby":                 ["T1059.006"],
    # Signed Binary Proxy Execution (T1218.*)
    "rundll32":             ["T1218.011"],
    "mshta":                ["T1218.005"],
    "regsvr32":             ["T1218.010"],
    "msiexec":              ["T1218.007"],
    "installutil":          ["T1218.004"],
    "regasm":               ["T1218.009"],
    "regsvcs":              ["T1218.009"],
    "cmstp":                ["T1218.003"],
    "odbcconf":             ["T1218.008"],
    "forfiles":             ["T1218"],
    "pcalua":               ["T1218"],
    "xwizard":              ["T1218"],
    "mavinject":            ["T1218.013"],
    # Deobfuscate / decode (T1140)
    "certutil":             ["T1140"],
    "expand":               ["T1140"],
    "extrac32":             ["T1140"],
    # BITS jobs
    "bitsadmin":            ["T1197"],
    # Windows Management Instrumentation
    "wmic":                 ["T1047"],
    # Scheduled tasks / jobs
    "schtasks":             ["T1053.005"],
    # Registry modification
    "reg":                  ["T1112"],
    # Service creation / modification
    "sc":                   ["T1543.003"],
    # Discovery
    "whoami":               ["T1033"],
    "systeminfo":           ["T1082"],
    "ipconfig":             ["T1016"],
    "netstat":              ["T1049"],
    "tasklist":             ["T1057"],
    "arp":                  ["T1016"],
    "route":                ["T1016"],
    "nslookup":             ["T1016"],
    "ping":                 ["T1018"],
    "tracert":              ["T1018"],
    "nmap":                 ["T1046"],
    "nltest":               ["T1482"],
    "dsquery":              ["T1087.002"],
    "net":                  ["T1087"],
    "net1":                 ["T1087"],
    # Credential access
    "mimikatz":             ["T1003.001"],
    "procdump":             ["T1003.001"],
    # Lateral movement
    "ssh":                  ["T1021.004"],
    "psexec":               ["T1021.002"],
    # Ingress tool transfer
    "curl":                 ["T1105"],
    "wget":                 ["T1105"],
    # Exfiltration over alt protocol
    "ftp":                  ["T1048"],
    # Impact
    "taskkill":             ["T1489"],
    "vssadmin":             ["T1490"],
    "bcdedit":              ["T1490"],
    "wbadmin":              ["T1490"],
    # Archive collected data
    "7z":                   ["T1560"],
    "winrar":               ["T1560"],
}

# (compiled pattern, [technique IDs]) — scanned against CommandLine values.
_CMDLINE_PATTERNS: list[tuple[re.Pattern, list[str]]] = [
    # Encoded command
    (re.compile(r"-e(?:nc(?:odedcommand)?)?(?:\s+|:)", re.I),                  ["T1027"]),
    # Hidden window
    (re.compile(r"-WindowStyle\s+[Hh]idden", re.I),                            ["T1564.003"]),
    # PowerShell download / execution
    (re.compile(r"(?:iex|invoke-expression)\b", re.I),                         ["T1059.001"]),
    (re.compile(
        r"(?:DownloadString|DownloadFile|WebClient|"
        r"Net\.WebClient|Invoke-WebRequest|\biwr\b)", re.I),                   ["T1105"]),
    # Execution policy bypass
    (re.compile(r"-ExecutionPolicy\s+[Bb]ypass", re.I),                        ["T1562.001"]),
    # Local account creation
    (re.compile(r"net\s+(?:user|localgroup)\b.*/add\b", re.I),                 ["T1136.001"]),
    # Shadow copy deletion
    (re.compile(r"vssadmin\s+delete\s+shadows", re.I),                         ["T1490"]),
    # AV exclusion via MpPreference
    (re.compile(r"(?:Add-MpPreference|Set-MpPreference).*Exclusion", re.I),   ["T1562.001"]),
    # Registry Run key persistence
    (re.compile(r"reg\s+(?:add|delete)\s+.*HKLM.*\\Run", re.I),               ["T1547.001"]),
    # Scheduled task creation
    (re.compile(r"schtasks\s+/create", re.I),                                  ["T1053.005"]),
    # Credential dumping keywords
    (re.compile(r"(?:sekurlsa|logonpasswords|lsadump)", re.I),                 ["T1003.001"]),
    # Archive creation
    (re.compile(r"(?:Compress-Archive|Expand-Archive|\b7z\b)\b", re.I),        ["T1560"]),
]

# EDR process name columns — checked case-insensitively in priority order.
_EXE_COLS = [
    "imagefilename", "filename", "processname",
    "targetprocessname", "parentbasefilename",
]
# EDR command-line columns.
_CMD_COLS = ["commandline"]


def tag_attck(process_exe: str, commandline: str = "") -> list[str]:
    """
    Return a de-duplicated list of ATT&CK technique IDs for one EDR row.

    Matches the process exe stem against PROCESS_TECHNIQUES, then scans
    the command-line value against _CMDLINE_PATTERNS.  Returns [] when
    neither source yields a match.
    """
    seen: set[str] = set()
    out: list[str] = []

    def _add(techs: list[str]) -> None:
        for t in techs:
            if t not in seen:
                seen.add(t)
                out.append(t)

    if process_exe and isinstance(process_exe, str):
        s = process_exe.strip()
        # Handle quoted paths: "C:\Program Files\app.exe" arg → C:\Program Files\app.exe
        if s.startswith('"'):
            end = s.find('"', 1)
            s = s[1:end] if end > 1 else s[1:]
        else:
            s = s.split()[0] if s.split() else s
        # Take the last path component (handles both / and \ separators).
        for sep in ("/", "\\"):
            if sep in s:
                s = s.rsplit(sep, 1)[-1]
        # Strip extension to get the exe stem.
        dot = s.rfind(".")
        stem = (s[:dot] if dot > 0 else s).lower()
        _add(PROCESS_TECHNIQUES.get(stem, []))

    if commandline and isinstance(commandline, str):
        for pattern, techs in _CMDLINE_PATTERNS:
            if pattern.search(commandline):
                _add(techs)

    return out


def add_attck_column(
    df: pd.DataFrame,
    process_col: Optional[str] = None,
    cmdline_col: Optional[str] = None,
) -> pd.DataFrame:
    """
    Return a copy of *df* with an 'ATT&CK' column inserted after *process_col*.

    Auto-detects process and command-line columns when not supplied.
    If no process column is found, the ATT&CK column is appended at the end.
    """
    df = df.copy()
    cols_lower = {c.lower(): c for c in df.columns}

    if process_col is None:
        for key in _EXE_COLS:
            if key in cols_lower:
                process_col = cols_lower[key]
                break

    if cmdline_col is None:
        for key in _CMD_COLS:
            if key in cols_lower:
                cmdline_col = cols_lower[key]
                break

    def _tag_row(row: pd.Series) -> str:
        exe = str(row[process_col]) if process_col and process_col in row.index else ""
        cmd = str(row[cmdline_col]) if cmdline_col and cmdline_col in row.index else ""
        techs = tag_attck(exe, cmd)
        return ", ".join(techs) if techs else ""

    attck_values = df.apply(_tag_row, axis=1)

    if process_col and process_col in df.columns:
        insert_at = df.columns.get_loc(process_col) + 1
    else:
        insert_at = len(df.columns)

    df.insert(insert_at, "ATT&CK", attck_values)
    return df
