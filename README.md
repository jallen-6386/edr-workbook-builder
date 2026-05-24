# EDR Workbook Builder

**Combine CrowdStrike EDR CSV exports into a single formatted Excel workbook.**

A Python CLI tool built for CSIRT/SOC analysts who export process tree logs
from CrowdStrike Falcon and need to quickly assemble them into a clean `.xlsx`
workbook for analysis — including with Excel Copilot.

---

## What it does

1. Reads all `.csv` files in one or more folders (optionally recursive), loading
   them in parallel for fast turnaround on large export sets
2. Detects the process name from CrowdStrike EDR column names
3. Writes each CSV as a separate worksheet, named after the process
4. Formats every sheet: header row, freeze panes, auto-filter, auto-sized columns
5. Optionally creates a **Timeline** sheet — all events merged and sorted
   chronologically across every CSV on the best shared timestamp column
6. Optionally highlights suspicious rows — LOLBin processes (yellow), possible
   obfuscation (salmon), PowerShell `-EncodedCommand` (red) — with `--highlight`
7. Optionally adds an `Analysis_Summary` sheet with case metadata, row counts,
   column inventory matrix, parent/child process relationship table, suspicious
   activity summary, analyst notes, and suggested Excel Copilot prompts
8. Optionally tags rows with MITRE ATT&CK technique IDs and names (`--attck`)
9. Optionally reconstructs the process tree across all sheets (`--process-tree`)
10. Optionally decodes PowerShell `-EncodedCommand` blobs inline (`--decode-encoded`)
11. Optionally extracts IOCs (hashes, IP addresses) into a deduplicated sheet (`--ioc-extract`)

---

## Requirements

- Python 3.10+
- `pandas >= 2.0`
- `openpyxl >= 3.1`

---

## Installation

```bash
# Clone or download the project
cd edr-workbook-builder

# Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate      # macOS/Linux
.venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt

# Optional: install as a package so `edr-workbook-builder` works anywhere
pip install -e .
```

---

## Usage

### Minimal — folder of CSVs → workbook

```bash
python edr_csv_to_xlsx.py --input ./crowdstrike_exports
```

Output: `edr_analysis_20240612_143022.xlsx` in the current directory.

---

### Multiple input folders

```bash
python edr_csv_to_xlsx.py -i ./exports_host1 -i ./exports_host2 -i ./exports_host3
```

Pass `--input` / `-i` multiple times to combine exports from different hosts or
time windows into a single workbook in one pass.

---

### Specify output path

```bash
python edr_csv_to_xlsx.py -i ./exports -o ./case123_edr_analysis.xlsx
```

---

### Add a case name (embedded in filename and summary sheet)

```bash
python edr_csv_to_xlsx.py \
  -i ./exports \
  --case-name "Falcon Alert - Suspicious PowerShell" \
  --summary
```

Output: `edr_analysis_Falcon_Alert___Suspicious_PowerShell_20240612_143022.xlsx`

---

### Add a Timeline sheet

```bash
python edr_csv_to_xlsx.py -i ./exports --timeline
```

Merges all CSV events into a single **Timeline** sheet (green tab) sorted
chronologically. Automatically detects the best shared timestamp column
(`Timestamp`, `EventTimeUTC`, `ContextTimeStamp`, etc.). A `SourceSheet` column
is prepended so every row traces back to its origin. Sheets that don't contain
the chosen column are excluded with a warning.

---

### Highlight suspicious rows

```bash
python edr_csv_to_xlsx.py -i ./exports --summary --highlight
```

Rows are color-coded in each data sheet:
- **Yellow** — LOLBin process (powershell, rundll32, certutil, mshta, …)
- **Salmon** — possible base64 or hex-encoded argument
- **Red** — PowerShell `-EncodedCommand` detected

The `Analysis_Summary` sheet gains a **Suspicious Activity** section listing every
flagged row when `--highlight` and `--summary` are used together.

---

### Prevent formula injection

```bash
python edr_csv_to_xlsx.py -i ./exports --escape-formulas
```

Cell values starting with `=`, `+`, `-`, or `@` are prefixed with `'` so Excel
does not interpret them as formulas when the workbook is opened.

---

### Tag rows with MITRE ATT&CK techniques

```bash
python edr_csv_to_xlsx.py -i ./exports --attck
```

Adds an `ATT&CK` column to each data sheet immediately after the detected process
name column. Technique IDs and their human-readable names are derived from both
the process executable name (e.g., `powershell.exe` → `T1059.001 (PowerShell)`)
and command-line patterns (e.g., `-EncodedCommand` → `T1027 (Obfuscated Files or
Information)`, `-WindowStyle Hidden` → `T1564.003 (Hidden Window)`). Multiple
matching techniques are comma-separated in the same cell.

---

### Reconstruct the process tree

```bash
python edr_csv_to_xlsx.py -i ./exports --process-tree
```

Adds a **ProcessTree** sheet (purple tab) built from `ProcessId` /
`ParentProcessId` columns across all CSVs. Displays parent → child relationships
with `├─` / `└─` tree characters. Columns: `Process`, `PID`, `PPID`,
`CommandLine`, `SourceSheet`. Capped at 500 nodes; cycles are skipped.

PID recycling is handled correctly: the same numeric PID appearing in exports from
different time windows is treated as a separate node (keyed by `sheet:PID`), so
unrelated processes that happen to share a PID don't collapse into one node.

---

### Decode PowerShell -EncodedCommand blobs

```bash
python edr_csv_to_xlsx.py -i ./exports --decode-encoded
```

Adds a `DecodedCommand` column immediately after the `CommandLine` column on any
sheet where at least one row contains a PowerShell `-EncodedCommand` (or `-enc`,
`-en`, `-e`) payload. The base64/UTF-16-LE blob is decoded to plain text so you
can read the script without a separate decoding step. Rows without an encoded
command get an empty cell. Sheets with no encoded commands are not changed.

---

### Extract IOCs to a dedicated sheet

```bash
python edr_csv_to_xlsx.py -i ./exports --ioc-extract
```

Scans all loaded CSVs for hash and IP address values and writes a deduplicated
**IOC_Extract** sheet (orange tab) as the first sheet in the workbook. Columns:
`Type`, `Value`, `SourceSheets`, `Count`.

Supported IOC types:

| Type | Detection |
|---|---|
| SHA256 | 64-char hex string in any column whose name hints at a hash |
| SHA1 | 40-char hex string in a hash-hinted column |
| MD5 | 32-char hex string in a hash-hinted column |
| IPv4 | Valid IPv4 address in a column hinted at remote/local/destination IPs |

Loopback (`127.0.0.1`), unspecified (`0.0.0.0`), and broadcast addresses are
excluded automatically. If no IOC columns are found, the sheet is not created.

---

### Filter to specific columns

```bash
python edr_csv_to_xlsx.py -i ./exports --columns "Timestamp,ImageFileName,CommandLine,SHA256"
```

Only the named columns are written to each data sheet. Columns that don't exist
in a particular CSV are silently skipped. If no columns match, the full
DataFrame is kept unchanged. This is useful for reducing workbook size when you
only care about a subset of EDR fields.

---

### Cap row count per sheet

```bash
python edr_csv_to_xlsx.py -i ./exports --max-rows 5000
```

Truncates each data sheet to the first N rows after loading. Useful when a single
CSV is too large for comfortable Excel navigation. A warning is logged for any
sheet that was truncated.

---

### Extend the LOLBin watchlist

```bash
python edr_csv_to_xlsx.py -i ./exports --highlight
```

The built-in LOLBin set (47 entries, sourced from the
[LOLBAS project](https://lolbas-project.github.io)) can be extended via the
config file without editing source code:

```ini
# .edr-workbook-builder.ini  (local) or ~/.config/edr-workbook-builder/config.ini (global)
[watchlist]
extra_lolbins = customtool, internal_runner, deploy_helper
```

The extra stems are merged with the baseline set at startup and apply to all
`--highlight` and `--summary` suspicious pattern checks.

---

### Save default flags to a config file

```bash
python edr_csv_to_xlsx.py -i ./exports --summary --highlight --attck --save-config
```

Writes the current flag values to `.edr-workbook-builder.ini` in the current
directory. Subsequent runs in the same directory pick up those defaults
automatically, so you don't have to retype `--summary --highlight --attck`
every time. Use `--no-summary` (etc.) to override a saved default for one run.

A global default config can also be placed at
`~/.config/edr-workbook-builder/config.ini`.

---

### Full options

```bash
python edr_csv_to_xlsx.py \
  --input ./exports \
  --output ./output/case123.xlsx \
  --case-name "INC-2024-0042" \
  --summary \
  --timeline \
  --highlight \
  --attck \
  --process-tree \
  --decode-encoded \
  --ioc-extract \
  --columns "Timestamp,ImageFileName,CommandLine,SHA256,RemoteIP" \
  --max-rows 10000 \
  --escape-formulas \
  --recursive \
  --add-source-column \
  --verbose
```

---

### Preview without creating any files

```bash
python edr_csv_to_xlsx.py --input ./exports --dry-run
```

---

## CLI Reference

| Argument | Short | Description |
|---|---|---|
| `--input FOLDER` | `-i` | **Required.** Folder containing CSV files. Repeat for multiple folders. |
| `--output FILE` | `-o` | Output `.xlsx` path (default: `edr_analysis_<timestamp>.xlsx`) |
| `--case-name NAME` | | Case or alert name — shown in filename and summary sheet |
| `--summary` / `--no-summary` | | Add `Analysis_Summary` as the first worksheet |
| `--timeline` / `--no-timeline` | | Add a Timeline sheet: all events merged and sorted chronologically |
| `--highlight` / `--no-highlight` | | Color-code suspicious rows (LOLBin, obfuscation, encoded commands) |
| `--escape-formulas` / `--no-escape-formulas` | | Prefix `=`/`+`/`-`/`@` cell values with `'` to prevent formula injection |
| `--attck` / `--no-attck` | | Add an `ATT&CK` column with MITRE technique IDs and names to each data sheet |
| `--process-tree` / `--no-process-tree` | | Add a ProcessTree sheet (purple tab) from ProcessId/ParentProcessId columns |
| `--decode-encoded` / `--no-decode-encoded` | | Add a `DecodedCommand` column decoding PowerShell -EncodedCommand blobs |
| `--ioc-extract` / `--no-ioc-extract` | | Add an IOC_Extract sheet (orange tab) with deduplicated hashes and IPs |
| `--columns COLS` | | Comma-separated list of columns to include in data sheets |
| `--max-rows N` | | Truncate each data sheet to the first N rows |
| `--recursive` / `--no-recursive` | `-r` | Search subfolders for CSV files |
| `--add-source-column` / `--no-add-source-column` | | Prepend a `SourceFile` column to each worksheet |
| `--config FILE` | | Load additional config from FILE (overrides global and local config) |
| `--save-config` | | Save current flag values to `.edr-workbook-builder.ini` |
| `--verbose` | `-v` | Debug-level logging |
| `--dry-run` | | Show what would happen without writing output |
| `--version` | `-V` | Print version and exit |

---

## Workbook formatting

Each data worksheet gets:

- **Header row** — dark blue background, white bold text (Calibri 11)
- **Freeze panes** — header stays visible while scrolling
- **Auto-filter** — click any column header to filter immediately
- **Auto-sized columns** — sampled from up to 500 rows, capped at 60 chars
  (prevents `CommandLine` columns from making the sheet unusably wide)
- **Worksheet name** — derived from the most common process name in the CSV,
  truncated and sanitized to satisfy Excel's 31-character limit

---

## Process name detection

The tool looks for these columns **in priority order**:

1. `ImageFileName` ← most reliable for CrowdStrike process events
2. `FileName`
3. `ProcessName`
4. `TargetProcessName`
5. `ParentBaseFileName`
6. `CommandLine`

Column matching is **case-insensitive**. The most common non-null value
(statistical mode) is used so that a process tree with mixed entries picks
the dominant process.

Path extraction examples:

| Raw value | Worksheet name |
|---|---|
| `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `powershell` |
| `"C:\Program Files\SomeApp\helper.exe" --flag` | `helper` |
| `/usr/bin/python3` | `python3` |
| `rundll32.exe shell32.dll,Control_RunDLL` | `rundll32` |

If no process name can be detected, the CSV filename (without extension) is
used as the sheet name. Duplicate process names are handled automatically:
`powershell`, `powershell_2`, `powershell_3`, …

---

## Analysis_Summary sheet

When `--summary` is passed, the first worksheet contains:

- **Case information** — case/alert name, generation timestamp, tool version
- **Processing statistics** — files found, processed, skipped, total row count
- **Worksheet inventory** — table of sheet name / source CSV / detected process / row count / status
- **Column inventory matrix** — per-sheet table showing row count, column count, and which key EDR
  field groups are present (Timestamp, ProcessId, ImageFileName, CommandLine, ParentProcessId,
  ParentProcess, Network, FileTarget, Hash, Registry) plus the full column list
- **Parent/child process relationship table** — automatically built from `ParentProcessId` /
  `ProcessId` columns when present; shows unique parent→child process pairs with PIDs and source sheet
- **Suspicious Activity summary** — when `--highlight` is also used, lists every flagged row with
  sheet, row number, process name, detected pattern, and severity (High / Medium / Info)
- **Import errors** — any files that could not be loaded and why
- **Analyst notes** — 6 blank lines for manual notes during analysis
- **Suggested Excel Copilot prompts** — ready-to-paste prompts for EDR analysis:
  - Summarize suspicious process activity across all sheets
  - Identify unusual command-line arguments
  - Find network connections, file writes, registry modifications, encoded commands
  - Compare parent/child process relationships
  - Identify LOLBin usage (powershell, rundll32, regsvr32, mshta, certutil, …)
  - Look for base64-encoded or obfuscated arguments
  - Build a chronological timeline from timestamp fields
  - Identify lateral movement indicators

---

## Safe usage with CrowdStrike EDR exports

**This tool is designed for secure internal SOC use:**

- Reads local files only — no network access, no external API calls
- Never modifies or deletes source CSV files
- Does not print EDR data values to the console (only file names, row counts, column names)
- Verbose mode (`--verbose`) only emits additional process names and column metadata —
  never full command lines or hash values
- All values are written to Excel as plain strings; no formulas are evaluated

**Be aware of:**

- **CSV injection / formula injection**: If a CrowdStrike CSV contains a cell
  that starts with `=`, `+`, or `-` (possible in CommandLine fields), Excel may
  interpret it as a formula when you open the file. This is a general Excel risk
  with any external data. Mitigate by keeping Excel macro security at the default
  "Disable all macros with notification" setting and reviewing any prompted formulas
  before enabling them. Use `--escape-formulas` to prefix vulnerable cell values
  with `'` and prevent accidental formula execution.

- **Sensitive data in the workbook**: The `.xlsx` output contains the full content
  of your EDR exports. Handle it with the same care as the source CSVs —
  appropriate access controls, no sharing outside the case team, and deletion
  after retention period.

- **Do not commit real case data** to version control.

---

## Running tests

```bash
pip install pytest
pytest
```

Tests cover: sheet name sanitization and deduplication, process name detection
from all supported column types, CSV loading with encoding fallback and parallel
loading, edge cases (empty files, header-only files, duplicate sheet names,
quoted paths), suspicious pattern detection (LOLBin, base64, hex blobs),
PowerShell -EncodedCommand decoding, configurable LOLBin watchlist, MITRE ATT&CK
tagging with human-readable technique names, process tree construction and PID
recycling, IOC extraction and deduplication, config file loading/saving, and
full integration tests that build real `.xlsx` files and inspect them.

---

## Project structure

```
edr-workbook-builder/
├── edr_csv_to_xlsx.py           # Convenience entry point (run directly)
├── requirements.txt
├── pyproject.toml
├── edr_workbook_builder/
│   ├── __init__.py              # Package version
│   ├── __main__.py              # python -m edr_workbook_builder
│   ├── cli.py                   # Argument parsing and orchestration
│   ├── config.py                # INI config file loading and saving
│   ├── csv_loader.py            # CSV discovery, multi-encoding load, parallel loading
│   ├── process_detection.py     # Extract process name from EDR columns
│   ├── sheet_names.py           # Excel sheet name sanitization/dedup
│   ├── workbook.py              # Workbook and worksheet formatting
│   ├── summary.py               # Analysis_Summary sheet builder
│   ├── patterns.py              # LOLBin/obfuscation detection, PS decode, configurable watchlist
│   ├── timeline.py              # Timeline sheet: merged, chronologically sorted
│   ├── attck.py                 # MITRE ATT&CK technique tagging with human-readable names
│   ├── proctree.py              # Process tree reconstruction (DFS, PID recycling aware)
│   └── ioc_extract.py           # IOC extraction: hashes, IPs, deduplicated output
├── tests/
│   ├── test_sheet_names.py
│   ├── test_process_detection.py
│   ├── test_csv_loader.py
│   ├── test_patterns.py
│   ├── test_summary_helpers.py
│   ├── test_timeline.py
│   ├── test_attck.py
│   ├── test_proctree.py
│   ├── test_config.py
│   ├── test_decode_and_lolbins.py
│   ├── test_ioc_extract.py
│   └── test_integration.py
└── examples/
    └── sample_exports/
```

---

## Library choices

| Library | Why |
|---|---|
| **pandas** | Best CSV loader: handles encoding fallback, malformed rows, and `dtype=str` preserves raw EDR values (hashes, PIDs, timestamps) without type coercion |
| **openpyxl** | The correct choice for `.xlsx`: supports formatting, freeze panes, auto-filter, workbook metadata. xlsxwriter can't read, xlrd is read-only, xlwt is `.xls` only |
| **argparse** | Standard library — zero extra dependency, easy for a security team to audit, works everywhere Python is installed |
| **pathlib** | Cross-platform path handling with no extra dependency |
| **logging** | Standard library structured logging with configurable verbosity |
| **concurrent.futures** | Standard library thread pool for parallel CSV loading — no extra dependency, safe for I/O-bound work |

---

## Version roadmap

| Version | Focus |
|---|---|
| **v0.1** | MVP: folder → workbook, process detection, safe sheet names, optional summary sheet |
| **v0.2** | Better summary: column inventory matrix, parent/child process relationship table |
| **v0.3** | Suspicious pattern highlighting: LOLBin flagging, base64/encoded command detection, `--escape-formulas` |
| **v0.4** | Timeline sheet: all events merged and sorted chronologically by detected timestamp column |
| **v1.0** | Config file (`--save-config`), MITRE ATT&CK column tagging (`--attck`), process tree reconstruction (`--process-tree`) |
| **v1.1** (current) | ATT&CK technique names, PowerShell decode (`--decode-encoded`), IOC extraction (`--ioc-extract`), parallel CSV loading, column filter (`--columns`), row cap (`--max-rows`), multiple `--input` folders, configurable LOLBin watchlist, PID recycling fix |

---

## Future enhancement ideas

- **CrowdStrike Falcon API integration** — pull exports directly via API instead
  of requiring manual CSV downloads
- **Splunk / Google SecOps CSV support** — extend process detection for alternate
  EDR export formats
- **Simple GUI / drag-and-drop** — Tkinter or a small web UI for analysts who
  prefer not to use the terminal
- **MITRE ATT&CK sheet** — dedicated worksheet with all technique hits aggregated
  across every CSV, with technique descriptions and external links
- **Sigma rule matching** — scan CommandLine fields against a local Sigma rule set
  and annotate matching rows

---

## License

MIT
