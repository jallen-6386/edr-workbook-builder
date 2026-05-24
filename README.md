# EDR Workbook Builder

**Combine CrowdStrike EDR CSV exports into a single formatted Excel workbook.**

A Python CLI tool built for CSIRT/SOC analysts who export process tree logs
from CrowdStrike Falcon and need to quickly assemble them into a clean `.xlsx`
workbook for analysis — including with Excel Copilot.

---

## What it does

1. Reads all `.csv` files in a folder (optionally recursive)
2. Detects the process name from CrowdStrike EDR column names
3. Writes each CSV as a separate worksheet, named after the process
4. Formats every sheet: header row, freeze panes, auto-filter, auto-sized columns
5. Optionally adds an `Analysis_Summary` sheet with case metadata, row counts,
   column inventory matrix, parent/child process relationship table,
   import warnings, analyst notes, and suggested Excel Copilot prompts

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

### Full options

```bash
python edr_csv_to_xlsx.py \
  --input ./exports \
  --output ./output/case123.xlsx \
  --case-name "INC-2024-0042" \
  --summary \
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
| `--input FOLDER` | `-i` | **Required.** Folder containing CSV files |
| `--output FILE` | `-o` | Output `.xlsx` path (default: `edr_analysis_<timestamp>.xlsx`) |
| `--case-name NAME` | | Case or alert name — shown in filename and summary sheet |
| `--summary` | | Add `Analysis_Summary` as the first worksheet |
| `--recursive` | `-r` | Search subfolders for CSV files |
| `--add-source-column` | | Prepend a `SourceFile` column to each worksheet |
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
  before enabling them. A future `--escape-formulas` flag is planned for v0.3.

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
from all supported column types, CSV loading with encoding fallback, and edge
cases (empty files, header-only files, duplicate sheet names, quoted paths).

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
│   ├── csv_loader.py            # CSV discovery and multi-encoding load
│   ├── process_detection.py     # Extract process name from EDR columns
│   ├── sheet_names.py           # Excel sheet name sanitization/dedup
│   ├── workbook.py              # Workbook and worksheet formatting
│   └── summary.py              # Analysis_Summary sheet builder
├── tests/
│   ├── test_sheet_names.py
│   ├── test_process_detection.py
│   └── test_csv_loader.py
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

---

## Version roadmap

| Version | Focus |
|---|---|
| **v0.1** | MVP: folder → workbook, process detection, safe sheet names, optional summary sheet |
| **v0.2** (current) | Better summary: column inventory matrix, parent/child process relationship table |
| **v0.3** | Suspicious pattern highlighting: base64 detection, LOLBin flagging, formula-escape option |
| **v0.4** | Timeline sheet: unified chronological view across all CSVs using timestamp columns |
| **v1.0** | Polished internal SOC utility: config file, MITRE ATT&CK column tagging, process tree reconstruction |

---

## Future enhancement ideas

- **Process tree reconstruction** — if `ParentProcessId` and `ProcessId` columns
  exist, build a visual tree in a dedicated sheet
- **LOLBin detection** — flag rows where the process is a known Living-off-the-Land binary
- **Base64 / encoded command detection** — regex scan of CommandLine fields
- **Timeline sheet** — merge all CSVs on a timestamp column, sorted chronologically
- **MITRE ATT&CK mapping** — tag events with likely technique IDs based on
  process name and command-line patterns
- **CrowdStrike Falcon API integration** — pull exports directly via API instead
  of requiring manual CSV downloads
- **Splunk / Google SecOps CSV support** — extend process detection for alternate
  EDR export formats
- **Simple GUI / drag-and-drop** — Tkinter or a small web UI for analysts who
  prefer not to use the terminal
- **`--escape-formulas` flag** — prefix `=`/`+`/`-` cells with `'` to prevent
  accidental formula execution

---

## License

MIT
