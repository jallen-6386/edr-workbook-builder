"""
Analysis_Summary sheet builder.

Creates the first worksheet with case metadata, processing statistics,
a per-sheet inventory table, analyst notes area, and suggested Excel
Copilot prompts for EDR analysis.
"""

from datetime import datetime
from typing import Optional

from openpyxl.styles import Alignment, Font, PatternFill

_TITLE_FONT = Font(name="Calibri", bold=True, size=14, color="1F497D")
_SECTION_FONT = Font(name="Calibri", bold=True, size=11, color="1F497D")
_LABEL_FONT = Font(name="Calibri", bold=True, size=10)
_VALUE_FONT = Font(name="Calibri", size=10)
_TABLE_HDR_FONT = Font(name="Calibri", bold=True, color="FFFFFF", size=10)
_TABLE_HDR_FILL = PatternFill(start_color="1F497D", end_color="1F497D", fill_type="solid")
_WARN_FONT = Font(name="Calibri", size=10, color="C00000")

_COPILOT_PROMPTS = [
    "Summarize suspicious process activity across all sheets in this workbook.",
    "Identify unusual or suspicious command-line arguments.",
    "Find all network connections, file writes, registry modifications, or encoded commands.",
    "Compare parent and child process relationships and identify anomalies.",
    "Identify indicators that suggest benign activity versus suspicious activity.",
    "List all unique processes and their frequency of occurrence.",
    (
        "Identify LOLBin usage: powershell, rundll32, regsvr32, mshta, certutil, "
        "wscript, cscript, bitsadmin, schtasks, cmd."
    ),
    "Look for base64-encoded or otherwise obfuscated command-line arguments.",
    "Build a chronological timeline of events using available timestamp fields.",
    "Identify lateral movement indicators such as remote host connections or admin share access.",
]


def _section(ws, row: int, title: str) -> int:
    ws.cell(row=row, column=1, value=title).font = _SECTION_FONT
    return row + 1


def _kv(ws, row: int, label: str, value: str = "", warn: bool = False) -> int:
    ws.cell(row=row, column=1, value=label).font = _LABEL_FONT
    cell = ws.cell(row=row, column=2, value=value)
    cell.font = _WARN_FONT if warn else _VALUE_FONT
    return row + 1


def create_summary_sheet(
    ws,
    case_name: Optional[str],
    timestamp: datetime,
    load_results: list,
    sheet_names: list[str],
    process_names: list[Optional[str]],
) -> None:
    successful = [r for r in load_results if r.error is None and r.dataframe is not None]
    failed = [r for r in load_results if r.error is not None]
    total_rows = sum(r.row_count for r in successful)

    row = 1
    ws.cell(row=row, column=1, value="EDR Analysis Workbook — Summary").font = _TITLE_FONT
    row += 2

    row = _section(ws, row, "CASE INFORMATION")
    row = _kv(ws, row, "Case / Alert:", case_name or "(not provided)")
    row = _kv(ws, row, "Generated:", timestamp.strftime("%Y-%m-%d %H:%M:%S"))
    row = _kv(ws, row, "Tool:", "EDR Workbook Builder v0.1.0")
    row += 1

    row = _section(ws, row, "PROCESSING STATISTICS")
    row = _kv(ws, row, "CSV files found:", str(len(load_results)))
    row = _kv(ws, row, "Files processed:", str(len(successful)))
    row = _kv(ws, row, "Files skipped (errors):", str(len(failed)), warn=bool(failed))
    row = _kv(ws, row, "Total data rows:", f"{total_rows:,}")
    row = _kv(ws, row, "Worksheets created:", str(len(successful)))
    row += 1

    # Inventory table
    row = _section(ws, row, "WORKSHEET INVENTORY")
    headers = ["Sheet Name", "Source CSV", "Detected Process", "Row Count", "Status"]
    for c_idx, h in enumerate(headers, start=1):
        cell = ws.cell(row=row, column=c_idx, value=h)
        cell.font = _TABLE_HDR_FONT
        cell.fill = _TABLE_HDR_FILL
        cell.alignment = Alignment(horizontal="left")
    row += 1

    for result, sheet_name, proc_name in zip(load_results, sheet_names, process_names):
        status = "OK" if result.error is None else f"SKIPPED — {result.error}"
        is_err = result.error is not None
        ws.cell(row=row, column=1, value=sheet_name).font = _VALUE_FONT
        ws.cell(row=row, column=2, value=result.path.name).font = _VALUE_FONT
        ws.cell(row=row, column=3, value=proc_name or "(fallback: filename)").font = _VALUE_FONT
        ws.cell(row=row, column=4, value=result.row_count).font = _VALUE_FONT
        cell = ws.cell(row=row, column=5, value=status)
        cell.font = _WARN_FONT if is_err else _VALUE_FONT
        row += 1
    row += 1

    # Errors block (only shown when there are failures)
    if failed:
        row = _section(ws, row, "IMPORT ERRORS / WARNINGS")
        for result in failed:
            row = _kv(ws, row, result.path.name, result.error or "Unknown error", warn=True)
        row += 1

    # Analyst notes (blank lines for manual fill-in)
    row = _section(ws, row, "ANALYST NOTES")
    for i in range(1, 7):
        ws.cell(row=row, column=1, value=f"Note {i}:").font = _LABEL_FONT
        ws.cell(row=row, column=2, value="").font = _VALUE_FONT
        row += 1
    row += 1

    # Copilot prompts
    row = _section(ws, row, "SUGGESTED EXCEL COPILOT PROMPTS")
    for prompt in _COPILOT_PROMPTS:
        ws.cell(row=row, column=1, value=f"• {prompt}").font = _VALUE_FONT
        row += 1

    # Column widths tuned for readability
    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 48
    ws.column_dimensions["C"].width = 25
    ws.column_dimensions["D"].width = 14
    ws.column_dimensions["E"].width = 52
