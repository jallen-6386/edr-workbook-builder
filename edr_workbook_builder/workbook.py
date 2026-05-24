"""
Excel workbook construction and per-sheet formatting.

Formatting choices:
  - Dark blue (#1F497D) header row with white bold text — easy to scan
  - Freeze pane at A2 so the header stays visible while scrolling
  - Auto-filter on every sheet so analysts can filter without extra steps
  - Column width sampled from up to 500 rows and capped at 60 chars
    (prevents CommandLine columns from making the sheet unusably wide)
  - All values written as strings — no type inference that could mangle
    hashes, timestamps, or numeric PIDs
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.utils.dataframe import dataframe_to_rows

logger = logging.getLogger(__name__)

_HEADER_FILL = PatternFill(start_color="1F497D", end_color="1F497D", fill_type="solid")
_HEADER_FONT = Font(name="Calibri", bold=True, color="FFFFFF", size=11)
_HEADER_ALIGN = Alignment(horizontal="left", vertical="center")
_BODY_FONT = Font(name="Calibri", size=10)
_BODY_ALIGN = Alignment(horizontal="left", vertical="center", wrap_text=False)

_MAX_COL_WIDTH = 60
_MIN_COL_WIDTH = 8
_SAMPLE_ROWS = 500


def _auto_size_columns(ws, df: pd.DataFrame) -> None:
    for col_idx, col_name in enumerate(df.columns, start=1):
        col_letter = get_column_letter(col_idx)
        max_len = len(str(col_name))
        for val in df.iloc[:_SAMPLE_ROWS, col_idx - 1]:
            if val:
                vlen = len(str(val))
                if vlen > max_len:
                    max_len = vlen
        ws.column_dimensions[col_letter].width = min(
            max(max_len + 2, _MIN_COL_WIDTH), _MAX_COL_WIDTH
        )


def write_dataframe_to_sheet(
    ws,
    df: pd.DataFrame,
    add_source: bool = False,
    source_name: str = "",
) -> None:
    """Write a DataFrame to an openpyxl worksheet with standard EDR formatting."""
    if df.empty and len(df.columns) == 0:
        ws["A1"] = "(no data in source CSV)"
        ws["A1"].font = Font(name="Calibri", italic=True, color="808080")
        return

    if add_source and source_name:
        df = df.copy()
        df.insert(0, "SourceFile", source_name)

    df = df.fillna("")

    for r_idx, row in enumerate(dataframe_to_rows(df, index=False, header=True), start=1):
        for c_idx, value in enumerate(row, start=1):
            cell = ws.cell(row=r_idx, column=c_idx, value=value)
            if r_idx == 1:
                cell.font = _HEADER_FONT
                cell.fill = _HEADER_FILL
                cell.alignment = _HEADER_ALIGN
            else:
                cell.font = _BODY_FONT
                cell.alignment = _BODY_ALIGN

    ws.freeze_panes = "A2"
    ws.row_dimensions[1].height = 18

    if ws.dimensions:
        ws.auto_filter.ref = ws.dimensions

    _auto_size_columns(ws, df)


def build_workbook(
    load_results: list,
    sheet_names: list[str],
    process_names: list[Optional[str]],
    output_path: Path,
    case_name: Optional[str] = None,
    add_summary: bool = False,
    add_source_column: bool = False,
    timestamp: Optional[datetime] = None,
) -> None:
    """Assemble and save the Excel workbook from loaded CSV results."""
    if timestamp is None:
        timestamp = datetime.now()

    wb = Workbook()
    wb.remove(wb.active)

    sheets_created = 0

    for result, sheet_name in zip(load_results, sheet_names):
        if result.error or result.dataframe is None:
            continue

        ws = wb.create_sheet(title=sheet_name)
        write_dataframe_to_sheet(
            ws,
            result.dataframe,
            add_source=add_source_column,
            source_name=result.path.name,
        )
        sheets_created += 1
        logger.debug("Wrote sheet '%s' (%d rows)", sheet_name, result.row_count)

    # Guarantee at least one sheet (Excel requires it)
    if sheets_created == 0 and not add_summary:
        ws = wb.create_sheet(title="No Data")
        ws["A1"] = "No CSV files could be processed. Run with --verbose for details."
        ws["A1"].font = Font(name="Calibri", bold=True, color="C00000")

    if add_summary:
        from edr_workbook_builder.summary import create_summary_sheet
        ws_summary = wb.create_sheet(title="Analysis_Summary", index=0)
        create_summary_sheet(
            ws=ws_summary,
            case_name=case_name,
            timestamp=timestamp,
            load_results=load_results,
            sheet_names=sheet_names,
            process_names=process_names,
        )

    wb.properties.title = case_name or "EDR Analysis Workbook"
    wb.properties.creator = "EDR Workbook Builder"
    wb.properties.description = f"Generated {timestamp.isoformat()}"

    wb.save(output_path)
    logger.info("Workbook saved: %s", output_path)
