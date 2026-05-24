"""
Command-line interface for EDR Workbook Builder.

Entry point for both `python edr_csv_to_xlsx.py` and `python -m edr_workbook_builder`.
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from edr_workbook_builder import __version__
from edr_workbook_builder.config import (
    apply_config_defaults,
    get_extra_lolbins,
    load_config,
    save_config,
)
from edr_workbook_builder.csv_loader import find_csv_files, load_all_csvs
from edr_workbook_builder.process_detection import detect_process_name
from edr_workbook_builder.sheet_names import make_unique_sheet_names
from edr_workbook_builder.workbook import build_workbook

logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        format="%(levelname)s: %(message)s",
        level=logging.DEBUG if verbose else logging.INFO,
    )


def _safe_slug(text: str, max_len: int = 50) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in text)
    return safe.strip("_")[:max_len]


def _default_output_path(case_name: Optional[str], timestamp: datetime) -> Path:
    ts = timestamp.strftime("%Y%m%d_%H%M%S")
    if case_name:
        slug = _safe_slug(case_name)
        return Path(f"edr_analysis_{slug}_{ts}.xlsx")
    return Path(f"edr_analysis_{ts}.xlsx")


def _parse_columns(value: str) -> list[str]:
    """Parse a comma-separated column list into a cleaned list of names."""
    return [c.strip() for c in value.split(",") if c.strip()]


def _build_parser() -> argparse.ArgumentParser:
    boa = argparse.BooleanOptionalAction
    parser = argparse.ArgumentParser(
        prog="edr-workbook-builder",
        description=(
            "Combine CrowdStrike EDR CSV exports into a single Excel workbook.\n"
            "Each CSV becomes a separate worksheet named after the detected process."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python edr_csv_to_xlsx.py -i ./exports
  python edr_csv_to_xlsx.py -i ./exports -o ./case123_edr.xlsx
  python edr_csv_to_xlsx.py -i ./alert1 -i ./alert2 --summary
  python edr_csv_to_xlsx.py -i ./exports --case-name "Suspicious PowerShell" --summary
  python edr_csv_to_xlsx.py -i ./exports --summary --highlight --attck --decode-encoded
  python edr_csv_to_xlsx.py -i ./exports --ioc-extract --process-tree --timeline
  python edr_csv_to_xlsx.py -i ./exports --columns "ImageFileName,CommandLine,ProcessId"
  python edr_csv_to_xlsx.py -i ./exports --max-rows 10000
  python edr_csv_to_xlsx.py -i ./exports --highlight --escape-formulas
  python edr_csv_to_xlsx.py -i ./exports --recursive --summary --verbose
  python edr_csv_to_xlsx.py -i ./exports --dry-run
  python edr_csv_to_xlsx.py -i ./exports --summary --highlight --save-config
        """,
    )
    parser.add_argument("--version", "-V", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-i", "--input", required=True, action="append", dest="inputs", metavar="FOLDER",
        help=(
            "Folder containing CSV files to process. "
            "Repeat to merge multiple folders: -i ./alert1 -i ./alert2"
        ),
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Output .xlsx path (default: edr_analysis_<timestamp>.xlsx in the current directory)",
    )
    parser.add_argument(
        "--case-name", metavar="NAME",
        help="Case or alert name — embedded in the filename and the summary sheet",
    )
    parser.add_argument(
        "--config", metavar="FILE",
        help="Path to a config file (overrides global and local config)",
    )
    parser.add_argument(
        "--save-config", action="store_true",
        help="Save current flag values to .edr-workbook-builder.ini in the current directory",
    )
    parser.add_argument(
        "--columns", metavar="COL,COL,...",
        help=(
            "Comma-separated list of columns to include in each data sheet. "
            "Feature columns (ATT&CK, DecodedCommand) are always appended. "
            "Example: --columns \"ImageFileName,CommandLine,ProcessId,Timestamp\""
        ),
    )
    parser.add_argument(
        "--max-rows", type=int, metavar="N",
        help="Truncate each data sheet to at most N rows (applied before all other transforms)",
    )
    parser.add_argument(
        "--summary", action=boa, default=None,
        help="Add an Analysis_Summary sheet as the first worksheet",
    )
    parser.add_argument(
        "-r", "--recursive", action=boa, default=None,
        help="Search subfolders recursively for CSV files",
    )
    parser.add_argument(
        "--add-source-column", action=boa, default=None,
        help="Prepend a SourceFile column showing the origin CSV on each worksheet",
    )
    parser.add_argument(
        "--timeline", action=boa, default=None,
        help=(
            "Add a Timeline sheet: all events from every CSV merged and sorted "
            "chronologically on the best shared timestamp column"
        ),
    )
    parser.add_argument(
        "--highlight", action=boa, default=None,
        help=(
            "Highlight suspicious rows in each data sheet: "
            "yellow = LOLBin process, salmon = possible obfuscation, "
            "red = PowerShell -EncodedCommand detected"
        ),
    )
    parser.add_argument(
        "--escape-formulas", action=boa, default=None,
        help=(
            "Prefix cell values starting with =, +, -, or @ with a single quote "
            "to prevent accidental formula execution when opening in Excel"
        ),
    )
    parser.add_argument(
        "--attck", action=boa, default=None,
        help=(
            "Add an ATT&CK column to each data sheet with MITRE technique IDs "
            "derived from the process name and command-line arguments"
        ),
    )
    parser.add_argument(
        "--decode-encoded", action=boa, default=None,
        help=(
            "Add a DecodedCommand column after CommandLine wherever a "
            "PowerShell -EncodedCommand base64 blob is detected"
        ),
    )
    parser.add_argument(
        "--process-tree", action=boa, default=None,
        help=(
            "Add a ProcessTree sheet reconstructed from ProcessId / ParentProcessId "
            "columns across all CSVs (purple tab)"
        ),
    )
    parser.add_argument(
        "--ioc-extract", action=boa, default=None,
        help=(
            "Add an IOC_Extract sheet with deduplicated hashes (SHA256/SHA1/MD5) "
            "and IP addresses found in known EDR columns (orange tab)"
        ),
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug-level logging",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be processed without writing any output files",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    _setup_logging(args.verbose)

    # Load config and fill in any unset boolean flags.
    config_path = Path(args.config) if args.config else None
    cfg = load_config(extra_path=config_path)
    apply_config_defaults(args, cfg)

    # Apply configurable LOLBin watchlist.
    extra_lolbins = get_extra_lolbins(cfg)
    if extra_lolbins:
        from edr_workbook_builder.patterns import configure_lolbins
        configure_lolbins(extra_lolbins)

    # Save config before doing any work so the file reflects the resolved flags.
    if args.save_config:
        saved = save_config(args)
        logger.info("Flags saved to: %s", saved)

    timestamp = datetime.now()

    # --- Validate and collect CSV files from all input folders ---
    csv_files: list[Path] = []
    for folder_str in args.inputs:
        folder = Path(folder_str)
        if not folder.exists():
            logger.error("Input folder not found: %s", folder)
            return 1
        if not folder.is_dir():
            logger.error("Input path is not a directory: %s", folder)
            return 1
        found = find_csv_files(folder, recursive=args.recursive)
        if not found:
            logger.warning(
                "No CSV files found in: %s%s",
                folder,
                " (try --recursive)" if not args.recursive else "",
            )
        csv_files.extend(found)

    if not csv_files:
        logger.error("No CSV files found across all input folders")
        return 1

    logger.info("Found %d CSV file(s) across %d folder(s)", len(csv_files), len(args.inputs))

    # Parse --columns filter.
    columns_filter: Optional[list[str]] = None
    if args.columns:
        columns_filter = _parse_columns(args.columns)
        logger.debug("Column filter: %s", columns_filter)

    # --- Determine output path ---
    output_path = (
        Path(args.output) if args.output
        else _default_output_path(args.case_name, timestamp)
    )
    if output_path.suffix.lower() != ".xlsx":
        output_path = output_path.with_suffix(".xlsx")

    # --- Dry run ---
    if args.dry_run:
        input_label = ", ".join(args.inputs)
        print(f"\n[DRY RUN] Input:   {input_label}")
        print(f"[DRY RUN] Output:  {output_path}")
        if args.case_name:
            print(f"[DRY RUN] Case:    {args.case_name}")
        if columns_filter:
            print(f"[DRY RUN] Columns: {', '.join(columns_filter)}")
        if args.max_rows:
            print(f"[DRY RUN] Max rows: {args.max_rows:,} per sheet")
        flags = [
            f"--{f.replace('_', '-')}" for f in (
                "summary", "timeline", "recursive", "add_source_column",
                "highlight", "escape_formulas", "attck", "decode_encoded",
                "process_tree", "ioc_extract",
            ) if getattr(args, f, False)
        ]
        if flags:
            print(f"[DRY RUN] Flags:   {' '.join(flags)}")
        print(f"\n[DRY RUN] {len(csv_files)} file(s) would be processed:")
        for f in csv_files:
            print(f"  {f.name}")
        return 0

    # --- Load CSVs (parallel) ---
    logger.info("Loading CSV files...")
    load_results = load_all_csvs(csv_files)

    # --- Detect process names and build sheet name list ---
    process_names: list[Optional[str]] = []
    raw_names: list[str] = []

    for result in load_results:
        if result.dataframe is not None and not result.dataframe.empty:
            proc_name = detect_process_name(result.dataframe)
        else:
            proc_name = None
        process_names.append(proc_name)
        raw_names.append(proc_name if proc_name else result.path.stem)

    sheet_names = make_unique_sheet_names(raw_names)

    # --- Log the plan ---
    logger.info("Output: %s", output_path)
    if args.case_name:
        logger.info("Case:   %s", args.case_name)

    for result, sheet_name, proc_name in zip(load_results, sheet_names, process_names):
        if result.error:
            logger.warning("  SKIP  %-40s %s", result.path.name, result.error)
        else:
            tag = f"(process: {proc_name})" if proc_name else "(fallback: filename)"
            logger.info(
                "  SHEET %-40s %5d rows  %s",
                result.path.name, result.row_count, tag,
            )

    # --- Create output directory if needed ---
    if output_path.parent != Path(".") and not output_path.parent.exists():
        output_path.parent.mkdir(parents=True, exist_ok=True)

    # --- Build workbook ---
    try:
        wb_result = build_workbook(
            load_results=load_results,
            sheet_names=sheet_names,
            process_names=process_names,
            output_path=output_path,
            case_name=args.case_name,
            add_summary=args.summary,
            add_source_column=args.add_source_column,
            timestamp=timestamp,
            highlight_suspicious=args.highlight,
            escape_formulas=args.escape_formulas,
            add_timeline=args.timeline,
            add_attck=args.attck,
            add_process_tree=args.process_tree,
            decode_encoded=args.decode_encoded,
            add_ioc_sheet=args.ioc_extract,
            columns_filter=columns_filter,
            max_rows=args.max_rows,
        )
    except Exception as exc:
        logger.error("Failed to create workbook: %s", exc)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    # --- Final summary ---
    successful = sum(1 for r in load_results if r.error is None)
    failed     = sum(1 for r in load_results if r.error is not None)
    total_rows = sum(r.row_count for r in load_results if r.error is None)

    print(f"\nWorkbook created: {output_path}")
    print(f"  Sheets:     {successful}")
    print(f"  Total rows: {total_rows:,}")
    if failed:
        print(f"  Skipped:    {failed} file(s) — run with --verbose for details")
    if columns_filter:
        print(f"  Columns:    filtered to {len(columns_filter)} column(s)")
    if args.max_rows:
        print(f"  Row cap:    {args.max_rows:,} rows per sheet")
    if args.summary:
        print("  Includes:   Analysis_Summary sheet")

    if args.timeline:
        if wb_result.timeline_timestamp_col:
            excl = (
                f", {len(wb_result.timeline_excluded)} sheet(s) excluded — "
                f"no '{wb_result.timeline_timestamp_col}' column"
                if wb_result.timeline_excluded else ""
            )
            print(
                f"  Timeline:   {wb_result.timeline_row_count:,} rows from "
                f"{len(wb_result.timeline_included)} sheet(s), "
                f"sorted by '{wb_result.timeline_timestamp_col}'{excl}"
            )
        else:
            print("  Timeline:   no timestamp column found — sheet not created")

    if args.highlight:
        findings = wb_result.findings
        if findings:
            high   = sum(1 for f in findings if f.severity >= 3)
            medium = sum(1 for f in findings if f.severity == 2)
            lolbin = sum(1 for f in findings if f.severity == 1)
            parts  = []
            if high:   parts.append(f"{high} High")
            if medium: parts.append(f"{medium} Medium")
            if lolbin: parts.append(f"{lolbin} LOLBin")
            detail = f" ({', '.join(parts)})" if parts else ""
            suffix = " — see Analysis_Summary sheet" if args.summary else ""
            print(f"  Suspicious: {len(findings)} row(s) flagged{detail}{suffix}")
        else:
            print("  Suspicious: no patterns detected")

    if args.escape_formulas:
        print("  Formulas:   formula-injection escaping applied")

    if args.attck:
        print("  ATT&CK:     technique column added to each data sheet")

    if args.decode_encoded:
        print("  Decoded:    DecodedCommand column added where -EncodedCommand detected")

    if args.process_tree:
        if wb_result.process_tree_node_count:
            print(f"  ProcessTree: {wb_result.process_tree_node_count} node(s) written (purple tab)")
        else:
            print("  ProcessTree: no ProcessId/ParentProcessId columns found — sheet not created")

    if args.ioc_extract:
        if wb_result.ioc_count:
            print(f"  IOC_Extract: {wb_result.ioc_count} unique indicator(s) written (orange tab)")
        else:
            print("  IOC_Extract: no hash or IP columns found — sheet not created")

    return 0


def run() -> None:
    sys.exit(main())
