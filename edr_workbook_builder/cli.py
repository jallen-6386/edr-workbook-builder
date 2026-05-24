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
    """Convert an arbitrary string into a safe filesystem slug."""
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in text)
    return safe.strip("_")[:max_len]


def _default_output_path(case_name: Optional[str], timestamp: datetime) -> Path:
    ts = timestamp.strftime("%Y%m%d_%H%M%S")
    if case_name:
        slug = _safe_slug(case_name)
        return Path(f"edr_analysis_{slug}_{ts}.xlsx")
    return Path(f"edr_analysis_{ts}.xlsx")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="edr-workbook-builder",
        description=(
            "Combine CrowdStrike EDR CSV exports into a single Excel workbook.\n"
            "Each CSV becomes a separate worksheet named after the detected process."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python edr_csv_to_xlsx.py -i ./crowdstrike_exports
  python edr_csv_to_xlsx.py -i ./exports -o ./case123_edr.xlsx
  python edr_csv_to_xlsx.py -i ./exports --case-name "Suspicious PowerShell" --summary
  python edr_csv_to_xlsx.py -i ./exports --summary --highlight
  python edr_csv_to_xlsx.py -i ./exports --highlight --escape-formulas
  python edr_csv_to_xlsx.py -i ./exports --recursive --summary --verbose
  python edr_csv_to_xlsx.py -i ./exports --dry-run
        """,
    )
    parser.add_argument("--version", "-V", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-i", "--input", required=True, metavar="FOLDER",
        help="Folder containing CSV files to process",
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
        "--summary", action="store_true",
        help="Add an Analysis_Summary sheet as the first worksheet",
    )
    parser.add_argument(
        "-r", "--recursive", action="store_true",
        help="Search subfolders recursively for CSV files",
    )
    parser.add_argument(
        "--add-source-column", action="store_true",
        help="Prepend a SourceFile column showing the origin CSV on each worksheet",
    )
    parser.add_argument(
        "--highlight", action="store_true",
        help=(
            "Highlight suspicious rows in each data sheet: "
            "yellow = LOLBin process, salmon = possible obfuscation, "
            "red = PowerShell -EncodedCommand detected"
        ),
    )
    parser.add_argument(
        "--escape-formulas", action="store_true",
        help=(
            "Prefix cell values starting with =, +, -, or @ with a single quote "
            "to prevent accidental formula execution when opening in Excel"
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

    timestamp = datetime.now()

    # --- Validate input ---
    input_folder = Path(args.input)
    if not input_folder.exists():
        logger.error("Input folder not found: %s", input_folder)
        return 1
    if not input_folder.is_dir():
        logger.error("Input path is not a directory: %s", input_folder)
        return 1

    csv_files = find_csv_files(input_folder, recursive=args.recursive)
    if not csv_files:
        logger.error(
            "No CSV files found in: %s%s",
            input_folder,
            " (try --recursive to search subfolders)" if not args.recursive else "",
        )
        return 1

    logger.info("Found %d CSV file(s) in %s", len(csv_files), input_folder)
    for f in csv_files:
        logger.debug("  %s", f.relative_to(input_folder))

    # --- Determine output path ---
    output_path = (
        Path(args.output) if args.output
        else _default_output_path(args.case_name, timestamp)
    )
    if output_path.suffix.lower() != ".xlsx":
        output_path = output_path.with_suffix(".xlsx")

    # --- Dry run ---
    if args.dry_run:
        print(f"\n[DRY RUN] Input:   {input_folder}")
        print(f"[DRY RUN] Output:  {output_path}")
        if args.case_name:
            print(f"[DRY RUN] Case:    {args.case_name}")
        flags = []
        if args.summary:
            flags.append("--summary")
        if args.recursive:
            flags.append("--recursive")
        if args.add_source_column:
            flags.append("--add-source-column")
        if args.highlight:
            flags.append("--highlight")
        if args.escape_formulas:
            flags.append("--escape-formulas")
        if flags:
            print(f"[DRY RUN] Flags:   {' '.join(flags)}")
        print(f"\n[DRY RUN] {len(csv_files)} file(s) would be processed:")
        for f in csv_files:
            print(f"  {f.name}")
        return 0

    # --- Load CSVs ---
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
        findings = build_workbook(
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
        )
    except Exception as exc:
        logger.error("Failed to create workbook: %s", exc)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    # --- Final summary ---
    successful = sum(1 for r in load_results if r.error is None)
    failed = sum(1 for r in load_results if r.error is not None)
    total_rows = sum(r.row_count for r in load_results if r.error is None)

    print(f"\nWorkbook created: {output_path}")
    print(f"  Sheets:     {successful}")
    print(f"  Total rows: {total_rows:,}")
    if failed:
        print(f"  Skipped:    {failed} file(s) — run with --verbose for details")
    if args.summary:
        print("  Includes:   Analysis_Summary sheet")

    if args.highlight:
        if findings:
            high = sum(1 for f in findings if f.severity >= 3)
            medium = sum(1 for f in findings if f.severity == 2)
            lolbin = sum(1 for f in findings if f.severity == 1)
            parts = []
            if high:
                parts.append(f"{high} High")
            if medium:
                parts.append(f"{medium} Medium")
            if lolbin:
                parts.append(f"{lolbin} LOLBin")
            detail = f" ({', '.join(parts)})" if parts else ""
            suffix = " — see Analysis_Summary sheet" if args.summary else ""
            print(f"  Suspicious: {len(findings)} row(s) flagged{detail}{suffix}")
        else:
            print("  Suspicious: no patterns detected")

    if args.escape_formulas:
        print("  Formulas:   formula-injection escaping applied")

    return 0


def run() -> None:
    sys.exit(main())
