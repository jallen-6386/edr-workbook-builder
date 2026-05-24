"""
Convenience entry point — run directly without installing the package.

Usage:
    python edr_csv_to_xlsx.py --input ./crowdstrike_exports
    python edr_csv_to_xlsx.py -i ./exports -o ./case123.xlsx --summary
    python edr_csv_to_xlsx.py --help
"""

from edr_workbook_builder.cli import run

if __name__ == "__main__":
    run()
