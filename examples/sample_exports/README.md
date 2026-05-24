# Sample Exports

Place CrowdStrike EDR CSV exports here for testing.

Each CSV should be a raw export from CrowdStrike Falcon's process tree view
or EDR event search. The tool detects the process name automatically from
common column names such as `ImageFileName`, `FileName`, `ProcessName`, and
`CommandLine`.

## Quick test with synthetic data

```bash
# From the project root
python edr_csv_to_xlsx.py -i examples/sample_exports --summary --dry-run
```

## Do not commit real EDR data

Real CrowdStrike exports contain sensitive host information, process paths,
hashes, and command-line arguments. Keep actual case exports out of version
control.
