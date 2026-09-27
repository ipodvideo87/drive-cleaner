# Drive Cleanr

Drive Cleanr helps Windows users find reclaimable disk space with WizTree, review conservative cleanup candidates, back up selected targets, and only then run an explicit cleanup plan.

**Nothing is deleted during scanning or analysis.** Generated PowerShell plans ask for confirmation, create and verify a backup, then clean only the listed targets. Backups are kept until the user removes them.

## Requirements

- Windows 10 or newer
- Python 3.10+
- [WizTree](https://diskanalyzer.com/), installed or available through `WIZTREE_PATH`
- Administrator rights for MFT scanning
- A non-system drive with at least 5 GB free for backups; the backup also needs enough room for the selected data

## Quick start

Open an elevated PowerShell terminal in this folder:

```powershell
python scan.py C:
python analyze.py --tui
```

The interactive report lets you pick the scan, review candidates, export a list, or generate a cleanup script. For direct commands, use the exact CSV path printed by `scan.py`.

```powershell
python analyze.py .\data\scan.csv --min-size 50 --list-items
python analyze.py .\data\scan.csv --min-size 50 --output clean_review.ps1 --priority high
```

Review every path in the report and script. Then run the script from PowerShell:

```powershell
& .\clean_review.ps1
```

The script lists numbered targets and lets you choose individual items, choose all, or cancel. It then shows the selected paths, asks you to type `CLEAN`, and backs up only those targets. Cleanup stops if the selected backup is missing or incomplete. Review the generated script itself before running it. For a reviewed noninteractive selection, use `-Select 1,3 -Force`; `-Force` skips only the final typed confirmation and never selects targets for you.

## Common options

```powershell
# Scan another drive; include individual files by default
python scan.py D:

# Smaller CSV when individual large files are not needed
python scan.py C: --folders-only

# Allow up to one hour for a very large scan
python scan.py C: --timeout 3600

# Analyze with a lower size threshold, print JSON, or write a categorized list
python analyze.py .\data\scan.csv --min-size 10 --json
python analyze.py .\data\scan.csv --min-size 10 --list-output candidates.txt

# Generate a medium, low, or all-tier reviewed plan
python analyze.py .\data\scan.csv --output clean_review.ps1 --priority medium
python analyze.py .\data\scan.csv --output clean_review.ps1 --priority low
python analyze.py .\data\scan.csv --output clean_review.ps1 --priority all
```

The analysis supports English and Chinese WizTree column headings and GUI CSV exports with the WizTree note line. It excludes protected locations, accepts only absolute local-drive paths, and refuses drive roots, UNC paths, device paths, and traversal paths.

Scans retain previous exports and reviewed scripts. To prune old scan files and generated plans intentionally, run `python scan.py --cleanup --keep-latest 1`.

## Backups

```powershell
python backup.py drive
python backup.py list
python backup.py info --id backup_YYYYMMDD_HHMMSS_microseconds
python backup.py restore --id backup_YYYYMMDD_HHMMSS_microseconds
python backup.py delete --id backup_YYYYMMDD_HHMMSS_microseconds
```

Keep backups through an observation period after cleanup. Restore a backup if an affected app or system feature stops working. Large directory backups use ZIP64, include hidden/system entries, and are verified before cleanup. `backup.py create --json` emits a machine-readable manifest and returns a nonzero exit code when any target was skipped or incompletely backed up.

## Safety model

- Pattern matches are suggestions, not proof that a file is disposable.
- High, medium, and low tiers communicate different levels of impact; read the notes for each item.
- Windows component stores, restore points, installed-program repair data, personal folders, messaging data, and credential folders are red lines.
- The report's folder sizes are estimates. Parent/child totals and hard links can make apparent savings larger than the actual disk space freed.
- Browser, editor, and build-process warnings can mean a cache stays in use or is recreated. Close affected apps before cleanup.
- When in doubt, omit the target.

See [references/knowledge.md](references/knowledge.md) for the detailed cleanup rules and [docs/GUIDE.md](docs/GUIDE.md) for the longer workflow guide.

## Development and tests

The project uses the Python standard library:

```powershell
python -m unittest discover -s tests -v
python -m py_compile analyze.py backup.py scan.py
```

Tests use temporary files and mocked processes. They do not run WizTree or delete real user data.
