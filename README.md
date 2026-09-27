# Drive Cleanr

Drive Cleanr helps Windows users find reclaimable disk space with WizTree or WinDirStat, review conservative cleanup candidates, back up selected targets, and only then run an explicit cleanup plan.

**Nothing is deleted during scanning or analysis.** Generated PowerShell plans ask for confirmation, create and verify a backup, then clean only the listed targets. Backups are kept until the user removes them.

## Get the project

```powershell
git clone https://github.com/ipodvideo87/drive-cleaner.git
cd drive-cleaner
```

## Requirements

- Windows 10 or newer
- Python 3.10+
- [WizTree](https://diskanalyzer.com/) or [WinDirStat](https://github.com/windirstat/windirstat), installed or available through `WIZTREE_PATH` / `WINDIRSTAT_PATH`
- Administrator rights for MFT scanning
- A non-system drive with at least 5 GB free for backups; the backup also needs enough room for the selected data

### Portable versions

Drive Cleanr supports the official portable versions of [WizTree](https://diskanalyzer.com/download) and [WinDirStat](https://github.com/windirstat/windirstat/releases). Automated WinDirStat scans require version 2.6.0 or newer and use its `/SaveTo` export. WizTree scans require an elevated terminal. If automatic discovery misses either executable, set `WIZTREE_PATH` or `WINDIRSTAT_PATH` to its full path.

## Quick start

Open PowerShell in this folder (use an elevated terminal when choosing WizTree):

```powershell
python drive_cleaner.py
```

The guided command-line menu lets you scan with WizTree or WinDirStat, review a new or existing scan, and manage backups. During a scan it asks for the scanner, drive, file-row preference, and timeout. After the scan it can open the results in the review menu. Existing scripts remain available for direct commands and automation.

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

# Choose the scanner directly (WinDirStat 2.6+ required for automated export)
python scan.py C: --app windirstat
python scan.py C: --app wiztree

# Start directly in the analysis menu or show scan options
python analyze.py --tui
python scan.py --help

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

The analysis supports WizTree English/Chinese CSV and WinDirStat 2.x CSV exports. WinDirStat uses its saved scan filters, so check those settings before scanning the whole drive; it can run without elevation, though protected items may be missed. Drive Cleanr requires an elevated terminal for any WizTree scan. Both formats exclude protected locations, accept only absolute local-drive paths, and refuse drive roots, UNC paths, device paths, and traversal paths.

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
