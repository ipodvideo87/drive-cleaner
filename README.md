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
- Administrator rights for fast MFT scanning (standard WizTree scans do not require elevation)
- A non-system drive with at least 5 GB free for backups; the backup also needs enough room for the selected data

### Portable versions

Drive Cleanr supports the official portable versions of [WizTree](https://diskanalyzer.com/download) and [WinDirStat](https://github.com/windirstat/windirstat/releases). Automated WinDirStat scans require version 2.6.0 or newer and use its `/SaveTo` export. WizTree's fast MFT mode requires an elevated terminal; its standard file-system scan can run without elevation but may miss files the current account cannot access. If automatic discovery misses either executable, set `WIZTREE_PATH` or `WINDIRSTAT_PATH` to its full path.

## Quick start

Open PowerShell in this folder. Use an elevated terminal for fast, full-drive WizTree scans; standard scans are available without elevation.

```powershell
python drive_cleaner.py
```

The guided command-line menu lets you scan with WizTree or WinDirStat, review a new or existing scan, and manage backups. During a scan it asks for the scanner, a drive or existing local folder, applicable scan options, and timeout. For WizTree, automatic mode uses fast MFT scanning for whole drives when elevated and standard scanning otherwise; you can choose either mode explicitly, whether to export individual file rows, and the maximum export depth (0 means unlimited). Standard scans can miss files the current account cannot access, and the review report carries that warning forward. WinDirStat always exports its scan tree and applies its saved filters and exclusions. Press Ctrl+C to stop the active scanner; Drive Cleanr removes only that interrupted run's incomplete export and keeps previous scans. After the scan it can open the results in the review menu. Existing scripts remain available for direct commands and automation.

Both scanners have native command-line options, and Drive Cleanr invokes those options directly. WizTree gets explicit standard or MFT mode, file/folder export, allocated-size sorting, capacity, and depth settings. WinDirStat gets `/SaveTo` with a CSV destination and scan target. WinDirStat also offers separate commands for loading saved scans and exporting duplicate or permission reports; Drive Cleanr uses the scan-tree export because its cleanup review needs file paths and sizes. WinDirStat's filters and scan exclusions come from its saved settings, so review those before scanning. See the official [WizTree command-line guide](https://www.diskanalyzer.com/guide) and [WinDirStat command-line and export reference](https://github.com/windirstat/windirstat/wiki/Command-Line-and-CSV) for their complete native options.

```powershell
python analyze.py .\data\scan.csv --min-size 50 --list-items
python analyze.py .\data\scan.csv --min-size 50 --output clean_review.ps1 --priority high
```

Review every path in the report and script. Then run the script from PowerShell:

```powershell
& .\clean_review.ps1
```

The script lists numbered targets and lets you choose individual items, choose all, or cancel. It then shows the selected paths, asks you to type `CLEAN`, and backs up only those targets. Cleanup stops if the selected backup is missing or incomplete. When cleaning a selected directory, the script preserves nested protected locations, detected project roots, and Claude data even when they sit inside that directory; it reports when it preserved nested data and refuses trees containing reparse points. Review the generated script itself before running it. Generated plans and candidate lists never overwrite existing files and cannot be written inside a selected cleanup target. For a reviewed noninteractive selection, use `-Select 1,3 -Force`; `-Force` skips only the final typed confirmation and never selects targets for you.

Folder size totals are estimates: a folder can contain protected nested data that the cleanup script deliberately preserves, so the recovered space can be lower. The cleanup script reports the size of files it actually removed.

## Common options

```powershell
# Scan another drive; include individual files by default
python scan.py D:

# Choose the scanner directly (WinDirStat 2.6+ required for automated export)
python scan.py C: --app windirstat
python scan.py C: --app wiztree

# Run WizTree without elevation (slower; protected files may be missing)
python scan.py C: --app wiztree --wiztree-mode standard

# Request fast MFT scanning; run PowerShell as administrator first
python scan.py C: --app wiztree --wiztree-mode fast

# Scan a specific folder instead of the whole drive; limit the WizTree export depth
python scan.py "$env:USERPROFILE\Videos" --app wiztree --max-depth 3

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

All menus, prompts, reports, and documentation are in English. The analyzer also accepts WizTree CSV files with Chinese column headings for compatibility, as well as WinDirStat 2.x CSV exports. WinDirStat uses its saved scan filters, so check those settings before scanning the whole drive; it can run without elevation, though protected items may be missed. Standard WizTree scans can run without elevation and may miss inaccessible files; fast MFT scans require an elevated terminal. Both formats exclude protected locations, accept only absolute local-drive paths, and refuse drive roots, UNC paths, device paths, and traversal paths.

Downloads, recovered previous-installation data, Windows Update downloads, Windows recovery staging, Windows Update logs, browser Service Worker data, Codex app and agent configuration, and container-machine state are excluded from direct cleanup suggestions. Candidate entries inside folders marked by common project files such as `.git`, `pyproject.toml`, `package.json`, or `Cargo.toml` are also omitted to help protect source and project data. To protect a project without one of those files, place an empty `.drive-cleanr-protect` file in its root. Use Windows Storage or Disk Cleanup to manage update downloads. Temporary-folder candidates are labeled for review; confirm that no installer or build is using them before selecting them. The cleanup plan warns if common browser, editor, Java, Node.js, Rust, Go, .NET build, Windows installer, updater, or package-manager processes are running. Generated plans recheck every target against its selected priority and exact cleanup label. A candidate report is not a deletion recommendation, and “lower risk” means usually recreatable, not guaranteed safe.

The analyzer checks that candidate paths still exist before including them in the report. Paths that disappeared after the scan are omitted from reclaimable totals and reported as stale. WinDirStat exports do not record volume capacity; when the scanned local drive is available, Drive Cleanr shows current capacity and free space with a clear note that these values were checked at analysis time.

Scans retain previous exports and reviewed scripts. To prune old scan files and generated plans intentionally, run `python scan.py --cleanup --keep-latest 1`.

## Backups

```powershell
python backup.py drive
python backup.py list
python backup.py info --id backup_YYYYMMDD_HHMMSS_microseconds
python backup.py restore --id backup_YYYYMMDD_HHMMSS_microseconds
python backup.py delete --id backup_YYYYMMDD_HHMMSS_microseconds
```

Keep backups through an observation period after cleanup. Restore a backup if an affected app or system feature stops working. New file, directory-copy, and ZIP backups record SHA-256 integrity fingerprints, which restore verifies for every item before writing any restored data. Large directory archives use ZIP64, include hidden/system entries, and are also checked with CRC and byte totals when created. Older manifests without hashes remain supported with size/structure checks and a warning. Backup creation accepts only absolute local paths below a drive root; it refuses a drive root, network/device path, or traversal path before creating backup storage. Restore also validates saved paths and refuses archive members that could escape through traversal, alternate streams, or reparse points. `backup.py create --json` emits a machine-readable manifest and returns a nonzero exit code when any target was skipped or incompletely backed up.

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
