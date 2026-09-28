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

Drive Cleanr supports the official portable versions of [WizTree](https://diskanalyzer.com/download) and [WinDirStat](https://github.com/windirstat/windirstat/releases). Automated WinDirStat scans require version 2.6.0 or newer and use its `/SaveTo` export. WizTree's fast MFT mode requires an elevated terminal; its standard file-system scan can run without elevation but may miss files the current account cannot access. If automatic discovery misses either executable, set `WIZTREE_PATH` to the 64-bit `WizTree64.exe` or `WINDIRSTAT_PATH` to the `WinDirStat.exe` full path.

## Quick start

Open PowerShell in this folder. Use an elevated terminal for fast, full-drive WizTree scans; standard scans are available without elevation.

```powershell
python drive_cleaner.py
```

The guided command-line menu lets you scan with WizTree or WinDirStat, review a new or existing scan, and manage backups. During a scan it asks for the scanner, a drive or existing local folder, applicable scan options, and timeout. For WizTree, automatic mode uses fast MFT scanning for whole-drive targets when elevated and standard scanning otherwise. Folder scans always use standard mode; fast MFT is only available for whole drives. You can choose the mode for whole-drive scans, whether to export individual file rows, and the maximum export depth (0 means unlimited). Standard scans can miss files the current account cannot access, and the review report carries that warning forward. WinDirStat always exports its scan tree and applies its saved filters and exclusions. Press Ctrl+C to stop the active scanner; Drive Cleanr removes only that interrupted run's incomplete export and keeps previous scans. Reports show when the source scan file was last modified; rescan if paths or contents may have changed. After the scan it can open the results in the review menu. Existing scripts remain available for direct commands and automation.

Both scanners have native command-line options, and Drive Cleanr invokes the scan and export options it needs. WizTree gets explicit standard or MFT mode, file/folder export, allocated-size sorting, capacity, and depth settings. WinDirStat gets `/SaveTo` with a CSV destination and scan target; its other native modes include loading saved scans and exporting duplicate or permission reports. Drive Cleanr uses scan-tree exports because its cleanup review needs item paths and sizes. WinDirStat's filters and scan exclusions come from its saved settings, so review those before scanning. See the official [WizTree command-line guide](https://www.diskanalyzer.com/guide) and [WinDirStat command-line and export reference](https://github.com/windirstat/windirstat/wiki/Command-Line-and-CSV) for their complete native options.

```powershell
python analyze.py .\data\scan.csv --min-size 50 --list-items
python analyze.py .\data\scan.csv --min-size 50 --output clean_review.ps1 --priority high
```

Review every path in the report and script. Run the script from a normal PowerShell session first; use an administrator session only when a reviewed target requires elevated access:

```powershell
& .\clean_review.ps1
```

The script lists numbered targets and lets you choose individual items, choose all, or cancel. Before the `CLEAN` confirmation it previews up to 12 direct children of each selected folder, so unexpected contents are visible without flooding the screen. It then shows the selected paths and backs up only those targets. Before confirmation or backup, it rechecks each target's type and every ancestor for reparse points, refusing stale or redirected paths. It repeats those checks after backup and immediately before cleanup, so a target that changes during a long backup is left untouched. Cleanup also stops if the selected backup is missing or incomplete, or if the saved backup and current source contents differ. Before each removal, it checks that the saved backup and current source contents still match and rechecks project markers in the target's ancestor folders. A target that becomes part of a recognized project after plan generation is refused; folders that cannot be checked are also refused. When cleaning a selected directory, the script preserves nested protected locations, detected project roots, and Claude data even when they sit inside that directory; it reports when it preserved nested data and refuses trees containing reparse points. Review the generated script itself before running it. Generated plans and candidate lists never overwrite existing files and cannot be written inside a selected cleanup target. For a reviewed noninteractive selection, use `-Select 1,3 -Force`; `-Force` skips only the final typed confirmation and never selects targets for you.

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

# Request fast MFT scanning for a whole drive; run PowerShell as administrator first
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

All text generated by Drive Cleanr, including menus, prompts, reports, and documentation, is in English. Original file and folder paths are preserved as scanned. Localized WizTree CSV column headings are accepted for input compatibility, including Chinese headings; this does not translate or change the English interface. WinDirStat 2.x exports are also supported. WinDirStat uses its saved scan filters, so check those settings before scanning the whole drive; it can run without elevation, though protected items may be missed. Standard WizTree scans can run without elevation and may miss inaccessible files; fast MFT scans require an elevated terminal. Both formats exclude protected locations, accept only absolute local-drive paths, and refuse drive roots, UNC paths, device paths, and traversal paths.

Common Windows personal folders, including Music, Contacts, Favorites, Links, Saved Games, Saved Pictures, Camera Roll, Searches, and 3D Objects, are excluded from direct cleanup suggestions along with Documents, Desktop, Pictures, Videos, and Downloads. Recovered previous-installation data, Windows Update downloads, Windows recovery staging, Windows Update logs, browser Service Worker data, Microsoft Store app package data, cloud and container CLI credentials, Codex app and agent configuration (including legacy `.codex-old` profiles), and container-machine state are excluded from direct cleanup suggestions. Crash-dump rules match only known direct locations under the drive's `Windows` folder and appear in the caution tier: these files can help investigate crashes, and some dump types can contain memory data. Cache-like candidates under recognized project roots are omitted to protect source and local project data. Recognition covers common manifests, lockfiles, build files, Git markers, IDE workspace folders (`.idea` and `.vs`), game-engine markers (`project.godot`, `ProjectSettings`, `.uproject`, and `.uplugin`), Visual Studio `.sln`/`.csproj` files, and `-requirements.txt` files. A root-level `.editorconfig` is treated as a project marker only below the user profile root, where it can be a shared editor setting. If a project has no recognized marker, place an empty `.drive-cleanr-protect` file in its root. Folders that cannot be checked for markers are left out of cleanup suggestions. Use Windows Storage or Disk Cleanup to manage update downloads. Scoop installer downloads are labeled separately and kept in the confirm-first tier because they may be useful for offline reinstalls; prefer Scoop's own cache controls. Known Windows and user temp locations are labeled for review; folders merely named `Temp` or `Tmp` elsewhere stay in the caution tier because their names do not prove their contents are temporary. Confirm that no installer or build is using known temp locations before selecting them. The cleanup plan warns if common browser, editor, Java, Conda/Mamba/Pixi, Node.js, Rust, Go, .NET build, Windows installer, updater, or package-manager processes are running. Generated plans recheck every target against its selected priority and exact cleanup label. A candidate report is not a deletion recommendation, and “lower risk” means usually recreatable, not guaranteed safe.

Chrome model suggestions require a Chrome User Data path. IndexedDB is suggested only beneath recognized Chrome or Edge User Data profiles because it can hold offline site data and sign-in state. NVIDIA App update artifacts are suggested only under known ProgramData updater paths and are marked for careful review because they may be needed to retry an update.

The analyzer checks that candidate paths still exist before including them in the report. Paths that disappeared after the scan are omitted from reclaimable totals and reported as stale. Candidate paths that cross a junction, symbolic link, or unreadable path component are also omitted and counted. Plan generation repeats the link check so a path redirected after analysis is rejected before a script is written. More specific cleanup rules take precedence over broad cache labels, so recognized package-manager data keeps its own category. Broad Cache, Caches, Logs, GPUCache, ShaderCache, and Code Cache labels remain caution suggestions: inspect the exact path and contents because their names alone do not prove the data is disposable. Candidate file/folder types are checked against the current filesystem: rows with missing WinDirStat type metadata use the current type, while rows whose exported type conflicts with the current path are skipped and flagged for a rescan. WinDirStat exports do not record volume capacity; when the scanned local drive is available, Drive Cleanr shows current capacity and free space with a clear note that these values were checked at analysis time.

Scans retain previous exports and reviewed scripts. To prune old scan files and generated plans intentionally, run `python scan.py --cleanup --keep-latest 1`.

## Backups

```powershell
python backup.py drive
python backup.py list
python backup.py info --id backup_YYYYMMDD_HHMMSS_microseconds
python backup.py verify --id backup_YYYYMMDD_HHMMSS_microseconds
python backup.py restore --id backup_YYYYMMDD_HHMMSS_microseconds
python backup.py delete --id backup_YYYYMMDD_HHMMSS_microseconds
```

Backup listing skips malformed manifests and entries whose root, backup folder, or manifest crosses a reparse point. Direct backup inspection, restore, and verification reject malformed or mismatched manifests. Backup deletion refuses to remove a backup directory if it contains a junction or other reparse point. Files restored from direct or ZIP backups use a staged copy and verify it before replacing or creating the destination. Ctrl+C at analyzer, restore, or backup-delete confirmation prompts cancels cleanly before the operation starts.

Keep backups through an observation period after cleanup. Restore a backup if an affected app or system feature stops working. New file, directory-copy, and ZIP backups record SHA-256 integrity fingerprints, which restore verifies for every item before writing any restored data. `backup.py verify --id <id>` checks the backup payload and current source; add `--paths <path>` to check selected source items. Large directory archives use ZIP64, include hidden/system entries, and are checked for CRC, total bytes, and file-by-file agreement with the source snapshot; a backup is marked partial if the source changed during archiving. Older manifests without hashes remain restorable with size/structure checks and a warning, but cannot pass the new content-match verification. Restore offers overwrite or merge: merge preserves existing files and restores missing ones, while overwrite replaces conflicts only after explicit approval. For unattended use, `backup.py restore --id <id> --yes` explicitly approves overwriting. Backup creation accepts only absolute local paths below a drive root; it refuses drive roots, network/device paths, traversal paths, and source paths that cross reparse points. The backup destination is also checked to prevent storing through a junction. Unreadable path metadata is treated as unsafe. Restore validates saved paths and preflights every ZIP member before writing; it refuses traversal, alternate streams, reparse points, duplicate or case-colliding names, and paths that require a Windows path to be both a file and a directory. Directory-copy restores repeat source and destination link checks immediately before calling Robocopy. `backup.py create --json` emits a machine-readable manifest and returns a nonzero exit code when any target was skipped or incompletely backed up.

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
python -m py_compile analyze.py backup.py scan.py drive_cleaner.py error_messages.py tests/test_safety.py
```

Tests use temporary files and mocked scanner processes. Windows integration tests exercise PowerShell cleanup and Robocopy backup/restore only against isolated fixtures, including hidden and system files. An end-to-end test uses a mock WizTree process, real backup creation and verification, explicit PowerShell selection, cleanup, and restore. Tests do not run WizTree or touch real user data.
