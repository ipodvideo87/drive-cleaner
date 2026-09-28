# Drive Cleanr user guide

Drive Cleanr is a conservative Windows CLI workflow. It finds disk usage with WizTree or WinDirStat, screens candidate paths against safety exclusions, creates a reviewable PowerShell plan, and requires a verified backup before cleanup.

## 1. Install and scan

Install Python 3.10+ and have either WizTree or WinDirStat available. WinDirStat 2.6.0 or newer is required for automated CSV export. Standard WizTree scans can run without elevation; only fast MFT scanning requires an administrator terminal. Standard WizTree and WinDirStat scans may miss files the current account cannot access.

Drive Cleanr supports the official portable versions of [WizTree](https://diskanalyzer.com/download) and [WinDirStat](https://github.com/windirstat/windirstat/releases). For WinDirStat, use 2.6.0 or newer; this project uses the current `/SaveTo` form. If a portable executable isn't discovered, set `WIZTREE_PATH` or `WINDIRSTAT_PATH` to its full path. WinDirStat applies its saved filters, so check those before a full-drive scan.

Start the guided workflow with:

```powershell
python drive_cleaner.py
```

Choose **Scan a drive**, then select WizTree or WinDirStat and answer the drive, export, and timeout prompts. The menu can open the completed scan in the review interface. You can also run `python scan.py --app wiztree C:` or `python scan.py --app windirstat C:` directly. Set `WIZTREE_PATH` or `WINDIRSTAT_PATH` if an executable isn't found automatically.

Scans include file rows so large individual files remain visible. The default timeout is 30 minutes; for a larger or slower volume, increase it with `--timeout 3600`. Progress shows elapsed time and bytes written. The scan is complete only after the selected scanner exits, its CSV is stable, and its path and size headers are recognized. WinDirStat applies its saved filters to command-line scans, so review its filter settings before scanning a whole drive.

Scans retain earlier exports and reviewed `clean_*.ps1` plans. Run `python scan.py --cleanup --keep-latest 1` only when you intend to remove older CSVs and generated plans in this project folder; increase `--keep-latest` to preserve more exports.

## 2. Review candidates

```powershell
python analyze.py --tui
```

Choose the latest scan or enter a CSV path. Review the disk summary, candidate tier, exact path, size, and description. You can list all candidates, export a text report, change the minimum size, or generate a plan. To use a fixed CSV instead, run `python analyze.py .\data\scan.csv --min-size 50 --list-items`.

The report shows when the scan export was last modified. Candidate paths and contents can change after a scan; rescan before generating a cleanup plan if the system has changed since then.

High, medium, and low are review tiers, not a guarantee of safety. Read [the knowledge base](../references/knowledge.md) before approving unfamiliar targets. Directory size estimates may overlap or include hard-linked data, so actual free-space gains can be smaller.

Drive Cleanr checks candidate file/folder types against the current filesystem. If WinDirStat did not include reliable type metadata, the current path type is used. If a row's exported type conflicts with the current path, it is skipped and counted in the report; rescan to refresh it.

When a path matches both a broad cache rule and a recognized package-manager rule, Drive Cleanr uses the more specific package-manager category and caution tier.

Crash-dump rules only apply under the drive's `Windows` directory, not to user archives or project folders with similar names.

## 3. Generate and inspect a cleanup plan

```powershell
python analyze.py .\data\scan.csv --min-size 50 --output clean_review.ps1 --priority high
```

Use `--priority medium`, `low`, or `all` for a different reviewed scope. Inspect the script and verify every exact path before running it. At runtime, select individual numbered targets, choose all, or cancel. The script backs up only the selected paths and asks for `CLEAN` before acting. Run it in a normal PowerShell session first; use an administrator session only when a reviewed target requires elevated access. `-Select 1,3 -Force` supplies an explicit reviewed selection and skips only the final confirmation prompt.

The analyzer rejects UNC/device paths, traversal paths, and drive roots from imported CSVs. It omits candidate paths that cross junctions, symbolic links, or path components with unreadable metadata. Before writing a plan, it repeats that link check and verifies each path matches the selected cleanup priority and exact rule label. The script checks that targets still exist with the same file/folder type and refuses reparse points. Take a new scan if the target changed after analysis.

## 4. Run, back up, and verify

Before deleting anything, the script invokes `backup.py` for every selected target. A missing or partial backup stops the cleanup. Immediately before removing each target, it verifies the backup payload and confirms the source still matches the content saved at backup time. A changed target is left in place. Backups go to a non-system drive with at least 5 GB free; there also needs to be sufficient room for the selected data. File backups are copied directly; smaller directories are copied; larger directories are compressed.

Keep the backup until the affected apps and Windows behave normally for an observation period. Restore offers overwrite or merge. Merge preserves existing files and restores missing files; overwrite replaces conflicts after you approve. For unattended use, `--yes` explicitly approves overwriting conflicts:

```powershell
python backup.py list
python backup.py restore --id backup_YYYYMMDD_HHMMSS_microseconds
# Explicitly approve overwriting existing files during a scripted restore
python backup.py restore --id backup_YYYYMMDD_HHMMSS_microseconds --yes
```

To remove one backup permanently, use `python backup.py delete --id <id>` and confirm the prompt. Do not remove a backup until you no longer need its recovery copy.

## 5. Other useful options

```powershell
# Exclude individual files from a smaller export
python scan.py C: --folders-only

# Allow a longer run
python scan.py C: --timeout 3600

# Machine-readable report and candidate list
python analyze.py .\data\scan.csv --json
python analyze.py .\data\scan.csv --list-output candidates.txt

# Manage stored backups
python backup.py drive
python backup.py list
python backup.py info --id backup_YYYYMMDD_HHMMSS_microseconds
python backup.py verify --id backup_YYYYMMDD_HHMMSS_microseconds
```

## Troubleshooting a scan

- Confirm the terminal is elevated for MFT scanning.
- Confirm `python scan.py --latest` and `python scan.py C:` use the project folder you expect.
- Set `WIZTREE_PATH` to the 64-bit `WizTree64.exe` if auto-detection fails.
- Try a longer timeout for a large drive; do not delete partial results until you confirm the scan is no longer running.
- The scanner now waits for the WizTree process to exit. If it times out, note the final elapsed time and export size, then retry with a longer timeout.

## Developer checks

```powershell
python -m unittest discover -s tests -v
python -m py_compile analyze.py backup.py scan.py
```

Tests use temporary fixtures and mocked scanner processes. They do not run scans against user drives or remove user data.
