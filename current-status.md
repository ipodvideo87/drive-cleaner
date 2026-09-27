# Current status

Updated: 2026-09-27

GitHub repository: https://github.com/ipodvideo87/drive-cleaner (public; local scan exports and generated plans are ignored).

## Project shape

This is a Python command-line utility for Windows that uses WizTree or WinDirStat exports. `python drive_cleaner.py` opens a guided menu for scanning, analysis, and backup management. Automated WinDirStat scanning requires 2.6.0 or later. It is not yet a signed installer or desktop GUI. The primary user flow is scan → review report → generate PowerShell plan → confirm → backup → cleanup → observe/restore if needed.

## Current capabilities

- Guided single-command menu for scan, review, and backup management.
- WizTree and WinDirStat 2.6+ scanning, selectable at the prompt or with `--app`; both auto-detected through environment variables, local folders, common install paths, and `PATH`. Official portable builds are supported when the executable is located or configured.
- WinDirStat CSV parsing using its full path, logical size, physical size, and directory attributes.
- Process-aware scan progress and configurable timeouts; prior scan exports and reviewed cleanup scripts stay until explicit cleanup.
- Full scans include file rows so large individual files are visible.
- English/Chinese and GUI WizTree export parsing plus WinDirStat 2.x export parsing; size threshold, JSON output, report export, and interactive TUI.
- High/medium/low cleanup classifications, safety exclusions, and generated scripts for selected tiers.
- Generated scripts let users select numbered targets, select all, or cancel. They back up only the selected targets, abort on an incomplete backup, recheck target type and reparse-point status, then report each cleanup result.
- Backups support files, direct directory copies, compressed directories, manifests, listing, restore, and deletion.
- Large directory archives use ZIP64 and include hidden entries; restore checks archive paths before writing and restores saved Windows attributes.
- Mock safety tests cover malformed paths, PowerShell quoting, backup failure, scan timeouts, and generated-script preservation.

## Verification snapshot

- `python -m py_compile analyze.py backup.py scan.py drive_cleaner.py tests/test_safety.py` — passed.
- `python -m unittest discover -s tests -v` — passed (25 tests), including PowerShell item selection, cancel, partial-backup abort, ZIP restore path validation, temporary-directory deletion behavior, WinDirStat CSV/launch mocks, and the guided scan-to-review menu.
- Parsed the existing 1.32 GB WizTree export read-only; English headers, volume capacity, and candidate extraction worked.
- An end-to-end scan was not run because it requires a working, elevated WizTree installation. The scan runner now waits for process exit, reports output growth, and defaults to a 30-minute timeout.
- Generated PowerShell was parsed and executed against isolated temporary directories with a mock backup helper; no real user data was targeted.

## Known work / limitations

- The real WizTree integration still needs validation on an elevated Windows machine with the user's installed WizTree version.
- The real WinDirStat 2.6+ integration needs a Windows scan pass; its saved filters affect command-line exports.
- Backup archive fidelity and restore behavior need a Windows integration pass with hidden/system entries and files larger than 4 GB.
- The TUI remains text-based; no installer, desktop interface, scheduled cleanup, or automatic deletion is provided.
- Review reclaimable-space estimates conservatively: hard links, busy files, and overlapping folder totals can make them differ from actual free-space changes.

## Repository hygiene

Local scan CSVs, backups, bytecode, and generated cleanup scripts are excluded from source control. Never commit scan exports or personal path data.
