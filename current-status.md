# Current status

Updated: 2026-09-27

GitHub repository: https://github.com/ipodvideo87/drive-cleaner (public; local scan exports and generated plans are ignored).

## Project shape

This is a Python command-line utility for Windows that uses WizTree or WinDirStat exports. `python drive_cleaner.py` opens a guided menu for scanning, analysis, and backup management. Automated WinDirStat scanning requires 2.6.0 or later. It is not yet a signed installer or desktop GUI. The primary user flow is scan → review report → generate PowerShell plan → confirm → backup → cleanup → observe/restore if needed.

## Current capabilities

- Guided single-command menu for scan, review, and backup management.
- WizTree and WinDirStat 2.6+ scanning, selectable at the prompt or with `--app`; both auto-detected through environment variables, local folders, common install paths, and `PATH`. Official portable builds are supported when the executable is located or configured. Scans accept a drive root or existing absolute local folder.
- WizTree exports use documented CLI options for standard or fast MFT scanning, file/folder rows, allocation sorting, drive capacity, and export depth. Automatic mode uses fast MFT for elevated whole-drive scans and standard mode otherwise; the scan mode is encoded in the export name and the review report carries the access limitation forward. The guided flow exposes scan mode, file rows, and depth. WinDirStat `/SaveTo` uses the app's saved filters and scan settings. WinDirStat also supports separate load, duplicate-report, and permission-report modes; Drive Cleanr keeps cleanup scans on the CSV tree-export mode.
- Cleanup category and protection rules match whole Windows path components (or adjacent component sequences) to avoid classifying folders because their names merely contain a keyword.
- Codex protection covers `.codex`, Microsoft Store package folders beginning `OpenAI.Codex_`, and `AppData\Roaming\Codex` profiles discovered in the shared candidate report.
- WinDirStat CSV parsing using its full path, logical size, physical size, and hexadecimal directory attributes plus file/folder counts.
- When a WinDirStat export lacks volume statistics, show current local drive capacity/free space and label it as checked at analysis time.
- English-language menus, prompts, reports, and reference documentation; the analyzer still accepts Chinese WizTree column headings.
- Process-aware scan progress and configurable timeouts; Ctrl+C stops the active scanner and removes only its partial export, while prior scan exports and reviewed cleanup scripts stay until explicit cleanup.
- Full scans include file rows so large individual files are visible.
- English/Chinese WizTree exports (including a generated-note preface) plus WinDirStat 2.x CSV exports; size threshold, JSON output, deduplicated candidate-list export, and interactive TUI.
- High/medium/low cleanup classifications, safety exclusions, and generated scripts for selected tiers. Downloads, OneDrive roots (including `OneDrive - <organization>`), recovered previous-installation trees, Windows Update downloads, Windows recovery staging, update logs, Service Worker data, Codex/agent settings, and container machine state are excluded from direct cleanup. Candidate rules match exact path components or adjacent component sequences; only explicitly named dump files accept dotted filenames. Candidates under detected project roots or folders containing `.drive-cleanr-protect` are omitted; plan generation revalidates local non-root paths, exclusions, project markers, selected priority, and exact rule labels for imported candidate data. Temporary-folder candidates carry an installer/build review warning, with process warnings for common browsers, editors, Java, Node.js, Rust, Go, .NET, Windows servicing, and package managers.
- Candidate list exports deduplicate overlapping parent/child paths across risk tiers and label the risk tier without calling any candidate guaranteed safe.
- Generated cleanup plans and candidate reports refuse to overwrite an existing file.
- Generated scripts let users select numbered targets, select all, or cancel. Plan indices stay attached to their original targets when another target has disappeared. They back up only selected targets, abort on an incomplete backup, recheck target type and reparse-point status, preserve nested protected data and project roots, then report each cleanup result.
- Directory cleanup also preserves nested excluded locations and detected project roots when a user selects a parent candidate, and refuses to clean directory trees containing reparse points. Tier subtotals explicitly warn that cross-tier folder overlaps affect category sums.
- Backups support files, direct directory copies, compressed directories, manifests, listing, restore, and deletion.
- Backup creation rejects drive roots and non-local or non-normalized source paths before creating backup storage.
- New file, directory-copy, and ZIP backups record SHA-256 integrity fingerprints; restore checks all payloads before writing any destination. Older manifests without hashes remain supported with size/structure checks and a warning. Same-size backup mismatches at creation mark the backup partial so cleanup cannot proceed.
- Large directory archives use ZIP64 and include hidden entries; restore validates all manifest targets before writing, refuses traversal/network/device targets and reparse-point redirection, and restores saved Windows attributes.
- Mock safety tests cover malformed paths, PowerShell quoting, backup failure, scan timeouts, and generated-script preservation.

## Verification snapshot

- `python -m py_compile analyze.py backup.py scan.py drive_cleaner.py tests/test_safety.py` — passed.
- `python -m unittest discover -s tests -v` — passed (73 tests), including generated-plan rejection for paths that do not match the selected tier or exact cleanup label, plus acceptance of valid lower-tier candidates in all-priority plans; automatic/non-admin WizTree mode selection, fast-mode elevation checks, and scan-mode warning retention in the report; backup-root rejection before storage creation; nested protected-path/project preservation and nested reparse-point refusal during PowerShell cleanup; same-size backup corruption detection during creation and restore; WinDirStat folder typing and current-volume fallback; protected system/user/tool data; project-root markers; reserved-path rejection; output overwrite/target-placement guards; cross-tier size deduplication; PowerShell quoting and execution; stable item selection after a target disappears; scanner cancellation/failure cleanup and terminate-to-kill escalation; partial-backup abort; complete manifest restore validation; ZIP traversal/alternate-stream/device-name/reparse-point protections; directory restore link checks; malformed CSV handling; whole-component cleanup/protection pattern matching, named dump file handling, and Codex paths from the shared candidate report; drive/folder target validation; scanner-specific option validation; both scanner launch mocks; guided prompts; English UI; and previous-scan/review menus.
- GitHub Actions runs the Windows mock and safety suite on Python 3.10 and 3.13 for pushes and pull requests.
- Live WinDirStat scan of a temporary fixture completed on the current code; its CSV parsed and produced an analyzer candidate. The earlier WinDirStat 2.9 scan on removable `E:` also completed in under 20 seconds and reported volume capacity/free space. All temporary exports were removed; no cleanup was run.
- Live WizTree 4.33 standard-mode scan of a temporary fixture completed in a non-elevated shell; the CSV parsed, its mode was retained for review messaging, and the expected candidate was found. The fixture/export were removed; no cleanup was run.
- A saved 3.2-million-row WinDirStat export was analyzed read-only in an earlier worktree revision. That export is unavailable in the current worktree, so the latest project-marker and protection rules have synthetic coverage but have not been rechecked against that full export.
- A 1.32 GB WizTree export was parsed read-only in an earlier worktree; no local export is present now to rerun against the latest code.
- A full-drive WizTree fast MFT scan has not been run because this shell is not elevated. Standard mode is available without elevation; the scan runner waits for process exit, reports output growth, and defaults to a 30-minute timeout.
- Generated PowerShell was parsed and executed against isolated temporary directories with a mock backup helper; no real user data was targeted.

## Known work / limitations

- Elevated full-drive WizTree MFT integration still needs validation on an administrator terminal. The non-elevated standard mode passed on an isolated fixture.
- The live WinDirStat scan passed on an isolated fixture and earlier on a small removable volume; a full main-drive pass and saved-filter review remain useful integration checks.
- Project detection relies on common marker files; put `.drive-cleanr-protect` in the root of an unmarked project whose contents must never appear as cleanup candidates.
- Backup archive fidelity and restore behavior need a Windows integration pass with hidden/system entries and files larger than 4 GB.
- The TUI remains text-based; no installer, desktop interface, scheduled cleanup, or automatic deletion is provided.
- Review reclaimable-space estimates conservatively: hard links, busy files, and overlapping folder totals can make them differ from actual free-space changes.

## Repository hygiene

Local scan CSVs, backups, bytecode, and generated cleanup scripts are excluded from source control. Never commit scan exports or personal path data.
