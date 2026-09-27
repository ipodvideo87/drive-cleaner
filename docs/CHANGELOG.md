# Changelog

## Unreleased
- Add a guided `python drive_cleaner.py` menu for scanning, reviewing, and managing backups.
- Add scanner selection for WizTree and WinDirStat 2.6+, with WinDirStat CSV parsing and physical-size handling.
- Document that official portable archives need no installation and are supported, with the correct WinDirStat CLI version and WizTree elevation requirements.
- Keep guided scan output focused on progress/results; omit raw executable commands and unrelated cleanup commands.
- Add mocked coverage for WinDirStat command construction, CSV parsing, and the guided scan-to-review flow.

This project follows [Semantic Versioning](https://semver.org/).

## [v1.2.0] - 2026-09-27

### Safety and reliability
- Fixed scans to wait for WizTree's process exit, report export growth, and default to a 30-minute timeout for large drives.
- Prevented a new scan from deleting reviewed cleanup scripts; script removal is now only part of explicit `--cleanup`.
- Automatic scans retain prior exports; explicit cleanup accepts a configurable retention count.
- Rejected UNC/device, traversal, and drive-root paths from imported CSVs; path comparisons now account for Windows case and separators.
- Preferred allocated size for reclaimable estimates and excluded WizTree hard-link rows.
- Limited Windows Update cleanup to `SoftwareDistribution\\Download`.
- Generated scripts use PowerShell-safe literals, request a backup first, stop on partial backups, validate target type and reparse-point status, and preserve `claude*` entries at any depth.
- Cleanup plans support explicit numbered per-item selection; cancellation exits before backup or deletion.
- Backups fail closed for unreadable, missing, empty, mismatched, or insufficient-space targets; file backups are supported and backup IDs cannot traverse directories.
- Large directory backups use ZIP64, include hidden/system entries, verify CRC and byte totals, and restore rejects archive path traversal.
- Restore and permanent backup deletion prompt before proceeding.

### Project usability
- Added contributor instructions, a root quick-start README, current status, mock safety tests, and a refreshed user guide.
- Added `.gitignore` rules for scan exports, backups, and generated cleanup plans.

## [v1.1.0] - 2026-07-17

Safety hardening and coverage expansion based on a full real-world run that freed 28.9 GB on a single machine.

### Safety hardening
- 🔒 Moved `Package Cache` / `InstallerCache` from the medium-priority cleanup list into the **safety red-line exclusion list**. Removing them can break software repair and uninstall flows.
- 🔒 Downgraded browser IndexedDB from high priority to low priority. It is offline web-app data, not a simple cache, and removing it can sign you out or delete data.
- 🔒 Added new red-line exclusions: system restore points, `Windows\Installer`, DriverStore, personal data directories (`Documents`, `Desktop`, `Pictures`, `OneDrive`), WeChat/QQ data (`Tencent Files` / `xwechat_files`), and `.ssh` / `.gnupg`.
- 🛡️ Administrator mode still keeps the "plan approval" gate: full automation skips manual script execution, but it does not skip user review.

### New
- 🆕 Added `references/knowledge.md` as the knowledge base: red lines, tiered pattern tables, locating regexes, and execution rules. This creates a two-layer analysis flow: pattern screening plus knowledge-base review.
- 🆕 Added pattern coverage for kernel crash dumps (`LiveKernelReports` / `Minidump`), Chrome on-device AI models (`OptGuideOnDeviceModel`, about 4 GB, with a flag note to prevent re-downloads), `$WinREAgent`, and Playwright test browsers.
- 🆕 Renamed `skill.md` to `SKILL.md` and added standard YAML frontmatter (`name` / `description`) so the skill can auto-trigger correctly.

### Fixes and improvements
- 🐛 Fixed a subdirectory de-duplication bug where `npm-cache2` was incorrectly treated as a child of `npm-cache`.
- 🐛 Made `analyze.py` compatible with GUI-exported first-line notes and English column names (`File Name` / `Size`).
- 🐛 Generated cleanup scripts now support single-file targets, exclude `claude*` files, check more processes (`VS Code` and Java/Gradle), and print clearer failures.
- 🔧 Made `scan.py` path resolution portable instead of hard-coding absolute paths. It now detects WizTree from `WIZTREE_PATH` -> skill directory -> Program Files -> PATH.
- 🔧 Changed `scan.py` to export file rows by default (`--folders-only` restores the older behavior). Single giant files such as dumps and AI models are now visible.
- 🔧 Made `backup.py` prefer `pwsh` (PowerShell 7+) to avoid the 4 GB `Compress-Archive` limit in Windows PowerShell 5.1.

---

## [v1.0.0] - 2026-01-27

### New
- 🛡️ **Backup and restore workflow**: automatically back up before cleanup and restore if something goes wrong
  - Automatically choose the non-C drive with the most free space for backups
  - Smart backup format: direct copy for items under 1 GB, compression for larger ones
  - Full restore support
  - Backup management commands (`list`, `info`, `delete`, `cleanup`)

### Changes
- Updated the workflow to include backup and verification stages
- Updated the guide with backup instructions
- Added FAQ entries for backup-related questions

### File changes
- Added `backup.py` - core backup and restore module
- Updated `skill.md` - workflow definition
- Updated `GUIDE.md` - usage guide
- Updated `README.md` - added version badge

---

## [v0.2.0] - 2026-01-26

### New
- Optional temporary-file cleanup after the main cleanup
- `scan.py --cleanup`

### Improvements
- Optimized WizTree export parameters and set `/exportmaxdepth=200` to reduce file size

---

## [v0.1.0] - 2026-01-25

### Initial release
- WizTree fast scanning integration
- AI-powered analysis to identify cleanup candidates
- Three priority levels: high / medium / low
- Safety rule: never delete system files
- Dual-mode support: standard permission / administrator permission

### Core files
- `scan.py` - automatic scanning script
- `analyze.py` - data analysis script
- `skill.md` - skill definition
- `GUIDE.md` - usage guide

---

## Versioning

- **MAJOR**: incompatible API changes
- **MINOR**: backward-compatible feature additions
- **PATCH**: backward-compatible bug fixes

[v1.1.0]: https://github.com/iziqing/-disk-cleaner/releases/tag/v1.1.0
[v1.0.0]: https://github.com/user/repo/releases/tag/v1.0.0
[v0.2.0]: https://github.com/user/repo/releases/tag/v0.2.0
[v0.1.0]: https://github.com/user/repo/releases/tag/v0.1.0
