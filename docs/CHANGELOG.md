# Changelog

## Unreleased
- Prefer the most specific matching cleanup rule so package-manager caches are not labeled by generic cache rules.
- Skip ambiguous WinDirStat candidate rows rather than defaulting them to files; report how many were omitted.
- Verify backup payloads and selected source contents immediately before cleanup; stop and leave changed targets in place.
- Add `backup.py verify` for checking all or selected backed-up paths.
- Require scan exports to contain a stable, readable CSV path and size header before reporting success; accept WizTree's optional generated-note line.
- Refuse scan creation and scan retention cleanup through a symlink or junction so pruning cannot follow redirected project storage.
- Preserve files already present at restore destinations unless overwrite is explicitly approved; allow safe directory merges of missing files, report conflicts, and preflight archive parent paths before writing.
- Reject backup sources reached through reparse points, backup storage roots that cross junctions, and backup ID collisions that could reuse an existing directory.
- Compare each large ZIP backup's streamed file hashes with a source fingerprint so changing files cannot pass verification as a complete backup.
- Expand project-root detection to common manifests, lockfiles, Visual Studio solution/project files, and build metadata; omit candidates when a directory cannot be checked for markers.
- Protect legacy `.codex-old` profiles that may contain credentials and task state, and warn when Conda, Mamba, or Pixi is active before package-cache cleanup.
- Revalidate cleanup-plan targets against the selected priority and exact rule label so edited or malformed candidate data cannot turn an unrelated path into a deletion target.
- Match automated cleanup and protection patterns on complete Windows path components, preventing embedded names such as `CacheInspector` and `OneDriveBackup` from inheriting unrelated classifications.
- Require exact component matches, list supported dump filenames explicitly, and use matching component boundaries when generated plans preserve protected paths.
- Keep standard `OneDrive - <organization>` roots protected without treating `OneDriveBackup` as the same folder.
- Protect Microsoft Store Codex package folders and `AppData\Roaming\Codex` state surfaced in the shared candidate report.
- Correct the WizTree elevation guidance: standard scans are available without elevation; only fast MFT scanning requires an administrator terminal.
- Run the Windows mock and safety suite in GitHub Actions on Python 3.10 and 3.13 for pushes and pull requests.
- Keep cleanup-script generation compatible with Python 3.10 and use a long Windows temp path in the nested-preservation integration test.
- Store SHA-256 integrity hashes in new file, directory-copy, and ZIP backup manifests; verify every payload before any restore writes, while retaining warned size/structure checks for older backups.
- Reject drive roots and unsafe/non-local paths as direct backup sources before creating backup storage.
- Document the useful scanner-native command-line modes and which modes Drive Cleanr uses for cleanup scans.
- Preserve excluded locations and nested project roots when a user selects a parent directory for cleanup, and refuse directory trees with reparse points; explain that priority subtotals can overlap across tiers.
- Clarify that reported folder totals may include protected nested data that cleanup will preserve.
- Allow guided and direct scans of an existing local folder as well as a drive root.
- Expose WizTree export depth in the guided scan setup and clarify that WinDirStat exports use its saved scan filters/settings.
- Reject WizTree-only export settings when WinDirStat is selected instead of silently ignoring them.
- Add non-admin standard WizTree scans alongside fast MFT mode, with automatic mode selection and access warnings carried into scan review.
- Reject scan CSVs that lack required path/size columns and let the review menu return cleanly to scan selection.
- Omit cleanup candidates beneath detected project roots, remove unreachable `$WinREAgent` candidate labeling, and describe risk tiers without promising an item is safe.
- Honor an empty `.drive-cleanr-protect` file as a user-defined project-root exclusion marker.
- Deduplicate overlapping candidate sizes in text-list exports so they match the report's cross-tier estimate.
- Detect the CSV header after a single GUI WizTree generated-note line, and return a useful format error when required headers are absent.
- Refuse to overwrite existing generated plans or candidate reports, and revalidate imported plan paths and types before writing PowerShell.
- Handle refused candidate-report destinations in the interactive menu without terminating the review session.
- Protect Codex/agent settings and container machine data from generic cache rules, and warn during Windows installer/update/package-manager activity.
- Correct WinDirStat 2.x folder detection from hexadecimal attributes and item counts.
- Exclude Downloads from cleanup suggestions and warn users to check for active installers or builds before cleaning temporary folders.
- Recheck protected paths when generating cleanup plans from imported or edited candidate data.
- Protect recovered installation data, Windows Update downloads, Windows recovery/update logs, and Service Worker storage from direct cleanup; add process warnings for Node.js and Rust package/build tools.
- Show row-count progress while analyzing large scan exports and read CSV rows by precomputed column index.
- Skip candidate paths that disappeared after the scan so stale entries do not inflate reclaimable totals.
- Validate every restore manifest destination before writing, limit restores to normalized local paths, and preflight ZIP entries against traversal, alternate streams, reserved device names, and existing reparse points.
- Keep cleanup-plan selection numbers tied to the original targets when a path goes missing before execution.
- Ask about file-row exports only for WizTree; WinDirStat's guided flow no longer prompts for an option it ignores.
- When WinDirStat omits capacity metadata, show current local-volume space with an explicit analysis-time label.
- Stop the scanner and remove only its partial export after Ctrl+C or an unexpected scan error.
- Make protected Claude subtree lookups scale with folder entries instead of repeatedly scanning all protected paths.
- Verify file and small-directory backup contents with SHA-256 fingerprints so same-size corruption cannot pass as a complete backup.
- Add a guided `python drive_cleaner.py` menu for scanning, reviewing, and managing backups.
- Add scanner selection for WizTree and WinDirStat 2.6+, with WinDirStat CSV parsing and physical-size handling.
- Document that official portable archives need no installation and are supported, with the correct WinDirStat CLI version and WizTree elevation requirements.
- Keep guided scan output focused on progress/results; omit raw executable commands and unrelated cleanup commands.
- Translate the user interface and cleanup knowledge base into English while retaining compatibility with Chinese WizTree CSV headers.
- Label the main-menu scan picker as “Use a previous scan.”
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
