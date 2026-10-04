# Changelog

- Verify candidate file/folder types against the current filesystem; use current type when WinDirStat metadata is missing and skip mismatches with a rescan message.

## Unreleased
- Recheck ZIP restore destinations before and after creating directory entries, and recheck directory-copy source and destination paths immediately before Robocopy after conflict inventory.
- Reject scanner exports that pass through a reparse point or junction before validation or promotion into the saved-scan list.
- Let guided scan users use the detected executable by default or choose another installed/portable scanner executable for one scan.
- Ignore a shared `.gitignore` at the user-profile root when detecting project roots, while continuing to protect nested projects and roots containing `.git`.
- Show byte and percentage progress during the final locked content check immediately before deletion, and while checking large named data streams.
- Escape nonprinting manifest and archive-derived error text; reject hidden-format restore paths and malformed byte counts before verification or writing.
- Index cleanup-rule matching by path components and cache configured temporary roots so large scan exports avoid checking every rule against every row.
- Keep recovery backups opt-in in every cleanup mode: interactive cleanup defaults to no backup, and reviewed `-Force` runs create one only when `-Backup` is supplied. Continue to verify any requested backup before the first removal.
- Filter detected projects, redirected paths, and missing files before building the bounded largest-file shortlist, so ineligible large entries cannot crowd eligible files out of manual review.
- Show up to 100 of the largest unclassified files in a separate manual-review list, with exact-file-only selection, protected/project filtering, no bulk selection, and a typed acknowledgement before a manual cleanup plan can be created.
- Include each folder's eligible descendant file-data size in cleanup-plan previews, and distinguish overlapping folder-row totals from the deduplicated overall total.
- List retained scans newest first in the guided review picker, including recognized legacy scan folders, with numeric selection and pagination.
- Limit scan retention cleanup to validated Drive Cleanr-generated scan exports and their exact paired plans; preserve unrelated CSV files and user-authored scripts.
- Reject restore destinations inside or above Drive Cleanr backup-storage roots before asking for approval or writing restored data.
- Skip and count scan paths with hidden formatting or terminal-control characters so cleanup targets cannot be visually spoofed in the terminal.
- Let guided users enter the full path to an installed or portable scanner executable when automatic discovery fails, and validate it before passing it to the scan process.
- Use the project directory consistently in `SKILL.md` script examples and guard its quoted YAML description against regressions.
- Reject malformed backup manifest field types and unsafe verification source paths cleanly before source filesystem checks.
- Render unrecognized backup manifest statuses as `Unknown` so malformed backups remain manageable for deletion without being treated as restorable.
- Reject Windows-invalid filename characters in restore destinations and ZIP entries before presenting or writing restored data.
- Validate guided restore destinations before prompting; reject incomplete, malformed, or overlapping paths and escape terminal controls in displayed paths.
- Make `D` and `B` distinct in the nested file/folder picker: `D` keeps picks from the current browse, while `B` returns without adding them and preserves earlier main-list selections.
- Browse scan entries hidden beneath a summarized folder to select exact files or subfolders. Paginate and filter large result sets, respect the chosen review levels, and explain when stale, project, or linked candidates were left off the list.
- Add `-PreviewOnly` to generated cleanup plans. It runs current safety checks and lists each eligible path and file size without creating a backup or removing data.
- Show progress during recovery restores: file copies and verification show byte and percentage progress, ZIP restores report archive-check and extraction progress, merge restores show existing-file checks, and directory restores show a periodic Robocopy status. Restore totals count completed items and keep conflicts and failures separate.
- Handle Ctrl+C and end-of-input throughout the guided scan review so the main menu returns cleanly instead of showing a traceback.
- Reject folders in the saved-scan picker and recover with a clear prompt when a scan file is missing or unreadable, in both the guided review and direct analyzer command.
- Show byte counts and per-file percentages while hashing large selected files, so long content checks remain visibly active.
- Rescan the selected folder for newly appeared project markers, protected paths, and reparse points after backup verification but before the first removal; stop cleanup if the review scope changed.
- Copy named NTFS streams explicitly during individual-file backup and staged restore so Python 3.10 does not produce incomplete recovery data.
- Recognize common AI-assistant project guidance files and editor settings folders as project markers, protect candidates beneath them during analysis and cleanup, and ignore shared settings at the user-profile root.
- Exclude agent/editor settings data folders from cleanup suggestions, while matching only the exact folder names so similarly named cache paths remain reviewable.
- Protect cache-like paths inside projects marked by a VS Code `.vscode` folder or `*.code-workspace` file, without treating profile-level VS Code extensions or workspace files as markers for the whole user profile.
- After a direct scan, point users to **Review a previous scan** in the guided menu instead of printing a second Python command.
- Detect WinDirStat executable versions before scanning; stop for versions older than 2.6 and explain when the version cannot be read.
- Parse localized WinDirStat CSV headers using the documented layout only after validating its path, numeric fields, and internal type/index values; keep the review output in English.
- Standardize the guided wording from scan setup through result review, individual file/folder selection, Administrator launch, cleanup confirmation, and recovery-backup management.
- Make the first cleanup status say the selected item is being checked and that nothing has been removed yet.
- Show clear project checks, folder reviews, and project-file/protected-data classification passes with a visible console count every 100 entries before any items in that folder can be removed, even when a terminal hides transient PowerShell progress bars.
- Print file-content check and removal counts every 100 files, and use larger sequential read buffers for hashing selected files.
- Include named data stream contents in cleanup snapshots, lock file streams and compare directory streams at the removal boundary, and keep the affected item if its streams change.
- Show the first folder entry and first file being checked immediately, then print long-running progress updates every 100 items or 10 seconds.
- Show the first entry and completion of each project-marker check, including slow pre-cleanup checks, and remove a redundant post-confirmation scan while keeping the cleanup-loop recheck.
- Remove an unsupported estimate of how much reclaimable space the analyzer's pattern rules cover; describe their actual scope and case-by-case review for unmatched large items.
- Clarify that the folder preflight completes before removal, then selected files are rechecked and removed one at a time; progress identifies the file currently being processed and counts only successful removals.
- Report exact successful file, folder, and byte removals, including partial results when a later cleanup check fails.
- Number cleanup progress by the selected-item processing order, show each exact path, and warn on later items that earlier selections may already have been removed.
- Use phase-specific preflight messages so later checks do not imply that earlier selected items are still untouched.
- Exercise generated cleanup in Windows PowerShell 5.1 as well as PowerShell 7 using an isolated temporary fixture.
- Avoid a separate PowerShell filesystem lookup for every selected child; retain the lexical folder-boundary check and validate the leaf type, reparse-point status, identity, size, timestamp, and hash through the native locked handle immediately before deletion.
- Find `backup.py` in the project folder when a cleanup plan is saved elsewhere, while using an adjacent helper when one is present.
- Use File/Folder labels in the selection and final plan review, explain that only scan-listed entries can be chosen, call the size filter an item-size filter, and make nested-space estimates easier to understand.
- Clarify that choosing a folder includes contents not listed as separate scan suggestions, while protected and project data are kept and higher-risk candidates stay unless explicitly selected too; warn that the 12-item preview is incomplete.
- Ignore the full local `data/` tree and default `*.clean.ps1` plans so scan exports and generated cleanup plans stay out of commits by default.
- After guided plan creation, detect an elevated administrator session and offer to run the saved plan there; declining leaves it saved, and the script's own cleanup confirmation remains required.
- Show detected project roots and the marker evidence that caused cleanup candidates beneath them to be withheld from console and exported review reports.
- Show progress while sizing, copying, compressing, hashing, and verifying large backups, including periodic heartbeats during Robocopy; keep `--json` output parseable by sending progress to stderr.
- Show CSV byte-read percentage while analyzing a scan export, with 100% reported after parsing finishes.
- Use monotonic time for scan-export stabilization deadlines so system-clock corrections do not shorten or extend the wait unexpectedly.
- Distinguish automatically suggested cleanup paths from manual-only examples in the safety knowledge base, and align its cache/log summaries with the analyzer's review tiers.
- Explain nested candidates that appear in multiple risk tiers, show their nearest containing candidate, and attribute nested space to its tier so tier estimates do not double count.
- Separate the live scan-progress line from the final scan-complete message so the two messages do not run together.
- Preserve nested candidates from more cautious tiers when a selected parent folder covers them, and show those paths in the cleanup review preview.
- Honor a user's explicit selection of a nested higher-risk candidate inside a selected parent folder, and show the nested choice in the plan preview.
- Normalize unexpected PowerShell cleanup errors to an English summary while retaining Drive Cleanr's specific safety explanations.
- Include and verify Windows alternate data streams in new recovery backups; use direct-copy backups for large folders containing them and stop if the destination cannot preserve their contents.
- Delete selected cleanup items through verified Windows handles, holding a shared byte-range lock during the final hash and deletion so ordinary file-handle writes and last-moment junction/path replacements cannot redirect or change the item being removed; keep changed files and nonempty folders in place.
- Preserve cleanup support for read-only selected files by clearing the read-only attribute only on the verified file handle before removal.
- Label Cargo install build output and Chocolatey package staging inside known temp roots as caution candidates, since they can contain compiled executables or installer payloads.
- Hash each selected-folder file before backup verification and again immediately before removal; leave a changed file in place even when its replacement has the same size and preserved timestamp.
- Write scanner output to an isolated incomplete-scan folder and publish it to the previous-scan list only after process exit and CSV validation; preserve and isolate partial output if the scanner cannot be confirmed stopped.
- Prefer the more cautious cleanup tier when equally specific rules overlap, so Cache, Logs, or GPUCache labels are not downgraded by a broad Temp match.
- Reopen each selected folder descendant and recheck its nested parent paths immediately before removal, so a junction introduced after backup verification stops cleanup; preserve files whose size or last-write time changes after the backup check.
- Recognize Unreal, Godot, and Unity project roots so their generic cache folders stay out of cleanup candidates.
- Move Windows crash dumps from the lower-risk tier to caution and explain their troubleshooting and privacy value.
- Recognize Git project files and `.idea`/`.vs` workspace directories as project markers, while ignoring a shared root-level `.editorconfig` when checking the user profile.
- Preview a bounded set of direct folder contents before the typed cleanup confirmation so users can spot unexpected files before backup or removal.
- Handle Ctrl+C and closed input as cancellation at interactive analyzer, restore, and backup-delete confirmations.
- Re-prompt on invalid guided scan options and accept `Q` to cancel setup instead of silently treating an unrecognized file-row answer as yes.
- Keep folders merely named `Temp` or `Tmp` in the caution tier unless they are standard Windows/user temp roots or the configured `TEMP`/`TMP` location.
- Avoid forcing ZIP64 headers for known-small backup members; Python 3.10 writes nonconforming local headers when ZIP64 is forced unnecessarily. Large known members still use ZIP64.
- Label Scoop's downloaded installer cache explicitly in the confirm-first tier and point users to Scoop's cache controls.
- Exclude common cloud, container, and GitHub CLI profile directories from generic cache candidates because they can contain credentials and environment settings.
- Exclude per-user Microsoft Store app package data from generic temporary and cache cleanup candidates, consistent with the guidance to manage these apps through Windows Settings or `winget`.
- Prefer WizTree64.exe when `WIZTREE_PATH` points to the 32-bit launcher and its paired 64-bit worker is available, so scan completion tracks the export process.
- Treat access-denied or otherwise uncheckable path metadata as unsafe during backup, restore, and cleanup path checks; genuinely missing paths remain allowed.
- Reject ZIP backup members that require the same Windows path to be both a file and a directory before restoring any data.
- Change broad cache, log, GPU-cache, shader-cache, and code-cache labels to explain that names are only cues and users must review the location and contents.
- Restrict IndexedDB labels to recognized Chrome and Edge User Data profile paths; leave other same-named folders unclassified.
- Restrict Chrome model labels to Chrome User Data and NVIDIA update artifact labels to known updater paths; show NVIDIA update data as a caution candidate rather than disposable cache.
- Treat selected paths literally throughout cleanup checks, so legal wildcard characters such as brackets in Windows names do not change path matching.
- Restrict automatic crash-dump labels to known direct locations under the drive's Windows directory.
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
