# Drive Cleanr

Drive Cleanr helps Windows users find files and folders they may want to remove. Scan with WizTree or WinDirStat, review the suggestions, choose the exact items for a cleanup plan, decide whether to make a recovery backup, and confirm before anything is removed.

Drive Cleanr's menus, explanations, and review labels are in English. File and folder names and paths come from the scan and stay unchanged; they may use another language. Paths are not translated because they must identify the exact items on disk.

**Nothing is deleted during scanning or analysis.** A generated PowerShell plan shows the saved entries and lets you choose which to clean. Choosing a folder includes files and folders inside it, even when they are not separate scan suggestions. Protected paths and detected projects are kept. Higher-risk candidates inside a selected folder are kept unless you explicitly select one of those listed candidates too; the plan shows explicitly selected nested items in its preview. The preview shows up to 12 direct items; other contents may also be removed. You can create and verify a recovery backup first or continue without one after a distinct typed confirmation. If you choose a backup and it is missing, incomplete, or fails verification, cleanup stops. Backups are kept until you delete them.

## Get the project

```powershell
git clone https://github.com/ipodvideo87/drive-cleaner.git
cd drive-cleaner
```

## Requirements

- Windows 10 or newer
- Python 3.10+
- Windows PowerShell 5.1 (included with Windows) or PowerShell 7 to run generated cleanup plans
- [WizTree](https://diskanalyzer.com/) or [WinDirStat](https://github.com/windirstat/windirstat), installed or available through the guided scanner-path prompt or `WIZTREE_PATH` / `WINDIRSTAT_PATH`
- An administrator terminal for WizTree's fast full-drive scan (standard WizTree scans do not require elevation)
- Optional: a separate non-system drive with enough free space for recovery backups

### Portable versions

Drive Cleanr supports the official portable versions of [WizTree](https://diskanalyzer.com/download) and [WinDirStat](https://github.com/windirstat/windirstat/releases). Automated WinDirStat scans require version 2.6.0 or newer and use its `/SaveTo` export. If Windows reports an older version, Drive Cleanr stops before scanning and asks you to update; if it cannot read the version, it warns and tries the scan. WizTree's fast full-drive scan requires an Administrator terminal; its standard scan can run without administrator access but may miss files this account cannot access. In the guided menu, Drive Cleanr shows the detected scanner; press Enter to use it or choose another installed or portable `.exe` for that scan. If it cannot find a scanner, enter the full path to its executable. For direct `scan.py` use, set `WIZTREE_PATH` to the 64-bit `WizTree64.exe` or `WINDIRSTAT_PATH` to the `WinDirStat.exe` full path; quoted values are accepted, including paths with spaces.

## Quick start

Open PowerShell in this folder. Use an Administrator terminal for fast, full-drive WizTree scans; standard scans are available without administrator access.

```powershell
python drive_cleaner.py
```

The guided menu walks you through these steps:

1. Scan a drive or folder with WizTree or WinDirStat.
2. Review the suggested files and folders.
3. Choose individual files, folders, or both for a cleanup plan.
4. Choose whether to create and verify a recovery backup.
5. Review the plan and confirm before cleanup starts.

Scanning and review never remove anything. The main menu also lets you review a saved scan or manage recovery backups. Scans started directly with `scan.py` are available under **Review a previous scan** in that menu.

The scan picker lists saved scans newest first, including recognized scans saved in older Drive Cleanr folder layouts. Choose a scan by number; enter `N` or `P` to browse older or newer pages. To open another supported scan CSV, enter `M` and provide its file path. The picker accepts files, not folders. If a scan is missing or cannot be read, Drive Cleanr explains the problem and lets you choose another scan. Press Ctrl+C or close terminal input to cancel the review; no cleanup starts.

WizTree includes individual files in the results by default. If you choose folders only, individual files cannot be selected later. Its fast full-drive scan requires an Administrator terminal; standard scans may miss files this account cannot access. WinDirStat follows its saved filters, exclusions, and other scan settings; these can leave files out of the results, so review them before expecting a full scan. The scan menu asks for the drive or folder, scan options, and time limit. Press Ctrl+C to stop a scan. If a scan is cancelled or fails, Drive Cleanr tries to stop the scanner before removing its incomplete export. If it cannot confirm that the scanner stopped or Windows prevents removal, it tells you the export was preserved and shows its location; incomplete exports are never offered for review. Earlier scans are kept. The review shows when the scan file last changed; scan again if the drive or folder may have changed. File candidates whose current byte length no longer matches the scan are skipped and reported; rescan before reviewing them again. Direct commands remain available for automation.

Both scanners have native command-line options, and Drive Cleanr invokes the scan and export options it needs. WizTree gets explicit fast or standard scan mode, file/folder export, allocated-size sorting, capacity, and depth settings. WinDirStat gets `/SaveTo` with a CSV destination and scan target; its other native modes include loading saved scans and exporting duplicate or permission reports. Drive Cleanr uses scan-tree exports because its cleanup review needs item paths and sizes. WinDirStat follows its saved filters, exclusions, and other scan settings, which can leave files out of results; review those settings before scanning. See the official [WizTree command-line guide](https://www.diskanalyzer.com/guide) and [WinDirStat command-line and export reference](https://github.com/windirstat/windirstat/wiki/Command-Line-and-CSV) for their complete native options.

```powershell
python analyze.py .\data\scan.csv --min-size 50 --list-items
python analyze.py .\data\scan.csv --min-size 50 --output clean_review.ps1 --priority high
```

While Drive Cleanr reads the scan file, progress shows the percentage completed and reaches 100% when the review is ready.

The review report also shows up to 100 of the largest scanned files that did not match an automatic cleanup rule. This separate list is for investigation, not a recommendation that those files are safe to remove. Protected locations, detected projects, redirected paths, and files that are no longer present are filtered before the list is ranked, so excluded large entries do not hide other files. These files are not counted in the suggested-space estimate, and none are selected automatically. Choose **Review the largest files outside cleanup suggestions** to select exact individual files; bulk selection and folders are disabled for this group. Drive Cleanr asks you to type `REVIEWED` before saving a plan, then the plan still asks for its normal backup choice and cleanup confirmation. Only select files you recognize and no longer need.

In the guided review menu, each suggestion is labeled **File** or **Folder** and shows its exact path, size, and reason. Enter item numbers to choose listed suggestions. Enter `D` to browse the scan entries inside a listed folder and choose exact files or subfolders; the browser shows 25 entries per page and supports `F` to filter by name or path and `N`/`P` to change pages. The browser follows the review group chosen earlier; choose **All review levels** to inspect nested entries assigned to more cautious groups. In the browser, `D` finishes and keeps its picks; `B` returns to the main picker without adding picks from that browse session. Both choices keep entries already selected in the main picker. Press Enter in the main picker to finish. `A` chooses every suggestion in the main list; it does not automatically choose hidden nested entries. The scan must include individual file rows for files to appear in the browser. Nothing is selected automatically, and `Q` cancels the selection. The saved plan contains only the entries you chose. Choosing a folder also includes its eligible contents, except protected paths and detected projects. Higher-risk candidates inside the folder are kept unless you explicitly select them too; the plan preview identifies nested selections. The plan previews up to 12 direct items; other contents may also be removed.

After saving, the guided menu offers a full read-only preview; press Enter to view it or `N` to skip. If Drive Cleanr is already running as Administrator, it then asks whether to run the new plan in that window. If the window is not running as Administrator, Drive Cleanr says so and leaves the plan saved. If it cannot determine the status, it reports that and does not start the plan. When started, the plan shows the saved entries again, lets you choose which to clean, and asks you to confirm. Press Enter or `N` to save it for later. Direct `--output` plan generation never starts a plan automatically.

Review every file and folder path in the report and plan. Run a plan from a normal PowerShell window; use an Administrator window only if Windows denies access to a selected path:

Plans created directly from the command line let you choose files and folders when the plan runs. A plan created in the review menu already contains only your selections and asks for final confirmation when run.

```powershell
& .\clean_review.ps1
```

When the plan runs, it labels each available file or folder and asks you to choose entries by number, choose all, or cancel. Choosing a folder includes its contents except protected paths and detected projects. Higher-risk candidates inside it are kept unless you explicitly select one of those listed candidates too; explicitly selected nested items appear in the folder preview. The preview shows up to 12 direct items; other contents may also be removed. Cleanup progress numbers selected items in the order they will be checked and shows each item's type, label, and exact path. It says nothing has been removed before the first item; later items warn that earlier selections may already have been removed. It shows what each check is doing, starts folder and file counts as soon as work begins, and repeats counts during long checks so a slow cleanup does not look idle. Folder review shows a running count and current path while it discovers contents, even before it knows the total; the link/project safety check, protected-data checks, and final rechecks also show the current item. Protected items use a generic label so their paths and names stay hidden. Progress labels distinguish checking from completed removals. During slow file or folder content checks, progress shows the current item's path (with hidden formatting characters replaced for display), bytes checked, percentage, and overall count. Folder cleanup skips and preserves descendants whose paths contain hidden formatting characters. Project-marker checks report the first entry and when each pass finishes. A redundant project check between confirmation or backup and the cleanup loop was removed; the loop still rechecks the target before processing it. Before removal starts, all selected files are inventoried and checked. After that, files are checked and removed one at a time, so if a later check fails, earlier files may already be removed. The final summary reports files, folders, and file-data lengths removed, including partial progress if a later check fails. File-data lengths are estimates of space reclaimed and can differ from actual free space. The plan explains each step; large folders can take time. It asks whether to create a verified recovery backup; Enter means no backup. Without one, removal is permanent and you must type `DELETE WITHOUT BACKUP`. If a requested backup is incomplete or fails verification, cleanup stops. If you opt in, progress stays visible while Drive Cleanr sizes, copies or compresses, hashes, and verifies the backup. The plan rechecks selected paths, protects nested data and detected projects, and leaves changed or linked paths in place. Review the saved PowerShell plan before running it. Plans do not overwrite existing files or save inside a selected cleanup folder. If a plan is saved outside the project folder, it can find the project's `backup.py`; keep the project folder in place if you choose backup. For noninteractive use after reviewing the plan, `-Select 1,3 -Force` runs the cleanup without creating a backup. Add `-Backup` to create and verify a recovery backup before removal. Without a backup, removal is permanent and Drive Cleanr cannot restore the items; if backup verification fails, cleanup stops.

Cleanup plans are saved PowerShell scripts and do not update themselves when Drive Cleanr changes. After updating Drive Cleanr, create and review a fresh plan before running cleanup so it includes the current safety checks and progress messages.

After saving a plan in the guided review menu, press Enter at **Show the full cleanup preview now? [Y/n]** to run a read-only preview. It lists every eligible file and folder path and its file-data size after the current safety checks; large selections can take time, with progress shown. The preview creates no backup and removes nothing. Folder rows include eligible data in nested folders and therefore overlap; the overall total counts each eligible file once. This is not a guarantee of space reclaimed because hard links and filesystem behavior can change the amount. If the preview cannot finish, the plan stays saved and the guided menu will not offer to start cleanup; rescan or review the saved plan. If you skip the guided preview or run a saved plan later, add `-PreviewOnly` to show the same full read-only preview. A later cleanup run repeats its checks because paths and contents can change after the preview.

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

# Request a fast full-drive scan; run PowerShell as administrator first
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
python analyze.py .\data\scan.csv --min-size 10 --list-output review-items.txt

# Generate a medium, low, or all-tier reviewed plan
python analyze.py .\data\scan.csv --output clean_review.ps1 --priority medium
python analyze.py .\data\scan.csv --output clean_review.ps1 --priority low
python analyze.py .\data\scan.csv --output clean_review.ps1 --priority all
```

## Scan support

Drive Cleanr's menus, prompts, and reports are in English. It accepts localized WizTree headings and validates WinDirStat's documented CSV column layout even when WinDirStat localizes the headers. Both scanners use their saved settings; check WinDirStat filters before a whole-drive scan. Standard scans may miss files this account cannot access. WizTree's fast full-drive scan requires an administrator terminal. Drive Cleanr accepts local drives and folders and rejects system roots, network paths, device paths, and unsafe path forms.

## How cleanup suggestions are chosen

- **Protected files and folders:** Personal folders, Windows recovery and update data, installed-program repair data, messaging data, credentials, Store app data, agent/editor settings such as `.claude`, `.cursor`, `.gemini`, `.github`, `.opencode`, and `.windsurf`, Codex settings, container state, and previous-installation data are left off the cleanup list. Use Windows Storage or Disk Cleanup to manage Windows update downloads.
- **Project folders:** Files and folders inside recognized projects are left off the cleanup list to protect source and local project data. Drive Cleanr recognizes common manifests, Git files, project guidance such as `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, and `SKILL.md`, agent/editor project settings folders such as `.claude`, `.cursor`, `.gemini`, `.github`, `.opencode`, and `.windsurf`, IDE workspace folders (including `.vscode`), VS Code `*.code-workspace` files, Unreal, Godot, Unity, Visual Studio, and `-requirements.txt` project files. Shared settings and a `.gitignore` at the user-profile root do not make the whole profile a project; `.git` still does. It lists detected project folders and the marker it found. Add an empty `.drive-cleanr-protect` file to an unrecognized project folder. Folders Drive Cleanr cannot inspect are left out.
- **Temporary folders:** Known Windows and user temporary folders are labeled for review, but the temporary folder itself is not selectable; eligible files and folders inside appear individually. A folder named Temp or Tmp elsewhere is not assumed to be temporary. Check that no installer or build is using a temporary location before selecting its contents.
- **Caches and logs:** Names such as Cache, Logs, GPUCache, ShaderCache, and Code Cache are clues, not proof that data can be removed. These suggestions require review of the exact path and contents. More specific package-manager labels take precedence. Scoop downloads, Cargo build output, and Chocolatey staging receive additional caution because they may be useful for offline installs or contain compiled files.
- **Application data:** Chrome's on-device model and IndexedDB data, NVIDIA App update files, and VS Code's CachedExtensionVSIXs, CachedData, Cache, and Crashpad folders are suggested only in known app locations and require careful review. Close the affected app first; cached data may be useful offline or during troubleshooting.
- **Before cleanup:** Drive Cleanr checks that each selected path still exists and has the same file or folder type. Paths that pass through a junction or symbolic link, or cannot be checked, are excluded. A cleanup plan repeats these checks before it runs. The plan warns about active browsers, editors, build tools, installers, and package managers that may be using selected items.
- **Clear path display:** Scan entries with hidden formatting or terminal-control characters in their paths are omitted from cleanup review and counted in the report, because they can make a path appear to name something else.
- **Space estimates:** Nested items are counted once across review levels, while each folder row shows its full size. A folder can contain protected data that the plan keeps, so the space actually recovered may be lower. WinDirStat does not save drive-capacity data; when possible, Drive Cleanr shows current capacity and free space and labels when it checked them.

Scans retain previous exports and review plans; if a generated scan name is already occupied, Drive Cleanr chooses a suffixed name instead of overwriting it. To prune old scan exports intentionally, run `python scan.py --cleanup --keep-latest 1`. Retention removes only validated Drive Cleanr scan exports and each pruned scan's exact default `.clean.ps1` plan. Unrelated CSV files and user-authored PowerShell files are left alone.

## Backups

```powershell
python backup.py drive
python backup.py list
python backup.py info --id backup_YYYYMMDD_HHMMSS_microseconds
python backup.py verify --id backup_YYYYMMDD_HHMMSS_microseconds
python backup.py restore --id backup_YYYYMMDD_HHMMSS_microseconds
python backup.py delete --id backup_YYYYMMDD_HHMMSS_microseconds
python backup.py cleanup --all
```

When creating a cleanup backup, Drive Cleanr selects the fixed or removable local drive with the most free space, excluding the Windows system volume and every drive that contains a selected source item. It requires at least 5 GB free. The `drive` command shows the default non-system destination; the actual cleanup backup also excludes the selected source drives.

The backup list shows whether each backup completed, is partial, or is still in progress, along with its saved location; unrecognized status values display as Unknown. It omits manifests with an invalid top-level shape or a backup path that crosses a reparse point. A backup with an unknown status or malformed entries inside its item list can remain listed so you can delete it, but it cannot be restored. Before guided restore, Drive Cleanr shows each validated original location and asks how to handle existing files. It refuses incomplete backups and malformed, overlapping, or unsafe restore paths before asking for approval, including destinations inside or over Drive Cleanr backup folders; path text is escaped before it is shown in the terminal. Direct backup inspection rejects corrupt JSON and invalid top-level data; restore and verification validate item paths and contents before doing work. Backup deletion refuses to remove a backup directory if it contains a junction or other reparse point. It shows counts while checking backup entries for links and periodic status messages if a large backup takes time to delete. If Ctrl+C interrupts the safety check, Drive Cleanr confirms that nothing was removed; if deletion fails or is interrupted after removal starts, it warns that the saved backup may be incomplete. Bulk backup cleanup stops after a deletion is interrupted and reports that it will not delete later backups. During restore, Drive Cleanr shows file and ZIP archive progress while it checks, copies, and verifies data; merge restores also show progress while checking existing-file conflicts, and directory restores show a periodic status while Robocopy works. Individual files are staged and verified before they replace or create the destination. Restore counts an item only after its step finishes and reports skipped conflicts or failures separately. Ctrl+C at analyzer, restore, backup-delete, or bulk-cleanup confirmation prompts cancels cleanly before the operation starts.

If you created a cleanup backup, keep it through an observation period and restore it if an affected app or system feature stops working. New file, directory-copy, and ZIP backups record SHA-256 integrity fingerprints, which restore verifies for every item before writing any restored data. On Windows, new backups include and verify alternate data streams alongside each file's usual contents; large folders with these streams use direct copies instead of ZIP. Cleanup plans also check file and folder named streams during review and immediately before removal; if a stream changes, that item is kept. If the backup destination cannot preserve streams, backup verification fails and cleanup stops. Older backups predate this check; verification warns and refuses to verify them when named streams are present. `backup.py verify --id <id>` checks the backup payload and current source; add `--paths <path>` to check selected source items. Large directory archives use ZIP64, include hidden/system entries, and are checked for CRC, total bytes, and file-by-file agreement with the source snapshot; a backup is marked partial if the source changed during archiving. Older manifests without hashes remain restorable with size/structure checks and a warning, but cannot pass the new content-match verification. Restore offers overwrite or merge: merge preserves existing files and restores missing ones, while overwrite replaces conflicts only after explicit approval. For unattended use, `backup.py restore --id <id> --yes` explicitly approves overwriting. Backup creation accepts only absolute local paths below a drive root; it refuses drive roots, network/device paths, traversal paths, overlapping source selections, and source paths that cross reparse points. The backup destination is also checked to prevent storing through a junction. Unreadable path metadata is treated as unsafe. Restore validates saved paths and preflights every ZIP member before writing; it refuses Windows-invalid filename characters, traversal, stream-qualified archive paths, reparse points, duplicate or overlapping restore destinations, duplicate or case-colliding archive members, invalid member timestamps, and paths that require a Windows path to be both a file and a directory. Directory-copy restores repeat source and destination link checks immediately before calling Robocopy. `backup.py create --json` emits a machine-readable manifest and returns a nonzero exit code when any target was skipped or incompletely backed up.

Bulk backup removal lists the backups first and requires typing `DELETE`. For deliberate unattended use, add `--yes`; this bypasses the prompt and permanently removes the listed backups.

## Safety model

- Pattern matches are suggestions, not proof that a file is disposable.
- High, medium, and low tiers communicate different levels of impact; read the notes for each item.
- Windows component stores, restore points, virtual-memory and hibernation files, installed-program repair data, personal folders, messaging data, and credential folders are red lines.
- Space totals count nested suggestions once, while each folder row still shows its full size. WizTree-marked hard-link file rows are excluded, but protected contents remain in place and actual free-space gains may differ from the estimate.
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
