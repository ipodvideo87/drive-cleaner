# Drive Cleanr

Drive Cleanr helps Windows users find files and folders they may want to remove. Scan with WizTree or WinDirStat, review the suggestions, choose the exact items for a cleanup plan, decide whether to make a recovery backup, and confirm before anything is removed.

Drive Cleanr's menus, explanations, and review labels are in English. File and folder names and paths come from the scan and stay unchanged; they may use another language. Paths are not translated because they must identify the exact items on disk.

**Nothing is deleted during scanning or analysis.** In the guided review, you choose exact items before saving, and the resulting plan contains only those selections; when run, it shows that saved selection and asks about an optional backup and final confirmation. A plan generated directly with `--output` presents its candidate list for selection when run. Choosing a folder includes files and folders inside it, even when they are not separate scan suggestions. Protected paths and detected projects are kept. Higher-risk candidates inside a selected folder are kept unless you explicitly select one of those listed candidates too; the plan shows explicitly selected nested items in its preview. The preview shows up to 12 direct items; other contents may also be removed. You can create and verify a recovery backup first or continue without one after a distinct typed confirmation. If you choose a backup and it is missing, incomplete, or fails verification, cleanup stops. Backups are kept until you delete them.

The optional verified backup gives you a way to restore selected data if cleanup affects something an app or Windows needs. A backup of a selected folder copies its accessible contents, including items the cleanup plan will preserve, so it may need more space than the cleanup removes.

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

Drive Cleanr supports the official portable versions of [WizTree](https://diskanalyzer.com/download) and [WinDirStat](https://github.com/windirstat/windirstat/releases). Automated WizTree CSV scans require version 3.18 or newer; WinDirStat scans require version 2.6.0 or newer and use its `/SaveTo` export. Optional WizTree features need newer versions: export depth limits require 4.02 or newer, allocation sorting requires 4.13 or newer, and drive-capacity details require 4.25 or newer. When Windows reports the version, Drive Cleanr adds optional settings only when that version supports them. A requested depth limit is refused on known versions older than 4.02; choose unlimited depth or update WizTree. If Windows cannot read the version, Drive Cleanr warns and tries the basic export; it also tries a requested depth limit but cannot confirm that the option is supported. WizTree's fast full-drive scan requires an Administrator terminal; its standard scan can run without administrator access but may miss files this account cannot access. In the guided menu, Drive Cleanr shows the detected scanner; press Enter to use it or choose another installed or portable `.exe` for that scan. If it cannot find a scanner, enter the full path to its executable. For direct `scan.py` use, set `WIZTREE_PATH` to the 64-bit `WizTree64.exe` or `WINDIRSTAT_PATH` to the `WinDirStat.exe` full path; quoted values are accepted, including paths with spaces.

## Choosing a scanner

WizTree 3.18 or newer and WinDirStat 2.6.0 or newer are supported choices; both scan drives and folders. Optional WizTree export details depend on its version: depth limits start in 4.02, allocation sorting in 4.13, and drive-capacity details in 4.25. WinDirStat uses its standard scan and does not require Administrator access, though it can only show files the current Windows account can access. For a whole drive, WizTree offers three methods: **Automatic** has Drive Cleanr choose Fast when this terminal has Administrator access, and Standard otherwise; **Fast full-drive** is WizTree's quickest method and requires a whole drive plus Administrator access; **Standard** uses normal Windows file access, works on drives or folders without Administrator access, and may take longer or miss files this account cannot access. Administrator access means opening PowerShell with **Run as administrator**. When Drive Cleanr finds a scanner, press **Enter** or type **Y** to use it, type **N** to choose another scanner program (`.exe`) for this scan, or type **Q** to cancel scan setup.

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

Scanning and review never remove anything. After a scan, press Enter to open its review, or enter `N` to return to the main menu and review it later; the scan remains saved either way. Invalid answers are retried. The main menu also lets you review a saved scan, manage saved scan history, or manage recovery backups. Scans started directly with `scan.py` are available under **Review a previous scan** in that menu.

The scan picker lists saved scans newest first, including validated scans saved with older Drive Cleanr names and folder layouts. Choose a scan by number; enter `N` or `P` to browse older or newer pages, or `0` to return to the main menu. To open another supported scan CSV, enter `M` and provide its file path. The picker accepts files, not folders. If a scan is missing or cannot be read, Drive Cleanr explains the problem and lets you choose another scan. Press Ctrl+C or close terminal input to cancel the review; no cleanup starts.

Drive Cleanr supports portable versions of both WizTree and WinDirStat. If the guided menu does not find one, select its `.exe` file; direct `scan.py` commands can use `WIZTREE_PATH` or `WINDIRSTAT_PATH`.

WizTree includes individual files in the results by default. If you choose folders only, individual files cannot be selected later. Its fast full-drive scan requires an Administrator terminal; standard scans may miss files this account cannot access. WinDirStat follows its saved filters, exclusions, and other scan settings; these can leave files out of the results, so review them before expecting a full scan. The scan menu asks for the drive or folder, scan options, and time limit. Press Ctrl+C to stop a scan. If a scan is cancelled or fails, Drive Cleanr tries to stop the scanner before removing its incomplete export. If it cannot confirm that the scanner stopped or Windows prevents removal, it tells you the export was preserved and shows its location; incomplete exports are never offered for review. Earlier scans are kept. The review shows when the scan file last changed; scan again if the drive or folder may have changed. File candidates whose current byte length no longer matches the scan are skipped and reported; rescan before reviewing them again. Direct commands remain available for automation.

Both scanners have native command-line options, and Drive Cleanr invokes the scan and export options it needs. WizTree gets explicit fast or standard scan mode and file/folder export; it adds depth limits, allocation sorting, and drive-capacity details only when the detected version supports them. WinDirStat gets `/SaveTo` with a CSV destination and scan target; its other native modes include loading saved scans and exporting duplicate or permission reports. Drive Cleanr uses scan-tree exports because its cleanup review needs item paths and sizes. WinDirStat follows its saved filters, exclusions, and other scan settings, which can leave files out of results; review those settings before scanning. See the official [WizTree command-line guide](https://www.diskanalyzer.com/guide) and [WinDirStat command-line and export reference](https://github.com/windirstat/windirstat/wiki/Command-Line-and-CSV) for their complete native options.

```powershell
python analyze.py .\data\scan.csv --min-size 50 --list-items
python analyze.py .\data\scan.csv --min-size 50 --output clean_review.ps1 --priority high
```

While Drive Cleanr reads the scan file, progress shows the percentage completed and reaches 100% when the review is ready.

The review report also shows up to 100 of the largest scanned files that did not match an automatic cleanup rule. This separate list is for investigation, not a recommendation that those files are safe to remove. Protected locations, detected projects, redirected paths, and files that are no longer present are filtered before the list is ranked, so excluded large entries do not hide other files. These files are not counted in the suggested-space estimate, and none are selected automatically. Choose **Review the largest files outside cleanup suggestions** to select exact individual files; bulk selection and folders are disabled for this group. Drive Cleanr asks you to type `REVIEWED` before saving a plan, then the plan still asks for its normal backup choice and cleanup confirmation. Only select files you recognize and no longer need.

In the guided review menu, each suggestion is labeled **File** or **Folder** and shows its exact path, size, and reason. In an interactive Windows terminal, use the **Up/Down arrow keys** to move the highlight, press **Spacebar** to select or clear that exact row, and press **Enter** to finish; your picks stay selected as you change pages. Use **PageUp/PageDown** or `N`/`P` to change pages, and `F` to filter by name or path. Press `D` while a folder is highlighted to browse the scan entries inside it; use the same arrow-key and Spacebar controls there. Folder browsing keeps the review level you chose. Choose **All review levels** before opening a folder if you also want to see entries assigned to more cautious levels. Press **Enter or D** to add those folder picks to the cleanup-plan selection. Press **B, Esc, or Q** to return without adding them; selections already made in the main list stay selected. `A` selects every suggestion in the main list only; entries hidden inside folders are not added automatically. If arrow-key controls are unavailable, enter item numbers to select or clear rows. Reopening a folder shows its previously selected scan entries checked, so you can revise that selection. The scan must include individual file rows for files to appear in folder browsing. Nothing is selected automatically. The saved plan contains only the entries you chose. Choosing a folder includes its files and subfolders that pass safety checks; protected data, detected projects, and higher-risk candidates you did not select stay in place. The plan preview identifies nested selections. The plan previews up to 12 direct items; other contents may also be removed.

After saving, the guided menu offers a full read-only preview; press Enter to view it or `N` to skip. If Drive Cleanr is already running as Administrator, it then asks whether to run the new plan in that window. If the window is not running as Administrator, Drive Cleanr says so and leaves the plan saved. If it cannot determine the status, it reports that and does not start the plan. When started, a guided-review plan shows your saved selection again, then asks about an optional backup and final confirmation; it does not ask you to select the same items again. Press Enter or `N` to save it for later. Direct `--output` plan generation never starts a plan automatically.

Review every file and folder path in the report and plan. Run a plan from a normal PowerShell window; use an Administrator window only if Windows denies access to a selected path:

Plans created directly from the command line let you choose files and folders when the plan runs. A plan created in the review menu already contains only your selections and asks for final confirmation when run.

```powershell
& .\clean_review.ps1
```

Plans generated directly with the command-line `--output` option show available suggestions as **File** or **Folder** and ask you to choose entries by number, choose all, or cancel. A plan saved from guided review already contains only the items you selected and shows that selection again for confirmation. Choosing a folder includes its contents except protected paths and detected projects. Higher-risk candidates inside it are kept unless you explicitly select one of those listed candidates too; explicitly selected nested items appear in the folder preview. The preview shows up to 12 direct items; other contents may also be removed. Cleanup progress numbers selected items in the order they will be checked and shows each item's type, label, and exact path. It says nothing has been removed before the first item; later items warn that earlier selections may already have been removed. It shows what each check is doing, starts folder and file counts as soon as work begins, and repeats counts during long checks so a slow cleanup does not look idle. Folder inventory, parent/project-marker scans, protected-data checks, and final rechecks show a running count and the current sanitized item path; project-marker and protected item names are hidden. Progress labels distinguish checking from completed removals. During slow file or folder content checks, progress shows the current item's path (with hidden formatting characters replaced for display), bytes checked, percentage, and overall count. Folder cleanup skips and preserves descendants whose paths contain hidden formatting characters. Folder cleanup scans for newly appeared project markers after backup verification, then checks each file's parent folders again immediately before removal. If a project marker appears, that file stays in place and cleanup stops. Results are reused only for folders that have not changed. Before removal starts, all selected files are inventoried and checked. After that, files are checked and removed one at a time, so if a later check fails, earlier files may already be removed. The final summary reports files, folders, and file-data lengths removed, including partial progress if a later check fails. File-data lengths are estimates of space reclaimed and can differ from actual free space. The plan explains each step; large folders can take time. It asks whether to create a verified recovery backup; Enter means no backup. Without one, removal is permanent and you must type `DELETE WITHOUT BACKUP`. If a requested backup is incomplete or fails verification, cleanup stops. If you opt in, progress stays visible while Drive Cleanr sizes, copies or compresses, hashes, and verifies the backup. The plan rechecks selected paths, protects nested data and detected projects, and leaves changed or linked paths in place. Review the saved PowerShell plan before running it. Plans do not overwrite existing files or save inside a selected cleanup folder. If a plan is saved outside the project folder, it can find the project's `backup.py`; keep the project folder in place if you choose backup. For noninteractive use after reviewing the plan, `-Select 1,3 -Force` runs the cleanup without creating a backup. Add `-Backup` to create and verify a recovery backup before removal. Without a backup, removal is permanent and Drive Cleanr cannot restore the items; if backup verification fails, cleanup stops.

Cleanup plans are saved PowerShell scripts and do not update themselves when Drive Cleanr changes. When a plan starts, it says this before loading its safety checks. After updating Drive Cleanr, create and review a fresh plan before running cleanup so it includes the current safety checks and progress messages. The plan first reports that it is loading its safety checks; nothing has been removed at that point. During checks, Drive Cleanr reuses project checks for parent folders that have not changed and checks a folder again if its contents change.

After saving a plan in the guided review menu, press Enter at **Show the full cleanup preview now? [Y/n]** to run a read-only preview. It lists every file and folder path that passes the current safety checks, with its file-data size; large selections can take time, with progress shown. The preview creates no backup and removes nothing. The same files can appear in more than one folder row because folder sizes include subfolders; the overall total counts each file once. The total shows file size, not guaranteed free space recovered; Windows can store file data in ways that change the amount. If the preview cannot finish, the plan stays saved and the guided menu will not offer to start cleanup; rescan or review the saved plan. If you skip the guided preview or run a saved plan later, add `-PreviewOnly` to show the same full read-only preview. A later cleanup run repeats its checks because paths and contents can change after the preview.

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

- **Relocated user profiles:** Generated project checks inspect the active USERPROFILE root, then stop the ancestor walk there. A project marker in a parent directory outside that profile does not make the profile's contents part of that project.
- **Protected files and folders:** Personal folders, Windows recovery and update data, installed-program repair data, messaging data, credentials, Store app data, agent/editor settings such as `.claude`, `.cursor`, `.gemini`, `.github`, `.opencode`, and `.windsurf`, Codex settings, container state, and previous-installation data are left off the cleanup list. Use Windows Storage or Disk Cleanup to manage Windows update downloads.
- **Project folders:** Files and folders inside recognized projects are left off the cleanup list to protect source and local project data. Drive Cleanr recognizes common manifests, including Node's `npm-shrinkwrap.json` lockfile, Git files, project guidance such as `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, and `SKILL.md`, agent/editor project settings folders such as `.claude`, `.cursor`, `.gemini`, `.github`, `.opencode`, and `.windsurf`, IDE workspace folders (including `.vscode`), VS Code `*.code-workspace` files; VS Code Dev Container settings in `.devcontainer/` or `.devcontainer.json`; Windows Sandbox `*.wsb` configuration files, Unreal, Godot, Unity, Helm chart metadata (`Chart.yaml`), Visual Studio, .NET SDK and MSBuild folder/solution configuration, Swift/CocoaPods, Apple Xcode bundle directories, Bazel, Nix, Terraform, Zig build files, Haskell Cabal/Stack files, OCaml Dune/opam files, Clojure `deps.edn` and Leiningen `project.clj`, RStudio/renv files (`*.Rproj`, `renv.lock`, and R package `DESCRIPTION`), Julia environments (`Project.toml`, `Manifest.toml`, `JuliaProject.toml`, and `JuliaManifest.toml`), and Python requirements lists such as `requirements-dev.txt`, `requirements-test.in`, `dev-requirements.txt`, and `dev-requirements.in`. At a user-profile root, including a custom path reported by `USERPROFILE`, shared editor and .NET SDK/MSBuild settings, `.gitignore`, and common Python requirements lists do not make the whole profile a project; `.wsb` files there are treated as shared configuration, and `.git` still marks a project. It lists detected project folders and the marker it found. Add an empty `.drive-cleanr-protect` file to an unrecognized project folder. Folders Drive Cleanr cannot inspect are left out.
- **Temporary folders:** Known Windows and user temporary folders are labeled for review, but the temporary folder itself is not selectable; eligible files and folders inside appear individually. Items whose names begin with `claude` are kept inside the system's configured temporary folders. A folder named Temp or Tmp elsewhere is not assumed to be temporary. Check that no installer or build is using a temporary location before selecting its contents.
- **Caches and logs:** Names such as Cache, `.cache`, Logs, GPUCache, ShaderCache, and Code Cache are clues, not proof that data can be removed. Lower-risk package-cache labels are limited to recognized Windows defaults for npm, pip, Yarn Classic, Puppeteer, and Electron downloads. Specific confirm-impact labels for Gradle, Cargo, NuGet, Go modules, Scoop downloads, and Playwright browsers require a recognized default or environment-variable root. Lookalike paths outside those roots get a caution-only label when another rule recognizes their structure; paths with no matching rule stay for manual review. Check the owning tool's settings and make sure no install, download, build, or test process is using the data. Cargo build output and Chocolatey staging also receive caution because they may contain compiled files or installer payloads.
- **Application data:** Chrome's on-device model and IndexedDB data, NVIDIA App update files, and VS Code's CachedExtensionVSIXs, CachedData, Cache, and Crashpad folders are suggested only in known app locations and require careful review. Close the affected app first; cached data may be useful offline or during troubleshooting.
- **Before cleanup:** Drive Cleanr checks that each selected path still exists and has the same file or folder type. Paths that pass through a junction or symbolic link, or cannot be checked, are excluded. A cleanup plan repeats these checks before it runs. The plan warns about active browsers, editors, build tools, installers, and package managers that may be using selected items.
- **Clear path display:** Scan entries with hidden formatting or terminal-control characters in their paths are omitted from cleanup review and counted in the report, because they can make a path appear to name something else.
- **Space estimates:** Nested items are counted once across review levels, while each folder row shows its full size. A folder can contain protected data that the plan keeps, so the space actually recovered may be lower. WinDirStat does not save drive-capacity data; when possible, Drive Cleanr shows current capacity and free space and labels when it checked them.

Scans retain previous exports and review plans; if a generated scan name is already occupied, Drive Cleanr chooses a suffixed name instead of overwriting it. To free space used by old scan results, choose **Manage saved scans** in the main menu, enter how many of the newest exports to keep, review the exact older scan files and any verified paired cleanup-plan paths, and type `DELETE OLD SCANS` to confirm. Press Enter at the keep-count prompt to cancel. This removes only validated Drive Cleanr scan exports. A cleanup plan is removed only when its generated header matches that exact scan export; user-authored scripts and older plans without this marker are kept. Removing scan history does not remove files or folders listed in a scan. Unrelated CSV files and PowerShell scripts are left alone. For direct command-line automation, `scan.py --cleanup --keep-latest <number>` remains available.

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

The backup list shows whether each backup completed, is partial, or is still in progress, along with its saved location; unrecognized status values display as Unknown. It omits manifests with an invalid top-level shape or a backup path that crosses a reparse point. A backup with an unknown status or malformed entries inside its item list can remain listed so you can delete it, but it cannot be restored. Before guided restore, Drive Cleanr checks every entry's exact nonnegative byte size and requires a valid integrity hash for each version 2 entry before asking how to handle existing files. Legacy version 1 entries without hashes remain size/structure checked. The menu shows each validated original location and refuses incomplete backups and malformed, overlapping, or unsafe restore paths before asking for approval, including destinations inside or over Drive Cleanr backup folders; path text is escaped before it is shown in the terminal. Direct backup inspection rejects corrupt JSON and invalid top-level data; restore and verification validate item paths and contents before doing work. Backup deletion refuses to remove a backup directory if it contains a junction or other reparse point. It shows counts while checking backup entries for links and periodic status messages if a large backup takes time to delete. If Ctrl+C interrupts the safety check, Drive Cleanr confirms that nothing was removed; if deletion fails or is interrupted after removal starts, it warns that the saved backup may be incomplete. Bulk backup cleanup stops after a deletion is interrupted and reports that it will not delete later backups. During restore, Drive Cleanr shows file and ZIP archive progress while it checks, copies, and verifies data; merge restores also show progress while checking existing-file conflicts, and directory restores show a periodic status while Robocopy works. Before Robocopy starts, directory-copy restores check the saved and destination folder trees for links and junctions, then repeat those checks after the existing-file conflict review; long checks show entry counts and a heartbeat with the current item at least every 10 seconds, even when one filesystem check is slow. Individual files are staged and verified before they replace or create the destination. Restore counts an item only after its step finishes and reports skipped conflicts or failures separately. Ctrl+C at analyzer, restore, backup-delete, or bulk-cleanup confirmation prompts cancels cleanly before the operation starts.

If you created a cleanup backup, keep it through an observation period and restore it if an affected app or system feature stops working. New file, directory-copy, and ZIP backups record SHA-256 integrity fingerprints, which restore verifies for every item before writing any restored data. On Windows, new backups include and verify alternate data streams alongside each file's usual contents; large folders with these streams use direct copies instead of ZIP. Cleanup plans also check file and folder named streams during review and immediately before removal; if a stream changes, that item is kept. If the backup destination cannot preserve streams, backup verification fails and cleanup stops. Older backups predate this check; verification warns and refuses to verify them when named streams are present. `backup.py verify --id <id>` checks the backup payload and current source; add `--paths <path>` to check selected source items. Large directory archives use ZIP64, include hidden/system entries, and are checked for CRC, total bytes, and file-by-file agreement with the source snapshot; a backup is marked partial if the source changed during archiving. Legacy version 1 manifests without hashes remain restorable with size/structure checks and a warning, but cannot pass the new content-match verification. Version 2 backups must include a valid integrity hash for every item or restore stops before writing. Restore offers overwrite or merge: merge preserves existing files and restores missing ones, while overwrite replaces conflicts only after explicit approval. For unattended use, `backup.py restore --id <id> --yes` explicitly approves overwriting. Backup creation accepts only absolute local paths below a drive root; it refuses drive roots, network/device paths, traversal paths, overlapping source selections, and source paths that cross reparse points. The backup destination is also checked to prevent storing through a junction. Unreadable path metadata is treated as unsafe. Restore validates saved paths and preflights every ZIP member before writing; it refuses Windows-invalid filename characters, traversal, stream-qualified archive paths, reparse points, duplicate or overlapping restore destinations, duplicate or case-colliding archive members, invalid member timestamps, and paths that require a Windows path to be both a file and a directory. Directory-copy restores repeat source and destination link checks immediately before calling Robocopy. `backup.py create --json` emits a machine-readable manifest and returns a nonzero exit code when any target was skipped or incompletely backed up.

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
