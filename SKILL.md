---
name: clean-c-drive
description: "Safe Windows drive cleanup. Use when the user wants to find reclaimable disk space or review files and folders that may be removable. Workflow: WizTree or WinDirStat scan -> conservative review with the pattern library and knowledge base -> user-selected files and folders -> optional verified backup -> cleanup. Safety first; do nothing when uncertain."
---

# /clean-c-drive Skill

Use WizTree or WinDirStat scans and a conservative review to help the user choose exact files and folders for cleanup on a Windows drive.

**Safety rules that must never be broken:**

1. If the purpose of a file is unclear, leave it alone. If the user says they do not recognize a file or app, mark it as a red line and ask the user.
2. **The user must approve the exact cleanup plan before execution.** The generated script asks for final confirmation by default. Use `-Force` only when the user has explicitly authorized noninteractive execution after reviewing the exact plan and targets. When the guided menu is already elevated, it may offer to run the saved plan in that same session; the script still asks for confirmation unless the user separately authorized `-Force`.
3. Ask whether the user wants a recovery backup. If they enable it, create and verify the complete backup before cleanup; if it fails, stop. If they decline, explain that Drive Cleanr cannot restore removed items. Interactive cleanup requires the generated plan's `DELETE WITHOUT BACKUP` confirmation. Noninteractive cleanup requires explicit user authorization after plan review; `-Force` runs without a backup by default, while `-Force -Backup` creates and verifies one before removal. If backup verification fails or is incomplete, stop before removal.
4. During analysis and planning, always cross-check `references/knowledge.md` for the safety red lines, tiered patterns, and execution rules.

## Workflow

### Stage 1: Check permissions and scan data

1. Check administrator privileges only to decide whether WizTree's fast full-drive scan is available. Standard WizTree scanning and WinDirStat scans can run without elevation.
2. Use a recent scan only if the user agrees it is suitable. Otherwise start the guided flow so the user can choose the scanner, target, and scan settings. Explain that files must be included in scan results to be available as individual selections:
   ```bash
   python "<project directory>/drive_cleaner.py"
   ```
   Automatic WizTree mode uses fast scanning for a whole drive when elevated and standard scanning otherwise. Standard scans may miss files this account cannot access. WinDirStat 2.6.0 or newer exports through `/SaveTo`; a detected older version is rejected before scanning, while unreadable version information produces a warning and a scan attempt. Review WinDirStat's saved filters before a whole-drive scan.
   If automatic scanner discovery fails in the guided menu, enter the full path to its `.exe` file. Direct `scan.py` commands can use `WIZTREE_PATH` or `WINDIRSTAT_PATH`.
3. Direct scan commands are also available:
   ```bash
   python "<project directory>/scan.py" C: --app wiztree --wiztree-mode standard
   python "<project directory>/scan.py" C: --app windirstat
   ```
   WizTree's fast full-drive scan requires an administrator terminal. Scans wait for the scanner process to exit, show export progress, and allow 30 minutes by default. Increase `--timeout` for a large volume; a pause in scan-file growth alone does not mean scanning finished.

### Stage 2: Analyze the scan data

```bash
python "<project directory>/analyze.py" "<csv_file>" --min-size 50
```

**Two-layer analysis is required:**

- **Pattern library screening**: `analyze.py` identifies known cache and junk directories, assigns them to high/medium/low tiers, and excludes red-line directories automatically.
- **Project protection context**: detected project roots and their marker files are listed when they cause scan candidates to be withheld. Explain that evidence to the user; a missing marker does not prove a folder is disposable. For an unmarked project, use `.drive-cleanr-protect` in its root.
- **Knowledge-base review**: `analyze.py` suggests only paths that match its defined rules. The report separately shows up to 100 of the largest unclassified files for investigation; they are not suggestions and are excluded from cleanup-space estimates. Protected paths, reparse points, and detected projects are omitted. Unmatched large items are not automatically safe or useless; review them individually against `references/knowledge.md`, especially unusual dumps, application model data, duplicate installs, abandoned app data, and DISM-related cleanup.
- Be conservative with size estimates. Hard links between WinSxS and System32 can make directory totals look larger than actual usage.

### Stage 3: Build the cleanup plan

Show the user:

1. **Disk summary**: total, used, and free space
2. **Suggested files and folders by review level**: label every entry File or Folder; show its exact path, size, and reason it was listed. Number each entry so the user can choose exact files and folders.
3. **Red line list**: make it clear what will not be touched
4. Ask the user to choose a review level or exact files and folders. **No approval means no execution. Silence is not consent.** State that only scan-listed entries can be selected and that nothing is selected automatically.
   The generated script labels every available entry File or Folder and requires an explicit selection or cancellation; it never defaults to cleaning every entry.
   In the guided picker, `D` opens a listed folder so the user can choose exact scan entries that the summary grouped under it. The browser shows 25 entries per page; `F` filters by name or path, `N`/`P` changes pages, `D` finishes and keeps picks from that browse session, and `B` returns without adding those picks. Both actions keep selections already made in the main list. The browser follows the review level chosen earlier; choose All review levels to include nested entries assigned to more cautious levels. `A` selects every suggestion in the main list only. Individual files appear only when the scan included file rows.
   Explain that choosing a folder includes its contents, even when they are not separate scan suggestions. Protected paths and detected projects are kept. Higher-risk candidates are kept unless the user explicitly selects a listed nested candidate too; show that choice in the plan preview. The preview shows up to 12 direct items; other contents may also be removed, so it is not a complete removal list.
   If the user wants to inspect unmatched large files, guide them to **Review the largest files outside cleanup suggestions**. Do not describe those files as safe; the user must recognize and approve each exact file. Folders and bulk selection are disabled, and the app requires typing `REVIEWED` before it saves this distinct plan. The normal backup choice and final cleanup confirmation still apply.
5. Ask whether the user wants a verified recovery backup. Make clear that declining it makes cleanup permanent through Drive Cleanr.

### Stage 4: Create an optional recovery backup

Create and verify a backup only when the user chooses one.

1. If the user chooses a backup, check backup drives. The utility automatically chooses an eligible local drive that is different from every selected source drive, has the most free space, and has at least 5 GB available:
   ```bash
   python "<project directory>/backup.py" drive
   ```
2. If the agent itself will perform cleanup and the user chose a backup, create it. Use a direct copy for targets under 1 GB and compression for targets 1 GB or larger. Generate `manifest.json`:
   ```bash
   python "<project directory>/backup.py" create --paths "path1" "path2" --priority high
   ```
   Note: robocopy backups preserve hidden and system attributes. Use `Get-ChildItem -Force` when checking the backup directory.
3. If backup fails, stop cleanup and ask the user to fix the issue.
   If the user will run a generated PowerShell plan, let that script create the backup once at execution time instead of creating a duplicate backup here. Continue only when the manifest status is `completed` and the backed-up item count matches the reviewed plan. If the user declines, do not create a backup in the background.

### Stage 5: Execute cleanup

- Execute only the exact plan and files/folders the user approved. A plan made in the guided review already contains those selections; a direct command plan asks the user to choose from its numbered list. The script offers a verified backup. If the user declines in an interactive run, it requires typing `DELETE WITHOUT BACKUP` before removing the selected files and folders.
- Elevate PowerShell only if Windows denies access to a selected target; scanner elevation does not authorize cleanup.
- Before execution, check for running processes. The generated script warns about browsers, editors, build tools, and package managers that may be using candidate files.
- The generated script preserves nested protected paths and project roots, rejects reparse points and stale file/folder type changes, and supports single-file targets.
- Do not use `-Force` unless the exact generated plan and selected targets have already been reviewed.
- For noninteractive execution, use `-Force` only after the user has reviewed and explicitly authorized the exact plan. It runs without a backup by default; add `-Backup` to create and verify one before removal. If the backup is missing, incomplete, or fails verification, cleanup must stop. Without a backup, removal is permanent; `-Force` is the explicit approval to proceed after review.

### Stage 6: Verify and confirm

If a backup was created, ask the user whether the system is still behaving normally:

```text
Cleanup is complete. Please check whether the system is working normally.
1. System is fine -> keep the backup for a 7-day observation period before deleting it
2. Something is wrong -> restore the backup immediately
3. Decide later -> keep the backup for now
```

Keep the verified backup through the observation period. If the system has problems, offer to restore it. If no backup was created, explain that Drive Cleanr cannot restore removed items.

- Restore: `python "<project directory>/backup.py" restore --id <backup_id>`
- Delete after the observation period: `python "<project directory>/backup.py" delete --id <backup_id>`

### Stage 7: Clean temporary files

After cleanup finishes, ask whether to delete the scan data and generated scripts:

```bash
python "<project directory>/scan.py" --cleanup
```

This removes older scan CSVs while keeping the newest scan by default. It removes a default `.clean.ps1` plan only when its matching scan CSV is pruned; custom output paths and unrelated PowerShell files are kept. Use `--keep-latest` to keep more scan exports.

## Core scripts

| Script | Responsibility | Common commands |
|---|---|---|
| `scan.py` | WizTree or WinDirStat scans with path detection; exports files by default | `python scan.py C: --app wiztree`, `--app windirstat`, `--wiztree-mode standard`, `--latest`, `--cleanup`, `--folders-only` |
| `analyze.py` | Stream CSV parsing, pattern-based tiers, cleanup script generation, item listing by category, interactive TUI | `python analyze.py "<csv>" --min-size 50`, `--json`, `--list-items`, `--list-output items.txt`, `--tui`, `--output clean.ps1 --priority high` |
| `backup.py` | Backup and restore with `manifest.json` | `drive` / `create` / `list` / `restore` / `delete` |

## Cleanup targets and safety red lines

Project guidance files (`AGENTS.md`, `AGENTS.override.md`, `CLAUDE.md`, `GEMINI.md`, `SKILL.md`, `.cursorrules`, and `copilot-instructions.md`) and agent/editor settings folders (`.claude`, `.cursor`, `.gemini`, `.github`, `.opencode`, and `.windsurf`) mark a project root and protect cache-like candidates beneath it. Those settings folders are also protected path components everywhere because they may contain authentication, history, account settings, or instructions. At the user-profile root, these shared guidance files and settings folders do not mark the entire profile as a project. Keep this list aligned with `analyze.py` and `references/knowledge.md`.

The full definitions live in two places and must stay in sync:

- `analyze.py` `CLEANABLE_PATTERNS` for the pattern library and `EXCLUDE_PATTERNS` for safety red lines
- `references/knowledge.md` for the complete knowledge base, including red lines, tiered patterns, locating rules, and execution rules

WizTree allocated size is preferred for reclaimable-space estimates; hard-linked file rows are excluded. Keep estimates conservative and explain that actual freed space can differ.

## WizTree command-line reference

```bash
WizTree64.exe <drive> /export="<path>" /admin=0|1 /exportfolders=1 /exportfiles=1 /sortby=2 /exportdrivecapacity=1 /exportmaxdepth=0
```

Use WizTree's `/admin=1` option for fast full-drive scanning; `/admin=0` selects standard scanning. WinDirStat cleanup scans use `WinDirStat.exe /SaveTo <path.csv> <drive-or-folder>`.

**Why export file rows by default (`/exportfiles=1`):**
The biggest cleanup wins often come from single large files such as 4.7 GB crash dumps, 4 GB Chrome on-device AI models, or multi-gigabyte partial downloads. If you export folders only, those files disappear from the report. The CSV may become large, but `analyze.py` streams it efficiently. Use `--folders-only` only when you truly need the older smaller export behavior.
