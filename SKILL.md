---
name: clean-c-drive
description: Safe C drive cleanup for Windows. Use when the user wants to free space on C:, the system drive is full, or they want to analyze and remove junk files safely. Workflow: WizTree scan -> two-layer analysis with pattern library and knowledge base -> user-approved cleanup plan -> backup -> execution -> observation period. Safety first; do nothing when uncertain.
---

# /clean-c-drive Skill

Use WizTree's fast scanning and AI analysis to safely clean junk files from the C drive.

**Safety rules that must never be broken:**

1. If the purpose of a file is unclear, leave it alone. If the user says they do not recognize a file or app, mark it as a red line and ask the user.
2. **In every permission mode, the cleanup plan must be approved by the user before execution.** Administrator mode only removes the need to manually run the script; it does not remove review.
3. Always back up before cleaning (`backup.py`). If backup fails, stop.
4. During analysis and planning, always cross-check `references/knowledge.md` for the safety red lines, tiered patterns, and execution rules.

## Workflow

### Stage 1: Check permissions and scan data

1. **Check administrator privileges**
   ```bash
   powershell -Command "([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
   ```

2. **If administrator privileges are available (`True`)**
   - Check whether the skill's `data/` directory already contains a scan file from the last 24 hours.
   - If not, automatically run a scan. WizTree path detection order:
     - `WIZTREE_PATH`
     - `WizTree\` inside the skill directory
     - `Program Files`
     - `PATH`
   ```bash
   python "<skill directory>/scan.py" C:
   ```
   WizTree scanning now waits for the process to exit, displays export progress, and allows 30 minutes by default. Increase with `--timeout` for a large volume; a pause in CSV growth alone does not mean scanning finished.

3. **If administrator privileges are not available (`False`)**
   - Use existing data from `data/` if available.
   - Otherwise tell the user:
     ```
     Administrator privileges are not available, so automatic scanning cannot run.
     Choose one:
     1. Restart Claude Code as Administrator (recommended: scan and execution become fully automatic)
     2. Run WizTree manually as Administrator, export data to the data directory, and then run this command again
        (when exporting, enable both folders and files; do not save the CSV on C:)
     ```

### Stage 2: Analyze the scan data

```bash
python "<skill directory>/analyze.py" "<csv_file>" --min-size 50
```

**Two-layer analysis is required:**

- **Pattern library screening**: `analyze.py` identifies known cache and junk directories, assigns them to high/medium/low tiers, and excludes red-line directories automatically.
- **Knowledge-base review**: the pattern library only covers about one-third of reclaimable space. The rest, including giant dumps, Chrome on-device AI models, duplicate installs, abandoned app data, and system-reclaimable space such as DISM-related cleanup, must be reviewed case by case against `references/knowledge.md`.
- Be conservative with size estimates. Hard links between WinSxS and System32 can make directory totals look larger than actual usage.

### Stage 3: Build the cleanup plan

Show the user:

1. **Disk summary**: total, used, and free space
2. **Cleanup candidates by priority**: for each item, list path, size, what it is, what happens if it is removed, and how it will be cleaned. Number each item clearly so the user can approve them one by one.
3. **Red line list**: make it clear what will not be touched
4. Ask the user to choose a cleanup level or approve individual items. **No approval means no execution. Silence is not consent.**
   The generated script presents a numbered list and requires selection of specific items, all items, or cancellation; it never defaults to deleting every candidate.

### Stage 4: Back up the directories to be cleaned

**Before any cleanup action, you must back up first.**

1. Check backup drives. Automatically choose the non-C drive with the most free space, with at least 5 GB required:
   ```bash
   python "<skill directory>/backup.py" drive
   ```
2. If the agent itself will perform cleanup, create the backup. Use a direct copy for targets under 1 GB and compression for targets 1 GB or larger. Generate `manifest.json`:
   ```bash
   python "<skill directory>/backup.py" create --paths "path1" "path2" --priority high
   ```
   Note: robocopy backups preserve hidden and system attributes. Use `Get-ChildItem -Force` when checking the backup directory.
3. If backup fails, stop cleanup and ask the user to fix the issue.
   If the user will run a generated PowerShell plan, let that script create the backup once at execution time instead of creating a duplicate backup here. Continue only when the manifest status is `completed` and the backed-up item count matches the reviewed plan.

### Stage 5: Execute cleanup

- **With administrator privileges**: execute the approved plan, show progress, and report reclaimed space item by item.
- **Without administrator privileges**: generate `clean_<level>.ps1` in the skill directory and tell the user to run it as Administrator.
- Before execution, check for running processes. The generated script already warns about browsers, VS Code, and Java/Gradle daemon processes, because they can leave some caches in use.
- The generated script preserves the directory itself when clearing contents, excludes `claude*` entries and their subtrees at any depth, rejects reparse points and stale file/folder type changes, and supports single-file targets.
- Do not use `-Force` unless the exact generated plan has already been reviewed.

### Stage 6: Verify and confirm

After cleanup, ask the user whether the system is still behaving normally:

```text
Cleanup is complete. Please check whether the system is working normally.
1. System is fine -> keep the backup for a 7-day observation period before deleting it
2. Something is wrong -> restore the backup immediately
3. Decide later -> keep the backup for now
```

- Restore: `python "<skill directory>/backup.py" restore --id <backup_id>`
- Delete after the observation period: `python "<skill directory>/backup.py" delete --id <backup_id>`

### Stage 7: Clean temporary files

After cleanup finishes, ask whether to delete the scan data and generated scripts:

```bash
python "<skill directory>/scan.py" --cleanup
```

This removes `data/*.csv` and `clean_*.ps1`.

## Core scripts

| Script | Responsibility | Common commands |
|---|---|---|
| `scan.py` | Automatic WizTree scanning with path detection; exports files by default | `python scan.py C:`, `--latest`, `--cleanup`, `--folders-only` |
| `analyze.py` | Stream CSV parsing, pattern-based tiers, cleanup script generation, item listing by category, interactive TUI | `python analyze.py "<csv>" --min-size 50`, `--json`, `--list-items`, `--list-output items.txt`, `--tui`, `--output clean.ps1 --priority high` |
| `backup.py` | Backup and restore with `manifest.json` | `drive` / `create` / `list` / `restore` / `delete` |

## Cleanup targets and safety red lines

The full definitions live in two places and must stay in sync:

- `analyze.py` `CLEANABLE_PATTERNS` for the pattern library and `EXCLUDE_PATTERNS` for safety red lines
- `references/knowledge.md` for the complete knowledge base, including red lines, tiered patterns, locating rules, and execution rules

WizTree allocated size is preferred for reclaimable-space estimates; hard-linked file rows are excluded. Keep estimates conservative and explain that actual freed space can differ.

## WizTree command-line reference

```bash
WizTree64.exe <drive> /export="<path>" /admin=1 /exportfolders=1 /exportfiles=1 /sortby=2 /exportdrivecapacity=1 /exportmaxdepth=0
```

**Why export file rows by default (`/exportfiles=1`):**
The biggest cleanup wins often come from single large files such as 4.7 GB crash dumps, 4 GB Chrome on-device AI models, or multi-gigabyte partial downloads. If you export folders only, those files disappear from the report. The CSV may become large, but `analyze.py` streams it efficiently. Use `--folders-only` only when you truly need the older smaller export behavior.
