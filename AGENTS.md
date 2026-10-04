# Project instructions

## Purpose

Drive Cleanr analyzes WizTree and WinDirStat 2.x exports and proposes conservative Windows cleanup plans. A scan is evidence for a review, not permission to remove anything.

## Safety requirements

- Never run a cleanup against a real user path as part of development or tests. Use temporary directories and mocked process calls.
- Never bypass the user's explicit plan review. Generated scripts must ask before doing work unless the user separately starts them with `-Force` after reviewing the script.
- Recovery backups are optional and must never be created without the user's choice. Offer the backup before interactive cleanup; declining it must not block cleanup. For a reviewed cleanup script started with `-Force`, create a backup only when the user explicitly passes `-Backup`. If the user opts in, create and verify the complete backup before the first removal; any missing, incomplete, or failed backup must stop the script. If no backup is chosen, clearly warn that Drive Cleanr cannot restore removed data and require a distinct typed confirmation before interactive cleanup; for a reviewed script, `-Force` is the explicit confirmation.
- Treat CSV content and backup manifests as untrusted input. Quote it as data, constrain paths and backup IDs, recheck target type and reparse-point status immediately before removal, and preserve safety exclusions.
- Do not include local scan exports, backup contents, generated scripts, or personal paths in source control.
- Keep `analyze.py` cleanup patterns and exclusions consistent with `references/knowledge.md`.
- Prefer leaving uncertain files untouched. Avoid overstating reclaimable size: folder totals can overlap and hard links can inflate apparent savings.

## User-facing wording

- Keep the entire user workflow clear and consistent in plain English: welcome screen, menus, prompts, progress messages, reports, cleanup results, and recovery options.
- Explain what each choice controls. Make it clear when a selection is an individual file or a folder, and when choosing a folder may preserve protected contents.
- Keep instructions brief and actionable. Prefer guided menu choices over follow-up command examples when the user can continue inside the running program.
- Use consistent everyday terms, explain necessary technical terms at the point of use, and check English-language output for accidental untranslated or garbled text.
- For long operations, say what is being checked and show periodic progress so users can tell the program is still working.
- During long file-content checks, show progress within the current large file (bytes checked and percentage) as well as the overall file or folder count.
- For long recovery restores, show bytes and percentage while copying or verifying individual files and archive contents, and a periodic heartbeat while Robocopy restores a directory. Count each top-level restore item only after its restore step finishes; label conflicts and failures accurately.

## Development

- Python standard library only; supported runtime is Python 3.10+ on Windows.
- Keep WizTree optional for tests. Mock its process and use small synthetic CSV fixtures.
- Run `python -m unittest discover -s tests -v` and `python -m py_compile analyze.py backup.py scan.py` after changes.
- Any cleanup workflow changes need negative tests for protected paths, stale paths, and backup failure.
- Update `README.md`, `current-status.md`, and relevant files under `docs/` when behavior or operator steps change.

## Main entry points

- `drive_cleaner.py`: guided command-line menu for scan, analysis, and backup tasks.
- `scan.py`: invoke WizTree and manage scan exports.
- `analyze.py`: analyze WizTree CSV, show reports, export candidate lists, and generate reviewed PowerShell plans.
- `backup.py`: create, list, inspect, restore, and delete backups.
- `references/knowledge.md`: cleanup knowledge base and red lines.
- `tests/test_safety.py`: destructive-boundary and mock tests.
