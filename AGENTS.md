# Project instructions

## Purpose

Drive Cleanr analyzes WizTree and WinDirStat 2.x exports and proposes conservative Windows cleanup plans. A scan is evidence for a review, not permission to remove anything.

## Safety requirements

- Never run a cleanup against a real user path as part of development or tests. Use temporary directories and mocked process calls.
- Detect likely project roots, including Git repositories and common development-project markers, and treat their contents as sensitive review candidates. At a user-profile root, `.gitignore` may be shared Git configuration and must not alone make the whole profile a project; `.gitignore` inside a nested directory and `.git` at any level still protect project contents. Never infer that a repository, build output, dependency folder, or cache is safe to remove from its name alone; preserve project data unless the user selects the exact eligible entries after reviewing them.
- Keep the largest-file manual-review list separate from automatic cleanup suggestions and their size totals. Show only exact ordinary files outside protected paths, links, and detected projects; never bulk-select them or describe them as safe. A generated manual-review plan may include only the exact files the user selected and acknowledged with `REVIEWED`, and must retain the normal cleanup review, backup choice, and final confirmation.
- A generated `-PreviewOnly` run must never create a backup or remove data. It must run the current safety checks, list every eligible file/folder and its file-data size, and state that later cleanup repeats the checks because paths can change.
- Never bypass the user's explicit plan review. Generated scripts must ask before doing work unless the user separately starts them with `-Force` after reviewing the script.
- Recovery backups are optional in every cleanup mode and must never be a prerequisite. Offer one during interactive cleanup; Enter means no backup, and declining it must not block cleanup. A reviewed script must create a backup only when the user explicitly passes `-Backup`; `-NoBackup` may explicitly confirm that no backup is wanted. Passing both switches must be rejected. If backup is enabled, create and verify it fully before the first removal; any missing, incomplete, or failed backup must stop cleanup. Without a backup, clearly warn that Drive Cleanr cannot restore removed data and require a distinct typed confirmation in the interactive flow; for a reviewed script, `-Force` is the explicit confirmation.
- Treat CSV content and backup manifests as untrusted input. Validate field types and path forms, quote path data, constrain paths and backup IDs, and reject malformed data cleanly without tracebacks. Reject paths with hidden formatting or terminal-control characters from cleanup review and report how many were skipped; never print raw untrusted control text. Recheck target type and reparse-point status immediately before removal, and preserve safety exclusions.
- Scan retention may prune only validated Drive Cleanr-generated scan exports and the exact default cleanup plan paired with an export it actually removed. Preserve unrelated CSV files and user-authored scripts, even when stored beside scan data.
- In the guided restore menu, validate that the backup is complete and every saved destination is a valid local path that does not overlap any Drive Cleanr backup-storage root before asking for approval. Require exact nonnegative integer byte counts in backup entries. Reject Windows-invalid filename characters and hidden formatting in saved paths and ZIP members before offering or writing a restore. Escape terminal control characters in all manifest-controlled text and untrusted error messages before displaying them. Keep malformed backups manageable for deletion, show unrecognized status values as `Unknown`, but never offer to restore them.
- The saved-scan picker must list available current and recognized legacy Drive Cleanr exports newest first, let users select them by number, and paginate long histories. Keep manual file-path selection as a fallback; do not make users type a path for a scan already in the list.
- Cleanup selection must let users choose individual scanned files as well as folders. A file selection targets that file; a folder selection targets its eligible descendants and must preserve protected contents. Never imply that a file can be selected individually when the scan did not record file-level entries; explain how to create a scan that includes them.
- Detect whether the program is running elevated and make that status clear when offering to run a newly generated cleanup script. Ask before running it; elevation alone is never permission to run it. Show the reviewed selection and retain the script's existing backup choice, safety rechecks, and explicit no-backup confirmation.
- Support WizTree and WinDirStat through their documented command-line interfaces, including installed and portable executable locations where supported. Verify options against the actual scanner version before claiming compatibility; let users locate an executable when automatic discovery fails and choose another copy when discovery succeeds.
- In the guided picker, `D` opens a listed folder to browse scan entries grouped beneath it. The nested browser must preserve the review level chosen earlier; tell users to choose All review levels to include nested entries assigned to more cautious levels. `A` selects suggestions in the main list only, not hidden nested entries. In the nested browser, `D` finishes and keeps picks from that browse session; `B` returns without adding those picks. Both actions must preserve selections already made in the main list.
- Do not include local scan exports, backup contents, generated scripts, or personal paths in source control.
- Keep `analyze.py` cleanup patterns and exclusions consistent with `references/knowledge.md`.
- Prefer leaving uncertain files untouched. Avoid overstating reclaimable size: folder totals can overlap and hard links can inflate apparent savings.

## User-facing wording

- Keep the entire user workflow clear and consistent in plain English: welcome screen, menus, prompts, progress messages, reports, cleanup results, and recovery options.
- Start the main command with a compact branded welcome and a short guide to the available tasks. Keep the workflow inside that command with guided choices whenever possible, including after a scan; do not leave users thinking they must copy a follow-up command to continue.
- If localization is implemented, detect the Windows display language and use a complete, reviewed translation shipped with the project. Fall back to English for unsupported languages; do not rely on live machine translation for cleanup, backup, restore, or confirmation prompts.
- Explain what each choice controls. Label each selection as an individual file or a folder, say whether a folder choice includes eligible descendants, and explain when protected contents will be preserved.
- Keep instructions brief and actionable. Prefer guided menu choices over follow-up command examples when the user can continue inside the running program.
- Use consistent everyday terms, explain necessary technical terms at the point of use, and check English-language output for accidental untranslated or garbled text.
- For long operations, say what is being checked and show periodic progress so users can tell the program is still working.
- For cleanup startup and safety rechecks, announce each phase before beginning potentially slow file or folder checks. Keep progress visible during those checks, including the current item and overall count; do not leave a message such as `Cleaning: npm cache...` as the only output while preflight work continues.
- During long file-content checks, including the final locked content recheck before removal and named data streams, show progress within the current item (bytes checked and percentage) as well as the overall file or folder count.
- For long recovery restores, show bytes and percentage while copying or verifying individual files and archive contents, and a periodic heartbeat while Robocopy restores a directory. Count each top-level restore item only after its restore step finishes; label conflicts and failures accurately.

## Development

- Python standard library only; supported runtime is Python 3.10+ on Windows.
- Keep WizTree optional for tests. Mock its process and use small synthetic CSV fixtures.
- Run `python -m unittest discover -s tests -v` and `python -m py_compile analyze.py backup.py scan.py` after changes.
- Any cleanup workflow changes need negative tests for protected paths, stale paths, and backup failure. Restore workflow changes also need negative tests for malformed or incomplete manifests, invalid or overlapping destinations, and confirmation that rejected backups write nothing.
- Manual-review file listing or planning changes need tests proving automatic candidates stay separate, protected/project/reparse-point files are omitted or rejected, folders and bulk selection are refused, and plans require an exact user selection and acknowledgement.
- Update `README.md`, `current-status.md`, and relevant files under `docs/` when behavior or operator steps change.

## Main entry points

- `drive_cleaner.py`: guided command-line menu for scan, analysis, and backup tasks.
- `scan.py`: invoke WizTree and manage scan exports.
- `analyze.py`: analyze WizTree CSV, show reports, export candidate lists, and generate reviewed PowerShell plans.
- `backup.py`: create, list, inspect, restore, and delete backups.
- `references/knowledge.md`: cleanup knowledge base and red lines.
- `tests/test_safety.py`: destructive-boundary and mock tests.
