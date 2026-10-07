#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guided command-line entry point for Drive Cleanr."""

import sys
from datetime import datetime
from pathlib import Path

import analyze
import backup
import scan
from error_messages import safe_terminal_text


def _prompt_yes_no(prompt, default=True, *, allow_cancel=True):
    """Read a yes/no answer, optionally accepting Q to cancel."""
    cancel_text = "; Q = cancel" if allow_cancel else ""
    if default:
        suffix = f" [Y/n] (Enter = Yes; N = No{cancel_text})"
    else:
        suffix = f" [y/N] (Y = Yes; Enter = No{cancel_text})"
    while True:
        answer = input(f"{prompt}{suffix}: ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        if allow_cancel and answer in {"q", "quit", "cancel"}:
            return None
        if allow_cancel:
            print("Enter Y for Yes, N for No, or Q to cancel.")
        else:
            print("Enter Y for Yes or N for No.")


def _prompt_integer(prompt, default, minimum, invalid_message):
    """Read a bounded whole number; return None when the user cancels."""
    while True:
        answer = input(f"{prompt} [{default}] (Enter = {default}; Q = cancel): ").strip().lower()
        if not answer:
            return default
        if answer in {"q", "quit", "cancel"}:
            return None
        try:
            value = int(answer)
        except ValueError:
            print("Enter a whole number, or Q to cancel.")
            continue
        if value < minimum:
            print(invalid_message)
            continue
        return value


def _pause():
    try:
        input("\nPress Enter to return to the main menu...")
    except (EOFError, KeyboardInterrupt):
        pass


def _prompt_scanner_executable_path(app):
    """Let a guided user locate an installed or portable scanner for one scan."""
    finder = scan.find_wiztree if app == "wiztree" else scan.find_windirstat
    scanner_name = "WizTree" if app == "wiztree" else "WinDirStat"
    detected_executable = finder()
    if detected_executable:
        shown_path = safe_terminal_text(detected_executable, fallback="scanner path")
        print(f"Found {scanner_name}: {shown_path}")
        while True:
            try:
                answer = input(
                    "Use this scanner for this scan? "
                    "[Y/n/q] (Enter or Y = use it; N = choose another .exe; Q = cancel scan setup): "
                ).strip().lower()
            except EOFError:
                print("Scan setup cancelled.")
                return None
            except KeyboardInterrupt:
                print("\nScan setup cancelled.")
                return None
            if answer in {"", "y", "yes"}:
                return detected_executable
            if answer in {"n", "no"}:
                break
            if answer in {"q", "quit", "cancel"}:
                print("Scan setup cancelled.")
                return None
            print("Enter Y to use this scanner, N to choose a different .exe file, or Q to cancel scan setup.")
    else:
        print(f"Drive Cleanr could not find {scanner_name} automatically.")
    print("Enter the full path to the scanner's .exe file. Press Enter to cancel scan setup.")
    while True:
        try:
            value = input(f"{scanner_name} executable path: ").strip()
        except EOFError:
            print("Scan setup cancelled.")
            return None
        except KeyboardInterrupt:
            print("\nScan setup cancelled.")
            return None
        if not value:
            print("Scan setup cancelled.")
            return None
        normalized = scan.normalize_scanner_executable_path(value, app=app)
        if normalized:
            return normalized
        print("That is not an existing .exe file at a full path. Try again, or press Enter to cancel scan setup.")


def _scan_flow():
    app = scan.choose_scanner()
    if not app:
        return
    scanner_executable_path = _prompt_scanner_executable_path(app)
    if scanner_executable_path is None:
        return
    try:
        target = input("Drive or folder to scan [C:] (Enter = C:; Q = cancel): ").strip() or "C:"
        if target.lower() in {"q", "quit", "cancel"}:
            print("Scan cancelled.")
            return
        wiztree_mode = "auto"
        include_files = True
        max_depth = 0
        if app == "windirstat":
            print("WinDirStat uses its standard scan. Administrator access is optional and affects which files it can show.")
        if app == "wiztree":
            try:
                normalized_target = scan._normalize_scan_target(target)
            except (TypeError, ValueError):
                normalized_target = None
            if normalized_target is not None and scan._is_whole_drive_target(normalized_target):
                wiztree_mode = scan.choose_wiztree_mode()
                if not wiztree_mode:
                    return
            elif normalized_target is not None:
                wiztree_mode = "standard"
                print("WizTree fast scanning is available only for a full drive; this folder will use standard scanning.")
            include_choice = _prompt_yes_no("Include individual files as well as folders in the scan results?", default=True)
            if include_choice is None:
                print("Scan cancelled.")
                return
            include_files = include_choice
            if not include_files:
                print("Folder-only results cannot be used to select individual files later.")
            max_depth = _prompt_integer(
                "Maximum folder depth to show (0 = all levels)", 0, 0,
                "Folder depth cannot be negative.",
            )
            if max_depth is None:
                print("Scan cancelled.")
                return
        timeout_minutes = _prompt_integer(
            "Maximum scan time in minutes", 30, 1,
            "Enter a positive number of minutes.",
        )
        if timeout_minutes is None:
            print("Scan cancelled.")
            return
        timeout = timeout_minutes * 60
    except EOFError:
        print("Scan setup cancelled.")
        return
    except KeyboardInterrupt:
        print("\nScan setup cancelled.")
        return

    scan_options = {
        "drive": target,
        "include_files": include_files,
        "max_depth": max_depth,
        "timeout": timeout,
        "app": app,
    }
    if app == "wiztree":
        scan_options["wiztree_mode"] = wiztree_mode
    if scanner_executable_path:
        scan_options["scanner_executable_path"] = scanner_executable_path
    csv_path = scan.scan(**scan_options)
    if not csv_path:
        _pause()
        return
    try:
        review_now = _prompt_yes_no("Review this scan now?", default=True, allow_cancel=False)
    except EOFError:
        print("Review cancelled. The scan is saved for later.")
        return
    except KeyboardInterrupt:
        print("\nReview cancelled. The scan is saved for later.")
        return
    if review_now:
        analyze.run_tui(initial_csv=csv_path)
    else:
        print("Scan saved. Choose Review a previous scan from the main menu when you are ready.")


def _saved_scans_menu():
    """Let users review retained scan exports and remove older history safely."""
    try:
        saved_scans = scan.get_saved_scans()
    except OSError as exc:
        print(f"Could not read saved scan history: {safe_terminal_text(exc)}")
        _pause()
        return

    print("\nManage saved scans")
    print("Scan exports are Drive Cleanr's saved results, not files from the scanned drive.")
    print("Removing an export does not remove any files or folders listed in that scan.")
    print("A matching default cleanup plan may also be removed with its scan export.")
    if not saved_scans:
        print("No saved scan exports are available.")
        _pause()
        return

    print("\nSaved scan export files, newest first:")
    for index, scan_path in enumerate(saved_scans, start=1):
        path = Path(scan_path)
        try:
            info = path.lstat()
            size = analyze.format_size(info.st_size)
            saved_at = datetime.fromtimestamp(info.st_mtime).strftime("%Y-%m-%d %H:%M")
        except (OSError, OverflowError, ValueError):
            size = "unknown size"
            saved_at = "unknown date"
        print(
            f"{index}) Scan export file | {size} | {saved_at} | "
            f"{safe_terminal_text(str(path), fallback='saved scan')}"
        )

    while True:
        try:
            answer = input(
                f"How many newest scan exports should stay saved? Enter a number from 1 to "
                f"{len(saved_scans)} (Enter = cancel): "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nScan history was left unchanged.")
            _pause()
            return
        if not answer:
            print("Scan history was left unchanged.")
            _pause()
            return
        try:
            keep_latest = int(answer)
        except ValueError:
            print(f"Enter a whole number from 1 to {len(saved_scans)}, or press Enter to cancel.")
            continue
        if not 1 <= keep_latest <= len(saved_scans):
            print(f"Enter a whole number from 1 to {len(saved_scans)}, or press Enter to cancel.")
            continue
        break

    older_scans = saved_scans[keep_latest:]
    if not older_scans:
        print("No older scan exports need removal. Scan history was left unchanged.")
        _pause()
        return

    print("\nThese older scan export files will be removed:")
    print("A paired cleanup plan is listed only when its header verifies it was generated for that exact scan.")
    print("Same-name files that cannot be verified are kept.")
    for scan_path in older_scans:
        print(f"  Scan export file | {safe_terminal_text(str(scan_path), fallback='saved scan')}")
        plan_path = Path(scan.DATA_DIR).parent / f"{Path(scan_path).stem}.clean.ps1"
        if scan._path_has_reparse_component(plan_path):
            continue
        try:
            plan_path.lstat()
        except OSError:
            continue
        if scan.is_paired_cleanup_plan(plan_path, scan_path):
            print(
                "  Paired Drive Cleanr cleanup plan | "
                f"{safe_terminal_text(str(plan_path), fallback='cleanup plan')}"
            )
    print("Unrelated CSV files and unrelated PowerShell scripts are left alone.")
    try:
        confirmation = input(
            "Type DELETE OLD SCANS to remove only this older scan history: "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nScan history was left unchanged.")
        _pause()
        return
    if confirmation != "DELETE OLD SCANS":
        print("Scan history removal cancelled.")
        _pause()
        return

    removed_count = scan.cleanup_old_scans(
        keep_latest=keep_latest,
        include_scripts=True,
        expected_scans=saved_scans,
    )
    if removed_count:
        print(f"Removed {removed_count} saved scan file(s) or default cleanup plan(s).")
    else:
        print("No saved scan files or cleanup plans were removed.")
    _pause()


def _backup_menu():
    while True:
        print("\nRecovery backups")
        print("Cleanup plans can create backups. Here you can list, check storage, restore, or delete saved backups.")
        print("1) List saved backups")
        print("2) Show the backup drive and free space")
        print("3) Restore a saved backup")
        print("4) Permanently delete a saved backup")
        print("0) Back to the main menu")
        try:
            choice = input("Select an option [0-4] (0 = back to the main menu): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if choice == "0":
            return
        if choice == "1":
            backup.print_backups_table(backup.list_backups())
            _pause()
        elif choice == "2":
            root = backup.find_backup_drive()
            if root:
                free_bytes = backup._get_drive_free_space(root)
                print(f"Backup location: {root}\nAvailable space: {backup.format_size(free_bytes)}")
            else:
                print("No separate backup drive with enough free space was found.")
            _pause()
        elif choice in {"3", "4"}:
            manifests = backup.list_backups()
            backup.print_backups_table(manifests)
            try:
                backup_id = input("Enter the backup ID shown in the list (blank to cancel): ").strip()
            except (EOFError, KeyboardInterrupt):
                return
            if not backup_id:
                continue
            manifest = next((item for item in manifests if item.get("id") == backup_id), None)
            if not manifest:
                print("That backup ID is not in the saved backup list.")
                _pause()
                continue
            if choice == "3":
                items = manifest.get("items")
                restore_paths = []
                manifest_version = backup._manifest_version(manifest)
                valid_manifest = (
                    manifest.get("status") == "completed" and
                    manifest_version is not None and
                    isinstance(items, list) and bool(items)
                )
                backup_roots = backup._existing_backup_roots() if valid_manifest else []
                if valid_manifest:
                    for item in items:
                        if not backup._restore_manifest_item_is_complete(item, manifest_version):
                            valid_manifest = False
                            break
                        restore_path = item.get("original_path")
                        if (not backup._valid_restore_target(restore_path) or
                                backup._restore_path_overlaps_backup_storage(restore_path, backup_roots) or
                                any(backup._paths_overlap(restore_path, previous)
                                    for previous in restore_paths)):
                            valid_manifest = False
                            break
                        restore_paths.append(restore_path)
                if not valid_manifest:
                    print("This backup is incomplete or contains invalid restore details. It cannot be restored safely.")
                    _pause()
                    continue
                print("Original locations in this backup:")
                for restore_path in restore_paths:
                    print(f"  {backup._safe_terminal_text(restore_path)}")
                print("Choose how to handle files already present at these locations:")
                try:
                    confirm = input("Type OVERWRITE to replace existing files, MERGE to restore missing files and keep existing ones, or press Enter to cancel: ").strip().upper()
                except (EOFError, KeyboardInterrupt):
                    return
                if confirm in {"OVERWRITE", "MERGE"}:
                    success = backup.restore_backup(backup_id, overwrite=confirm == "OVERWRITE")
                    print("Restore completed." if success else "Restore incomplete or failed; see conflicts and errors above.")
                else:
                    print("Restore cancelled.")
            else:
                try:
                    confirm = input(f"Permanently delete saved backup {backup_id}? Type DELETE to continue: ").strip()
                except (EOFError, KeyboardInterrupt):
                    return
                if confirm == "DELETE":
                    delete_result = backup.delete_backup(backup_id)
                    if delete_result is None:
                        print("Backup deletion stopped.")
                    else:
                        print("Backup deleted." if delete_result else "Backup deletion failed.")
                else:
                    print("Backup deletion cancelled.")
            _pause()
        else:
            print("Choose 0, 1, 2, 3, or 4.")


def _print_welcome():
    """Show the compact, once-per-launch welcome screen."""
    print(r"""
      .-----------------------------.
      |   D R I V E   C L E A N R   |
      |   [####------] SPACE MAP    |
      '-----------------------------'
          FIND SPACE. KEEP CONTROL.

    Scan -> Review -> Choose files/folders -> Optional full preview -> Optional backup -> Confirm -> Clean
    Scanning and review never remove anything.
    Choose individual files, folders, or both from the review list.
    Choosing a folder includes files and subfolders, even if they are not listed separately.
    Protected items and data in detected projects stay in place.
    Higher-risk items inside a folder stay unless you select them too.
    A full read-only preview can show every file and folder the plan could remove after its safety checks.
    The saved plan shows your selected items again, then asks about an optional backup and final confirmation.
    Without a backup, removed items cannot be restored by Drive Cleanr.
    Choose 1 to scan, 2 to review a saved scan, 3 to manage saved scans, or 4 to manage recovery backups.
""")


def main_menu():
    """Show the main guided workflow until the user exits."""
    _print_welcome()
    while True:
        print("\nDrive Cleanr")
        print("=" * 48)
        print("1) Scan a drive or folder (WizTree or WinDirStat)")
        print("2) Review a previous scan")
        print("3) Manage saved scans")
        print("4) Manage recovery backups")
        print("0) Exit")
        try:
            choice = input("Select an option [0-4] (0 = exit): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            return
        if choice == "0":
            print("Goodbye.")
            return
        if choice == "1":
            _scan_flow()
        elif choice == "2":
            analyze.run_tui()
        elif choice == "3":
            _saved_scans_menu()
        elif choice == "4":
            _backup_menu()
        else:
            print("Choose 1, 2, 3, or 4, or enter 0 to exit.")


def main():
    if len(sys.argv) > 1 and sys.argv[1] in {"-h", "--help"}:
        print("Drive Cleanr guided command line\n\nRun `python drive_cleaner.py` to open the menu.\nUse `python scan.py --help` or `python analyze.py --help` for direct options.")
        return
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nOperation cancelled.")


if __name__ == "__main__":
    main()
