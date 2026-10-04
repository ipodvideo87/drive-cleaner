#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guided command-line entry point for Drive Cleanr."""

import sys

import analyze
import backup
import scan
from error_messages import safe_terminal_text


def _prompt_yes_no(prompt, default=True):
    """Read a yes/no answer; return None when the user cancels."""
    suffix = " [Y/n]" if default else " [y/N]"
    while True:
        answer = input(f"{prompt}{suffix}: ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        if answer in {"q", "quit", "cancel"}:
            return None
        print("Enter Y or N, or Q to cancel.")


def _prompt_integer(prompt, default, minimum, invalid_message):
    """Read a bounded whole number; return None when the user cancels."""
    while True:
        answer = input(f"{prompt} [{default}]: ").strip().lower()
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
                answer = input("Use this scanner for this scan? [Y/n/q]: ").strip().lower()
            except EOFError:
                print("Scan setup cancelled.")
                return None
            except KeyboardInterrupt:
                print("\nScan setup cancelled.")
                return None
            if answer in {"", "y", "yes"}:
                return ""
            if answer in {"n", "no"}:
                break
            if answer in {"q", "quit", "cancel"}:
                print("Scan setup cancelled.")
                return None
            print("Enter Y to use the found scanner, N to choose another .exe file, or Q to cancel.")
    else:
        print(f"Drive Cleanr could not find {scanner_name} automatically.")
    print("Enter the full path to its .exe file for this scan, or press Enter to cancel.")
    while True:
        try:
            value = input(f"{scanner_name} executable path: ").strip()
        except EOFError:
            print("Scan setup cancelled.")
            return None
        except KeyboardInterrupt:
            print("\nScan setup cancelled.")
            return None
        if not value or value.casefold() in {"q", "quit", "cancel"}:
            print("Scan setup cancelled.")
            return None
        normalized = scan.normalize_scanner_executable_path(value, app=app)
        if normalized:
            return normalized
        print("That is not an existing .exe file at a full path. Try again, or press Enter to cancel.")


def _scan_flow():
    app = scan.choose_scanner()
    if not app:
        return
    scanner_executable_path = _prompt_scanner_executable_path(app)
    if scanner_executable_path is None:
        return
    try:
        target = input("Drive or folder to scan [C:]: ").strip() or "C:"
        if target.lower() in {"q", "quit", "cancel"}:
            print("Scan cancelled.")
            return
        wiztree_mode = "auto"
        include_files = True
        max_depth = 0
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
        choice = input("Review this scan now? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if choice not in {"n", "no"}:
        analyze.run_tui(initial_csv=csv_path)


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
            choice = input("Select an option [0-4]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if choice in {"0", "q", "back"}:
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
                valid_manifest = (
                    manifest.get("status") == "completed" and
                    isinstance(items, list) and bool(items)
                )
                backup_roots = backup._existing_backup_roots() if valid_manifest else []
                if valid_manifest:
                    for item in items:
                        if not isinstance(item, dict):
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
                    print("This backup is incomplete or has invalid restore locations. It cannot be restored safely.")
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
                    print("Backup deleted." if backup.delete_backup(backup_id) else "Backup deletion failed.")
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

    Scan -> Review -> Choose files/folders -> Optional backup -> Confirm -> Clean
    Scanning and review never remove anything.
    Choose individual files, folders, or both from the review list.
    Protected and project data are always kept. Higher-risk candidates inside a folder are kept unless you explicitly select their listed entries too.
    The preview shows up to 12 direct items; other contents may also be removed.
    The saved plan lets you choose the final items again before cleanup.
    Without a backup, removed items cannot be restored by Drive Cleanr.
    Choose 1 to scan now or 2 to review a saved scan.
""")


def main_menu():
    """Show the main guided workflow until the user exits."""
    _print_welcome()
    while True:
        print("\nDrive Cleanr")
        print("=" * 48)
        print("1) Scan a drive or folder (WizTree or WinDirStat)")
        print("2) Review a previous scan")
        print("3) Manage recovery backups")
        print("0) Exit")
        try:
            choice = input("Select an option [0-3]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            return
        if choice in {"0", "q", "quit", "exit"}:
            print("Goodbye.")
            return
        if choice == "1":
            _scan_flow()
        elif choice == "2":
            analyze.run_tui()
        elif choice == "3":
            _backup_menu()
        else:
            print("Enter 0, 1, 2, or 3.")


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
