#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guided command-line entry point for Drive Cleanr."""

import sys

import analyze
import backup
import scan


def _pause():
    try:
        input("\nPress Enter to return to the main menu...")
    except (EOFError, KeyboardInterrupt):
        pass


def _scan_flow():
    app = scan.choose_scanner()
    if not app:
        return
    try:
        wiztree_mode = scan.choose_wiztree_mode() if app == "wiztree" else "auto"
        if not wiztree_mode:
            return
        target = input("Drive or folder to scan [C:]: ").strip() or "C:"
        if target.lower() in {"q", "quit", "cancel"}:
            print("Scan cancelled.")
            return
        include_files = True
        max_depth = 0
        if app == "wiztree":
            include_files = input("Include individual files in the export? [Y/n]: ").strip().lower() not in {"n", "no"}
            depth_text = input("Maximum export depth (0 = unlimited) [0]: ").strip() or "0"
            max_depth = int(depth_text)
            if max_depth < 0:
                raise ValueError("Export depth must be zero or greater.")
        timeout_text = input("Maximum scan time in minutes [30]: ").strip() or "30"
        timeout = int(timeout_text) * 60
        if timeout <= 0:
            raise ValueError("Enter a positive number of minutes.")
    except (ValueError, EOFError) as exc:
        print(f"Scan setup cancelled: {exc}")
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
    csv_path = scan.scan(**scan_options)
    if not csv_path:
        _pause()
        return
    try:
        choice = input("Open this scan in the review menu now? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if choice not in {"n", "no"}:
        analyze.run_tui(initial_csv=csv_path)


def _backup_menu():
    while True:
        print("\nBackup manager")
        print("1) List saved backups")
        print("2) Check backup drive")
        print("3) Restore a backup")
        print("4) Permanently delete a backup")
        print("0) Back")
        try:
            choice = input("Choice: ").strip().lower()
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
                print(f"Backup drive: {root}\nFree space: {backup.format_size(free_bytes)}")
            else:
                print("No suitable non-system backup drive was found.")
            _pause()
        elif choice in {"3", "4"}:
            manifests = backup.list_backups()
            backup.print_backups_table(manifests)
            try:
                backup_id = input("Backup ID (blank to cancel): ").strip()
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
                print("Choose how to handle files that already exist at these saved paths:")
                for item in manifest.get("items", []):
                    print(f"  {item.get('original_path', '(unknown path)')}")
                try:
                    confirm = input("Type OVERWRITE to replace existing files, MERGE to preserve them and restore missing files, or press Enter to cancel: ").strip().upper()
                except (EOFError, KeyboardInterrupt):
                    return
                if confirm in {"OVERWRITE", "MERGE"}:
                    success = backup.restore_backup(backup_id, overwrite=confirm == "OVERWRITE")
                    print("Restore completed." if success else "Restore incomplete or failed; see conflicts and errors above.")
                else:
                    print("Restore cancelled.")
            else:
                try:
                    confirm = input(f"Permanently delete backup {backup_id}? Type DELETE to continue: ").strip()
                except (EOFError, KeyboardInterrupt):
                    return
                if confirm == "DELETE":
                    print("Backup deleted." if backup.delete_backup(backup_id) else "Backup deletion failed.")
                else:
                    print("Backup deletion cancelled.")
            _pause()
        else:
            print("Enter 0, 1, 2, 3, or 4.")


def main_menu():
    """Show the main guided workflow until the user exits."""
    while True:
        print("\nDrive Cleanr")
        print("=" * 48)
        print("1) Scan a drive or folder (choose WizTree or WinDirStat)")
        print("2) Use a previous scan")
        print("3) Manage backups")
        print("0) Exit")
        try:
            choice = input("Choice: ").strip().lower()
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
