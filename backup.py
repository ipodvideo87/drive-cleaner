#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Disk cleanup backup module
Provides backup, restore, and backup deletion features for safe cleanup
"""

import os
import sys
import json
import hashlib
import io
import ntpath
import re
import shutil
import stat
import subprocess
import zipfile
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="backslashreplace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(errors="backslashreplace")

# Configuration
BACKUP_DIR_NAME = "CleanBackups"
SIZE_THRESHOLD = 1 * 1024 * 1024 * 1024  # Compress directories at or above 1 GB.


def format_size(size_bytes: int) -> str:
    """Format a file size"""
    if size_bytes >= 1024 ** 3:
        return f"{size_bytes / (1024 ** 3):.2f} GB"
    elif size_bytes >= 1024 ** 2:
        return f"{size_bytes / (1024 ** 2):.2f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KB"
    return f"{size_bytes} B"


def _is_reparse_point(path: str) -> bool:
    if os.path.islink(path):
        return True
    if hasattr(os.path, "isjunction") and os.path.isjunction(path):
        return True
    try:
        attributes = os.stat(path, follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def get_dir_size(path: str) -> int:
    """Get the complete size without following links or hiding read errors."""
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    with os.scandir(path) as entries:
        for entry in entries:
            if _is_reparse_point(entry.path):
                raise RuntimeError(f"Refusing to back up a path containing a link: {entry.path}")
            if entry.is_file(follow_symlinks=False):
                total += entry.stat(follow_symlinks=False).st_size
            elif entry.is_dir(follow_symlinks=False):
                total += get_dir_size(entry.path)
    return total


def _create_zip_backup(source_path: str, archive_path: str) -> None:
    """Write a ZIP64 archive of all files, including hidden/system entries."""
    source_path = os.path.abspath(source_path)

    def raise_walk_error(error):
        raise error

    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=1, allowZip64=True) as archive:
        for current, dirs, files in os.walk(source_path, topdown=True, onerror=raise_walk_error, followlinks=False):
            for name in list(dirs):
                item_path = os.path.join(current, name)
                if _is_reparse_point(item_path):
                    raise RuntimeError(f"Refusing to archive a reparse point: {item_path}")
            relative_dir = os.path.relpath(current, source_path)
            if relative_dir != ".":
                archive_name = relative_dir.replace(os.sep, "/").rstrip("/") + "/"
                info = zipfile.ZipInfo.from_file(current, archive_name)
                directory_attributes = os.stat(current, follow_symlinks=False)
                info.external_attr = (info.external_attr & 0xFFFF0000) | getattr(directory_attributes, "st_file_attributes", 0) & 0xFF
                archive.writestr(info, b"")
            for name in files:
                file_path = os.path.join(current, name)
                if _is_reparse_point(file_path):
                    raise RuntimeError(f"Refusing to archive a reparse point: {file_path}")
                relative_file = os.path.relpath(file_path, source_path).replace(os.sep, "/")
                info = zipfile.ZipInfo.from_file(file_path, relative_file)
                info.compress_type = zipfile.ZIP_DEFLATED
                file_attributes = os.stat(file_path, follow_symlinks=False)
                info.external_attr = (info.external_attr & 0xFFFF0000) | getattr(file_attributes, "st_file_attributes", 0) & 0xFF
                with open(file_path, "rb") as source, archive.open(info, "w", force_zip64=True) as destination:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)


def _extract_zip_backup(archive_path: str, destination: str) -> None:
    """Extract a generated archive only when every member stays under destination."""
    destination = os.path.abspath(destination)
    archived_attributes = []
    with zipfile.ZipFile(archive_path, "r") as archive:
        for info in archive.infolist():
            member = info.filename.replace("\\", "/")
            parts = member.split("/")
            if member.startswith("/") or any(part == ".." for part in parts) or ntpath.splitdrive(member)[0]:
                raise RuntimeError(f"Unsafe path inside backup archive: {info.filename}")
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise RuntimeError(f"Refusing a link inside backup archive: {info.filename}")
            target = os.path.abspath(os.path.join(destination, *[part for part in parts if part]))
            if os.path.commonpath([destination, target]) != destination:
                raise RuntimeError(f"Unsafe path inside backup archive: {info.filename}")
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with archive.open(info, "r") as source, open(target, "wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                timestamp = datetime(*info.date_time).timestamp()
                os.utime(target, (timestamp, timestamp))
            archived_attributes.append((target, info.external_attr & 0xFF))

    if os.name == "nt":
        import ctypes
        for target, attributes in archived_attributes:
            if attributes and not ctypes.windll.kernel32.SetFileAttributesW(target, attributes):
                raise OSError(f"Could not restore Windows file attributes: {target}")


def find_backup_drive(exclude_drives=None, required_space_bytes=0) -> Optional[str]:
    """
    Automatically select the non-C drive with the most free space

    Returns:
        str: backup root path (for example D:\\CleanBackups), or None if space is insufficient
    """
    import ctypes

    best_drive = None
    max_free = 0
    min_required = max(5 * 1024 * 1024 * 1024, required_space_bytes + 100 * 1024 * 1024)
    excluded = {str(letter).upper().rstrip(":\\/") for letter in (exclude_drives or set())}

    # Check all eligible drive letters.
    for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
        if letter in excluded:
            continue
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            try:
                # Read available disk space.
                free_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p(drive), None, None, ctypes.pointer(free_bytes)
                )
                free = free_bytes.value

                if free > max_free and free >= min_required:
                    max_free = free
                    best_drive = letter
            except:
                continue

    if best_drive:
        backup_root = f"{best_drive}:\\{BACKUP_DIR_NAME}"
        return backup_root

    return None


def get_backup_root(exclude_drives=None, required_space_bytes=0) -> str:
    """Get the backup root directory and create it if needed"""
    backup_root = find_backup_drive(exclude_drives, required_space_bytes)
    if not backup_root:
        raise RuntimeError("No suitable backup drive found (requires a different drive with at least 5 GB free)")

    os.makedirs(backup_root, exist_ok=True)
    return backup_root


def _existing_backup_roots():
    """Find backup roots on attached data drives, independent of free-space order."""
    roots = []
    for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\{BACKUP_DIR_NAME}"
        if os.path.isdir(root):
            roots.append(root)
    return roots


def _find_backup_dir(backup_id: str):
    if not _valid_backup_id(backup_id):
        return None
    for root in _existing_backup_roots():
        candidate = os.path.join(root, backup_id)
        if os.path.isdir(candidate):
            return candidate
    return None


def sanitize_path_name(path: str) -> str:
    """Convert a path into a safe filename"""
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", path).strip("_ .")
    # Limit the generated filename length.
    if len(name) > 100:
        name = name[:100]
    return name


def create_backup(paths: List[str], priority: str = "high") -> Dict:
    """
    Create a backup

    Args:
        paths: list of directories to back up
        priority: priority label (high/medium/low)

    Returns:
        dict: backup information (including manifest)
    """
    source_drives = {
        os.path.splitdrive(os.path.abspath(path))[0].rstrip(":\\/").upper()
        for path in paths if os.path.splitdrive(os.path.abspath(path))[0]
    }
    backup_root = get_backup_root(exclude_drives=source_drives)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_id = f"backup_{timestamp}"
    backup_dir = os.path.join(backup_root, backup_id)

    os.makedirs(backup_dir, exist_ok=True)

    manifest = {
        "id": backup_id,
        "timestamp": datetime.now().isoformat(),
        "priority": priority,
        "backup_root": backup_root,
        "items": [],
        "status": "in_progress",
        "errors": [],
        "total_size": 0,
        "total_size_formatted": ""
    }

    print(f"Backup directory: {backup_dir}")
    print(f"Backup drive free space: {format_size(_get_drive_free_space(backup_root))}")
    print("-" * 50)

    for path in paths:
        if not os.path.exists(path):
            print(f"[Skip] Path does not exist: {path}")
            manifest["errors"].append(f"Path does not exist: {path}")
            continue

        if _is_reparse_point(path):
            manifest["errors"].append(f"Refusing to back up a reparse point: {path}")
            continue

        try:
            dir_size = get_dir_size(path)
        except (PermissionError, OSError, RuntimeError) as exc:
            manifest["errors"].append(f"Could not fully read {path}: {exc}")
            continue
        if dir_size == 0:
            manifest["errors"].append(f"Path is empty and could not be verified by backup: {path}")
            continue

        remaining_free = _get_drive_free_space(backup_root)
        if dir_size + 100 * 1024 * 1024 > remaining_free:
            manifest["errors"].append(
                f"Not enough free space to safely back up {path} ({format_size(dir_size)} required, {format_size(remaining_free)} available)"
            )
            continue

        digest = hashlib.sha256(os.path.normcase(os.path.abspath(path)).encode("utf-8")).hexdigest()[:10]
        safe_name = f"{sanitize_path_name(path) or 'item'}_{digest}"
        is_file = os.path.isfile(path)

        # Choose a backup format based on the target type and size.
        if is_file:
            backup_format = "file"
            backup_path = os.path.join(backup_dir, safe_name)
            try:
                shutil.copy2(path, backup_path)
            except Exception as e:
                print(f"        [Failed] {e}")
                manifest["errors"].append(f"File backup failed for {path}: {e}")
                continue
        elif dir_size < SIZE_THRESHOLD:
            # Copy directories smaller than 1 GB.
            backup_format = "copy"
            backup_path = os.path.join(backup_dir, safe_name)
            print(f"[Backup] {format_size(dir_size):>10} {path}")
            print(f"        → Copy directly to {backup_path}")

            try:
                # Copy with robocopy (preserves attributes and supports long paths)
                result = subprocess.run(
                    [
                        "robocopy", path, backup_path,
                        "/E",  # Copy all subdirectories.
                        "/COPY:DAT",  # Copy data, attributes, and timestamps.
                        "/XJ",  # Never follow junctions
                        "/R:1",  # Retry once.
                        "/W:1",  # Wait one second between retries.
                        "/NFL", "/NDL", "/NJH", "/NJS",  # Reduce console output.
                    ],
                    capture_output=True,
                    timeout=300  # Five-minute timeout.
                )
                # Robocopy codes 0-7 indicate success or copied extras.
                if result.returncode >= 8:
                    raise RuntimeError(f"Robocopy failed with exit code {result.returncode}")
                print(f"        [Done]")
            except Exception as e:
                print(f"        [Failed] {e}")
                continue
        else:
            # Compress directories of 1 GB or larger.
            backup_format = "zip"
            backup_path = os.path.join(backup_dir, f"{safe_name}.zip")
            print(f"[Backup] {format_size(dir_size):>10} {path}")
            print(f"        → Compress to {backup_path}")

            try:
                _create_zip_backup(path, backup_path)
                print(f"        [Done]")
            except Exception as e:
                print(f"        [Failed] {e}")
                continue

        if backup_format == "copy":
            try:
                if not os.path.isdir(backup_path) or get_dir_size(backup_path) != dir_size:
                    manifest["errors"].append(f"Backup output is missing or incomplete for {path}")
                    continue
            except (OSError, RuntimeError) as exc:
                manifest["errors"].append(f"Could not verify backup output for {path}: {exc}")
                continue
        if backup_format == "file" and (not os.path.isfile(backup_path) or os.path.getsize(backup_path) != dir_size):
            manifest["errors"].append(f"Backup output is incomplete for {path}")
            continue
        if backup_format == "zip":
            try:
                with zipfile.ZipFile(backup_path) as archive:
                    damaged = archive.testzip()
                    archive_size = sum(entry.file_size for entry in archive.infolist() if not entry.is_dir())
                if damaged or archive_size != dir_size:
                    manifest["errors"].append(f"Backup archive is damaged or incomplete for {path}")
                    continue
            except (OSError, zipfile.BadZipFile) as exc:
                manifest["errors"].append(f"Could not verify backup archive for {path}: {exc}")
                continue

        manifest["items"].append({
            "original_path": path,
            "backup_path": backup_path,
            "size": dir_size,
            "size_formatted": format_size(dir_size),
            "format": backup_format
        })
        manifest["total_size"] += dir_size

    manifest["total_size_formatted"] = format_size(manifest["total_size"])
    manifest["status"] = "completed" if not manifest["errors"] and len(manifest["items"]) == len(paths) else "partial"

    # Save the backup manifest.
    manifest_path = os.path.join(backup_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print("-" * 50)
    print(f"Backup complete! {len(manifest['items'])} directories backed up, total {manifest['total_size_formatted']}")
    print(f"Backup ID: {backup_id}")

    return manifest


def _get_drive_free_space(path: str) -> int:
    """Get free space for a drive"""
    import ctypes
    drive = os.path.splitdrive(path)[0] + "\\"
    free_bytes = ctypes.c_ulonglong(0)
    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
        ctypes.c_wchar_p(drive), None, None, ctypes.pointer(free_bytes)
    )
    return free_bytes.value


def _ps_literal(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _valid_backup_id(backup_id: str) -> bool:
    # Accept legacy v1.1 IDs while requiring the timestamp-only safe format.
    return bool(re.fullmatch(r"backup_\d{8}_\d{6}(?:_\d{6})?", backup_id or ""))


def list_backups() -> List[Dict]:
    """
    List all backups

    Returns:
        list: list of backup manifests
    """
    backups = []

    for backup_root in _existing_backup_roots():
        for item in os.listdir(backup_root):
            backup_dir = os.path.join(backup_root, item)
            manifest_path = os.path.join(backup_dir, "manifest.json")

            if os.path.isdir(backup_dir) and _valid_backup_id(item) and os.path.exists(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        manifest = json.load(f)
                    backups.append(manifest)
                except (OSError, ValueError):
                    continue

    # Sort newest backups first.
    backups.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return backups


def get_backup(backup_id: str) -> Optional[Dict]:
    """
    Get information about a specific backup.

    Args:
        backup_id: Backup identifier.

    Returns:
        dict: Backup information, or None if it does not exist.
    """
    if not _valid_backup_id(backup_id):
        return None
    backup_dir = _find_backup_dir(backup_id)
    if not backup_dir:
        return None
    manifest_path = os.path.join(backup_dir, "manifest.json")

    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)

    return None


def restore_backup(backup_id: str) -> bool:
    """
    Restore a specific backup.

    Args:
        backup_id: Backup identifier.

    Returns:
        bool: Whether restoration succeeded.
    """
    manifest = get_backup(backup_id)
    if not manifest:
        print(f"Backup not found: {backup_id}")
        return False
    if manifest.get("status") != "completed" or not manifest.get("items"):
        print("Refusing to restore an incomplete or empty backup")
        return False

    print(f"Restoring backup: {backup_id}")
    print(f"Backup time: {manifest['timestamp']}")
    print(f"Items: {len(manifest['items'])}")
    print("-" * 50)

    success_count = 0

    for item in manifest["items"]:
        original_path = item["original_path"]
        backup_path = item["backup_path"]
        backup_format = item["format"]

        drive, tail = os.path.splitdrive(original_path)
        if not drive or not tail.startswith(("\\", "/")) or tail.rstrip("\\/") == "":
            print("        [Skipped] Invalid original path or drive root")
            continue

        print(f"[Restore] {original_path}")

        backup_dir = _find_backup_dir(backup_id)
        if (not backup_dir or not os.path.exists(backup_path) or
                os.path.commonpath([os.path.abspath(backup_dir), os.path.abspath(backup_path)]) != os.path.abspath(backup_dir)):
            print("        [Skipped] Backup data is missing")
            continue

        try:
            if backup_format == "file":
                os.makedirs(os.path.dirname(original_path), exist_ok=True)
                shutil.copy2(backup_path, original_path)
            elif backup_format == "copy":
                os.makedirs(original_path, exist_ok=True)
                # Restore by copying the saved directory.
                result = subprocess.run(
                    [
                        "robocopy", backup_path, original_path,
                        "/E", "/COPY:DAT", "/R:1", "/W:1",
                        "/XJ",
                        "/NFL", "/NDL", "/NJH", "/NJS",
                    ],
                    capture_output=True,
                    timeout=300
                )
                if result.returncode >= 8:
                    raise RuntimeError(f"Robocopy failed with exit code {result.returncode}")
            else:
                _extract_zip_backup(backup_path, original_path)

            print("        [Done]")
            success_count += 1
        except Exception as e:
            print(f"        [Failed] {e}")

    print("-" * 50)
    print(f"Restore complete: {success_count}/{len(manifest['items'])} items")

    return success_count == len(manifest["items"])


def delete_backup(backup_id: str) -> bool:
    """
    Delete a specific backup.

    Args:
        backup_id: Backup identifier.

    Returns:
        bool: Whether deletion succeeded.
    """
    if not _valid_backup_id(backup_id):
        print(f"Invalid backup ID: {backup_id}")
        return False
    backup_dir = _find_backup_dir(backup_id)

    if not backup_dir:
        print(f"Backup not found: {backup_id}")
        return False

    try:
        shutil.rmtree(backup_dir)
        print(f"Deleted backup: {backup_id}")
        return True
    except Exception as e:
        print(f"Backup deletion failed: {e}")
        return False


def cleanup_all_backups() -> int:
    """
    Delete all backups.

    Returns:
        int: Number of backups deleted.
    """
    backups = list_backups()
    deleted = 0

    for backup in backups:
        if delete_backup(backup["id"]):
            deleted += 1

    return deleted


def get_latest_backup() -> Optional[Dict]:
    """Get the most recent backup."""
    backups = list_backups()
    return backups[0] if backups else None


def print_backups_table(backups: List[Dict]):
    """Print a backup list table"""
    if not backups:
        print("No backups found")
        return

    print("=" * 70)
    print("                         Backup List")
    print("=" * 70)
    print(f"{'ID':<30} {'Time':<20} {'Size':<12} {'Items':<8}")
    print("-" * 70)

    for backup in backups:
        backup_id = backup["id"]
        timestamp = backup["timestamp"][:19].replace("T", " ")
        size = backup.get("total_size_formatted", "Unknown")
        items = len(backup.get("items", []))
        print(f"{backup_id:<30} {timestamp:<20} {size:<12} {items:<8}")

    print("=" * 70)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Disk cleanup backup tool')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Create command.
    create_parser = subparsers.add_parser('create', help='Create a backup')
    create_parser.add_argument('--paths', nargs='+', required=True, help='Directories to back up')
    create_parser.add_argument('--priority', default='high', choices=['high', 'medium', 'low', 'all'],
                               help='Priority label')
    create_parser.add_argument('--json', action='store_true', help='Print only the JSON manifest (for automation)')

    # List command.
    subparsers.add_parser('list', help='List all backups')

    # Restore command.
    restore_parser = subparsers.add_parser('restore', help='Restore a backup')
    restore_parser.add_argument('--id', required=True, help='Backup ID')
    restore_parser.add_argument('--yes', action='store_true', help='Confirm overwriting restored paths')

    # Delete command.
    delete_parser = subparsers.add_parser('delete', help='Delete a backup')
    delete_parser.add_argument('--id', required=True, help='Backup ID')
    delete_parser.add_argument('--yes', action='store_true', help='Confirm permanently deleting the backup')

    # Cleanup command.
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up backups')
    cleanup_parser.add_argument('--all', action='store_true', help='Confirm deleting all backups')

    # Info command.
    info_parser = subparsers.add_parser('info', help='Show backup details')
    info_parser.add_argument('--id', required=True, help='Backup ID')

    # Backup-drive command.
    subparsers.add_parser('drive', help='Show backup drive information')

    args = parser.parse_args()

    if args.command == 'create':
        try:
            if args.json:
                with redirect_stdout(io.StringIO()):
                    manifest = create_backup(args.paths, args.priority)
            else:
                manifest = create_backup(args.paths, args.priority)
            print(json.dumps(manifest, ensure_ascii=bool(args.json), indent=2))
            if manifest.get("status") != "completed":
                sys.exit(1)
        except RuntimeError as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == 'list':
        backups = list_backups()
        print_backups_table(backups)

    elif args.command == 'restore':
        if not args.yes:
            answer = input("Restore this backup? Existing files at the saved paths may be overwritten. (y/N): ").strip().lower()
            if answer != "y":
                print("Restore cancelled")
                return
        success = restore_backup(args.id)
        sys.exit(0 if success else 1)

    elif args.command == 'delete':
        if not args.yes:
            answer = input("Permanently delete this backup? This cannot be undone. (y/N): ").strip().lower()
            if answer != "y":
                print("Backup deletion cancelled")
                return
        success = delete_backup(args.id)
        sys.exit(0 if success else 1)

    elif args.command == 'cleanup':
        if args.all:
            deleted = cleanup_all_backups()
            print(f"Cleaned up {deleted} backups")
        else:
            print("Please specify --all to confirm deleting all backups")

    elif args.command == 'info':
        manifest = get_backup(args.id)
        if manifest:
            print(json.dumps(manifest, ensure_ascii=False, indent=2))
        else:
            print(f"Backup not found: {args.id}")
            sys.exit(1)

    elif args.command == 'drive':
        backup_root = find_backup_drive()
        if backup_root:
            free_space = _get_drive_free_space(backup_root)
            print(f"Backup drive: {backup_root}")
            print(f"Free space: {format_size(free_space)}")
        else:
            print("No suitable backup drive found (requires a non-C drive with at least 5GB free)")
            sys.exit(1)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
