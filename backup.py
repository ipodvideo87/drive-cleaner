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
WINDOWS_RESERVED_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
})


def _is_windows_reserved_name(part: str) -> bool:
    return part.split(".")[0].rstrip(" .").upper() in WINDOWS_RESERVED_NAMES


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
    try:
        metadata = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        # Unknown path state must not be treated as safe for backup, restore,
        # or deletion checks.
        return True

    if stat.S_ISLNK(metadata.st_mode):
        return True
    if hasattr(os.path, "isjunction"):
        try:
            if os.path.isjunction(path):
                return True
        except OSError:
            return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def _path_has_reparse_component(path: str) -> bool:
    """Check every existing component so reads and writes do not cross links."""
    absolute = os.path.abspath(path)
    drive, tail = os.path.splitdrive(absolute)
    current = drive + os.sep if drive else os.path.abspath(os.sep)
    for part in tail.strip("\\/").replace("/", os.sep).split(os.sep):
        if not part:
            continue
        current = os.path.join(current, part)
        if _is_reparse_point(current):
            return True
    return False


def _tree_has_reparse_point(path: str) -> bool:
    """Check an existing destination tree without following directory links."""
    if not os.path.lexists(path):
        return False
    if _is_reparse_point(path):
        return True
    if not os.path.isdir(path):
        return False
    with os.scandir(path) as entries:
        for entry in entries:
            if _is_reparse_point(entry.path):
                return True
            if entry.is_dir(follow_symlinks=False) and _tree_has_reparse_point(entry.path):
                return True
    return False


def _valid_restore_target(path: str) -> bool:
    """Accept only normalized, non-root local Windows paths from manifests."""
    if not isinstance(path, str) or not path or path.startswith(("\\\\", "//")):
        return False
    normalized = path.replace("/", "\\")
    drive, tail = ntpath.splitdrive(normalized)
    if (len(drive) != 2 or not drive[0].isalpha() or drive[1] != ":" or
            not tail.startswith("\\") or not tail.strip("\\")):
        return False
    parts = tail.split("\\")
    if any(part in {".", ".."} for part in parts):
        return False
    if (any(character in tail for character in "*?:") or
            any(part.endswith((".", " ")) or _is_windows_reserved_name(part) or
                any(ord(character) < 32 for character in part) for part in parts if part)):
        return False
    return ntpath.normpath(normalized) == normalized.rstrip("\\")


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


def _sha256_file(path: str) -> str:
    """Hash a file in bounded memory for content-level backup verification."""
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _directory_fingerprint(path: str) -> Dict[str, tuple]:
    """Map directory entries to content hashes without following reparse points."""
    root = os.path.abspath(path)

    def raise_walk_error(error):
        raise error

    entries = {}
    for current, directories, files in os.walk(root, topdown=True, onerror=raise_walk_error, followlinks=False):
        directories.sort()
        files.sort()
        for name in directories:
            item_path = os.path.join(current, name)
            if _is_reparse_point(item_path):
                raise RuntimeError(f"Refusing to verify a reparse point: {item_path}")
            relative = os.path.normcase(os.path.relpath(item_path, root))
            entries[relative] = ("directory",)
        for name in files:
            item_path = os.path.join(current, name)
            if _is_reparse_point(item_path):
                raise RuntimeError(f"Refusing to verify a reparse point: {item_path}")
            relative = os.path.normcase(os.path.relpath(item_path, root))
            size = os.path.getsize(item_path)
            entries[relative] = ("file", size, _sha256_file(item_path))
    return entries


def _directory_fingerprint_sha256(path: str) -> str:
    """Hash a directory's names, types, sizes, and file contents deterministically."""
    return _fingerprint_entries_sha256(_directory_fingerprint(path))


def _fingerprint_entries_sha256(entries: Dict[str, tuple]) -> str:
    """Hash a previously collected directory fingerprint."""
    canonical = json.dumps(
        [(name, *entries[name]) for name in sorted(entries)],
        ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _create_zip_backup(source_path: str, archive_path: str) -> Dict[str, tuple]:
    """Write a ZIP64 archive and fingerprint the exact content it contains."""
    source_path = os.path.abspath(source_path)
    archived_entries = {}

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
                archived_entries[os.path.normcase(relative_dir)] = ("directory",)
            for name in files:
                file_path = os.path.join(current, name)
                if _is_reparse_point(file_path):
                    raise RuntimeError(f"Refusing to archive a reparse point: {file_path}")
                relative_file = os.path.relpath(file_path, source_path).replace(os.sep, "/")
                info = zipfile.ZipInfo.from_file(file_path, relative_file)
                info.compress_type = zipfile.ZIP_DEFLATED
                file_attributes = os.stat(file_path, follow_symlinks=False)
                info.external_attr = (info.external_attr & 0xFFFF0000) | getattr(file_attributes, "st_file_attributes", 0) & 0xFF
                digest = hashlib.sha256()
                written = 0
                with open(file_path, "rb") as source, archive.open(
                        info, "w", force_zip64=info.file_size > zipfile.ZIP64_LIMIT) as destination:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        destination.write(chunk)
                        digest.update(chunk)
                        written += len(chunk)
                archived_entries[os.path.normcase(relative_file.replace("/", os.sep))] = (
                    "file", written, digest.hexdigest()
                )
    return archived_entries


def _extract_zip_backup(archive_path: str, destination: str, overwrite: bool = False) -> list[str]:
    """Restore an archive without replacing existing files unless approved."""
    destination = os.path.abspath(destination)
    if _path_has_reparse_component(destination):
        raise RuntimeError("Refusing to restore through a reparse point or symbolic link")

    planned_entries = []
    archived_attributes = []
    conflicts = []
    seen_targets = set()
    archive_path_types = {}
    with zipfile.ZipFile(archive_path, "r") as archive:
        for info in archive.infolist():
            member = info.filename.replace("\\", "/")
            parts = member.split("/")
            safe_parts = [part for part in parts if part]
            if (member.startswith("/") or any(part in {".", ".."} for part in parts) or
                    not safe_parts or any(":" in part for part in safe_parts) or
                    any(part.endswith((".", " ")) for part in safe_parts) or
                    any(_is_windows_reserved_name(part) or
                        any(ord(character) < 32 for character in part)
                        for part in safe_parts) or ntpath.splitdrive(member)[0]):
                raise RuntimeError(f"Unsafe path inside backup archive: {info.filename}")
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                raise RuntimeError(f"Refusing a link inside backup archive: {info.filename}")
            target = os.path.abspath(os.path.join(destination, *safe_parts))
            try:
                contained = os.path.normcase(os.path.commonpath([destination, target])) == os.path.normcase(destination)
            except ValueError:
                contained = False
            if not contained:
                raise RuntimeError(f"Unsafe path inside backup archive: {info.filename}")
            target_key = os.path.normcase(os.path.normpath(target)).casefold()
            if target_key in seen_targets:
                raise RuntimeError(f"Refusing duplicate or case-colliding paths in backup archive: {info.filename}")
            seen_targets.add(target_key)

            # Windows cannot represent a file as both a path and a parent
            # directory. Validate every explicit and implicit path component
            # before writing any archive member, regardless of ZIP entry order.
            for index in range(1, len(safe_parts) + 1):
                relative_key = "\\".join(safe_parts[:index]).casefold()
                component_type = (
                    "directory" if index < len(safe_parts) or info.is_dir() else "file"
                )
                existing_type = archive_path_types.get(relative_key)
                if existing_type is not None and existing_type != component_type:
                    raise RuntimeError(
                        f"Refusing file/directory path conflict in backup archive: {info.filename}"
                    )
                archive_path_types[relative_key] = component_type

            if _path_has_reparse_component(target):
                raise RuntimeError(f"Refusing to restore through a reparse point: {info.filename}")
            parent = os.path.dirname(target)
            while parent:
                if os.path.lexists(parent) and not os.path.isdir(parent):
                    raise RuntimeError(f"Refusing to restore through a non-directory path component: {parent}")
                if os.path.normcase(parent) == os.path.normcase(destination):
                    break
                next_parent = os.path.dirname(parent)
                if next_parent == parent:
                    break
                parent = next_parent
            if os.path.lexists(target):
                if info.is_dir() and not os.path.isdir(target):
                    raise RuntimeError(f"Refusing to replace a file with a directory: {info.filename}")
                if not info.is_dir() and not os.path.isfile(target):
                    raise RuntimeError(f"Refusing to replace a directory with a file: {info.filename}")
                if not info.is_dir() and not overwrite:
                    conflicts.append(target)
            planned_entries.append((info, target))

        # Validate every member before writing any of them, avoiding partial
        # restoration when a later entry is unsafe or has damaged contents.
        print("        [Checking archive contents before restore]")
        damaged_member = archive.testzip()
        if damaged_member is not None:
            raise RuntimeError(f"Refusing a damaged backup archive member: {damaged_member}")

        for info, target in planned_entries:
            if info.is_dir():
                existed = os.path.lexists(target)
                os.makedirs(target, exist_ok=True)
                if existed and not overwrite:
                    continue
            else:
                if os.path.lexists(target) and not overwrite:
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                try:
                    with archive.open(info, "r") as source, open(target, "wb" if overwrite else "xb") as output:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
                except FileExistsError:
                    conflicts.append(target)
                    continue
                timestamp = datetime(*info.date_time).timestamp()
                os.utime(target, (timestamp, timestamp))
            archived_attributes.append((target, info.external_attr & 0xFF))

    if os.name == "nt":
        import ctypes
        for target, attributes in archived_attributes:
            if attributes and not ctypes.windll.kernel32.SetFileAttributesW(target, attributes):
                raise OSError(f"Could not restore Windows file attributes: {target}")
    return conflicts


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
    if _path_has_reparse_component(backup_root):
        raise RuntimeError("Refusing to store backups through a reparse point or junction")
    if os.path.lexists(backup_root) and not os.path.isdir(backup_root):
        raise RuntimeError("Backup destination exists but is not a directory")

    os.makedirs(backup_root, exist_ok=True)
    if _path_has_reparse_component(backup_root):
        raise RuntimeError("Backup destination changed to a reparse point or junction")
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
        if (not _path_has_reparse_component(root) and
                not _is_reparse_point(candidate) and os.path.isdir(candidate)):
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
        paths: list of absolute local files or directories to back up
        priority: priority label (high/medium/low)

    Returns:
        dict: backup information (including manifest)
    """
    if not paths:
        raise ValueError("At least one backup path is required")
    normalized_paths = []
    for path in paths:
        try:
            source_path = os.fspath(path)
        except TypeError as exc:
            raise ValueError("Backup paths must be absolute local paths below a drive root") from exc
        if not _valid_restore_target(source_path):
            raise ValueError(f"Refusing an unsafe backup path: {source_path}")
        normalized_paths.append(source_path)
    paths = normalized_paths

    source_drives = {
        os.path.splitdrive(path)[0].rstrip(":\\/").upper()
        for path in paths if os.path.splitdrive(path)[0]
    }
    backup_root = get_backup_root(exclude_drives=source_drives)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_id = f"backup_{timestamp}"
    backup_dir = os.path.join(backup_root, backup_id)

    # Never merge a new run into or truncate an existing backup if the
    # timestamp collides or the destination was pre-created unexpectedly.
    os.makedirs(backup_dir, exist_ok=False)

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

        if _path_has_reparse_component(path):
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
        source_integrity_sha256 = None

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
                source_fingerprint = _directory_fingerprint(path)
                archived_fingerprint = _create_zip_backup(path, backup_path)
                if archived_fingerprint != source_fingerprint:
                    manifest["errors"].append(f"Source changed while its backup archive was being created: {path}")
                    continue
                print(f"        [Done]")
            except Exception as e:
                print(f"        [Failed] {e}")
                continue

        if backup_format == "copy":
            try:
                source_entries = _directory_fingerprint(path)
                if (not os.path.isdir(backup_path) or get_dir_size(backup_path) != dir_size or
                        source_entries != _directory_fingerprint(backup_path)):
                    manifest["errors"].append(f"Backup output is missing, incomplete, or has different file contents for {path}")
                    continue
                source_integrity_sha256 = _fingerprint_entries_sha256(source_entries)
            except (OSError, RuntimeError) as exc:
                manifest["errors"].append(f"Could not verify backup output for {path}: {exc}")
                continue
        if backup_format == "file":
            try:
                source_integrity_sha256 = _sha256_file(path)
                if (not os.path.isfile(backup_path) or os.path.getsize(backup_path) != dir_size or
                        source_integrity_sha256 != _sha256_file(backup_path)):
                    manifest["errors"].append(f"Backup output is incomplete or has different file contents for {path}")
                    continue
            except OSError as exc:
                manifest["errors"].append(f"Could not verify backup output for {path}: {exc}")
                continue
        if backup_format == "zip":
            try:
                source_integrity_sha256 = _fingerprint_entries_sha256(source_fingerprint)
                with zipfile.ZipFile(backup_path) as archive:
                    damaged = archive.testzip()
                    archive_size = sum(entry.file_size for entry in archive.infolist() if not entry.is_dir())
                if damaged or archive_size != dir_size:
                    manifest["errors"].append(f"Backup archive is damaged or incomplete for {path}")
                    continue
            except (OSError, zipfile.BadZipFile) as exc:
                manifest["errors"].append(f"Could not verify backup archive for {path}: {exc}")
                continue

        try:
            if backup_format == "file":
                integrity_sha256 = _sha256_file(backup_path)
            elif backup_format == "copy":
                integrity_sha256 = _directory_fingerprint_sha256(backup_path)
            else:
                integrity_sha256 = _sha256_file(backup_path)
        except (OSError, RuntimeError) as exc:
            manifest["errors"].append(f"Could not fingerprint backup output for {path}: {exc}")
            continue

        manifest["items"].append({
            "original_path": path,
            "backup_path": backup_path,
            "size": dir_size,
            "size_formatted": format_size(dir_size),
            "format": backup_format,
            "integrity_sha256": integrity_sha256,
            "source_integrity_sha256": source_integrity_sha256,
        })
        manifest["total_size"] += dir_size

    manifest["total_size_formatted"] = format_size(manifest["total_size"])
    manifest["status"] = "completed" if not manifest["errors"] and len(manifest["items"]) == len(paths) else "partial"

    # Save the backup manifest.
    manifest_path = os.path.join(backup_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print("-" * 50)
    print(f"Backup complete! {len(manifest['items'])} items backed up, total {manifest['total_size_formatted']}")
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


def verify_backup(backup_id: str, paths: Optional[List[str]] = None) -> bool:
    """Verify saved payloads and ensure current sources still match them."""
    manifest = get_backup(backup_id)
    if (not isinstance(manifest, dict) or manifest.get("status") != "completed" or
            not isinstance(manifest.get("items"), list) or not manifest["items"]):
        print("Refusing to verify an incomplete or empty backup")
        return False

    backup_dir = _find_backup_dir(backup_id)
    if not backup_dir or _path_has_reparse_component(backup_dir):
        print("Refusing to verify through an unavailable or linked backup location")
        return False

    def path_key(path):
        return ntpath.normcase(ntpath.normpath(path.replace("/", "\\")))

    requested = None
    if paths is not None:
        if not isinstance(paths, list) or not paths:
            print("At least one source path is required")
            return False
        requested = set()
        for path in paths:
            if not _valid_restore_target(path):
                print(f"Refusing to verify an unsafe source path: {path}")
                return False
            requested.add(path_key(path))

    items_by_path = {}
    for item in manifest["items"]:
        if not isinstance(item, dict) or not isinstance(item.get("original_path"), str):
            print("Refusing to verify a malformed backup manifest")
            return False
        key = path_key(item["original_path"])
        if key in items_by_path:
            print("Refusing to verify a backup with duplicate source paths")
            return False
        items_by_path[key] = item

    if requested is not None:
        missing = requested - items_by_path.keys()
        if missing:
            print("Requested source path is not present in this backup")
            return False
        selected_items = [items_by_path[key] for key in requested]
    else:
        selected_items = list(manifest["items"])

    backup_root = os.path.abspath(backup_dir)
    for item in selected_items:
        original_path = item["original_path"]
        backup_path = item.get("backup_path")
        backup_format = item.get("format")
        source_digest = item.get("source_integrity_sha256")
        payload_digest = item.get("integrity_sha256")
        if (backup_format not in {"file", "copy", "zip"} or
                not isinstance(source_digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", source_digest) or
                not isinstance(payload_digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", payload_digest) or
                not isinstance(backup_path, str)):
            print(f"Backup lacks verifiable integrity data for: {original_path}")
            return False

        backup_path = os.path.abspath(backup_path)
        try:
            contained = os.path.normcase(os.path.commonpath([backup_root, backup_path])) == os.path.normcase(backup_root)
        except ValueError:
            contained = False
        if (not contained or _path_has_reparse_component(backup_path) or
                not os.path.exists(backup_path) or _path_has_reparse_component(original_path) or
                not os.path.exists(original_path)):
            print(f"Backup or source path is unavailable or linked: {original_path}")
            return False

        try:
            if backup_format == "file":
                if not os.path.isfile(backup_path) or not os.path.isfile(original_path):
                    print(f"Source item type changed since backup: {original_path}")
                    return False
                current_source_digest = _sha256_file(original_path)
                current_payload_digest = _sha256_file(backup_path)
            elif backup_format == "copy":
                if not os.path.isdir(backup_path) or not os.path.isdir(original_path):
                    print(f"Source item type changed since backup: {original_path}")
                    return False
                if _tree_has_reparse_point(backup_path) or _tree_has_reparse_point(original_path):
                    print(f"Source or backup tree contains a reparse point: {original_path}")
                    return False
                current_source_digest = _directory_fingerprint_sha256(original_path)
                current_payload_digest = _directory_fingerprint_sha256(backup_path)
            else:
                if not os.path.isfile(backup_path) or not os.path.isdir(original_path):
                    print(f"Source item type changed since backup: {original_path}")
                    return False
                if _tree_has_reparse_point(original_path):
                    print(f"Source tree contains a reparse point: {original_path}")
                    return False
                current_source_digest = _directory_fingerprint_sha256(original_path)
                current_payload_digest = _sha256_file(backup_path)
        except (OSError, RuntimeError) as exc:
            print(f"Could not verify source or backup contents for {original_path}: {exc}")
            return False

        if current_payload_digest.lower() != payload_digest.lower():
            print(f"Backup contents changed since verification: {original_path}")
            return False
        if current_source_digest.lower() != source_digest.lower():
            print(f"Source changed since backup; refusing cleanup: {original_path}")
            return False

    print("Backup and selected source contents match.")
    return True


def restore_backup(backup_id: str, overwrite: bool = False) -> bool:
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
    if (not isinstance(manifest, dict) or manifest.get("status") != "completed" or
            not isinstance(manifest.get("items"), list) or not manifest["items"]):
        print("Refusing to restore an incomplete or empty backup")
        return False

    backup_dir = _find_backup_dir(backup_id)
    if not backup_dir or _path_has_reparse_component(backup_dir):
        print("Refusing to restore from an unavailable or linked backup location")
        return False

    # Validate the complete untrusted manifest before restoring any item. This
    # avoids arbitrary/network/device destinations and partial restores caused
    # by a malformed later entry.
    validated_items = []
    for item in manifest["items"]:
        if not isinstance(item, dict):
            print("Refusing to restore a malformed backup manifest")
            return False
        original_path = item.get("original_path")
        backup_path = item.get("backup_path")
        backup_format = item.get("format")
        if (not _valid_restore_target(original_path) or not isinstance(backup_path, str) or
                backup_format not in {"file", "copy", "zip"}):
            print("Refusing to restore an invalid backup manifest entry")
            return False
        backup_path = os.path.abspath(backup_path)
        try:
            contained = os.path.normcase(os.path.commonpath([os.path.abspath(backup_dir), backup_path])) == os.path.normcase(os.path.abspath(backup_dir))
        except ValueError:
            contained = False
        if (not contained or _path_has_reparse_component(backup_path) or
                not os.path.exists(backup_path) or _path_has_reparse_component(original_path)):
            print("Refusing to restore through an unsafe or missing path")
            return False
        if ((backup_format == "file" and not os.path.isfile(backup_path)) or
                (backup_format == "copy" and not os.path.isdir(backup_path)) or
                (backup_format == "zip" and not os.path.isfile(backup_path))):
            print("Refusing to restore mismatched backup data")
            return False
        if os.path.lexists(original_path):
            if ((backup_format == "file" and not os.path.isfile(original_path)) or
                    (backup_format in {"copy", "zip"} and not os.path.isdir(original_path))):
                print("Refusing to overwrite a path with a different item type")
                return False
        if backup_format in {"copy", "zip"} and _tree_has_reparse_point(original_path):
            print("Refusing to restore into a directory tree containing a reparse point")
            return False
        validated_items.append((item, original_path, backup_path, backup_format))

    # Verify every saved payload before writing any restored data. This catches
    # later disk corruption (including same-size changes) without allowing a
    # failed later item to leave an earlier item partially restored.
    for item, _original_path, backup_path, backup_format in validated_items:
        expected_digest = item.get("integrity_sha256")
        if expected_digest is not None:
            if not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_digest):
                print("Refusing to restore a backup with an invalid integrity hash")
                return False
            try:
                if backup_format == "copy":
                    actual_digest = _directory_fingerprint_sha256(backup_path)
                else:
                    actual_digest = _sha256_file(backup_path)
            except (OSError, RuntimeError) as exc:
                print(f"Refusing to restore an unreadable backup payload: {exc}")
                return False
            if actual_digest.lower() != expected_digest.lower():
                print("Refusing to restore: backup contents changed after verification")
                return False
        else:
            # Older manifests predate persistent hashes. Preserve their restore
            # support with structural/size checks, and tell users the limit.
            try:
                expected_size = item.get("size")
                if backup_format == "file":
                    legacy_valid = isinstance(expected_size, int) and os.path.getsize(backup_path) == expected_size
                elif backup_format == "copy":
                    legacy_valid = isinstance(expected_size, int) and get_dir_size(backup_path) == expected_size
                else:
                    with zipfile.ZipFile(backup_path) as archive:
                        archive_size = sum(entry.file_size for entry in archive.infolist() if not entry.is_dir())
                        legacy_valid = archive.testzip() is None and archive_size == expected_size
            except (OSError, RuntimeError, zipfile.BadZipFile):
                legacy_valid = False
            if not legacy_valid:
                print("Refusing to restore: legacy backup data is incomplete or damaged")
                return False
            print("Warning: this older backup has no content hash; only size and structure were checked.")

    print(f"Restoring backup: {backup_id}")
    print(f"Backup time: {manifest.get('timestamp', 'Unknown')}")
    print(f"Items: {len(validated_items)}")
    print("-" * 50)

    success_count = 0
    conflict_count = 0
    failure_count = 0

    for item, original_path, backup_path, backup_format in validated_items:
        print(f"[Restore] {original_path}")
        item_conflicts = 0

        try:
            if backup_format == "file":
                if os.path.lexists(original_path) and not overwrite:
                    print("        [Skipped; existing file preserved. Use explicit overwrite approval to replace it.]\n")
                    conflict_count += 1
                    item_conflicts += 1
                    continue
                os.makedirs(os.path.dirname(original_path), exist_ok=True)
                if overwrite:
                    shutil.copy2(backup_path, original_path)
                else:
                    with open(backup_path, "rb") as source, open(original_path, "xb") as destination:
                        shutil.copyfileobj(source, destination, length=1024 * 1024)
                    shutil.copystat(backup_path, original_path)
            elif backup_format == "copy":
                os.makedirs(original_path, exist_ok=True)
                # Restore by copying the saved directory.
                command = [
                        "robocopy", backup_path, original_path,
                        "/E", "/COPY:DAT", "/R:1", "/W:1",
                        "/XJ",
                        "/NFL", "/NDL", "/NJH", "/NJS",
                    ]
                if not overwrite:
                    # Avoid replacing files users may have recreated since cleanup.
                    command.extend(["/XC", "/XN", "/XO"])
                    for current, _dirs, files in os.walk(backup_path):
                        for name in files:
                            relative = os.path.relpath(os.path.join(current, name), backup_path)
                            if os.path.lexists(os.path.join(original_path, relative)):
                                conflict_count += 1
                                item_conflicts += 1
                result = subprocess.run(
                    command,
                    capture_output=True,
                    timeout=300
                )
                if result.returncode >= 8:
                    raise RuntimeError(f"Robocopy failed with exit code {result.returncode}")
            else:
                conflicts = _extract_zip_backup(backup_path, original_path, overwrite=overwrite)
                if conflicts:
                    conflict_count += len(conflicts)
                    item_conflicts += len(conflicts)

            if item_conflicts:
                print("        [Restored without replacing existing files]")
            else:
                print("        [Done]")
            success_count += 1
        except Exception as e:
            failure_count += 1
            print(f"        [Failed] {e}")

    print("-" * 50)
    if conflict_count or failure_count:
        print(
            f"Restore incomplete: {success_count}/{len(manifest['items'])} items; "
            f"{failure_count} failed; preserved {conflict_count} existing file(s)"
        )
    else:
        print(f"Restore complete: {success_count}/{len(manifest['items'])} items")

    return success_count == len(manifest["items"]) and conflict_count == 0


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
    create_parser.add_argument('--paths', nargs='+', required=True, help='Absolute local files or directories to back up')
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

    # Verify command: confirm both the saved payload and current source contents.
    verify_parser = subparsers.add_parser('verify', help='Verify backup and current source contents')
    verify_parser.add_argument('--id', required=True, help='Backup ID')
    verify_parser.add_argument('--paths', nargs='+', help='Specific source paths to verify (defaults to all items)')

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
        except (RuntimeError, ValueError) as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == 'list':
        backups = list_backups()
        print_backups_table(backups)

    elif args.command == 'restore':
        overwrite = bool(args.yes)
        if not args.yes:
            answer = input(
                "Handle existing files: O to overwrite, M to restore missing files and preserve existing ones, or Q to cancel [M]: "
            ).strip().lower()
            if answer in {"o", "overwrite"}:
                overwrite = True
            elif answer in {"", "m", "merge"}:
                overwrite = False
            else:
                print("Restore cancelled")
                return
        success = restore_backup(args.id, overwrite=overwrite)
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

    elif args.command == 'verify':
        success = verify_backup(args.id, args.paths)
        sys.exit(0 if success else 1)

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
