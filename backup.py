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
import tempfile
import threading
import time
import unicodedata
import zipfile
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Dict, Optional

from error_messages import describe_error, safe_terminal_text as _safe_terminal_text

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="backslashreplace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(errors="backslashreplace")

# Configuration
BACKUP_DIR_NAME = "CleanBackups"
SIZE_THRESHOLD = 1 * 1024 * 1024 * 1024  # Compress directories at or above 1 GB.
BACKUP_PROGRESS_BYTES_INTERVAL = 64 * 1024 * 1024
BACKUP_PROGRESS_TIME_INTERVAL_SECONDS = 10
BACKUP_PROGRESS_ENTRY_INTERVAL = 100
BACKUP_DELETE_PROGRESS_INTERVAL_SECONDS = 10
BACKUP_COPY_CHUNK_BYTES = 4 * 1024 * 1024
ROBOCOPY_TIMEOUT_SECONDS = 300
ROBOCOPY_PROGRESS_INTERVAL_SECONDS = 10
WINDOWS_INVALID_NAME_CHARS = frozenset('<>:"|?*')
WINDOWS_RESERVED_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
    *(f"COM{digit}" for digit in "¹²³"),
    *(f"LPT{digit}" for digit in "¹²³"),
})


def _is_windows_reserved_name(part: str) -> bool:
    return part.split(".")[0].rstrip(" .").upper() in WINDOWS_RESERVED_NAMES


def _contains_hidden_formatting(value: str) -> bool:
    """Detect Unicode format controls that can visually reorder or hide names."""
    return any(unicodedata.category(character) == "Cf" for character in value)


def format_size(size_bytes: int) -> str:
    """Format a file size"""
    if size_bytes >= 1024 ** 3:
        return f"{size_bytes / (1024 ** 3):.2f} GB"
    elif size_bytes >= 1024 ** 2:
        return f"{size_bytes / (1024 ** 2):.2f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KB"
    return f"{size_bytes} B"


class _BackupProgress:
    """Print throttled English progress for backup, verification, restore, and deletion work."""

    def __init__(self, phase: str, stream=None):
        self.phase = phase
        self.stream = sys.stdout if stream is None else stream
        self.items = 0
        self.known_bytes = 0
        self._last_message = time.monotonic()
        self._active_file = None
        self._active_file_action = None
        self._active_file_bytes = 0
        self._last_file_message_bytes = 0
        self._item_action = "checked"

    def _emit(self, message: str) -> None:
        print(f"{self.phase}: {message}", file=self.stream, flush=True)
        self._last_message = time.monotonic()

    def item(self, path: str, known_bytes: int = 0, action: str = "checked") -> None:
        self.items += 1
        self.known_bytes += max(0, int(known_bytes))
        self._item_action = action
        elapsed = time.monotonic() - self._last_message
        if (self.items == 1 or self.items % BACKUP_PROGRESS_ENTRY_INTERVAL == 0 or
                elapsed >= BACKUP_PROGRESS_TIME_INTERVAL_SECONDS):
            name = _safe_terminal_text(os.path.basename(str(path).rstrip("\\/")), "item")
            item_label = "item" if self.items == 1 else "items"
            self._emit(
                f"{self.items:,} {item_label} {action}; {format_size(self.known_bytes)} of file data found so far. Current item: {name}"
            )

    def file_bytes(self, path: str, processed: int, total: int, action: str = "checked") -> None:
        processed = max(0, int(processed))
        total = max(0, int(total))
        if path != self._active_file or action != self._active_file_action:
            self._active_file = path
            self._active_file_action = action
            self._active_file_bytes = 0
            self._last_file_message_bytes = 0
        self._active_file_bytes = max(self._active_file_bytes, processed)
        elapsed = time.monotonic() - self._last_message
        if (processed - self._last_file_message_bytes >= BACKUP_PROGRESS_BYTES_INTERVAL or
                elapsed >= BACKUP_PROGRESS_TIME_INTERVAL_SECONDS or
                (total >= BACKUP_PROGRESS_BYTES_INTERVAL and processed == total)):
            name = _safe_terminal_text(os.path.basename(str(path)), "file")
            percent = int(min(100, 100 * processed / total)) if total else 100
            self._emit(
                f"{name}: {format_size(processed)} of {format_size(total)} {action} ({percent}%)."
            )
            self._last_file_message_bytes = processed

    def heartbeat(self, elapsed_seconds: float) -> None:
        elapsed = max(0, int(elapsed_seconds))
        self._emit(
            f"Still working after {elapsed} seconds; Drive Cleanr will report when this step is finished."
        )

    def tree_heartbeat(self, elapsed_seconds: float, current_path: str) -> None:
        elapsed = max(0, int(elapsed_seconds))
        item_count = self.items
        entry_label = "entry" if item_count == 1 else "entries"
        name = _safe_terminal_text(
            os.path.basename(str(current_path).rstrip("\\/")) or "folder entries", "item"
        )
        self._emit(
            f"Still checking links and junctions after {elapsed} seconds; "
            f"{item_count:,} {entry_label} checked so far. Current item: {name}."
        )

    def finish(self) -> None:
        item_label = "item" if self.items == 1 else "items"
        detail = f"{self.items:,} {item_label} {self._item_action}" if self.items else ""
        suffix = f": {detail}." if detail else "."
        print(f"{self.phase} complete{suffix}", file=self.stream, flush=True)


def _is_reparse_point(path: str) -> bool:
    try:
        metadata = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except (OSError, ValueError):
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


def _tree_has_reparse_point(
    path: str, progress_callback: Optional[Callable[[str], None]] = None,
    current_callback: Optional[Callable[[str], None]] = None,
) -> bool:
    """Check an existing destination tree without following directory links."""
    if not os.path.lexists(path):
        return False
    if _is_reparse_point(path):
        return True
    if not os.path.isdir(path):
        return False
    with os.scandir(path) as entries:
        for entry in entries:
            if current_callback is not None:
                current_callback(entry.path)
            if _is_reparse_point(entry.path):
                if progress_callback is not None:
                    progress_callback(entry.path)
                return True
            if progress_callback is not None:
                progress_callback(entry.path)
            if entry.is_dir(follow_symlinks=False) and _tree_has_reparse_point(
                entry.path, progress_callback, current_callback,
            ):
                return True
    return False


def _tree_has_reparse_point_with_progress(path: str, phase: str) -> bool:
    """Check a directory tree for links while keeping long checks visible."""
    print(f"Checking {phase} for links and junctions...", flush=True)
    progress = _BackupProgress(f"Checking {phase}")
    progress_lock = threading.Lock()
    stop_heartbeat = threading.Event()
    started_at = time.monotonic()
    current = {"path": path}

    def report_entry(entry: str) -> None:
        with progress_lock:
            current["path"] = entry
            progress.item(entry, action="checked")

    def report_current(entry: str) -> None:
        with progress_lock:
            current["path"] = entry

    def report_heartbeat() -> None:
        interval = max(0.01, float(BACKUP_PROGRESS_TIME_INTERVAL_SECONDS))
        while not stop_heartbeat.wait(interval):
            with progress_lock:
                progress.tree_heartbeat(time.monotonic() - started_at, current["path"])

    heartbeat_thread = threading.Thread(
        target=report_heartbeat, name="drive-cleanr-link-check-progress", daemon=True
    )
    heartbeat_thread.start()
    try:
        contains_reparse_point = _tree_has_reparse_point(
            path, progress_callback=report_entry, current_callback=report_current
        )
        progress.finish()
        return contains_reparse_point
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=max(1.0, float(BACKUP_PROGRESS_TIME_INTERVAL_SECONDS)))


def _rmtree_with_progress(path: str) -> None:
    """Keep users informed while shutil removes a large saved backup."""
    finished = threading.Event()
    started_at = time.monotonic()
    progress = _BackupProgress("Backup deletion")
    interval = max(0.1, float(BACKUP_DELETE_PROGRESS_INTERVAL_SECONDS))

    def report_heartbeat() -> None:
        while not finished.wait(interval):
            try:
                progress.heartbeat(time.monotonic() - started_at)
            except (OSError, ValueError):
                return

    heartbeat_thread = threading.Thread(
        target=report_heartbeat,
        name="drive-cleanr-backup-delete-progress",
        daemon=True,
    )
    heartbeat_thread.start()
    try:
        shutil.rmtree(path)
    finally:
        finished.set()
        heartbeat_thread.join()
    progress.finish()


def _valid_restore_target(path: str) -> bool:
    """Accept only normalized, non-root local Windows paths from manifests."""
    if (not isinstance(path, str) or not path or _contains_hidden_formatting(path) or
            path.startswith(("\\\\", "//"))):
        return False
    normalized = path.replace("/", "\\")
    drive, tail = ntpath.splitdrive(normalized)
    if (len(drive) != 2 or not drive[0].isalpha() or drive[1] != ":" or
            not tail.startswith("\\") or not tail.strip("\\")):
        return False
    parts = tail.split("\\")
    if any(part in {".", ".."} for part in parts):
        return False
    if (any(character in WINDOWS_INVALID_NAME_CHARS for part in parts for character in part) or
            any(part.endswith((".", " ")) or _is_windows_reserved_name(part) or
                any(ord(character) < 32 for character in part) for part in parts if part)):
        return False
    return ntpath.normpath(normalized) == normalized.rstrip("\\")


def _windows_path_key(path: str) -> str:
    """Normalize a local Windows path for case-insensitive overlap checks."""
    return ntpath.normcase(ntpath.normpath(os.fspath(path).replace("/", "\\")))


def _paths_overlap(left: str, right: str) -> bool:
    """Return whether two Windows paths name the same or nested locations."""
    left_key = _windows_path_key(left).rstrip("\\")
    right_key = _windows_path_key(right).rstrip("\\")
    return (
        left_key == right_key or
        left_key.startswith(right_key + "\\") or
        right_key.startswith(left_key + "\\")
    )


def _restore_path_overlaps_backup_storage(path: str, roots=None) -> bool:
    """Return whether a restore target would alter Drive Cleanr backup storage."""
    if roots is None:
        roots = _existing_backup_roots()
    return any(
        isinstance(root, (str, os.PathLike)) and
        ntpath.basename(ntpath.normpath(os.fspath(root))).casefold() == BACKUP_DIR_NAME.casefold() and
        _paths_overlap(path, root)
        for root in roots
    )


def _named_data_streams(path: str) -> list[tuple[str, int]]:
    """List named NTFS data streams without treating the default stream as an extra."""
    if os.name != "nt":
        return []

    import ctypes
    from ctypes import wintypes

    class FindStreamData(ctypes.Structure):
        _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", ctypes.c_wchar * 296)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    find_first = kernel32.FindFirstStreamW
    find_first.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(FindStreamData), wintypes.DWORD]
    find_first.restype = wintypes.HANDLE
    find_next = kernel32.FindNextStreamW
    find_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(FindStreamData)]
    find_next.restype = wintypes.BOOL
    find_close = kernel32.FindClose
    find_close.argtypes = [wintypes.HANDLE]
    find_close.restype = wintypes.BOOL

    data = FindStreamData()
    handle = find_first(os.fspath(path), 0, ctypes.byref(data), 0)
    if handle == ctypes.c_void_p(-1).value:
        error = ctypes.get_last_error()
        if error in (38, 87):  # No streams, or a file system without stream support.
            return []
        raise OSError(error, ctypes.FormatError(error), os.fspath(path))

    streams = {}
    try:
        while True:
            name = data.cStreamName
            if name and name.casefold() != "::$data":
                if not name.startswith(":") or not name.casefold().endswith(":$data"):
                    raise OSError(f"Could not safely identify a named data stream on {path}")
                streams[name] = int(data.StreamSize)
            if not find_next(handle, ctypes.byref(data)):
                error = ctypes.get_last_error()
                if error == 38:  # ERROR_HANDLE_EOF
                    break
                raise OSError(error, ctypes.FormatError(error), os.fspath(path))
    finally:
        find_close(handle)

    return sorted(streams.items(), key=lambda item: item[0].casefold())


def _named_stream_fingerprints(
    path: str, progress: Optional[_BackupProgress] = None,
    action: str = "checked", display_path: Optional[str] = None,
) -> list[tuple[str, int, str]]:
    """Hash every named stream and fail if its enumerated size changes while read."""
    streams = _named_data_streams(path)
    fingerprints = []
    for stream_name, expected_size in streams:
        stream_path = os.fspath(path) + stream_name
        progress_path = (display_path or path) + stream_name
        digest = _sha256_file(
            stream_path, progress=progress, action=action,
            display_path=progress_path,
        )
        if os.path.getsize(stream_path) != expected_size:
            raise RuntimeError(f"A named data stream changed while it was being checked: {path}")
        fingerprints.append((stream_name, expected_size, digest))
    if _named_data_streams(path) != streams:
        raise RuntimeError(f"Named data streams changed while they were being checked: {path}")
    return fingerprints


def _copy_named_data_streams(
    source: str, destination: str, progress: Optional[_BackupProgress] = None,
    action: str = "copied", display_path: Optional[str] = None,
) -> None:
    """Copy a file's named streams explicitly across Python versions."""
    streams = _named_data_streams(source)
    for stream_name, expected_size in streams:
        source_stream_path = os.fspath(source) + stream_name
        destination_stream_path = os.fspath(destination) + stream_name
        with open(source_stream_path, "rb") as source_stream:
            with open(destination_stream_path, "wb") as destination_stream:
                _copy_stream_with_progress(
                    source_stream, destination_stream,
                    (display_path or destination) + stream_name,
                    os.path.getsize(source_stream_path), progress, action,
                )
        if os.path.getsize(destination_stream_path) != expected_size:
            raise RuntimeError(f"A named data stream was not fully copied: {source}")
    if _named_data_streams(source) != streams:
        raise RuntimeError(f"Named data streams changed while they were being copied: {source}")


def _file_integrity_sha256(
    path: str, progress: Optional[_BackupProgress] = None,
    action: str = "checked", display_path: Optional[str] = None,
) -> str:
    """Hash the default file data and all named streams when the file system supports them."""
    default_hash = _sha256_file(
        path, progress=progress, action=action, display_path=display_path
    )
    streams = _named_stream_fingerprints(
        path, progress=progress, action=action, display_path=display_path
    )
    if not streams:
        # Keep the existing digest for ordinary files and older manifests.
        return default_hash
    snapshot = {
        "default": [os.path.getsize(path), default_hash],
        "streams": [[name, size, digest] for name, size, digest in streams],
    }
    canonical = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _path_size_and_named_streams(
    path: str, include_named_streams: bool = True,
    progress: Optional[_BackupProgress] = None,
) -> tuple[int, bool]:
    """Measure file data and detect named streams without following links."""
    if _is_reparse_point(path):
        raise RuntimeError(f"Refusing to size a path containing a link: {path}")
    streams = _named_data_streams(path) if include_named_streams else []
    total = sum(size for _name, size in streams)
    if os.path.isfile(path):
        total += os.path.getsize(path)
        if progress is not None:
            progress.item(path, total)
        return total, bool(streams)
    if progress is not None:
        progress.item(path)
    streams_found = bool(streams)
    with os.scandir(path) as entries:
        for entry in entries:
            if _is_reparse_point(entry.path):
                raise RuntimeError(f"Refusing to back up a path containing a link: {entry.path}")
            if entry.is_file(follow_symlinks=False) or entry.is_dir(follow_symlinks=False):
                child_size, child_has_streams = _path_size_and_named_streams(
                    entry.path, include_named_streams, progress
                )
                total += child_size
                streams_found = streams_found or child_has_streams
    return total, streams_found


def get_dir_size(
    path: str, include_named_streams: bool = True,
    progress: Optional[_BackupProgress] = None,
) -> int:
    """Get the complete size without following links or hiding read errors."""
    return _path_size_and_named_streams(path, include_named_streams, progress)[0]


def _sha256_file(
    path: str, progress: Optional[_BackupProgress] = None,
    action: str = "checked", display_path: Optional[str] = None,
) -> str:
    """Hash a file in bounded memory for content-level backup verification."""
    digest = hashlib.sha256()
    total = os.path.getsize(path) if progress is not None else 0
    processed = 0
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            processed += len(chunk)
            if progress is not None:
                progress.file_bytes(display_path or path, processed, total, action=action)
    return digest.hexdigest()


def _copy_stream_with_progress(
    source, destination, display_path: str, total: int,
    progress: Optional[_BackupProgress] = None,
    action: str = "copied", chunk_size: int = 1024 * 1024,
) -> int:
    """Copy a stream in bounded chunks and report per-file byte progress."""
    copied = 0
    while True:
        chunk = source.read(chunk_size)
        if not chunk:
            break
        destination.write(chunk)
        copied += len(chunk)
        if progress is not None:
            progress.file_bytes(display_path, copied, total, action=action)
    return copied


def _copy_file_with_progress(
    source_path: str, destination_path: str,
    progress: Optional[_BackupProgress] = None,
    action: str = "copied", exclusive: bool = True,
    display_path: Optional[str] = None,
) -> str:
    """Copy a file in bounded chunks while preserving copy2 metadata."""
    total = os.path.getsize(source_path)
    destination_mode = "xb" if exclusive else "wb"
    with open(source_path, "rb") as source, open(destination_path, destination_mode) as destination:
        _copy_stream_with_progress(
            source, destination, display_path or source_path, total, progress, action,
            chunk_size=BACKUP_COPY_CHUNK_BYTES,
        )
    shutil.copystat(source_path, destination_path)
    return destination_path


def _run_robocopy_with_progress(
    command: list[str], timeout: int = ROBOCOPY_TIMEOUT_SECONDS,
    progress: Optional[_BackupProgress] = None,
) -> int:
    """Run quiet Robocopy with an English heartbeat and bounded runtime."""
    process = subprocess.Popen(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    started = time.monotonic()
    while True:
        elapsed = time.monotonic() - started
        remaining = timeout - elapsed
        if remaining <= 0:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
            raise subprocess.TimeoutExpired(command, timeout)
        try:
            return process.wait(timeout=min(ROBOCOPY_PROGRESS_INTERVAL_SECONDS, remaining))
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - started
            if progress is not None:
                progress.heartbeat(elapsed)


def _write_file_atomically(destination: str, write_staged: Callable[[str], None], overwrite: bool,
                           expected_sha256: Optional[str] = None,
                           expected_size: Optional[int] = None,
                           timestamp: Optional[float] = None,
                           verify_named_streams: bool = True,
                           progress: Optional[_BackupProgress] = None,
                           display_path: Optional[str] = None) -> bool:
    """Write and verify a same-directory staging file before publishing it."""
    if _path_has_reparse_component(destination):
        raise RuntimeError("Refusing to restore through a reparse point or symbolic link")

    destination_dir = os.path.dirname(destination)
    os.makedirs(destination_dir, exist_ok=True)
    if _path_has_reparse_component(destination):
        raise RuntimeError("Restore destination changed to a reparse point or symbolic link")

    descriptor, staged_path = tempfile.mkstemp(
        prefix=".drive-cleanr-restore-", suffix=".tmp", dir=destination_dir
    )
    os.close(descriptor)
    try:
        write_staged(staged_path)
        if expected_sha256:
            actual_digest = (
                _file_integrity_sha256(
                    staged_path, progress=progress, action="verified",
                    display_path=display_path,
                ) if verify_named_streams else
                _sha256_file(
                    staged_path, progress=progress, action="verified",
                    display_path=display_path,
                )
            )
            if actual_digest.lower() != expected_sha256.lower():
                raise RuntimeError("Staged restore file failed its SHA-256 integrity check")
        elif (not isinstance(expected_size, int) or
              os.path.getsize(staged_path) != expected_size):
            raise RuntimeError("Staged restore file failed its size check")

        if timestamp is not None:
            os.utime(staged_path, (timestamp, timestamp))
        if _path_has_reparse_component(destination):
            raise RuntimeError("Restore destination changed to a reparse point or symbolic link")
        if overwrite:
            os.replace(staged_path, destination)
        else:
            # On Windows, rename fails atomically if a destination appeared
            # after the earlier conflict check, preserving that user's file.
            try:
                os.rename(staged_path, destination)
            except FileExistsError:
                return False
        return True
    finally:
        try:
            os.unlink(staged_path)
        except FileNotFoundError:
            pass


def _restore_file_atomically(backup_path: str, destination: str, overwrite: bool,
                             expected_sha256: Optional[str], expected_size: Optional[int],
                             verify_named_streams: bool = True,
                             progress: Optional[_BackupProgress] = None) -> bool:
    """Stage and verify a backup file before making it visible at its destination."""
    def copy_backup(staged_path):
        _copy_file_with_progress(
            backup_path, staged_path, progress=progress,
            action="copied", exclusive=False, display_path=destination,
        )
        if verify_named_streams:
            _copy_named_data_streams(
                backup_path, staged_path, progress=progress, action="copied",
                display_path=destination,
            )

    return _write_file_atomically(
        destination, copy_backup, overwrite, expected_sha256, expected_size,
        verify_named_streams=verify_named_streams, progress=progress,
        display_path=destination,
    )


def _directory_fingerprint(
    path: str, include_named_streams: bool = True,
    progress: Optional[_BackupProgress] = None,
) -> Dict[str, tuple]:
    """Map directory entries and optional named streams to hashes without following links."""
    root = os.path.abspath(path)

    def raise_walk_error(error):
        raise error

    entries = {}
    if progress is not None:
        progress.item(root)
    if include_named_streams:
        for stream_name, stream_size, stream_hash in _named_stream_fingerprints(root, progress):
            entries[f".\0{stream_name}"] = ("stream", stream_size, stream_hash)
    for current, directories, files in os.walk(root, topdown=True, onerror=raise_walk_error, followlinks=False):
        directories.sort()
        files.sort()
        for name in directories:
            item_path = os.path.join(current, name)
            if _is_reparse_point(item_path):
                raise RuntimeError(f"Refusing to verify a reparse point: {item_path}")
            relative = os.path.normcase(os.path.relpath(item_path, root))
            entries[relative] = ("directory",)
            if progress is not None:
                progress.item(item_path)
            if include_named_streams:
                for stream_name, stream_size, stream_hash in _named_stream_fingerprints(item_path, progress):
                    entries[f"{relative}\0{stream_name}"] = ("stream", stream_size, stream_hash)
        for name in files:
            item_path = os.path.join(current, name)
            if _is_reparse_point(item_path):
                raise RuntimeError(f"Refusing to verify a reparse point: {item_path}")
            relative = os.path.normcase(os.path.relpath(item_path, root))
            size = os.path.getsize(item_path)
            entries[relative] = ("file", size, _sha256_file(item_path, progress=progress))
            if progress is not None:
                progress.item(item_path, size)
            if include_named_streams:
                for stream_name, stream_size, stream_hash in _named_stream_fingerprints(item_path, progress):
                    entries[f"{relative}\0{stream_name}"] = ("stream", stream_size, stream_hash)
    return entries


def _directory_fingerprint_sha256(
    path: str, include_named_streams: bool = True,
    progress: Optional[_BackupProgress] = None,
) -> str:
    """Hash a directory's names, types, sizes, and file contents deterministically."""
    return _fingerprint_entries_sha256(
        _directory_fingerprint(path, include_named_streams, progress)
    )


def _fingerprint_entries_sha256(entries: Dict[str, tuple]) -> str:
    """Hash a previously collected directory fingerprint."""
    canonical = json.dumps(
        [(name, *entries[name]) for name in sorted(entries)],
        ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _create_zip_backup(
    source_path: str, archive_path: str,
    progress: Optional[_BackupProgress] = None,
) -> Dict[str, tuple]:
    """Write a ZIP64 archive and fingerprint the exact content it contains."""
    source_path = os.path.abspath(source_path)
    archived_entries = {}
    if progress is not None:
        progress.item(source_path)

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
                if progress is not None:
                    progress.item(current)
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
                        if progress is not None:
                            progress.file_bytes(
                                file_path, written, info.file_size, action="added to archive"
                            )
                archived_entries[os.path.normcase(relative_file.replace("/", os.sep))] = (
                    "file", written, digest.hexdigest()
                )
                if progress is not None:
                    progress.item(file_path, written)
    return archived_entries


def _verify_zip_contents(
    archive: zipfile.ZipFile, progress: Optional[_BackupProgress] = None,
) -> int:
    """Read every ZIP member to EOF, checking CRCs while reporting progress."""
    total_bytes = 0
    for info in archive.infolist():
        if info.is_dir():
            if progress is not None:
                progress.item(info.filename)
            continue
        member_bytes = 0
        with archive.open(info, "r") as member:
            while True:
                chunk = member.read(1024 * 1024)
                if not chunk:
                    break
                member_bytes += len(chunk)
                if progress is not None:
                    progress.file_bytes(
                        info.filename, member_bytes, info.file_size, action="verified"
                    )
        if member_bytes != info.file_size:
            raise zipfile.BadZipFile(f"Incomplete ZIP member: {info.filename}")
        total_bytes += member_bytes
        if progress is not None:
            progress.item(info.filename, member_bytes)
    return total_bytes


def _verify_zip_archive(archive_path: str, progress: Optional[_BackupProgress] = None) -> int:
    """Check every ZIP member's CRC and byte count, with optional progress."""
    with zipfile.ZipFile(archive_path) as archive:
        return _verify_zip_contents(archive, progress=progress)


def _extract_zip_backup(
    archive_path: str, destination: str, overwrite: bool = False,
    progress: Optional[_BackupProgress] = None,
) -> list[str]:
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
                    not safe_parts or
                    any(_contains_hidden_formatting(part) for part in safe_parts) or
                    any(any(character in WINDOWS_INVALID_NAME_CHARS for character in part)
                        for part in safe_parts) or
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
            try:
                timestamp = datetime(*info.date_time).timestamp()
            except (OverflowError, OSError, ValueError) as exc:
                raise RuntimeError(
                    f"Refusing an invalid timestamp inside backup archive: {info.filename}"
                ) from exc
            planned_entries.append((info, target, timestamp))

        # Validate every member before writing any of them, avoiding partial
        # restoration when a later entry is unsafe or has damaged contents.
        print("        [Checking archive contents before restore]")
        try:
            _verify_zip_contents(archive, progress=progress)
        except zipfile.BadZipFile as exc:
            raise RuntimeError(f"Refusing a damaged backup archive member: {exc}") from exc

        for info, target, timestamp in planned_entries:
            if (_path_has_reparse_component(destination) or
                    _path_has_reparse_component(target)):
                raise RuntimeError("Restore destination changed to a reparse point or symbolic link")
            if info.is_dir():
                existed = os.path.lexists(target)
                os.makedirs(target, exist_ok=True)
                if (_path_has_reparse_component(destination) or
                        _path_has_reparse_component(target)):
                    raise RuntimeError("Restore destination changed to a reparse point or symbolic link")
                if existed and not overwrite:
                    continue
            else:
                if os.path.lexists(target) and not overwrite:
                    continue
                def write_member(staged_path):
                    with archive.open(info, "r") as source, open(staged_path, "wb") as output:
                        _copy_stream_with_progress(
                            source, output, info.filename, info.file_size,
                            progress=progress, action="copied",
                        )

                restored = _write_file_atomically(
                    target,
                    write_member,
                    overwrite,
                    expected_size=info.file_size,
                    timestamp=timestamp,
                    progress=progress,
                )
                if not restored:
                    conflicts.append(target)
                    continue
            archived_attributes.append((target, info.external_attr & 0xFF))

    if os.name == "nt":
        import ctypes
        for target, attributes in archived_attributes:
            if attributes:
                if _path_has_reparse_component(target):
                    raise RuntimeError("Restore destination changed to a reparse point or symbolic link")
                if not ctypes.windll.kernel32.SetFileAttributesW(target, attributes):
                    raise OSError(f"Could not restore Windows file attributes: {target}")
    return conflicts


def find_backup_drive(exclude_drives=None, required_space_bytes=0) -> Optional[str]:
    """Choose the eligible local drive with the most free space.

    The Windows volume and all selected source volumes are excluded so a
    recovery copy cannot consume space on the system or cleanup drive.
    """
    system_drive = _windows_system_drive_letter()
    if not system_drive:
        return None

    best_drive = None
    max_free = 0
    min_required = max(5 * 1024 * 1024 * 1024, required_space_bytes + 100 * 1024 * 1024)
    excluded = {str(letter).upper().rstrip(":\\/") for letter in (exclude_drives or set())}
    excluded.add(system_drive)

    # Skip A: and B: legacy floppy letters; inspect all other possible volumes.
    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        if letter in excluded:
            continue
        drive = f"{letter}:\\"
        if not os.path.exists(drive):
            continue
        if _get_backup_drive_type(drive) not in {2, 3}:  # Removable or fixed local volume.
            continue
        try:
            free = _get_drive_free_space(drive)
        except (OSError, AttributeError, TypeError, ValueError):
            continue

        if free > max_free and free >= min_required:
            max_free = free
            best_drive = letter

    if best_drive:
        backup_root = f"{best_drive}:\\{BACKUP_DIR_NAME}"
        return backup_root

    return None


def _windows_system_drive_letter() -> Optional[str]:
    """Return the drive containing the active Windows directory, if known."""
    windows_directory = None
    if os.name == "nt":
        try:
            import ctypes
            buffer = ctypes.create_unicode_buffer(32768)
            length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
            if 0 < length < len(buffer):
                windows_directory = buffer.value
        except (AttributeError, OSError, TypeError, ValueError):
            pass
    if not windows_directory:
        windows_directory = (
            os.environ.get("SystemRoot") or os.environ.get("WINDIR") or
            os.environ.get("SystemDrive")
        )
    drive, _tail = ntpath.splitdrive(windows_directory or "")
    letter = drive.rstrip(":\\/").upper()
    return letter if len(letter) == 1 and letter.isalpha() else None


def _get_backup_drive_type(drive_root: str) -> Optional[int]:
    """Return GetDriveTypeW for a volume; unknown drives are not backup targets."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        return int(ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive_root)))
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def get_backup_root(exclude_drives=None, required_space_bytes=0) -> str:
    """Get the backup root directory and create it if needed"""
    backup_root = find_backup_drive(exclude_drives, required_space_bytes)
    if not backup_root:
        raise RuntimeError(
            "No suitable backup drive found (requires at least 5 GB free on a non-system "
            "local drive outside the selected item drives)"
        )
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
    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
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


def create_backup(
    paths: List[str], priority: str = "high", progress_stream=None,
) -> Dict:
    """
    Create a backup

    Args:
        paths: list of absolute local files or directories to back up
        priority: priority label (high/medium/low/all/manual)

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
    for index, path in enumerate(normalized_paths):
        if any(_paths_overlap(path, earlier) for earlier in normalized_paths[:index]):
            raise ValueError("Backup paths must not duplicate or overlap")
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
        "version": 2,
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
            print(f"[Skip] Path does not exist: {_safe_terminal_text(path, 'path')}")
            manifest["errors"].append(f"Path does not exist: {path}")
            continue

        if _path_has_reparse_component(path):
            manifest["errors"].append(f"Refusing to back up a reparse point: {path}")
            continue

        try:
            size_progress = _BackupProgress("Checking backup contents", stream=progress_stream)
            dir_size, has_named_streams = _path_size_and_named_streams(
                path, progress=size_progress
            )
            size_progress.finish()
        except (PermissionError, OSError, RuntimeError) as exc:
            manifest["errors"].append(f"Could not fully read {path}: {describe_error(exc)}")
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
        source_fingerprint = None
        if not is_file and dir_size >= SIZE_THRESHOLD and not has_named_streams:
            try:
                source_progress = _BackupProgress(
                    "Checking source contents before backup", stream=progress_stream
                )
                source_fingerprint = _directory_fingerprint(path, progress=source_progress)
                source_progress.finish()
            except Exception as e:
                manifest["errors"].append(
                    f"Could not inspect directory before backup for {path}: {describe_error(e)}"
                )
                continue
            has_named_streams = any(
                isinstance(entry, tuple) and entry and entry[0] == "stream"
                for entry in source_fingerprint.values()
            )

        # Choose a backup format based on the target type and size.
        if is_file:
            backup_format = "file"
            backup_path = os.path.join(backup_dir, safe_name)
            try:
                copy_progress = _BackupProgress("Copying backup file", stream=progress_stream)
                _copy_file_with_progress(path, backup_path, progress=copy_progress)
                # Python 3.10's shutil.copy2 uses a buffered copy on Windows
                # that omits NTFS alternate data streams. Copy them explicitly
                # so the backup guarantees do not depend on the Python version.
                _copy_named_data_streams(path, backup_path, progress=copy_progress)
                copy_progress.finish()
            except Exception as e:
                print(f"        [Failed] {describe_error(e)}")
                manifest["errors"].append(f"File backup failed for {path}: {describe_error(e)}")
                continue
        elif dir_size < SIZE_THRESHOLD or has_named_streams:
            # Copy directories smaller than 1 GB.
            backup_format = "copy"
            backup_path = os.path.join(backup_dir, safe_name)
            display_path = _safe_terminal_text(path, "path")
            print(f"[Backup] {format_size(dir_size):>10} {display_path}")
            print(f"        → Copy directly to {_safe_terminal_text(backup_path, 'backup path')}")
            if has_named_streams and dir_size >= SIZE_THRESHOLD:
                print("        This folder contains extra Windows file data; the direct copy preserves and verifies it.")

            try:
                # Copy with robocopy (preserves attributes and supports long paths)
                copy_progress = _BackupProgress("Copying backup folder", stream=progress_stream)
                return_code = _run_robocopy_with_progress(
                    [
                        "robocopy", path, backup_path,
                        "/E",  # Copy all subdirectories.
                        "/COPY:DAT",  # Copy data, attributes, and timestamps.
                        "/DCOPY:DAT",  # Include data streams and timestamps on directories.
                        "/XJ",  # Never follow junctions
                        "/R:1",  # Retry once.
                        "/W:1",  # Wait one second between retries.
                        "/NFL", "/NDL", "/NJH", "/NJS",  # Reduce console output.
                    ], progress=copy_progress,
                )
                # Robocopy codes 0-7 indicate success or copied extras.
                if return_code >= 8:
                    raise RuntimeError(f"Robocopy failed with exit code {return_code}")
                copy_progress.finish()
                print(f"        [Done]")
            except Exception as e:
                print(f"        [Failed] {describe_error(e)}")
                manifest["errors"].append(f"Directory copy backup failed for {path}: {describe_error(e)}")
                continue
        else:
            # Compress directories of 1 GB or larger.
            backup_format = "zip"
            backup_path = os.path.join(backup_dir, f"{safe_name}.zip")
            display_path = _safe_terminal_text(path, "path")
            print(f"[Backup] {format_size(dir_size):>10} {display_path}")
            print(f"        → Compress to {_safe_terminal_text(backup_path, 'backup path')}")

            try:
                archive_progress = _BackupProgress(
                    "Compressing backup folder", stream=progress_stream
                )
                archived_fingerprint = _create_zip_backup(
                    path, backup_path, progress=archive_progress
                )
                archive_progress.finish()
                if archived_fingerprint != source_fingerprint:
                    manifest["errors"].append(f"Source changed while its backup archive was being created: {path}")
                    continue
                print(f"        [Done]")
            except Exception as e:
                print(f"        [Failed] {describe_error(e)}")
                manifest["errors"].append(f"Directory archive backup failed for {path}: {describe_error(e)}")
                continue

        if backup_format == "copy":
            try:
                verify_progress = _BackupProgress(
                    "Verifying backup contents", stream=progress_stream
                )
                backup_size = get_dir_size(backup_path, progress=verify_progress)
                source_entries = _directory_fingerprint(path, progress=verify_progress)
                backup_entries = _directory_fingerprint(backup_path, progress=verify_progress)
                if (not os.path.isdir(backup_path) or backup_size != dir_size or
                        source_entries != backup_entries):
                    manifest["errors"].append(f"Backup output is missing, incomplete, or has different file contents for {path}")
                    continue
                source_integrity_sha256 = _fingerprint_entries_sha256(source_entries)
                verify_progress.finish()
            except (OSError, RuntimeError) as exc:
                manifest["errors"].append(f"Could not verify backup output for {path}: {describe_error(exc)}")
                continue
        if backup_format == "file":
            try:
                verify_progress = _BackupProgress(
                    "Verifying backup contents", stream=progress_stream
                )
                source_integrity_sha256 = _file_integrity_sha256(path, progress=verify_progress)
                backup_size = get_dir_size(backup_path, progress=verify_progress)
                backup_integrity_sha256 = _file_integrity_sha256(backup_path, progress=verify_progress)
                if (not os.path.isfile(backup_path) or backup_size != dir_size or
                        source_integrity_sha256 != backup_integrity_sha256):
                    manifest["errors"].append(f"Backup output is incomplete or has different file contents for {path}")
                    continue
                verify_progress.finish()
            except (OSError, RuntimeError) as exc:
                manifest["errors"].append(f"Could not verify backup output for {path}: {describe_error(exc)}")
                continue
        if backup_format == "zip":
            try:
                source_integrity_sha256 = _fingerprint_entries_sha256(source_fingerprint)
                verify_progress = _BackupProgress(
                    "Verifying compressed backup", stream=progress_stream
                )
                archive_size = _verify_zip_archive(backup_path, progress=verify_progress)
                if archive_size != dir_size:
                    manifest["errors"].append(f"Backup archive is damaged or incomplete for {path}")
                    continue
                verify_progress.finish()
            except (OSError, zipfile.BadZipFile) as exc:
                manifest["errors"].append(f"Could not verify backup archive for {path}: {describe_error(exc)}")
                continue

        try:
            integrity_progress = _BackupProgress(
                "Recording backup integrity", stream=progress_stream
            )
            if backup_format == "file":
                integrity_sha256 = _file_integrity_sha256(backup_path, progress=integrity_progress)
            elif backup_format == "copy":
                integrity_sha256 = _directory_fingerprint_sha256(
                    backup_path, progress=integrity_progress
                )
            else:
                integrity_sha256 = _file_integrity_sha256(backup_path, progress=integrity_progress)
            integrity_progress.finish()
        except (OSError, RuntimeError) as exc:
            manifest["errors"].append(f"Could not fingerprint backup output for {path}: {describe_error(exc)}")
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
    if manifest["status"] == "completed":
        print(f"Backup complete! {len(manifest['items'])} items backed up, total {manifest['total_size_formatted']}")
    else:
        print(
            f"Backup incomplete: {len(manifest['items'])}/{len(paths)} items backed up, "
            f"total {manifest['total_size_formatted']}. Review the reported issues before cleanup."
        )
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
        if _path_has_reparse_component(backup_root):
            continue
        try:
            entries = os.listdir(backup_root)
        except OSError:
            continue

        for item in entries:
            if not _valid_backup_id(item):
                continue
            backup_dir = os.path.join(backup_root, item)
            manifest_path = os.path.join(backup_dir, "manifest.json")
            if (_path_has_reparse_component(backup_dir) or
                    not os.path.isdir(backup_dir) or
                    _path_has_reparse_component(manifest_path) or
                    not os.path.isfile(manifest_path)):
                continue

            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest = json.load(f)
            except (OSError, ValueError):
                continue
            if (not isinstance(manifest, dict) or _manifest_version(manifest) is None or
                    manifest.get("id") != item or
                    not isinstance(manifest.get("timestamp"), str) or
                    not isinstance(manifest.get("items"), list)):
                continue
            backups.append(manifest)

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

    if (_path_has_reparse_component(manifest_path) or
            not os.path.isfile(manifest_path)):
        return None
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError):
        return None

    if (not isinstance(manifest, dict) or _manifest_version(manifest) is None or
            manifest.get("id") != backup_id or
            not isinstance(manifest.get("timestamp"), str) or
            not isinstance(manifest.get("items"), list)):
        return None
    return manifest


def _manifest_version(manifest: Dict) -> Optional[int]:
    version = manifest.get("version", 1)
    return version if type(version) is int and version in (1, 2) else None


def _manifest_uses_named_stream_integrity(manifest: Dict) -> bool:
    return _manifest_version(manifest) == 2


def _valid_manifest_size(size) -> bool:
    """Require an exact, nonnegative byte count in untrusted manifests."""
    return type(size) is int and size >= 0


def _valid_sha256_digest(value) -> bool:
    """Recognize a complete SHA-256 digest from an untrusted manifest."""
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None


def _restore_manifest_item_is_complete(item, manifest_version: int) -> bool:
    """Validate restorable entry fields; allow size-checked legacy v1 items."""
    if (not isinstance(item, dict) or
            not _valid_restore_target(item.get("original_path")) or
            not isinstance(item.get("backup_path"), str) or not item["backup_path"] or
            not isinstance(item.get("format"), str) or
            item.get("format") not in {"file", "copy", "zip"} or
            not _valid_manifest_size(item.get("size"))):
        return False
    digest = item.get("integrity_sha256")
    if digest is None:
        return manifest_version == 1
    return _valid_sha256_digest(digest)


def verify_backup(backup_id: str, paths: Optional[List[str]] = None) -> bool:
    """Verify saved payloads and ensure current sources still match them."""
    manifest = get_backup(backup_id)
    if (not isinstance(manifest, dict) or manifest.get("status") != "completed" or
            not isinstance(manifest.get("items"), list) or not manifest["items"]):
        print("Refusing to verify an incomplete or empty backup")
        return False
    verify_named_streams = _manifest_uses_named_stream_integrity(manifest)
    if not verify_named_streams:
        print("Warning: this older backup does not verify named NTFS data streams.")

    backup_dir = _find_backup_dir(backup_id)
    if not backup_dir or _path_has_reparse_component(backup_dir):
        print("Refusing to verify through an unavailable or linked backup location")
        return False

    requested = None
    if paths is not None:
        if not isinstance(paths, list) or not paths:
            print("At least one source path is required")
            return False
        requested = set()
        for path in paths:
            if not _valid_restore_target(path):
                print(f"Refusing to verify an unsafe source path: {_safe_terminal_text(path, 'path')}")
                return False
            requested.add(_windows_path_key(path))

    items_by_path = {}
    seen_source_paths = []
    for item in manifest["items"]:
        if (not isinstance(item, dict) or
                not _valid_restore_target(item.get("original_path")) or
                not _valid_manifest_size(item.get("size"))):
            print("Refusing to verify a malformed or unsafe backup manifest")
            return False
        key = _windows_path_key(item["original_path"])
        if any(_paths_overlap(item["original_path"], previous) for previous in seen_source_paths):
            print("Refusing to verify a backup with duplicate or overlapping source paths")
            return False
        seen_source_paths.append(item["original_path"])
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
    progress = _BackupProgress("Verifying recovery backup")
    for item in selected_items:
        original_path = item["original_path"]
        display_path = _safe_terminal_text(original_path, "path")
        backup_path = item.get("backup_path")
        backup_format = item.get("format")
        source_digest = item.get("source_integrity_sha256")
        payload_digest = item.get("integrity_sha256")
        if (not isinstance(backup_format, str) or backup_format not in {"file", "copy", "zip"} or
                not _valid_sha256_digest(source_digest) or
                not _valid_sha256_digest(payload_digest) or
                not isinstance(backup_path, str)):
            print(f"Backup lacks verifiable integrity data for: {display_path}")
            return False

        backup_path = os.path.abspath(backup_path)
        try:
            contained = os.path.normcase(os.path.commonpath([backup_root, backup_path])) == os.path.normcase(backup_root)
        except ValueError:
            contained = False
        if (not contained or _path_has_reparse_component(backup_path) or
                not os.path.exists(backup_path) or _path_has_reparse_component(original_path) or
                not os.path.exists(original_path)):
            print(f"Backup or source path is unavailable or linked: {display_path}")
            return False

        if not verify_named_streams:
            try:
                source_has_streams = _path_size_and_named_streams(
                    original_path, progress=progress
                )[1]
                backup_has_streams = (
                    backup_format != "zip" and
                    _path_size_and_named_streams(backup_path, progress=progress)[1]
                )
            except (OSError, RuntimeError) as exc:
                print(f"Could not inspect named data streams for {display_path}: {describe_error(exc)}")
                return False
            if source_has_streams or backup_has_streams:
                print("This older backup cannot verify the named data streams; refusing verification.")
                return False

        try:
            if backup_format == "file":
                if not os.path.isfile(backup_path) or not os.path.isfile(original_path):
                    print(f"Source item type changed since backup: {display_path}")
                    return False
                if verify_named_streams:
                    current_source_digest = _file_integrity_sha256(original_path, progress=progress)
                    current_payload_digest = _file_integrity_sha256(backup_path, progress=progress)
                else:
                    current_source_digest = _sha256_file(original_path, progress=progress)
                    current_payload_digest = _sha256_file(backup_path, progress=progress)
            elif backup_format == "copy":
                if not os.path.isdir(backup_path) or not os.path.isdir(original_path):
                    print(f"Source item type changed since backup: {display_path}")
                    return False
                if (_tree_has_reparse_point_with_progress(backup_path, "saved backup") or
                        _tree_has_reparse_point_with_progress(original_path, "source folder")):
                    print(f"Source or backup tree contains a reparse point: {display_path}")
                    return False
                current_source_digest = _directory_fingerprint_sha256(
                    original_path, include_named_streams=verify_named_streams, progress=progress
                )
                current_payload_digest = _directory_fingerprint_sha256(
                    backup_path, include_named_streams=verify_named_streams, progress=progress
                )
            else:
                if not os.path.isfile(backup_path) or not os.path.isdir(original_path):
                    print(f"Source item type changed since backup: {display_path}")
                    return False
                if _tree_has_reparse_point_with_progress(original_path, "source folder"):
                    print(f"Source tree contains a reparse point: {display_path}")
                    return False
                current_source_digest = _directory_fingerprint_sha256(
                    original_path, include_named_streams=verify_named_streams, progress=progress
                )
                current_payload_digest = (
                    _file_integrity_sha256(backup_path, progress=progress) if verify_named_streams
                    else _sha256_file(backup_path, progress=progress)
                )
        except (OSError, RuntimeError) as exc:
            print(f"Could not verify source or backup contents for {display_path}: {describe_error(exc)}")
            return False

        if current_payload_digest.lower() != payload_digest.lower():
            print(f"Backup contents changed since verification: {display_path}")
            return False
        if current_source_digest.lower() != source_digest.lower():
            print(f"Source changed since backup; refusing cleanup: {display_path}")
            return False
        progress.item(original_path)

    progress.finish()
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
        print(f"Backup not found: {_safe_terminal_text(backup_id)}")
        return False
    manifest_version = _manifest_version(manifest) if isinstance(manifest, dict) else None
    if (not isinstance(manifest, dict) or manifest_version is None or
            manifest.get("status") != "completed" or
            not isinstance(manifest.get("items"), list) or not manifest["items"]):
        print("Refusing to restore an incomplete or empty backup")
        return False

    backup_dir = _find_backup_dir(backup_id)
    if not backup_dir or _path_has_reparse_component(backup_dir):
        print("Refusing to restore from an unavailable or linked backup location")
        return False
    verify_named_streams = manifest_version == 2
    if not verify_named_streams:
        print("Warning: this older backup predates named-stream verification and may not preserve every NTFS data stream.")

    # Validate the complete untrusted manifest before restoring any item. This
    # avoids arbitrary/network/device destinations and partial restores caused
    # by a malformed later entry.
    backup_storage_roots = _existing_backup_roots()
    validated_items = []
    restore_destinations = []
    for item in manifest["items"]:
        if not _restore_manifest_item_is_complete(item, manifest_version):
            print("Refusing to restore an invalid or unverifiable backup manifest entry")
            return False
        original_path = item.get("original_path")
        backup_path = item.get("backup_path")
        backup_format = item.get("format")
        if _restore_path_overlaps_backup_storage(original_path, backup_storage_roots):
            print("Refusing to restore into or over Drive Cleanr backup storage")
            return False
        if any(_paths_overlap(original_path, previous) for previous in restore_destinations):
            print("Refusing duplicate or overlapping restore destinations in backup manifest")
            return False
        restore_destinations.append(original_path)
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
        if (backup_format in {"copy", "zip"} and
                _tree_has_reparse_point_with_progress(original_path, "restore destination")):
            print("Refusing to restore into a directory tree containing a reparse point")
            return False
        validated_items.append((item, original_path, backup_path, backup_format))

    # Verify every saved payload before writing any restored data. This catches
    # later disk corruption (including same-size changes) without allowing a
    # failed later item to leave an earlier item partially restored.
    progress = _BackupProgress("Checking saved backup")
    for item, original_path, backup_path, backup_format in validated_items:
        expected_digest = item.get("integrity_sha256")
        if expected_digest is not None:
            if not _valid_sha256_digest(expected_digest):
                print("Refusing to restore a backup with an invalid integrity hash")
                return False
            try:
                if backup_format == "copy":
                    actual_digest = _directory_fingerprint_sha256(
                        backup_path, include_named_streams=verify_named_streams,
                        progress=progress,
                    )
                elif backup_format == "file" and verify_named_streams:
                    actual_digest = _file_integrity_sha256(
                        backup_path, progress=progress, display_path=original_path
                    )
                elif backup_format == "zip" and verify_named_streams:
                    actual_digest = _file_integrity_sha256(
                        backup_path, progress=progress, display_path=original_path
                    )
                else:
                    actual_digest = _sha256_file(
                        backup_path, progress=progress, display_path=original_path
                    )
            except (OSError, RuntimeError) as exc:
                print(f"Refusing to restore an unreadable backup payload: {describe_error(exc)}")
                return False
            if actual_digest.lower() != expected_digest.lower():
                print("Refusing to restore: backup contents changed after verification")
                return False
            progress.item(original_path)
        else:
            # Older manifests predate persistent hashes. Preserve their restore
            # support with structural/size checks, and tell users the limit.
            try:
                expected_size = item.get("size")
                if backup_format == "file":
                    legacy_valid = isinstance(expected_size, int) and os.path.getsize(backup_path) == expected_size
                elif backup_format == "copy":
                    legacy_valid = (
                        isinstance(expected_size, int) and
                        get_dir_size(
                            backup_path, include_named_streams=verify_named_streams,
                            progress=progress,
                        ) == expected_size
                    )
                else:
                    archive_size = _verify_zip_archive(backup_path, progress=progress)
                    legacy_valid = archive_size == expected_size
            except (OSError, RuntimeError, zipfile.BadZipFile):
                legacy_valid = False
            if not legacy_valid:
                print("Refusing to restore: legacy backup data is incomplete or damaged")
                return False
            print("Warning: this older backup has no content hash; only size and structure were checked.")
            progress.item(original_path)

    progress.finish()

    print(f"Restoring backup: {backup_id}")
    print(f"Backup time: {_safe_terminal_text(manifest.get('timestamp', 'Unknown'))}")
    print(f"Items: {len(validated_items)}")
    print("-" * 50)

    success_count = 0
    conflict_count = 0
    failure_count = 0
    restore_progress = _BackupProgress("Restoring backup")

    for item, original_path, backup_path, backup_format in validated_items:
        print(f"[Restore] {_safe_terminal_text(original_path, 'path')}")
        item_conflicts = 0

        try:
            if backup_format == "file":
                if os.path.lexists(original_path) and not overwrite:
                    print("        [Skipped; existing file preserved. Use explicit overwrite approval to replace it.]\n")
                    conflict_count += 1
                    item_conflicts += 1
                    continue
                restored = _restore_file_atomically(
                    backup_path,
                    original_path,
                    overwrite,
                    item.get("integrity_sha256"),
                    item.get("size"),
                    verify_named_streams=verify_named_streams,
                    progress=restore_progress,
                )
                if not restored:
                    print("        [Skipped; destination appeared during restore and was preserved.]\n")
                    conflict_count += 1
                    item_conflicts += 1
                    continue
            elif backup_format == "copy":
                if _path_has_reparse_component(original_path) or _path_has_reparse_component(backup_path):
                    raise RuntimeError("Refusing to restore through a reparse point or symbolic link")
                os.makedirs(original_path, exist_ok=True)

                def recheck_copy_restore_paths():
                    if (_path_has_reparse_component(original_path) or
                            _path_has_reparse_component(backup_path) or
                            _tree_has_reparse_point_with_progress(
                                original_path, "restore destination"
                            ) or
                            _tree_has_reparse_point_with_progress(
                                backup_path, "saved backup"
                            ) or
                            _path_has_reparse_component(original_path) or
                            _path_has_reparse_component(backup_path)):
                        raise RuntimeError(
                            "Restore source or destination changed to a reparse point"
                        )

                recheck_copy_restore_paths()
                # Restore by copying the saved directory.
                command = [
                        "robocopy", backup_path, original_path,
                        "/E", "/COPY:DAT", "/DCOPY:DAT", "/R:1", "/W:1",
                        "/XJ",
                        "/NFL", "/NDL", "/NJH", "/NJS",
                    ]
                if not overwrite:
                    # Avoid replacing files users may have recreated since cleanup.
                    command.extend(["/XC", "/XN", "/XO"])
                    inventory_progress = _BackupProgress("Checking files to preserve")
                    for current, _dirs, files in os.walk(backup_path):
                        for name in files:
                            saved_file = os.path.join(current, name)
                            relative = os.path.relpath(saved_file, backup_path)
                            if os.path.lexists(os.path.join(original_path, relative)):
                                conflict_count += 1
                                item_conflicts += 1
                            try:
                                file_size = os.path.getsize(saved_file)
                            except OSError:
                                file_size = 0
                            inventory_progress.item(saved_file, file_size)
                    inventory_progress.finish()
                recheck_copy_restore_paths()
                return_code = _run_robocopy_with_progress(
                    command, timeout=300, progress=restore_progress
                )
                if return_code >= 8:
                    raise RuntimeError(f"Robocopy failed with exit code {return_code}")
            else:
                conflicts = _extract_zip_backup(
                    backup_path, original_path, overwrite=overwrite,
                    progress=restore_progress,
                )
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
            print(f"        [Failed] {describe_error(e)}")
        finally:
            item_size = item.get("size", 0)
            if not isinstance(item_size, int) or isinstance(item_size, bool) or item_size < 0:
                item_size = 0
            restore_progress.item(
                original_path, known_bytes=item_size, action="processed"
            )

    restore_progress.finish()

    print("-" * 50)
    if conflict_count or failure_count:
        print(
            f"Restore incomplete: {success_count}/{len(manifest['items'])} items; "
            f"{failure_count} failed; preserved {conflict_count} existing file(s)"
        )
    else:
        print(f"Restore complete: {success_count}/{len(manifest['items'])} items")

    return success_count == len(manifest["items"]) and conflict_count == 0


def delete_backup(backup_id: str) -> Optional[bool]:
    """
    Delete a specific backup.

    Args:
        backup_id: Backup identifier.

    Returns:
        True when deletion succeeds, False on failure, or None when interrupted.
    """
    if not _valid_backup_id(backup_id):
        print(f"Invalid backup ID: {_safe_terminal_text(backup_id)}")
        return False
    backup_dir = _find_backup_dir(backup_id)

    if not backup_dir:
        print(f"Backup not found: {_safe_terminal_text(backup_id)}")
        return False

    print("Checking saved backup contents for linked files and folders before deletion.", flush=True)
    checked_entries = 0
    last_progress = time.monotonic()

    def report_checked_entry(path: str) -> None:
        nonlocal checked_entries, last_progress
        checked_entries += 1
        now = time.monotonic()
        if (checked_entries == 1 or
                checked_entries % BACKUP_PROGRESS_ENTRY_INTERVAL == 0 or
                now - last_progress >= BACKUP_PROGRESS_TIME_INTERVAL_SECONDS):
            name = _safe_terminal_text(os.path.basename(path.rstrip("\\/")) or "backup item", "item")
            entry_label = "entry" if checked_entries == 1 else "entries"
            print(
                f"Checking backup contents: {checked_entries:,} {entry_label} examined. "
                f"Current item: {name}",
                flush=True,
            )
            last_progress = now

    try:
        if _tree_has_reparse_point(backup_dir, report_checked_entry):
            print("Refusing to delete a backup containing a reparse point or junction")
            return False
    except KeyboardInterrupt:
        print("Backup deletion cancelled while checking its contents; nothing was removed.")
        return None
    except OSError as exc:
        print(f"Could not safely inspect backup before deletion: {describe_error(exc)}")
        return False

    print(f"Backup contents check complete: {checked_entries:,} entries examined.", flush=True)
    print("Deleting the saved backup now. This cannot be undone.", flush=True)

    try:
        _rmtree_with_progress(backup_dir)
        print(f"Deleted backup: {backup_id}")
        return True
    except KeyboardInterrupt:
        print("Backup deletion interrupted; the saved backup may be incomplete.")
        return None
    except Exception as e:
        print(
            "Backup deletion failed; the saved backup may be incomplete: "
            f"{describe_error(e)}"
        )
        return False


def cleanup_all_backups(backups: Optional[List[Dict]] = None) -> int:
    """
    Delete all backups from a previously displayed snapshot, if supplied.

    Returns:
        int: Number of backups deleted.
    """
    if backups is None:
        backups = list_backups()
    deleted = 0

    for backup in backups:
        result = delete_backup(backup["id"])
        if result is None:
            print("Backup cleanup stopped; no additional backups will be deleted.")
            break
        if result:
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

    print("=" * 96)
    print("                         Backup List")
    print("=" * 96)
    print(f"{'ID':<30} {'Time':<20} {'Size':<12} {'Items':<8} {'Status':<14}")
    print("-" * 96)

    for backup in backups:
        backup_id = _safe_terminal_text(backup.get("id", "Unknown"))
        timestamp = _safe_terminal_text(backup.get("timestamp", "Unknown")[:19].replace("T", " "))
        size = _safe_terminal_text(backup.get("total_size_formatted", "Unknown"))
        items = len(backup.get("items", []))
        status_labels = {
            "completed": "Completed",
            "partial": "Partial",
            "in_progress": "In progress",
        }
        raw_status = backup.get("status")
        status = status_labels.get(raw_status, "Unknown") if isinstance(raw_status, str) else "Unknown"
        print(f"{backup_id:<30} {timestamp:<20} {size:<12} {items:<8} {status:<14}")
        backup_root = backup.get("backup_root")
        if isinstance(backup_root, str) and backup_root:
            location = _safe_terminal_text(ntpath.join(backup_root, backup_id))
            print(f"  Saved to: {location}")

    print("=" * 96)


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Disk cleanup backup tool')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Create command.
    create_parser = subparsers.add_parser('create', help='Create a backup')
    create_parser.add_argument('--paths', nargs='+', required=True, help='Absolute local files or directories to back up')
    create_parser.add_argument('--priority', default='high', choices=['high', 'medium', 'low', 'all', 'manual'],
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
    cleanup_parser.add_argument('--all', action='store_true', help='Select every currently saved backup for deletion')
    cleanup_parser.add_argument('--yes', action='store_true', help='Skip the deletion prompt for deliberate unattended use')

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
                    manifest = create_backup(
                        args.paths, args.priority, progress_stream=sys.stderr
                    )
            else:
                manifest = create_backup(args.paths, args.priority)
            print(json.dumps(manifest, ensure_ascii=bool(args.json), indent=2))
            if manifest.get("status") != "completed":
                sys.exit(1)
        except (RuntimeError, ValueError) as e:
            print(f"Error: {describe_error(e)}")
            sys.exit(1)

    elif args.command == 'list':
        backups = list_backups()
        print_backups_table(backups)

    elif args.command == 'restore':
        overwrite = bool(args.yes)
        if not args.yes:
            while True:
                try:
                    answer = input(
                        "If a file already exists: O = replace it; M = restore only missing files; Q = cancel. "
                        "Press Enter to choose M: "
                    ).strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print("Restore cancelled")
                    return
                if answer in {"o", "overwrite"}:
                    overwrite = True
                    break
                if answer in {"", "m", "merge"}:
                    overwrite = False
                    break
                if answer in {"q", "quit", "cancel"}:
                    print("Restore cancelled")
                    return
                print(
                    "Enter O to replace existing files, M or Enter to restore only missing files "
                    "and keep existing ones, or Q to cancel."
                )
        success = restore_backup(args.id, overwrite=overwrite)
        sys.exit(0 if success else 1)

    elif args.command == 'delete':
        if not args.yes:
            try:
                answer = input(
                    "Permanently delete this saved backup? This cannot be undone. "
                    "[y/N] (Y = delete; Enter or N = keep it): "
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("Backup deletion cancelled")
                return
            if answer not in {"y", "yes"}:
                print("Backup deletion cancelled")
                return
        success = delete_backup(args.id)
        sys.exit(0 if success else 1)

    elif args.command == 'cleanup':
        if not args.all:
            print("Please specify --all to confirm deleting all backups")
            return
        backups = list_backups()
        if not backups:
            print("No saved backups were found.")
            return
        print_backups_table(backups)
        if not args.yes:
            try:
                answer = input(
                    f"Permanently delete all {len(backups)} listed backups? Type DELETE to continue: "
                ).strip()
            except (EOFError, KeyboardInterrupt):
                print("Backup cleanup cancelled")
                return
            if answer != "DELETE":
                print("Backup cleanup cancelled")
                return
        deleted = cleanup_all_backups(backups)
        print(f"Deleted {deleted} of {len(backups)} listed backups.")

    elif args.command == 'info':
        manifest = get_backup(args.id)
        if manifest:
            print(json.dumps(manifest, ensure_ascii=True, indent=2))
        else:
            print(f"Backup not found: {_safe_terminal_text(args.id)}")
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
            print("No suitable non-system local backup drive found (requires at least 5 GB free)")
            sys.exit(1)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
