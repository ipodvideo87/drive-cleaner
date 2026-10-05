#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run a supported disk-usage scanner and wait for its export to finish."""

import os
import sys
import time
import shutil
import subprocess
import ctypes
import re
import csv
import stat
from datetime import datetime
from pathlib import Path

from error_messages import describe_error, safe_terminal_text

# Configuration: resolve relative to this script's directory instead of hardcoding an absolute path
SKILL_DIR = Path(__file__).resolve().parent
DATA_DIR = str(SKILL_DIR / "data")
_DRIVECLEANR_SCAN_NAME = re.compile(
    r"^scan_(?:wiztree_(?:fast|standard)|windirstat)_\d{20}(?:_\d+)?$",
    re.IGNORECASE,
)
_LEGACY_SCAN_NAME = re.compile(r"^_\d{20}(?:_\d+)?$", re.IGNORECASE)
_LEGACY_SCAN_FOLDERS = (
    ("scan",),
    ("scan", "_wiztree", "_fast"),
    ("scan", "_wiztree", "_standard"),
    ("scan", "_windirstat"),
)


def find_wiztree():
    """Probe for WizTree64.exe in priority order: env var → skill dir → common install paths → PATH"""
    candidates = [
        os.environ.get("WIZTREE_PATH", ""),
        str(SKILL_DIR / "WizTree" / "WizTree64.exe"),
        str(SKILL_DIR.parent / "WizTree" / "WizTree64.exe"),
        r"C:\Program Files\WizTree\WizTree64.exe",
        r"C:\Program Files (x86)\WizTree\WizTree64.exe",
    ]
    for c in candidates:
        normalized = normalize_scanner_executable_path(c, app="wiztree") if c else None
        if normalized:
            return normalized
    path_candidate = shutil.which("WizTree64.exe") or shutil.which("WizTree64")
    return normalize_scanner_executable_path(path_candidate, app="wiztree") if path_candidate else None


def find_windirstat():
    """Find WinDirStat 2.6+. Set WINDIRSTAT_PATH for portable/custom installs."""
    candidates = [
        os.environ.get("WINDIRSTAT_PATH", ""),
        str(SKILL_DIR / "WinDirStat" / "WinDirStat.exe"),
        str(SKILL_DIR.parent / "WinDirStat" / "WinDirStat.exe"),
        r"C:\Program Files\WinDirStat\WinDirStat.exe",
        r"C:\Program Files (x86)\WinDirStat\WinDirStat.exe",
    ]
    for candidate in candidates:
        normalized = normalize_scanner_executable_path(candidate, app="windirstat") if candidate else None
        if normalized:
            return normalized
    path_candidate = shutil.which("WinDirStat.exe") or shutil.which("WinDirStat")
    return normalize_scanner_executable_path(path_candidate, app="windirstat") if path_candidate else None


def normalize_scanner_executable_path(path, app=None):
    """Return a normalized absolute path to an existing scanner executable."""
    try:
        value = os.fspath(path).strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        value = os.path.expandvars(os.path.expanduser(value))
        if (not value or not os.path.isabs(value)
                or Path(value).suffix.casefold() != ".exe"
                or not os.path.isfile(value)):
            return None
        normalized = os.path.normpath(value)
        if (isinstance(app, str) and app.casefold() == "wiztree"
                and Path(normalized).name.casefold() == "wiztree.exe"):
            worker = Path(normalized).with_name("WizTree64.exe")
            if worker.is_file():
                return os.path.normpath(str(worker))
        return normalized
    except (OSError, TypeError, ValueError):
        return None


def _get_windows_file_version(path):
    """Read a Windows executable's fixed product version, or return None."""
    if os.name != "nt":
        return None

    class FixedFileInfo(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint32) for name in (
            "dwSignature", "dwStrucVersion", "dwFileVersionMS", "dwFileVersionLS",
            "dwProductVersionMS", "dwProductVersionLS", "dwFileFlagsMask", "dwFileFlags",
            "dwFileOS", "dwFileType", "dwFileSubtype", "dwFileDateMS", "dwFileDateLS",
        )]

    try:
        version_api = ctypes.WinDLL("version", use_last_error=True)
        get_size = version_api.GetFileVersionInfoSizeW
        get_size.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
        get_size.restype = ctypes.c_uint32
        get_info = version_api.GetFileVersionInfoW
        get_info.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        get_info.restype = ctypes.c_int
        query = version_api.VerQueryValueW
        query.argtypes = [
            ctypes.c_void_p, ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32),
        ]
        query.restype = ctypes.c_int

        ignored_handle = ctypes.c_uint32()
        size = get_size(os.fspath(path), ctypes.byref(ignored_handle))
        if not size:
            return None
        version_data = ctypes.create_string_buffer(size)
        if not get_info(os.fspath(path), 0, size, ctypes.byref(version_data)):
            return None

        info_pointer = ctypes.c_void_p()
        info_size = ctypes.c_uint32()
        if not query(ctypes.byref(version_data), "\\", ctypes.byref(info_pointer), ctypes.byref(info_size)):
            return None
        if info_size.value < ctypes.sizeof(FixedFileInfo):
            return None

        info = ctypes.cast(info_pointer, ctypes.POINTER(FixedFileInfo)).contents
        if info.dwSignature != 0xFEEF04BD:
            return None
        version_ms = info.dwProductVersionMS or info.dwFileVersionMS
        version_ls = info.dwProductVersionLS if info.dwProductVersionMS else info.dwFileVersionLS
        return (
            version_ms >> 16, version_ms & 0xFFFF,
            version_ls >> 16, version_ls & 0xFFFF,
        )
    except (AttributeError, ctypes.ArgumentError, OSError, TypeError, ValueError):
        return None


def _is_reparse_point(path):
    """Detect symlinks, junctions, and other Windows reparse points."""
    try:
        if os.path.islink(path):
            return True
        if hasattr(os.path, "isjunction") and os.path.isjunction(path):
            return True
        attributes = os.stat(path, follow_symlinks=False).st_file_attributes
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        # If an existing path cannot be inspected, it must not be trusted as
        # ordinary scan storage or removed as a partial scan export.
        return True
    except AttributeError:
        # Non-Windows platforms do not expose Windows file attributes; the
        # explicit symbolic-link checks above still apply there.
        return False
    return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def _path_has_reparse_component(path):
    """Return true if any existing component redirects outside scan storage."""
    absolute = os.path.abspath(os.fspath(path))
    drive, tail = os.path.splitdrive(absolute)
    current = drive + os.sep if drive else os.path.abspath(os.sep)
    for part in tail.strip("\\/").replace("/", os.sep).split(os.sep):
        if not part:
            continue
        current = os.path.join(current, part)
        if _is_reparse_point(current):
            return True
    return False


def choose_scanner():
    """Ask an interactive user which installed scanner should create the export."""
    print("Choose which scanner to use:")
    print("  1. WizTree (fast full-drive scan or standard scan)")
    print("  2. WinDirStat 2.6+ (standard scan; Administrator access optional)")
    while True:
        try:
            choice = input("Select scanner [1/2]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nScan cancelled.")
            return None
        if choice in {"q", "quit", "cancel"}:
            print("Scan cancelled.")
            return None
        if choice in ("1", "wiztree", "w"):
            return "wiztree"
        if choice in ("2", "windirstat", "win", "wds"):
            return "windirstat"
        print("Enter 1 for WizTree or 2 for WinDirStat.")


def choose_wiztree_mode():
    """Ask which WizTree scan mode to use; auto balances speed and access."""
    print("Choose a WizTree scan mode for the selected drive or folder:")
    print("  1. Automatic (fast for a whole drive when run as Administrator; standard otherwise)")
    print("  2. Fast full-drive scan (requires an Administrator terminal)")
    print("  3. Standard scan (no Administrator access; may miss files this account cannot access)")
    while True:
        try:
            choice = input("Select scan mode [1/2/3]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nScan cancelled.")
            return None
        if choice in {"q", "quit", "cancel"}:
            print("Scan cancelled.")
            return None
        if choice in ("", "1", "auto", "automatic"):
            return "auto"
        if choice in ("2", "fast", "mft"):
            return "fast"
        if choice in ("3", "standard", "normal"):
            return "standard"
        print("Enter 1 for automatic, 2 for fast full-drive scanning, or 3 for standard scanning.")


def check_admin_status() -> bool | None:
    """Return the current Administrator status, or None when it cannot be checked."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return None


def check_admin() -> bool:
    """Return True only when the current process is confirmed elevated."""
    return check_admin_status() is True


def wait_for_file(filepath, timeout=30, stable_time=2):
    """
    Wait for the output file to be created and stabilize

    Args:
        filepath: file path
        timeout: timeout in seconds
        stable_time: file-size stability time in seconds

    Returns:
        bool: whether the file is ready
    """
    print("Waiting for scan results to finish saving...", flush=True)
    start = time.monotonic()
    last_size = -1
    stable_count = 0
    last_wait_report = -5

    while time.monotonic() - start < timeout:
        if _path_has_reparse_component(filepath):
            print("Scan results path changed to a reparse point or junction; refusing to read it.")
            return False
        try:
            size = os.path.getsize(filepath)
        except FileNotFoundError:
            size = None
            wait_reason = "Waiting for results file"
        except OSError:
            size = None
            wait_reason = "Checking results file access"
        if size is not None and size > 0:
            if size == last_size:
                stable_count += 1
                if stable_count >= stable_time:
                    # File size is stable; scan is complete.
                    print(f"\nScan complete! Results file size: {size / 1024 / 1024:.2f} MB")
                    return True
            else:
                stable_count = 0
            last_size = size

            elapsed = int(time.monotonic() - start)
            print(f"\rSaving results... {elapsed}s | Saved so far: {size / 1024 / 1024:.2f} MB", end="", flush=True)
        else:
            # A missing, empty, or unreadable interval breaks the consecutive
            # stable-size samples required before an export is accepted.
            stable_count = 0
            last_size = -1
            if size == 0:
                wait_reason = "Results file is still empty"
            elapsed = int(time.monotonic() - start)
            if elapsed - last_wait_report >= 5:
                print(f"\rChecking scan results... {elapsed}s | {wait_reason}", end="", flush=True)
                last_wait_report = elapsed

        time.sleep(1)

    print(f"\nThe scan did not finish within {timeout} seconds.")
    return False


def _looks_like_localized_windirstat_row(headers, row):
    """Recognize WinDirStat's localized CSV schema from its documented field order and values."""
    if len(headers) not in (9, 10) or len(row) != len(headers):
        return False
    path = str(row[0] or "").strip()
    if not re.match(r"^[A-Za-z]:[\\/]", path):
        return False
    for index in (1, 2, 3, 4):
        if not re.fullmatch(r"\d+", str(row[index] or "").strip()):
            return False
    try:
        flags_text = str(row[7] or "").strip()
        index_text = str(row[8] or "").strip()
        flags = int(flags_text[2:] if flags_text.casefold().startswith("0x") else flags_text, 16)
        int(index_text[2:] if index_text.casefold().startswith("0x") else index_text, 16)
    except ValueError:
        return False
    return (flags & 0xF) in {0x4, 0x8}


def validate_scan_export(filepath):
    """Check a CSV header and sample row without loading a potentially huge export."""
    path_headers = {"\u6587\u4ef6\u540d\u79f0", "filename", "name"}
    size_headers = {"\u5927\u5c0f", "size", "logicalsize"}

    def is_header(row):
        keys = {str(value or "").strip().casefold().replace(" ", "") for value in row}
        return bool(keys & path_headers) and bool(keys & size_headers)

    try:
        with open(filepath, "r", encoding="utf-8-sig", newline="") as source:
            reader = csv.reader(source, strict=True)
            first_row = next(reader, [])
            if is_header(first_row):
                return True, None
            first_sample = next(reader, [])
            if _looks_like_localized_windirstat_row(first_row, first_sample):
                return True, None
            # GUI-generated WizTree exports can have one informational line
            # before the actual column headings.
            second_row = first_sample
            if is_header(second_row):
                return True, None
            second_sample = next(reader, [])
            if _looks_like_localized_windirstat_row(second_row, second_sample):
                return True, None
            scan_mode_hint = Path(filepath).name.casefold().startswith("scan_windirstat_")
            if scan_mode_hint and not first_sample and len(first_row) in (9, 10):
                return True, None
            if scan_mode_hint and is_header(second_row) is False and not second_sample and len(second_row) in (9, 10):
                return True, None
            return False, "CSV is missing a recognized path and size header"
    except (OSError, UnicodeError, csv.Error) as exc:
        return False, f"CSV could not be read: {describe_error(exc)}"


def _stop_scan_process(process):
    """Stop a scanner, escalating to kill and confirming that it exited."""
    if process is None:
        return True
    try:
        if process.poll() is not None:
            return True
    except OSError:
        return False
    try:
        process.terminate()
    except OSError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            return _scan_process_has_exited(process)
    except OSError:
        return _scan_process_has_exited(process)
    return _scan_process_has_exited(process)


def _scan_process_has_exited(process):
    try:
        return process.poll() is not None
    except OSError:
        return False


def _remove_or_preserve_partial_scan(process, filepath):
    """Stop a scanner before cleanup and report how its partial export ended."""
    if _stop_scan_process(process):
        return _remove_partial_scan_export(filepath)
    print("Scanner could not be confirmed stopped; preserving its incomplete export:")
    print(safe_terminal_text(filepath))
    return "running"


def _remove_partial_scan_export(filepath):
    if _path_has_reparse_component(filepath):
        print("Refusing to remove a partial export through a reparse point or junction; it was preserved at:")
        print(safe_terminal_text(filepath))
        return "preserved"
    try:
        os.unlink(filepath)
    except FileNotFoundError:
        return "missing"
    except OSError as exc:
        print(f"Could not remove the incomplete scan export; it was preserved. {describe_error(exc)}")
        print(safe_terminal_text(filepath))
        return "preserved"
    return "removed"


def wait_for_scan_process(process, filepath, timeout=1800, scanner_name="scanner"):
    """Wait for the scanner itself to finish, then verify its closed export file."""
    started = time.monotonic()
    last_report = -5
    print(f"Waiting for the scanner to finish (timeout: {timeout // 60} minutes)...")
    while process.poll() is None:
        elapsed = int(time.monotonic() - started)
        if elapsed >= timeout:
            print(f"\nScan timed out after {timeout} seconds; stopping {scanner_name}")
            _stop_scan_process(process)
            return False

        if elapsed - last_report >= 5:
            if _path_has_reparse_component(filepath):
                print(f"\nScan export path changed to a reparse point or junction; stopping {scanner_name}.")
                _stop_scan_process(process)
                return False
            try:
                size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
            except OSError:
                print(f"\rScanning... {elapsed}s | Checking scan file...", end="", flush=True)
            else:
                print(f"\rScanning... {elapsed}s | Saved so far: {size / 1024 / 1024:.1f} MB", end="", flush=True)
            last_report = elapsed
        time.sleep(1)

    return_code = process.wait()
    if return_code != 0:
        print(f"\nScanner exited with code {return_code}")
        return False
    print("\nScan finished; checking the results file...")
    if _path_has_reparse_component(filepath):
        print("Refusing to read scan results through a reparse point or junction.")
        return False
    if not wait_for_file(filepath, timeout=30, stable_time=2):
        return False
    if _path_has_reparse_component(filepath):
        print("Scan results changed to a reparse point or junction; refusing to validate them.")
        return False
    valid, error = validate_scan_export(filepath)
    if not valid:
        print(f"\nScan results could not be validated: {error}")
        return False
    if _path_has_reparse_component(filepath):
        print("Scan results changed while they were being validated; refusing to use them.")
        return False
    return True


def _normalize_scan_target(target):
    """Accept a local drive root or an existing absolute local folder."""
    target = str(target).strip().strip('"')
    if re.fullmatch(r"[A-Za-z]:", target):
        return target.upper()
    drive, _ = os.path.splitdrive(target)
    if (not drive or target.startswith(("\\\\", "//"))
            or not os.path.isabs(target) or not os.path.isdir(target)):
        raise ValueError("target must be a drive such as C: or an existing absolute local folder")
    return os.path.normpath(target)


def _is_whole_drive_target(target):
    """Recognize drive roots whether entered as C: or C:\\."""
    try:
        normalized = _normalize_scan_target(target)
    except (TypeError, ValueError):
        return False
    return bool(re.fullmatch(r"[A-Za-z]:", normalized.rstrip("\\/")))


def scan(drive="C:", include_files=True, max_depth=0, timeout=1800, app="wiztree",
         wiztree_mode="auto", scanner_executable_path=None):
    """
    Run a scan with the selected disk-usage scanner.

    Args:
        drive: drive to scan
        include_files: whether to include file rows (default True; single huge files such as dumps/models
                       are only visible in file rows and often provide the biggest cleanup win)
        max_depth: maximum export depth; 0 means unlimited
        app: scanner to invoke ("wiztree" or "windirstat")
        wiztree_mode: "auto", "fast" (full-drive scan; Administrator required), or "standard"
        scanner_executable_path: optional full path selected for this scan

    Returns:
        str: exported CSV file path, or None on failure
    """
    try:
        drive = _normalize_scan_target(drive)
    except (TypeError, ValueError):
        print("Error: target must be a drive such as C: or an existing absolute local folder")
        return None
    if max_depth < 0 or timeout <= 0:
        print("Error: folder depth must be zero or more, and the scan time limit must be positive")
        return None

    app = app.lower().strip()
    if app not in {"wiztree", "windirstat"}:
        print("Error: app must be 'wiztree' or 'windirstat'")
        return None
    if app == "windirstat" and max_depth != 0:
        print("Error: --max-depth is supported only by WizTree")
        return None
    if app == "windirstat" and not include_files:
        print("Error: Drive Cleanr cannot hide individual files in WinDirStat results; use WizTree to scan folders only")
        return None
    if wiztree_mode not in {"auto", "fast", "standard"}:
        print("Error: WizTree mode must be 'auto', 'fast', or 'standard'")
        return None
    if app == "windirstat" and wiztree_mode != "auto":
        print("Error: --wiztree-mode is supported only by WizTree")
        return None

    elevated = check_admin() if app == "wiztree" else False
    is_whole_drive = _is_whole_drive_target(drive)
    if app == "wiztree":
        effective_wiztree_mode = wiztree_mode
        if effective_wiztree_mode == "auto":
            effective_wiztree_mode = "fast" if (elevated and is_whole_drive) else "standard"
        if effective_wiztree_mode == "fast" and not is_whole_drive:
            print("Error: fast full-drive scanning is only available for drives; choose standard scanning for a folder")
            return None
        if effective_wiztree_mode == "fast" and not elevated:
            print("Error: fast full-drive scanning requires an Administrator terminal")
            print("Run this command in an Administrator terminal, or choose standard scanning with --wiztree-mode standard")
            return None
        if effective_wiztree_mode == "standard":
            print("WizTree standard scan selected; it may be slower and can miss files the current account cannot access.")
        else:
            print("WizTree fast full-drive scan selected.")

    if scanner_executable_path is None:
        executable = find_wiztree() if app == "wiztree" else find_windirstat()
    else:
        executable = normalize_scanner_executable_path(scanner_executable_path, app=app)
        if executable is None:
            print("Error: scanner location must be the full path to an existing .exe file")
            return None
    app_name = "WizTree" if app == "wiztree" else "WinDirStat"
    if not executable:
        print(f"Error: {app_name} executable was not found")
        env_name = "WIZTREE_PATH" if app == "wiztree" else "WINDIRSTAT_PATH"
        folder_name = "WizTree" if app == "wiztree" else "WinDirStat"
        print(f"Place the executable in this project's {folder_name}\\ folder, or set the {env_name} environment variable")
        if app == "windirstat":
            print("Scanning with Drive Cleanr requires WinDirStat 2.6.0 or newer.")
        return None

    if app == "windirstat":
        version = _get_windows_file_version(executable)
        if version is None:
            print("Warning: Could not verify WinDirStat's version. Drive Cleanr needs version 2.6.0 or newer for CSV export; continuing may fail.")
        elif version[:2] < (2, 6):
            detected_version = ".".join(str(part) for part in version)
            print(f"Error: WinDirStat {detected_version} is too old for automated CSV export.")
            print("Update to WinDirStat 2.6.0 or newer, then try again.")
            return None

    # Keep completed exports visible at the top level; unfinished scans stay
    # isolated so the review menu and retention cleanup cannot mistake them for
    # usable scan files.
    if _path_has_reparse_component(DATA_DIR):
        print("Error: scan storage crosses a reparse point or junction")
        return None
    partial_dir = os.path.join(DATA_DIR, ".incomplete")
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(partial_dir, exist_ok=True)
    except OSError as exc:
        print(f"Error: could not prepare scan storage: {describe_error(exc)}")
        return None
    if _path_has_reparse_component(DATA_DIR):
        print("Error: scan storage changed to a reparse point or junction")
        return None
    if _path_has_reparse_component(partial_dir):
        print("Error: incomplete-scan storage crosses a reparse point or junction")
        return None

    # Generate output filename
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    mode_label = f"wiztree_{effective_wiztree_mode}" if app == "wiztree" else "windirstat"
    output_stem = os.path.join(DATA_DIR, f"scan_{mode_label}_{timestamp}")
    output_file = f"{output_stem}.csv"
    partial_stem = os.path.join(partial_dir, os.path.basename(output_stem))
    partial_file = f"{partial_stem}.csv"
    collision_index = 1
    while os.path.lexists(output_file) or os.path.lexists(partial_file):
        output_file = f"{output_stem}_{collision_index}.csv"
        partial_file = f"{partial_stem}_{collision_index}.csv"
        collision_index += 1

    if app == "wiztree":
        # Admin mode enables MFT scanning. Standard mode uses normal filesystem
        # access and remains available to non-administrator users.
        admin_flag = "/admin=1" if effective_wiztree_mode == "fast" else "/admin=0"
        cmd = [executable, drive, f'/export={partial_file}', admin_flag,
               '/exportfolders=1', f'/exportfiles={1 if include_files else 0}',
               '/sortby=2', '/exportdrivecapacity=1', f'/exportmaxdepth={max_depth}']
    else:
        # WinDirStat 2.6+ /SaveTo runs headlessly and selects CSV from the suffix.
        print("Note: WinDirStat follows its saved filters, exclusions, and other scan settings.")
        print("These settings can leave files out of the results; review them in WinDirStat before expecting a full scan.")
        cmd = [executable, '/SaveTo', partial_file, drive]

    print(f"Starting {app_name} scan: {drive}")

    process = None
    try:
        # Wait on the scanner's real process lifetime. File size can pause during
        # large exports and is not a reliable completion signal.
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )

        if wait_for_scan_process(process, partial_file, timeout=timeout, scanner_name=app_name):
            if (_path_has_reparse_component(partial_file) or
                    _path_has_reparse_component(output_file)):
                print("Scan storage or its export changed to a reparse point or junction; refusing to save it.")
                return None
            try:
                os.rename(partial_file, output_file)
            except OSError as exc:
                print(f"Scan completed, but its export could not be moved into the scan list: {describe_error(exc)}")
                print(f"The verified export remains at: {partial_file}")
                return None
            print("\nScan complete.")
            print(f"Scan saved to: {output_file}")
            print("Earlier scans and cleanup plans were kept.")

            return output_file
        else:
            _remove_or_preserve_partial_scan(process, partial_file)
            print("Scan timed out or failed")
            return None

    except subprocess.TimeoutExpired:
        _remove_or_preserve_partial_scan(process, partial_file)
        print("Process timed out")
        return None
    except KeyboardInterrupt:
        partial_status = _remove_or_preserve_partial_scan(process, partial_file)
        if partial_status == "removed":
            print("\nScan cancelled; the scanner was stopped and its partial export was removed.")
        elif partial_status == "missing":
            print("\nScan cancelled; the scanner was stopped and no incomplete export remained.")
        elif partial_status == "preserved":
            print("\nScan cancelled; the scanner was stopped, but its incomplete export could not be removed and was preserved.")
        else:
            print("\nScan cancelled; its incomplete export was preserved because the scanner may still be running.")
        return None
    except Exception as e:
        _remove_or_preserve_partial_scan(process, partial_file)
        print(f"Scan error: {describe_error(e)}")
        return None


def get_latest_scan():
    """Get the newest validated saved Drive Cleanr scan export."""
    scans = get_saved_scans()
    return scans[0] if scans else None


def get_saved_scans():
    """Return validated current and known legacy exports, newest first."""
    data_path = Path(DATA_DIR)
    if not data_path.exists() or _path_has_reparse_component(data_path):
        return []

    search_dirs = [data_path]
    for relative_parts in _LEGACY_SCAN_FOLDERS:
        legacy_dir = data_path.joinpath(*relative_parts)
        if (not _path_has_reparse_component(legacy_dir) and legacy_dir.is_dir()):
            search_dirs.append(legacy_dir)

    found = []
    seen = set()
    for folder in search_dirs:
        try:
            csv_files = folder.glob("*.csv")
            for candidate in csv_files:
                key = os.path.normcase(os.path.abspath(candidate))
                if key in seen or not _is_saved_scan_export(candidate, data_path):
                    continue
                seen.add(key)
                try:
                    file_info = candidate.stat(follow_symlinks=False)
                except OSError:
                    continue
                if not stat.S_ISREG(file_info.st_mode):
                    continue
                found.append((file_info.st_mtime_ns, key, str(candidate)))
        except OSError:
            continue

    found.sort(key=lambda item: (-item[0], item[1]))
    return [item[2] for item in found]


def _is_drive_cleanr_scan_export(path):
    """Match a current generated scan name and a recognizable scan CSV."""
    candidate = Path(path)
    if not _DRIVECLEANR_SCAN_NAME.fullmatch(candidate.stem):
        return False
    if _path_has_reparse_component(candidate):
        return False
    valid, _error = validate_scan_export(str(candidate))
    return valid


def _is_saved_scan_export(path, data_path=None):
    """Recognize current exports and the known pre-migration scan folders."""
    candidate = Path(path)
    if _is_drive_cleanr_scan_export(candidate):
        return True

    if data_path is None:
        data_path = Path(DATA_DIR)
    try:
        relative = candidate.relative_to(data_path)
    except (OSError, ValueError):
        return False
    parent_parts = tuple(part.casefold() for part in relative.parts[:-1])
    if (parent_parts not in _LEGACY_SCAN_FOLDERS or
            not _LEGACY_SCAN_NAME.fullmatch(candidate.stem) or
            _path_has_reparse_component(candidate)):
        return False
    valid, _error = validate_scan_export(str(candidate))
    return valid


def cleanup_old_scans(keep_latest=1, include_scripts=False):
    """
    Clean old scan files and keep only the newest few

    Args:
        keep_latest: number of newest files to keep (default 1)

    Returns:
        int: number of deleted files
    """
    if keep_latest < 1:
        raise ValueError("keep_latest must be at least one")
    data_path = Path(DATA_DIR)
    skill_path = data_path.parent
    if _path_has_reparse_component(data_path):
        print("Refusing to prune scan files through a reparse point or junction")
        return 0
    if include_scripts and _path_has_reparse_component(skill_path):
        print("Refusing to prune cleanup plans through a reparse point or junction")
        return 0
    deleted = 0

    # Identify validated current and recognized legacy exports outside the
    # retention window. Only delete the exact default review plan paired with
    # an export that was actually removed.
    old_exports = []
    pruned_exports = []
    csv_files = [Path(path) for path in get_saved_scans()]
    if len(csv_files) > keep_latest:
        old_exports = csv_files[keep_latest:]

        # Delete old files only if they are still recognized scan exports.
        for old_file in old_exports:
            if (_path_has_reparse_component(old_file) or
                    not _is_saved_scan_export(old_file, data_path)):
                print(f"Refusing to prune changed or linked scan file: {old_file.name}")
                continue
            try:
                old_file.unlink()
                print(f"Deleted old scan file: {old_file.name}")
                deleted += 1
                pruned_exports.append(old_file)
            except OSError as e:
                print(f"Failed to delete {old_file.name}: {describe_error(e)}")

    # Script deletion is a separate explicit action; only remove the default
    # plan named after an export that is itself being pruned. Custom output
    # paths and unrelated PowerShell files are intentionally left untouched.
    if include_scripts:
        remaining_stems = {Path(path).stem.casefold() for path in get_saved_scans()}
        for old_file in pruned_exports:
            if old_file.stem.casefold() in remaining_stems:
                continue
            script = skill_path / f"{old_file.stem}.clean.ps1"
            if not script.exists():
                continue
            if _path_has_reparse_component(script):
                print(f"Refusing to prune linked cleanup plan: {script.name}")
                continue
            try:
                script.unlink()
                print(f"Deleted cleanup script: {script.name}")
                deleted += 1
            except Exception as e:
                print(f"Failed to delete {script.name}: {describe_error(e)}")

    return deleted


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Drive Cleanr disk usage scan tool')
    parser.add_argument('drive', nargs='?', default='C:', help='Drive or existing absolute local folder to scan (default: C:)')
    parser.add_argument('--folders-only', action='store_true', help='Do not include individual files in results (default includes files and folders)')
    parser.add_argument('--max-depth', type=int, default=0, help='Limit how many folder levels appear in WizTree results; 0 includes all levels (default: 0)')
    parser.add_argument('--wiztree-mode', choices=['auto', 'fast', 'standard'], default='auto',
                        help='WizTree scan mode: fast full-drive scan when run as Administrator, standard scan otherwise (default: auto)')
    parser.add_argument('--timeout', type=int, default=1800, help='Maximum scan time in seconds (default: 1800 / 30 minutes)')
    parser.add_argument('--app', choices=['wiztree', 'windirstat'], help='Scanner to use; if omitted, ask interactively')
    parser.add_argument('--latest', action='store_true', help='Show the latest scan file')
    parser.add_argument('--cleanup', action='store_true', help='Clean old data and keep only the newest one')
    parser.add_argument('--keep-latest', type=int, default=1, help='When using --cleanup, keep this many newest scan CSVs (default: 1)')

    args = parser.parse_args()

    if args.cleanup:
        if args.keep_latest < 1:
            parser.error('--keep-latest must be at least 1')
        deleted = cleanup_old_scans(keep_latest=args.keep_latest, include_scripts=True)
        if deleted > 0:
            print(f"Removed {deleted} old scan file(s) and/or paired review plan(s).")
        else:
            print("No old scan files or paired review plans needed cleanup.")
        return

    if args.latest:
        latest = get_latest_scan()
        if latest:
            print(f"Latest scan file: {latest}")
        else:
            print("No scan file found")
        return

    app = args.app or choose_scanner()
    if not app:
        sys.exit(1)

    wiztree_mode = args.wiztree_mode
    if app == "wiztree" and wiztree_mode == "auto" and sys.stdin.isatty():
        try:
            normalized_target = _normalize_scan_target(args.drive)
        except (TypeError, ValueError):
            normalized_target = None
        if normalized_target is not None and _is_whole_drive_target(normalized_target):
            wiztree_mode = choose_wiztree_mode()
        elif normalized_target is not None:
            wiztree_mode = "standard"
            print("WizTree fast scanning is available only for a full drive; this folder will use standard scanning.")
    if wiztree_mode is None:
        sys.exit(1)

    result = scan(
        drive=args.drive,
        include_files=not args.folders_only,
        max_depth=args.max_depth,
        timeout=args.timeout,
        app=app,
        wiztree_mode=wiztree_mode,
    )

    if result:
        print("This scan is available in Drive Cleanr's main menu under 'Review a previous scan'.")
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
