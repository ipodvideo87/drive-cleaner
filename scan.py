#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run a supported disk-usage scanner and wait for its export to finish."""

import os
import sys
import time
import shutil
import subprocess
import re
import csv
from datetime import datetime
from pathlib import Path

# Configuration: resolve relative to this script's directory instead of hardcoding an absolute path
SKILL_DIR = Path(__file__).resolve().parent
DATA_DIR = str(SKILL_DIR / "data")


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
        if c and os.path.isfile(c):
            candidate = Path(c)
            # On 64-bit Windows, WizTree.exe is the 32-bit launcher and may
            # return before its WizTree64.exe worker finishes exporting. Use
            # the paired 64-bit executable whenever it is available.
            if candidate.name.casefold() == "wiztree.exe":
                wide_candidate = candidate.with_name("WizTree64.exe")
                if wide_candidate.is_file():
                    return str(wide_candidate)
            return c
    return shutil.which("WizTree64.exe") or shutil.which("WizTree64")


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
        if candidate and os.path.isfile(candidate):
            return candidate
    return shutil.which("WinDirStat.exe") or shutil.which("WinDirStat")


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
    print("Choose a disk usage scanner:")
    print("  1. WizTree (fast MFT or standard scan)")
    print("  2. WinDirStat 2.6+ (standard scan; administrator rights optional)")
    while True:
        try:
            choice = input("Scanner [1/2]: ").strip().lower()
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
    print("Choose a WizTree scan mode:")
    print("  1. Automatic (fast MFT for a whole drive when elevated; standard otherwise)")
    print("  2. Fast MFT (requires administrator rights; recommended for a whole drive)")
    print("  3. Standard file-system scan (no elevation required; inaccessible files may be missed)")
    while True:
        try:
            choice = input("Mode [1/2/3]: ").strip().lower()
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
        print("Enter 1 for automatic, 2 for fast MFT, or 3 for standard scanning.")


def check_admin():
    """Check whether the current process has administrator privileges"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


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
    print("Waiting for scan to finish...")
    start = time.time()
    last_size = -1
    stable_count = 0

    while time.time() - start < timeout:
        if os.path.exists(filepath):
            try:
                size = os.path.getsize(filepath)
                if size > 0:
                    if size == last_size:
                        stable_count += 1
                        if stable_count >= stable_time:
                            # File size is stable; scan is complete
                            print(f"Scan complete! File size: {size / 1024 / 1024:.2f} MB")
                            return True
                    else:
                        stable_count = 0
                    last_size = size

                    # Show progress
                    elapsed = int(time.time() - start)
                    print(f"\rScanning... {elapsed}s, current file size: {size / 1024 / 1024:.2f} MB", end="", flush=True)
            except:
                pass

        time.sleep(1)

    print(f"\nTimed out after waiting {timeout} seconds")
    return False


def validate_scan_export(filepath):
    """Check the first CSV header without loading a potentially huge export."""
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
            # GUI-generated WizTree exports can have one informational line
            # before the actual column headings.
            if is_header(next(reader, [])):
                return True, None
            return False, "CSV is missing a recognized path and size header"
    except (OSError, UnicodeError, csv.Error) as exc:
        return False, f"CSV could not be read: {exc}"


def _stop_scan_process(process):
    """Terminate a started scanner, escalating to kill if it will not exit."""
    if process is None:
        return
    try:
        if process.poll() is not None:
            return
    except OSError:
        return
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
            pass
    except OSError:
        pass


def _remove_partial_scan_export(filepath):
    if _path_has_reparse_component(filepath):
        print("Refusing to remove a partial export through a reparse point")
        return
    try:
        os.unlink(filepath)
    except OSError:
        pass


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
            size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
            print(f"\rScanning... {elapsed}s, exported {size / 1024 / 1024:.1f} MB", end="", flush=True)
            last_report = elapsed
        time.sleep(1)

    return_code = process.wait()
    if return_code != 0:
        print(f"\nScanner exited with code {return_code}")
        return False
    print("\nScanner finished; checking the export file...")
    if not wait_for_file(filepath, timeout=30, stable_time=2):
        return False
    valid, error = validate_scan_export(filepath)
    if not valid:
        print(f"\nScan export is invalid: {error}")
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


def scan(drive="C:", include_files=True, max_depth=0, timeout=1800, app="wiztree", wiztree_mode="auto"):
    """
    Run a WizTree scan

    Args:
        drive: drive to scan
        include_files: whether to include file rows (default True; single huge files such as dumps/models
                       are only visible in file rows and often provide the biggest cleanup win)
        max_depth: maximum export depth; 0 means unlimited
        app: scanner to invoke ("wiztree" or "windirstat")
        wiztree_mode: "auto", "fast" (MFT/elevated), or "standard" (Windows API scan)

    Returns:
        str: exported CSV file path, or None on failure
    """
    try:
        drive = _normalize_scan_target(drive)
    except (TypeError, ValueError):
        print("Error: target must be a drive such as C: or an existing absolute local folder")
        return None
    if max_depth < 0 or timeout <= 0:
        print("Error: max-depth must be nonnegative and timeout must be positive")
        return None

    app = app.lower().strip()
    if app not in {"wiztree", "windirstat"}:
        print("Error: app must be 'wiztree' or 'windirstat'")
        return None
    if app == "windirstat" and max_depth != 0:
        print("Error: --max-depth is supported only by WizTree")
        return None
    if app == "windirstat" and not include_files:
        print("Error: WinDirStat exports files and folders together; --folders-only is supported only by WizTree")
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
            print("Error: fast MFT scanning is only available for whole-drive targets; choose standard mode for a folder")
            return None
        if effective_wiztree_mode == "fast" and not elevated:
            print("Error: fast MFT scanning requires administrator privileges")
            print("Run this script as administrator, or choose standard scanning with --wiztree-mode standard")
            return None
        if effective_wiztree_mode == "standard":
            print("WizTree standard scan selected; it may be slower and can miss files the current account cannot access.")
        else:
            print("WizTree fast MFT scan selected.")

    executable = find_wiztree() if app == "wiztree" else find_windirstat()
    app_name = "WizTree" if app == "wiztree" else "WinDirStat"
    if not executable:
        print(f"Error: {app_name} executable was not found")
        env_name = "WIZTREE_PATH" if app == "wiztree" else "WINDIRSTAT_PATH"
        folder_name = "WizTree" if app == "wiztree" else "WinDirStat"
        print(f"Place the executable in this project's {folder_name}\\ folder, or set the {env_name} environment variable")
        if app == "windirstat":
            print("Automated CSV scanning requires WinDirStat 2.6.0 or newer.")
        return None

    # Keep scan creation and later retention cleanup within project storage.
    if _path_has_reparse_component(DATA_DIR):
        print("Error: scan storage crosses a reparse point or junction")
        return None
    os.makedirs(DATA_DIR, exist_ok=True)
    if _path_has_reparse_component(DATA_DIR):
        print("Error: scan storage changed to a reparse point or junction")
        return None

    # Generate output filename
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    mode_label = f"wiztree_{effective_wiztree_mode}" if app == "wiztree" else "windirstat"
    output_file = os.path.join(DATA_DIR, f"scan_{mode_label}_{timestamp}.csv")

    if app == "wiztree":
        # Admin mode enables MFT scanning. Standard mode uses normal filesystem
        # access and remains available to non-administrator users.
        admin_flag = "/admin=1" if effective_wiztree_mode == "fast" else "/admin=0"
        cmd = [executable, drive, f'/export={output_file}', admin_flag,
               '/exportfolders=1', f'/exportfiles={1 if include_files else 0}',
               '/sortby=2', '/exportdrivecapacity=1', f'/exportmaxdepth={max_depth}']
    else:
        # WinDirStat 2.6+ /SaveTo runs headlessly and selects CSV from the suffix.
        print("Note: WinDirStat applies its saved filters and scan exclusions.")
        print("Check them in WinDirStat if you expect a full scan.")
        cmd = [executable, '/SaveTo', output_file, drive]

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

        if wait_for_scan_process(process, output_file, timeout=timeout, scanner_name=app_name):
            print("\nScan complete.")
            print(f"Results: {output_file}")
            print("Previous scans and cleanup plans were kept.")

            return output_file
        else:
            # The export belongs to this failed run and is incomplete.
            _remove_partial_scan_export(output_file)
            print("Scan timed out or failed")
            return None

    except subprocess.TimeoutExpired:
        _stop_scan_process(process)
        _remove_partial_scan_export(output_file)
        print("Process timed out")
        return None
    except KeyboardInterrupt:
        _stop_scan_process(process)
        _remove_partial_scan_export(output_file)
        print("\nScan cancelled; the scanner was stopped and its partial export was removed.")
        return None
    except Exception as e:
        _stop_scan_process(process)
        _remove_partial_scan_export(output_file)
        print(f"Scan error: {e}")
        return None


def get_latest_scan():
    """Get the latest scan file"""
    data_path = Path(DATA_DIR)
    if not data_path.exists():
        return None

    csv_files = list(data_path.glob("*.csv"))
    if not csv_files:
        return None

    # Sort by modification time and return the newest
    latest = max(csv_files, key=lambda f: f.stat().st_mtime)
    return str(latest)


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

    # Clean CSV data files
    if data_path.exists():
        csv_files = list(data_path.glob("*.csv"))
        if len(csv_files) > keep_latest:
            # Sort by modification time (newest first)
            csv_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

            # Delete old files
            for old_file in csv_files[keep_latest:]:
                if _path_has_reparse_component(old_file):
                    print(f"Refusing to prune linked scan file: {old_file.name}")
                    continue
                try:
                    old_file.unlink()
                    print(f"Deleted old data file: {old_file.name}")
                    deleted += 1
                except Exception as e:
                    print(f"Failed to delete {old_file.name}: {e}")

    # Script deletion is a separate explicit action; never remove a user's
    # reviewed cleanup plan as a side effect of creating a new scan.
    if include_scripts:
        for script in skill_path.glob("clean_*.ps1"):
            if _path_has_reparse_component(script):
                print(f"Refusing to prune linked cleanup plan: {script.name}")
                continue
            try:
                script.unlink()
                print(f"Deleted cleanup script: {script.name}")
                deleted += 1
            except Exception as e:
                print(f"Failed to delete {script.name}: {e}")

    return deleted


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Drive Cleanr disk usage scan tool')
    parser.add_argument('drive', nargs='?', default='C:', help='Drive or existing absolute local folder to scan (default: C:)')
    parser.add_argument('--folders-only', action='store_true', help='Export folders only (default also includes file rows so large single files stay visible)')
    parser.add_argument('--max-depth', type=int, default=0, help='WizTree maximum export depth; 0 means unlimited (default: 0)')
    parser.add_argument('--wiztree-mode', choices=['auto', 'fast', 'standard'], default='auto',
                        help='WizTree scan mode: fast MFT when elevated, standard otherwise (default: auto)')
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
            print(f"Removed {deleted} old data files")
        else:
            print("No old data files needed cleanup")
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
            print("Folder scans use standard mode; fast MFT is available only for whole-drive scans.")
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
        print(f"\nYou can analyze it with:")
        print(f'python analyze.py "{result}" --min-size 50')
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
