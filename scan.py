#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run a supported disk-usage scanner and wait for its export to finish."""

import os
import sys
import time
import shutil
import subprocess
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
        if c and os.path.exists(c):
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


def choose_scanner():
    """Ask an interactive user which installed scanner should create the export."""
    print("Choose a disk usage scanner:")
    print("  1. WizTree (fast NTFS scan; administrator rights recommended)")
    print("  2. WinDirStat 2.6+ (standard scan; administrator rights optional)")
    while True:
        try:
            choice = input("Scanner [1/2]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nScan cancelled.")
            return None
        if choice in ("1", "wiztree", "w"):
            return "wiztree"
        if choice in ("2", "windirstat", "win", "wds"):
            return "windirstat"
        print("Enter 1 for WizTree or 2 for WinDirStat.")


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


def wait_for_scan_process(process, filepath, timeout=1800):
    """Wait for the scanner itself to finish, then verify its closed export file."""
    started = time.monotonic()
    last_report = -5
    print(f"Waiting for the scanner to finish (timeout: {timeout // 60} minutes)...")
    while process.poll() is None:
        elapsed = int(time.monotonic() - started)
        if elapsed >= timeout:
            print(f"\nScan timed out after {timeout} seconds; stopping WizTree")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
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
    return wait_for_file(filepath, timeout=30, stable_time=2)


def scan(drive="C:", include_files=True, max_depth=0, timeout=1800, app="wiztree"):
    """
    Run a WizTree scan

    Args:
        drive: drive to scan
        include_files: whether to include file rows (default True; single huge files such as dumps/models
                       are only visible in file rows and often provide the biggest cleanup win)
        max_depth: maximum export depth; 0 means unlimited
        app: scanner to invoke ("wiztree" or "windirstat")

    Returns:
        str: exported CSV file path, or None on failure
    """
    drive = drive.strip().upper().rstrip("\\/")
    if len(drive) != 2 or drive[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" or drive[1] != ":":
        print("Error: drive must be a letter such as C:")
        return None
    if max_depth < 0 or timeout <= 0:
        print("Error: max-depth must be nonnegative and timeout must be positive")
        return None

    app = app.lower().strip()
    if app not in {"wiztree", "windirstat"}:
        print("Error: app must be 'wiztree' or 'windirstat'")
        return None

    # WizTree's MFT-based scan requires elevation. WinDirStat can scan as a
    # regular user, though protected paths may be missing from its results.
    if app == "wiztree" and not check_admin():
        print("Error: administrator privileges are required to scan")
        print("Please run this script as administrator")
        return None

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

    # Ensure the data directory exists
    os.makedirs(DATA_DIR, exist_ok=True)

    # Generate output filename
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    output_file = os.path.join(DATA_DIR, f"scan_{timestamp}.csv")

    if app == "wiztree":
        # /admin=1 enables the fast NTFS MFT scan; export files as well as folders.
        cmd = [executable, drive, f'/export={output_file}', '/admin=1',
               '/exportfolders=1', f'/exportfiles={1 if include_files else 0}',
               '/sortby=2', '/exportdrivecapacity=1', f'/exportmaxdepth={max_depth}']
    else:
        # WinDirStat 2.6+ /SaveTo runs headlessly and selects CSV from the suffix.
        cmd = [executable, '/SaveTo', output_file, drive]

    print(f"Starting {app_name} scan: {drive}")

    try:
        # Wait on the scanner's real process lifetime. File size can pause during
        # large exports and is not a reliable completion signal.
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )

        if wait_for_scan_process(process, output_file, timeout=timeout):
            print("\nScan complete.")
            print(f"Results: {output_file}")
            print("Previous scans and cleanup plans were kept.")

            return output_file
        else:
            # Timeout, terminate the process
            try:
                os.unlink(output_file)
            except OSError:
                pass
            print("Scan timed out or failed")
            return None

    except subprocess.TimeoutExpired:
        process.terminate()
        print("Process timed out")
        return None
    except Exception as e:
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
    deleted = 0

    # Clean CSV data files
    if data_path.exists():
        csv_files = list(data_path.glob("*.csv"))
        if len(csv_files) > keep_latest:
            # Sort by modification time (newest first)
            csv_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

            # Delete old files
            for old_file in csv_files[keep_latest:]:
                try:
                    old_file.unlink()
                    print(f"Deleted old data file: {old_file.name}")
                    deleted += 1
                except Exception as e:
                    print(f"Failed to delete {old_file.name}: {e}")

    # Script deletion is a separate explicit action; never remove a user's
    # reviewed cleanup plan as a side effect of creating a new scan.
    if include_scripts:
        skill_path = Path(DATA_DIR).parent
        for script in skill_path.glob("clean_*.ps1"):
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
    parser.add_argument('drive', nargs='?', default='C:', help='Drive to scan (default: C:)')
    parser.add_argument('--folders-only', action='store_true', help='Export folders only (default also includes file rows so large single files stay visible)')
    parser.add_argument('--max-depth', type=int, default=0, help='Maximum export depth; 0 means unlimited (default: 0)')
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

    result = scan(
        drive=args.drive,
        include_files=not args.folders_only,
        max_depth=args.max_depth,
        timeout=args.timeout,
        app=app,
    )

    if result:
        print(f"\nYou can analyze it with:")
        print(f'python analyze.py "{result}" --min-size 50')
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
