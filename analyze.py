#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analyze WizTree and WinDirStat CSV exports and find cleanup candidates."""

import csv
import ntpath
import os
import shutil
import sys
import json
import re
from datetime import datetime
from pathlib import Path

from scan import get_latest_scan

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="backslashreplace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(errors="backslashreplace")

# Patterns used to identify potential cleanup candidates.
CLEANABLE_PATTERNS = {
    "high": {
        "name": "High Priority (Lower Risk)",
        "patterns": [
            {"pattern": "livekernelreports", "name": "Kernel crash dumps (diagnostic snapshots; system does not depend on them)", "safe": True},
            {"pattern": "crashdump", "name": "Crash dumps", "safe": True},
            {"pattern": "minidump", "name": "Blue screen mini dumps", "safe": True},
            {"pattern": "optguideondevicemodel", "name": "Chrome on-device AI model (after deleting, consider disabling optimization-guide-on-device-model in chrome://flags to prevent re-download)", "safe": True},
            {"pattern": "ota-artifacts", "name": "NVIDIA update cache", "safe": True},
            {"pattern": "\\pip\\cache", "name": "pip cache", "safe": True},
            {"pattern": "\\.cache\\puppeteer", "name": "Puppeteer cache", "safe": True},
            {"pattern": "\\electron\\cache", "name": "Electron cache", "safe": True},
            {"pattern": "\\bcut\\cache", "name": "BCUT cache", "safe": True},
            {"pattern": "\\npm-cache", "name": "npm cache", "safe": True},
            {"pattern": "\\yarn\\cache", "name": "Yarn cache", "safe": True},
            {"pattern": "\\temp\\", "name": "Temporary files (check for installers or builds in progress)", "safe": True},
            {"pattern": "\\tmp\\", "name": "Temporary files (check for installers or builds in progress)", "safe": True},
        ]
    },
    "medium": {
        "name": "Medium Priority (Use Caution)",
        "patterns": [
            {"pattern": "\\cache\\", "name": "Application cache", "safe": False},
            {"pattern": "\\caches\\", "name": "Application cache", "safe": False},
            {"pattern": "\\logs\\", "name": "Log files", "safe": False},
            {"pattern": "gpucache", "name": "GPU cache", "safe": False},
            {"pattern": "shadercache", "name": "Shader cache", "safe": False},
            {"pattern": "code cache", "name": "Code cache", "safe": False},
        ]
    },
    "low": {
        "name": "Low Priority (Confirm First)",
        "patterns": [
            {"pattern": "\\.gradle\\caches", "name": "Gradle cache", "safe": False},
            {"pattern": "\\.cargo\\registry", "name": "Cargo cache", "safe": False},
            {"pattern": "\\.nuget\\packages", "name": "NuGet cache", "safe": False},
            {"pattern": "\\go\\pkg\\mod", "name": "Go modules cache", "safe": False},
            {"pattern": "\\ms-playwright", "name": "Playwright test browsers (can be reinstalled with `npx playwright install`)", "safe": False},
            {"pattern": "indexeddb", "name": "Browser site data IndexedDB (offline web app data / login state; deleting it can sign you out or lose data)", "safe": False},
        ]
    }
}

# Safety exclusions: never recommend these paths for cleanup.
EXCLUDE_PATTERNS = [
    # Critical Windows data
    "\\windows\\winsxs",
    "\\windows\\system32",
    "\\windows\\syswow64",
    "\\windows\\installer",              # Repair/uninstall data for installed software
    "\\program files\\",
    "\\program files (x86)\\",
    "\\programdata\\microsoft\\windows\\",
    "\\windows\\softwaredistribution\\download\\", # Use Windows maintenance tools for update downloads
    "\\$mft",                            # NTFS file-system metadata
    "\\$extend",                         # NTFS file-system metadata
    "system volume information",         # System restore points
    "\\driverstore\\",                   # Active driver store
    "$recycle.bin",
    # Installer repair caches
    "package cache",
    "installercache",
    # Personal data
    "\\documents\\",
    "\\desktop\\",
    "\\pictures\\",
    "\\videos\\",
    "\\downloads\\",                   # May contain projects, installers, and user files
    "\\recovered-windowsold\\",         # Preserve data retained from a previous Windows installation
    "\\$winreagent",                      # Windows-managed update recovery staging
    "\\programdata\\usoshared\\logs\\", # Active Windows Update diagnostics
    "\\service worker\\",               # May contain offline site data and user state
    "\\.codex\\",                       # Codex settings, extensions, and task data
    "\\.agents\\",                      # User-installed agent skills and configuration
    "\\.local\\share\\containers\\",  # Container or Podman machine state
    "\\onedrive",
    "tencent files",                     # Files received through QQ
    "xwechat_files",                     # WeChat files
    "wechat files",
    # Credentials and application settings
    "\\.ssh\\",
    "\\.gnupg\\",
]

ANALYSIS_PROGRESS_INTERVAL = 100_000
PROJECT_MARKERS = (
    ".drive-cleanr-protect", ".git", ".hg", ".svn", "pyproject.toml", "package.json", "cargo.toml",
    "go.mod", "cmakelists.txt", "makefile", "setup.py", "pom.xml",
    "build.gradle", "composer.json",
)


def format_size(size_bytes):
    """Format a byte count for display."""
    if size_bytes >= 1024 ** 3:
        return f"{size_bytes / (1024 ** 3):.2f} GB"
    elif size_bytes >= 1024 ** 2:
        return f"{size_bytes / (1024 ** 2):.2f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KB"
    return f"{size_bytes} B"


def _scan_mode_from_filename(csv_path):
    """Read scan-mode hints encoded by Drive Cleanr without altering scanner CSVs."""
    name = Path(csv_path).name.casefold()
    if name.startswith("scan_wiztree_standard_"):
        return "wiztree_standard"
    if name.startswith("scan_wiztree_fast_"):
        return "wiztree_fast"
    if name.startswith("scan_windirstat_"):
        return "windirstat"
    return None


def classify_path(path):
    """Classify a scan row as a file or directory from its path."""
    if path.endswith("\\") or path.endswith("/"):
        return "Directory"
    return "File"


def _is_directory_row(fields):
    """Read WinDirStat's folder indicators when a row becomes a candidate."""
    attributes = str(fields.get('attributes') or '').casefold()
    windirstat_attributes = str(fields.get('windirstatattributes') or '')
    try:
        windirstat_type = int(windirstat_attributes, 0) & 0xF
    except (TypeError, ValueError):
        windirstat_type = None
    try:
        has_children = int(fields.get('files') or 0) > 0 or int(fields.get('folders') or 0) > 0
    except (TypeError, ValueError):
        has_children = False
    return (
        'directory' in attributes or attributes.strip() == 'd' or
        windirstat_type == 0x4 or has_children
    )


def _is_under(child, parent):
    """Windows-aware path containment, including case and trailing separators."""
    child_key = _path_key(child)
    parent_key = _path_key(parent)
    return child_key != parent_key and child_key.startswith(parent_key.rstrip("\\") + "\\")


def _path_key(path):
    return ntpath.normcase(ntpath.normpath(path.replace("/", "\\")))


def _path_components(path):
    """Return case-insensitive Windows path components without drive/root syntax."""
    normalized = str(path).replace("/", "\\").casefold()
    _drive, tail = ntpath.splitdrive(normalized)
    return [part for part in tail.split("\\") if part]


def _contains_component_sequence(components, wanted):
    """Match pre-split path fragments on component boundaries."""
    if not wanted or len(wanted) > len(components):
        return False
    return any(components[index:index + len(wanted)] == wanted
               for index in range(len(components) - len(wanted) + 1))


def _matches_cleanup_pattern(components, wanted):
    if not wanted:
        return False
    if len(wanted) > 1:
        return _contains_component_sequence(components, wanted)
    # Accept a suffix such as CrashDump.dmp while excluding similarly named
    # tools and project folders such as CrashDumpManager.
    return any(component == wanted[0] or component.startswith(wanted[0] + ".")
               for component in components)


_EXCLUDE_COMPONENTS = tuple(_path_components(pattern) for pattern in EXCLUDE_PATTERNS)
_CLEANABLE_COMPONENTS = {
    priority: tuple((pattern_info, _path_components(pattern_info["pattern"]))
                    for pattern_info in category["patterns"])
    for priority, category in CLEANABLE_PATTERNS.items()
}


def _is_excluded_path(path, components=None):
    """Return whether a path matches a protected-path fragment."""
    components = components if components is not None else _path_components(path)
    return any(_contains_component_sequence(components, pattern) for pattern in _EXCLUDE_COMPONENTS)


def _inside_project_tree(path, directory, cache):
    """Recognize project roots above a candidate to avoid recursive project cleanup."""
    normalized = ntpath.normpath(path.replace("/", "\\"))
    current = normalized if directory else ntpath.dirname(normalized)
    visited = []
    project_found = False
    while current:
        key = _path_key(current)
        if key in cache:
            project_found = cache[key]
            break
        _, tail = ntpath.splitdrive(current)
        top_level = [part for part in tail.strip("\\").split("\\") if part]
        if (len(top_level) <= 2 and top_level and
                top_level[0].casefold() in {"users", "documents and settings"}):
            break
        visited.append(key)
        if any(os.path.isdir(os.path.join(current, marker)) or
               os.path.isfile(os.path.join(current, marker)) for marker in PROJECT_MARKERS):
            project_found = True
            break
        parent = ntpath.dirname(current)
        if parent == current:
            break
        current = parent
    for key in visited:
        cache[key] = project_found
    return project_found


def _is_local_drive_path(path):
    if not isinstance(path, str) or not path:
        return False
    normalized = path.replace("/", "\\")
    drive, tail = ntpath.splitdrive(normalized)
    if (len(drive) != 2 or not drive[0].isalpha() or drive[1] != ":" or
            not tail.startswith("\\") or normalized.startswith("\\\\") or
            ntpath.normpath(normalized) != normalized.rstrip("\\") or
            ntpath.normpath(normalized) == drive + "\\"):
        return False
    parts = [part for part in tail.strip("\\").split("\\") if part]
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    reserved.update(f"COM{index}" for index in range(1, 10))
    reserved.update(f"LPT{index}" for index in range(1, 10))
    return not any(
        part in {".", ".."} or part.endswith((".", " ")) or
        part.split(".")[0].rstrip(" .").upper() in reserved or
        any(character in part for character in '<>:"|?*') or
        any(ord(character) < 32 for character in part)
        for part in parts
    )


def _ps_literal(value):
    """Encode untrusted data as a PowerShell single-quoted string literal."""
    return "'" + str(value).replace("'", "''") + "'"


def _ensure_output_outside_targets(output_path, items):
    """Do not place a generated report where a selected cleanup would remove it."""
    destination = _path_key(os.path.abspath(os.fspath(output_path)))
    for item in items:
        target = item.get("path")
        if isinstance(target, str) and (
                destination == _path_key(target) or _is_under(destination, target)):
            raise ValueError("Choose an output path outside the selected cleanup targets")


def _non_overlapping_items(items):
    """Keep the outermost candidate paths so parent/child sizes are not added."""
    ordered = sorted(items, key=lambda item: (item["path"].count("\\") + item["path"].count("/"), -item["size"]))
    selected = []
    for item in ordered:
        if any(_path_key(item["path"]) == _path_key(parent["path"]) or
               _is_under(item["path"], parent["path"]) for parent in selected):
            continue
        selected.append(item)
    return selected


def analyze_csv(csv_path, min_size_mb=50, progress_callback=None):
    """Analyze a scanner CSV export."""
    results = {
        "scan_file": csv_path,
        "scan_mode": _scan_mode_from_filename(csv_path),
        "scan_time": datetime.now().isoformat(),
        "total_size": 0,
        "free_space": 0,
        "used_space": 0,
        "space_source": None,
        "stale_candidate_count": 0,
        "project_candidate_count": 0,
        "categories": {
            "high": {"name": "High priority — lower risk (review each path)", "items": [], "total_size": 0},
            "medium": {"name": "Medium priority — review carefully", "items": [], "total_size": 0},
            "low": {"name": "Low priority — confirm the impact first", "items": [], "total_size": 0},
        }
    }

    if min_size_mb < 0:
        raise ValueError("min_size_mb must be zero or greater")
    min_size = min_size_mb * 1024 * 1024

    def has_required_headers(line):
        fields = next(csv.reader([line]), [])
        keys = {str(value or "").strip().casefold().replace(" ", "") for value in fields}
        return (bool(keys & {"文件名称", "filename", "name"}) and
                bool(keys & {"大小", "size", "logicalsize"}))

    with open(csv_path, 'r', encoding='utf-8-sig') as f:
        # GUI WizTree exports may start with a generated note line. Both scanner
        # formats are accepted; WinDirStat 2.x uses Name/Logical Size/Physical Size.
        first_line_position = f.tell()
        first_line = f.readline()
        if has_required_headers(first_line):
            f.seek(first_line_position)
        else:
            header_position = f.tell()
            second_line = f.readline()
            if not has_required_headers(second_line):
                raise ValueError(
                    "CSV is missing required columns. Expected a path column (Name or File Name) "
                    "and a size column (Size or Logical Size)."
                )
            f.seek(header_position)
        reader = csv.reader(f)
        headers = next(reader, [])
        header_keys = {
            str(key or '').strip().casefold().replace(' ', ''): index
            for index, key in enumerate(headers)
        }

        def column(*names):
            return next((header_keys[name] for name in names if name in header_keys), None)

        path_column = column('文件名称', 'filename', 'name')
        size_column = column('大小', 'size', 'logicalsize')
        allocated_columns = [column(name) for name in (
            'allocated', '已分配', '分配大小', '占用空间', 'physicalsize'
        )]
        allocated_columns = [name for name in allocated_columns if name is not None]
        wiztree_allocated_columns = [column(name) for name in (
            'allocated', '已分配', '分配大小', '占用空间'
        )]
        wiztree_allocated_columns = [name for name in wiztree_allocated_columns if name is not None]
        attributes_column = column('attributes')
        windirstat_attributes_column = column('windirstatattributes')
        files_column = column('files')
        folders_column = column('folders')
        capacity_column = column('drivecapacity')
        free_space_column = column('freespace')
        used_space_column = column('usedspace')

        if path_column is None or size_column is None:
            raise ValueError(
                "CSV is missing required columns. Expected a path column (Name or File Name) "
                "and a size column (Size or Logical Size)."
            )

        def cell(row, index):
            return row[index] if index is not None and index < len(row) else None

        rows_processed = 0
        source_drives = set()
        project_path_cache = {}
        for row in reader:
            rows_processed += 1
            if progress_callback and rows_processed % ANALYSIS_PROGRESS_INTERVAL == 0:
                progress_callback(rows_processed)
            try:
                # Resolve column positions once per export. csv.reader parses
                # quoted rows without allocating a dictionary for every item.
                path = cell(row, path_column) or ''
                logical_size = int(cell(row, size_column) or 0)
                drive, drive_tail = ntpath.splitdrive(path.replace("/", "\\"))
                if (len(drive) == 2 and drive[0].isalpha() and drive[1] == ":" and
                        drive_tail.startswith("\\") and not path.startswith(("\\\\", "//"))):
                    source_drives.add(drive.upper())
                allocated_raw = next((cell(row, name) for name in allocated_columns
                                      if cell(row, name) not in (None, '')), None)
                if allocated_raw is None or allocated_raw == "":
                    size = logical_size
                else:
                    allocated_raw = str(allocated_raw).strip()
                    # WizTree prefixes hard-link allocated values with 0. Its
                    # Physical Size counterpart is a regular decimal byte count.
                    is_wiztree_allocated = any(cell(row, name) is not None
                                               for name in wiztree_allocated_columns)
                    size = (0 if is_wiztree_allocated and len(allocated_raw) > 1 and
                            allocated_raw.startswith("0") else int(allocated_raw or 0))

                # Read drive capacity when the export provides it.
                if path.rstrip("\\/").endswith(":"):
                    results["total_size"] = int(cell(row, capacity_column) or 0)
                    results["free_space"] = int(cell(row, free_space_column) or 0)
                    results["used_space"] = int(cell(row, used_space_column) or 0)
                    if results["total_size"] > 0:
                        results["space_source"] = "scan"

                # Imported CSVs are data, not authority. Only accept ordinary
                # absolute drive paths and reject roots, traversal, UNC, and
                # device paths before any item can become executable.
                if not _is_local_drive_path(path):
                    continue

                # Skip small entries and excluded paths.
                if size <= 0 or size < min_size:
                    continue

                # Apply the safety exclusion list.
                path_components = _path_components(path)
                if _is_excluded_path(path, path_components):
                    continue

                # Match the path against cleanup categories.
                for priority, category in CLEANABLE_PATTERNS.items():
                    for pattern_info, pattern_components in _CLEANABLE_COMPONENTS[priority]:
                        if _matches_cleanup_pattern(path_components, pattern_components):
                            # Type metadata is only needed for candidates; most
                            # scanner rows are ordinary files we can skip here.
                            row_is_directory = path.endswith(('\\', '/')) or _is_directory_row({
                                'attributes': cell(row, attributes_column),
                                'windirstatattributes': cell(row, windirstat_attributes_column),
                                'files': cell(row, files_column),
                                'folders': cell(row, folders_column),
                            })
                            if (path and not path.endswith(('\\', '/')) and row_is_directory):
                                path += '\\'
                            if not os.path.exists(path.rstrip("\\/")):
                                results["stale_candidate_count"] += 1
                            elif _inside_project_tree(path, row_is_directory, project_path_cache):
                                results["project_candidate_count"] += 1
                            else:
                                # Avoid double-counting an entry under a selected parent.
                                existing_paths = [item["path"] for item in results["categories"][priority]["items"]]
                                is_subdir = any(_is_under(path, p) for p in existing_paths)

                                if not is_subdir:
                                    # Replace selected children with this outer directory.
                                    results["categories"][priority]["items"] = [
                                        item for item in results["categories"][priority]["items"]
                                        if not _is_under(item["path"], path) and _path_key(item["path"]) != _path_key(path)
                                    ]

                                    results["categories"][priority]["items"].append({
                                        "path": path,
                                        "size": size,
                                        "size_formatted": format_size(size),
                                        "name": pattern_info["name"],
                                        "safe": pattern_info["safe"],
                                        "kind": classify_path(path),
                                    })
                            break
                    else:
                        continue
                    break
            except (ValueError, KeyError):
                continue

    # WinDirStat exports do not include volume capacity. If this is a local
    # single-drive export, offer current space values with an explicit label.
    if results["space_source"] is None and len(source_drives) == 1:
        try:
            usage = shutil.disk_usage(next(iter(source_drives)) + "\\")
            results["total_size"] = usage.total
            results["used_space"] = usage.used
            results["free_space"] = usage.free
            results["space_source"] = "current"
        except OSError:
            pass

    # Calculate category totals and sort candidates by size.
    for priority in results["categories"]:
        items = results["categories"][priority]["items"]
        items.sort(key=lambda x: x["size"], reverse=True)
        results["categories"][priority]["total_size"] = sum(item["size"] for item in items)
        results["categories"][priority]["total_size_formatted"] = format_size(
            results["categories"][priority]["total_size"]
        )

    return results


def print_category_items(category, show_all=False, item_limit=10):
    """Print candidate items for a cleanup category."""
    items = category["items"]
    if not items:
        return

    visible_items = items if show_all else items[:item_limit]
    for item in visible_items:
        print(f"  {item['size_formatted']:>10}  {item.get('kind', 'item')}  {item['name']}")
        print(f"             {item['path']}")

    if not show_all and len(items) > item_limit:
        print(f"  ... and {len(items) - item_limit} more items")


def print_report(results, show_all_items=False, item_limit=10):
    """Print the analysis report."""
    print("=" * 60)
    print("           Disk Cleanup Analysis Report")
    print("=" * 60)
    print()

    if results.get("scan_mode") == "wiztree_standard":
        print("Scan mode: WizTree standard file-system scan; files inaccessible to this account may be missing.")
    elif results.get("scan_mode") == "wiztree_fast":
        print("Scan mode: WizTree fast MFT scan.")
    elif results.get("scan_mode") == "windirstat":
        print("Scan mode: WinDirStat; saved filters and access permissions apply.")

    if results["total_size"] > 0:
        if results.get("space_source") == "current":
            print(f"Current capacity: {format_size(results['total_size'])}")
            print(f"Current used:     {format_size(results['used_space'])}")
            print(f"Current free:     {format_size(results['free_space'])}")
            print("Volume space was checked now; this may differ from the time of the scan.")
        else:
            print(f"Total capacity: {format_size(results['total_size'])}")
            print(f"Used space:     {format_size(results['used_space'])}")
            print(f"Free space:     {format_size(results['free_space'])}")
        print()

    total_cleanable = 0
    print("Tier subtotals can overlap when one listed folder contains a candidate from another tier.")

    for priority in ["high", "medium", "low"]:
        category = results["categories"][priority]
        if category["items"]:
            print("-" * 60)
            print(f"[{category['name']}] - {category['total_size_formatted']} total")
            print("-" * 60)

            print_category_items(category, show_all=show_all_items, item_limit=item_limit)

            print()
            total_cleanable += category["total_size"]

    print("=" * 60)
    all_items = [item for category in results["categories"].values() for item in category["items"]]
    unique_size = sum(item["size"] for item in _non_overlapping_items(all_items))
    print(f"Potential cleanable space (deduplicated across tiers): {format_size(unique_size)}")
    print("Protected: Windows system stores and update downloads, restore data, personal folders, messaging data, and credentials.")
    print("Estimate uses allocated size when WizTree provides it; hard links are excluded. Actual free space may differ.")
    print("Folder sizes can include nested protected data, which cleanup preserves; reclaimed space may be lower.")
    print("Lower-risk means usually recreatable, not guaranteed safe; review every exact path before cleanup.")
    if results.get("stale_candidate_count", 0):
        print(f"Skipped {results['stale_candidate_count']} candidate paths that no longer exist.")
    if results.get("project_candidate_count", 0):
        print(f"Skipped {results['project_candidate_count']} candidate entries inside detected project folders.")
    print("=" * 60)


def generate_clean_script(results, output_path, priority="high"):
    """Generate a reviewed PowerShell cleanup script."""
    if priority not in {"high", "medium", "low", "all"}:
        raise ValueError("priority must be high, medium, low, or all")
    if priority == "all":
        items = []
        for key in ["high", "medium", "low"]:
            items.extend(results["categories"][key]["items"])
        # Deduplicate paths and sort by size before writing the script.
        deduped = {}
        for item in items:
            deduped[_path_key(item["path"])] = item
        items = list(deduped.values())
        priority_name = "All priorities (high / medium / low)"
    else:
        items = results["categories"][priority]["items"]
        priority_name = CLEANABLE_PATTERNS[priority]["name"]

    # Candidate data can come from imported or edited results, so reapply the
    # path and project protections at the plan-generation boundary as well.
    project_path_cache = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("Cleanup plan contains a malformed target")
        path = item["path"]
        if (not isinstance(item.get("name"), str) or
                not isinstance(item.get("size_formatted"), str) or
                not isinstance(item.get("size"), int) or item["size"] < 0):
            raise ValueError("Cleanup plan contains a malformed target")
        if not _is_local_drive_path(path):
            raise ValueError("Cleanup plan contains an unsafe path; only absolute non-root local paths are allowed")
        if _is_excluded_path(path):
            raise ValueError("Cleanup plan contains a protected path; remove it and rescan")
        kind = item.get("kind", classify_path(path))
        if not isinstance(kind, str) or kind.lower() not in ("file", "directory", "folder", "目录"):
            raise ValueError("Cleanup plan contains an invalid target type")
        is_directory = kind.lower() in ("directory", "folder", "目录")
        if _inside_project_tree(path, is_directory, project_path_cache):
            raise ValueError("Cleanup plan contains a path inside a detected project folder")

    # A parent candidate covers descendants even when rules put them in
    # different tiers. Emit a non-overlapping plan to prevent double counting.
    items = _non_overlapping_items(items)
    if not items:
        raise ValueError("No cleanup candidates were found for the selected priority")
    _ensure_output_outside_targets(output_path, items)

    script = '''# Disk Cleanup Script - {priority_name}
# Auto-generated: {timestamp}
# Run with administrator privileges

param(
    [switch]$Force,
    [int[]]$Select = @()
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "       Disk Cleanup Tool - {priority_name}" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {{
    Write-Host "[Warning] Not running as administrator; some directories may not be cleanable" -ForegroundColor Yellow
}}

# Check related processes
$chrome = Get-Process -Name "chrome" -ErrorAction SilentlyContinue
$edge = Get-Process -Name "msedge" -ErrorAction SilentlyContinue
if ($chrome -or $edge) {{
    Write-Host "[Warning] A browser is running; some cache items may not be fully cleanable" -ForegroundColor Yellow
}}
$vscode = Get-Process -Name "Code" -ErrorAction SilentlyContinue
if ($vscode) {{
    Write-Host "[Warning] VS Code is running; its cache cleanup may be incomplete" -ForegroundColor Yellow
}}
$javaproc = Get-Process -Name "java" -ErrorAction SilentlyContinue
if ($javaproc) {{
    Write-Host "[Warning] Java is running (possibly a Gradle daemon); build cache cleanup may be incomplete" -ForegroundColor Yellow
}}
$nodeproc = Get-Process -Name "node", "npm", "yarn", "pnpm" -ErrorAction SilentlyContinue
if ($nodeproc) {{
    Write-Host "[Warning] A Node.js or package-manager process is running; defer related cache cleanup until it finishes" -ForegroundColor Yellow
}}
$rustproc = Get-Process -Name "cargo", "rustc" -ErrorAction SilentlyContinue
if ($rustproc) {{
    Write-Host "[Warning] A Rust/Cargo process is running; defer related cache or temporary-folder cleanup until it finishes" -ForegroundColor Yellow
}}
$goproc = Get-Process -Name "go" -ErrorAction SilentlyContinue
if ($goproc) {{
    Write-Host "[Warning] A Go process is running; defer Go module cache cleanup until it finishes" -ForegroundColor Yellow
}}
$dotnetproc = Get-Process -Name "dotnet", "MSBuild" -ErrorAction SilentlyContinue
if ($dotnetproc) {{
    Write-Host "[Warning] A .NET build process is running; defer NuGet package cleanup until it finishes" -ForegroundColor Yellow
}}
$installproc = Get-Process -Name "msiexec", "TiWorker", "TrustedInstaller", "MoUsoCoreWorker", "SetupHost", "winget", "choco", "scoop" -ErrorAction SilentlyContinue
if ($installproc) {{
    Write-Host "[Warning] A Windows installer, updater, or package manager is running; defer related temporary-folder cleanup until it finishes" -ForegroundColor Yellow
}}

$cleanTargets = @(
{targets}
)
$protectedPathPattern = [regex]::new({protected_pattern}, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)
$projectMarkers = @(
{project_markers}
)

$available = @()
Write-Host "Choose exactly which items to clean:" -ForegroundColor White
for ($i = 0; $i -lt $cleanTargets.Count; $i++) {{
    $target = $cleanTargets[$i]
    $target | Add-Member -NotePropertyName Index -NotePropertyValue ($i + 1) -Force | Out-Null
    if (Test-Path -LiteralPath $target.Path) {{
        $available += $target
        Write-Host "  [$($target.Index)] $($target.Name) - $($target.Size) - $($target.Path)" -ForegroundColor White
    }} else {{
        Write-Host "  [Missing] $($target.Name) - $($target.Path)" -ForegroundColor Gray
    }}
}}
if ($available.Count -eq 0) {{ Write-Host "No existing targets are available." -ForegroundColor Yellow; exit 0 }}
$availableIndexes = @($available | ForEach-Object {{ $_.Index }})

if ($Select.Count -gt 0) {{
    $invalid = @($Select | Where-Object {{ $availableIndexes -notcontains $_ }})
    if ($invalid.Count -gt 0) {{ throw "Selection index is unavailable. Existing item numbers: $($availableIndexes -join ', ')." }}
    $cleanTargets = @()
    foreach ($index in ($Select | Select-Object -Unique)) {{
        $cleanTargets += @($available | Where-Object {{ $_.Index -eq $index }})
    }}
}} else {{
    $choice = Read-Host "Enter item numbers separated by commas, A for all, or Q to cancel"
    if ([string]::IsNullOrWhiteSpace($choice) -or $choice -match '^(?i:q|quit)$') {{
        Write-Host "Cancelled; nothing was changed." -ForegroundColor Yellow
        exit 0
    }} elseif ($choice -match '^(?i:a|all)$') {{
        $cleanTargets = $available
    }} else {{
        $numbers = @()
        foreach ($token in ($choice -split '[,; ]+')) {{
            $number = 0
            if (-not [int]::TryParse($token, [ref]$number)) {{ throw "Invalid selection '$token'. Enter item numbers, A, or Q." }}
            $numbers += $number
        }}
        $invalid = @($numbers | Where-Object {{ $availableIndexes -notcontains $_ }})
        if ($invalid.Count -gt 0) {{ throw "Selection index is unavailable. Existing item numbers: $($availableIndexes -join ', ')." }}
        $cleanTargets = @()
        foreach ($index in ($numbers | Select-Object -Unique)) {{
            $cleanTargets += @($available | Where-Object {{ $_.Index -eq $index }})
        }}
    }}
}}

Write-Host "`nOnly these selected items will be cleaned:" -ForegroundColor Cyan
foreach ($target in $cleanTargets) {{ Write-Host "  [$($target.Index)] $($target.Path) - $($target.Size)" }}
if (-not $Force) {{
    $confirm = Read-Host "Type CLEAN to back up and remove only the selected items"
    if ($confirm -cne "CLEAN") {{ Write-Host "Cancelled; nothing was changed." -ForegroundColor Yellow; exit 0 }}
}}

# Every run creates and verifies a backup before any removal. An incomplete
# backup aborts the cleanup.
$backupScript = Join-Path $PSScriptRoot 'backup.py'
if (-not (Test-Path -LiteralPath $backupScript)) {{
    throw "Required backup tool is missing: $backupScript"
}}
$backupPaths = @($cleanTargets | ForEach-Object {{ $_.Path }})
Write-Host "`nCreating backup before cleanup..." -ForegroundColor Cyan
$backupOutput = & python $backupScript create --priority {priority_arg} --paths $backupPaths --json
if ($LASTEXITCODE -ne 0) {{ throw "Backup failed. No cleanup was performed." }}
try {{ $backup = ($backupOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop }}
catch {{ throw "Could not verify the backup result. No cleanup was performed." }}
if ($backup.status -ne 'completed' -or $backup.items.Count -ne $cleanTargets.Count) {{
    throw "Backup was incomplete. No cleanup was performed. Review backup $($backup.id)."
}}
Write-Host "Backup created: $($backup.id)" -ForegroundColor Green

Write-Host "`nStarting cleanup..." -ForegroundColor Cyan

$totalCleaned = 0
foreach ($target in $cleanTargets) {{
    Write-Host "Cleaning: $($target.Name)..." -NoNewline
    if (-not (Test-Path $target.Path)) {{
        Write-Host " [Skipped]" -ForegroundColor Gray
        continue
    }}
    try {{
        $item = Get-Item -LiteralPath $target.Path -Force -EA Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{
            throw "Refusing to remove a reparse point or junction"
        }}
        if ([bool]$item.PSIsContainer -ne [bool]$target.IsDirectory) {{
            throw "The item type changed since the scan; rescan before cleanup"
        }}
        if ($item.PSIsContainer) {{
            $entries = @(Get-ChildItem -LiteralPath $target.Path -Recurse -Force -EA Stop)
            $reparseEntry = $entries | Where-Object {{ ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }} | Select-Object -First 1
            if ($reparseEntry) {{ throw "Refusing to clean a directory tree containing a reparse point: $($reparseEntry.FullName)" }}
            # Preserve excluded paths and nested projects even when the user
            # selected a parent folder that contains them.
            $targetRoot = $target.Path.TrimEnd('\\') + '\\'
            $targetRootPath = $targetRoot.TrimEnd('\\')
            $protectedRoots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($entry in $entries) {{
                $protectedRoot = $null
                if ($entry.Name -like 'claude*') {{ $protectedRoot = $entry.FullName }}
                if ($projectMarkers -contains $entry.Name) {{
                    $protectedRoot = [System.IO.Directory]::GetParent($entry.FullName).FullName
                }}
                $normalizedPath = $entry.FullName.TrimEnd('\\') + '\\'
                if ($protectedPathPattern.IsMatch($normalizedPath)) {{ $protectedRoot = $entry.FullName }}
                if ($protectedRoot) {{
                    # Keep only the outermost protected root to avoid a large
                    # list when the scanner reports every descendant.
                    $ancestor = $protectedRoot
                    $alreadyProtected = $false
                    while ($ancestor.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {{
                        if ($protectedRoots.Contains($ancestor.TrimEnd('\\'))) {{ $alreadyProtected = $true; break }}
                        $parent = [System.IO.Directory]::GetParent($ancestor)
                        if (-not $parent) {{ break }}
                        $ancestor = $parent.FullName
                    }}
                    if (-not $alreadyProtected) {{ [void]$protectedRoots.Add($protectedRoot.TrimEnd('\\')) }}
                }}
            }}
            $preservePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($entry in $entries) {{
                $ancestor = $entry.FullName
                $isProtected = $false
                while ($ancestor.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {{
                    if ($protectedRoots.Contains($ancestor.TrimEnd('\\'))) {{ $isProtected = $true; break }}
                    $parent = [System.IO.Directory]::GetParent($ancestor)
                    if (-not $parent) {{ break }}
                    $ancestor = $parent.FullName
                }}
                if ($isProtected) {{
                    $current = $entry.FullName
                    while ($current.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {{
                        [void]$preservePaths.Add($current)
                        $parent = [System.IO.Directory]::GetParent($current)
                        if (-not $parent) {{ break }}
                        $current = $parent.FullName
                    }}
                    [void]$preservePaths.Add($targetRootPath)
                }}
            }}
            $deletable = @($entries | Where-Object {{
                -not $preservePaths.Contains($_.FullName)
            }})
            $before = ($deletable | Where-Object {{ -not $_.PSIsContainer }} | Measure-Object -Property Length -Sum).Sum
            $deletable | Sort-Object {{ $_.FullName.Length }} -Descending | Remove-Item -Force -EA Stop
            if ($preservePaths.Count -gt 0) {{ Write-Host " [Partially cleaned; protected data was preserved]" -ForegroundColor Yellow }}
        }} else {{
            $before = $item.Length
            Remove-Item -LiteralPath $target.Path -Force -EA Stop
        }}
        $cleanedMB = [math]::Round($before / 1MB, 2)
        $totalCleaned += $cleanedMB
        Write-Host " [Done - $cleanedMB MB]" -ForegroundColor Green
    }} catch {{
        Write-Host " [Failed] $($_.Exception.Message)" -ForegroundColor Red
    }}
}}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Cleanup complete! Total: $([math]::Round($totalCleaned / 1024, 2)) GB" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
'''

    # Build the target list.
    targets_str = ""
    for item in items:
        path = _ps_literal(item["path"])
        is_directory = item.get('kind', '').lower() in ('directory', 'folder', '\u76ee\u5f55')
        targets_str += f'''    @{{
        Name = {_ps_literal(item['name'])}
        Path = {path}
        Size = {_ps_literal(item['size_formatted'])}
        IsDirectory = ${str(is_directory).lower()}
    }},
'''

    protected_pattern = "(?:" + "|".join(re.escape(fragment) for fragment in EXCLUDE_PATTERNS) + ")"
    project_markers_str = ",\n".join(f"        {_ps_literal(marker)}" for marker in PROJECT_MARKERS)

    script = script.format(
        priority_name=priority_name,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        targets=targets_str.rstrip(",\n"),
        protected_pattern=_ps_literal(protected_pattern),
        project_markers=project_markers_str,
        priority_arg=priority if priority != "all" else "low"
    )

    # The BOM lets Windows PowerShell 5.1 read Unicode paths correctly.
    with open(output_path, 'x', encoding='utf-8-sig') as f:
        f.write(script)

    return output_path


def write_item_list_report(results, output_path):
    """Write candidates grouped by category to a text file."""
    all_candidate_items = [
        item for category in results["categories"].values() for item in category["items"]
    ]
    _ensure_output_outside_targets(output_path, all_candidate_items)
    lines = []
    lines.append("Disk Cleanup Candidate List")
    lines.append(f"Generated at: {datetime.now().isoformat()}")
    lines.append("")
    lines.append("Tier subtotals may overlap when folders contain candidates from another tier; the overall estimate deduplicates them.")
    lines.append("")

    all_items = []
    for priority in ["high", "medium", "low"]:
        category = results["categories"][priority]
        lines.append("=" * 60)
        lines.append(f"[{category['name']}] - {category['total_size_formatted']} total")
        lines.append("=" * 60)
        if not category["items"]:
            lines.append("(none)")
        else:
            for item in category["items"]:
                all_items.append(item)
                lines.append(f"- {item['size_formatted']}  {item.get('kind', 'item')}  {item['name']}")
                lines.append(f"  {item['path']}")
                risk = "lower risk; review first" if item.get("safe") else "caution; review carefully"
                lines.append(f"  Risk level: {risk}")
        lines.append("")

    lines.append("=" * 60)
    unique_size = sum(item["size"] for item in _non_overlapping_items(all_items))
    lines.append(f"Potential cleanable space (deduplicated across tiers): {format_size(unique_size)}")
    lines.append("Folder totals can include nested protected data, which cleanup preserves.")
    lines.append("Every exact path still requires review; estimates can differ from space actually recovered.")
    lines.append("=" * 60)

    with open(output_path, "x", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return output_path


def clear_screen():
    """Clear the terminal screen for the interactive UI."""
    os.system("cls" if os.name == "nt" else "clear")


def prompt_choice(prompt, choices, default=None):
    """Read a menu choice, optionally using a default value."""
    suffix = f" [{default}]" if default is not None else ""
    while True:
        value = input(f"{prompt}{suffix}: ").strip()
        if not value and default is not None:
            return default
        if value in choices:
            return value
        print(f"Please enter one of: {', '.join(choices)}")


def prompt_existing_csv(initial_csv=None):
    """Choose a scan CSV or enter its path."""
    if initial_csv and os.path.exists(initial_csv):
        return initial_csv

    latest = get_latest_scan()

    while True:
        clear_screen()
        print("Disk Cleanup Analyzer - Select a data source")
        print("=" * 60)
        if latest:
            print(f"Latest scan file: {latest}")
        else:
            print("No recent scan file found")
        print()
        print("1) Use latest scan file")
        print("2) Enter CSV path manually")
        print("0) Exit")
        choice = input("\nChoice: ").strip()

        if choice == "1":
            if latest:
                return latest
            print("No latest scan file is available.")
            input("Press Enter to continue...")
        elif choice == "2":
            manual = input("Enter the CSV file path: ").strip().strip('"')
            if os.path.exists(manual):
                return manual
            print("File not found. Please try again.")
            input("Press Enter to continue...")
        elif choice in {"0", "q", "Q"}:
            return None
        else:
            print("Invalid choice.")
            input("Press Enter to continue...")


def run_tui(initial_csv=None, min_size_mb=50):
    """Run the interactive terminal interface."""
    csv_file = prompt_existing_csv(initial_csv)
    if not csv_file:
        return

    current_min_size = min_size_mb

    while True:
        if not os.path.exists(csv_file):
            print(f"Error: file not found - {csv_file}")
            input("Press Enter to choose a different data source...")
            csv_file = prompt_existing_csv()
            if not csv_file:
                return
            continue

        print("Analyzing scan export...", end="", flush=True)

        def show_analysis_progress(rows_processed):
            print(f"\rAnalyzing scan export... {rows_processed:,} rows", end="", flush=True)

        try:
            results = analyze_csv(csv_file, current_min_size, progress_callback=show_analysis_progress)
        except (ValueError, csv.Error) as exc:
            print(f"\nCould not analyze this scan export: {exc}")
            input("Press Enter to choose another scan...")
            csv_file = prompt_existing_csv()
            if not csv_file:
                return
            continue
        print("\rAnalysis complete.                              ", flush=True)

        while True:
            clear_screen()
            print("Disk Cleanup Analyzer - TUI")
            print("=" * 60)
            print(f"CSV: {csv_file}")
            print(f"Minimum file size: {current_min_size} MB")
            print()
            print_report(results, item_limit=5)
            print()
            print("1) View all candidates")
            print("2) Export candidate list to a file")
            print("3) Generate cleanup script")
            print("4) Adjust minimum file size and re-analyze")
            print("5) Switch CSV file")
            print("0) Exit")

            choice = input("\nChoice: ").strip().lower()

            if choice == "1":
                clear_screen()
                print("All candidates")
                print("=" * 60)
                print_report(results, show_all_items=True, item_limit=9999)
                input("\nPress Enter to go back...")
            elif choice == "2":
                default_name = f"{Path(csv_file).stem}.candidates.txt"
                output_path = input(f"Output file path [{default_name}]: ").strip().strip('"') or default_name
                try:
                    write_item_list_report(results, output_path)
                    print(f"Candidate list written to: {output_path}")
                except (ValueError, OSError) as exc:
                    print(f"Could not write candidate list: {exc}")
                input("Press Enter to continue...")
            elif choice == "3":
                default_name = f"{Path(csv_file).stem}.clean.ps1"
                output_path = input(f"Cleanup script path [{default_name}]: ").strip().strip('"') or default_name
                priority = prompt_choice("Priority", ["high", "medium", "low", "all"], default="high")
                try:
                    generate_clean_script(results, output_path, priority)
                    print(f"Cleanup script written to: {output_path}")
                except (ValueError, OSError) as exc:
                    print(f"Could not create cleanup script: {exc}")
                input("Press Enter to continue...")
            elif choice == "4":
                new_size = input(f"New minimum file size MB [{current_min_size}]: ").strip()
                if new_size:
                    try:
                        current_min_size = max(1, int(new_size))
                    except ValueError:
                        print("Please enter a valid integer.")
                        input("Press Enter to continue...")
                        continue
                break
            elif choice == "5":
                new_csv = prompt_existing_csv()
                if new_csv:
                    csv_file = new_csv
                else:
                    return
                break
            elif choice in {"0", "q", "quit", "exit"}:
                return
            else:
                print("Invalid choice.")
                input("Press Enter to continue...")


def main():
    import argparse

    parser = argparse.ArgumentParser(description='WizTree CSV analysis tool')
    parser.add_argument('csv_file', nargs='?', help='Path to a WizTree CSV export')
    parser.add_argument('--min-size', type=int, default=50, help='Minimum file size (MB)')
    parser.add_argument('--output', help='Output path for the cleanup script')
    parser.add_argument('--priority', choices=['high', 'medium', 'low', 'all'], default='high',
                        help='Priority level for generated cleanup scripts')
    parser.add_argument('--list-items', action='store_true', help='List all candidates by category (files and folders)')
    parser.add_argument('--list-output', help='Write the categorized candidate list to a text file')
    parser.add_argument('--item-limit', type=int, default=10, help='Number of items to show per category in the normal report')
    parser.add_argument('--tui', action='store_true', help='Start the interactive terminal UI')
    parser.add_argument('--json', action='store_true', help='Output JSON format')

    args = parser.parse_args()

    if args.tui:
        run_tui(args.csv_file, args.min_size)
        return

    if not args.csv_file:
        parser.error('csv_file is required unless --tui is used')

    if not os.path.exists(args.csv_file):
        print(f"Error: file not found - {args.csv_file}")
        sys.exit(1)

    try:
        results = analyze_csv(args.csv_file, args.min_size)
    except (ValueError, csv.Error) as exc:
        parser.error(f"could not analyze scan export: {exc}")

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        print_report(results, show_all_items=args.list_items, item_limit=args.item_limit)

    if args.output:
        try:
            generate_clean_script(results, args.output, args.priority)
        except (ValueError, OSError) as exc:
            parser.error(f"could not create cleanup script: {exc}")
        print(f"\nCleanup script written to: {args.output}")

    if args.list_output:
        try:
            write_item_list_report(results, args.list_output)
        except (ValueError, OSError) as exc:
            parser.error(f"could not write candidate list: {exc}")
        print(f"\nCandidate list written to: {args.list_output}")


if __name__ == "__main__":
    main()
