#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WizTree CSV 分析工具
分析扫描结果，识别可清理的目录
"""

import csv
import ntpath
import os
import sys
import json
from datetime import datetime
from pathlib import Path

from scan import get_latest_scan

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="backslashreplace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(errors="backslashreplace")

# 可清理目录的模式定义
CLEANABLE_PATTERNS = {
    "high": {
        "name": "High Priority (Safe to Clean)",
        "patterns": [
            {"pattern": "\\softwaredistribution\\download\\", "name": "Windows Update download cache", "safe": True},
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
            {"pattern": "\\temp\\", "name": "Temporary files", "safe": True},
            {"pattern": "\\tmp\\", "name": "Temporary files", "safe": True},
        ]
    },
    "medium": {
        "name": "Medium Priority (Use Caution)",
        "patterns": [
            {"pattern": "\\cache\\", "name": "Application cache", "safe": False},
            {"pattern": "\\caches\\", "name": "Application cache", "safe": False},
            {"pattern": "\\logs\\", "name": "Log files", "safe": False},
            {"pattern": "$winreagent", "name": "Windows update recovery staging (only after the update has been successful for more than 10 days)", "safe": False},
            {"pattern": "gpucache", "name": "GPU cache", "safe": False},
            {"pattern": "shadercache", "name": "Shader cache", "safe": False},
            {"pattern": "code cache", "name": "Code cache", "safe": False},
            {"pattern": "service worker", "name": "Service Worker cache", "safe": False},
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

# 安全红线：绝不列入清理建议（宁可漏清，不可错删）
EXCLUDE_PATTERNS = [
    # 系统关键
    "\\windows\\winsxs",
    "\\windows\\system32",
    "\\windows\\syswow64",
    "\\windows\\installer",              # 已装软件的修复/卸载依赖
    "\\program files\\",
    "\\program files (x86)\\",
    "\\programdata\\microsoft\\windows\\",
    "system volume information",         # 系统还原点
    "\\driverstore\\",                   # 现役驱动库
    "$recycle.bin",
    # 安装修复缓存（删了软件将无法修复/卸载）
    "package cache",
    "installercache",
    # 个人数据
    "\\documents\\",
    "\\desktop\\",
    "\\pictures\\",
    "\\videos\\",
    "\\onedrive",
    "tencent files",                     # QQ 接收的文件
    "xwechat_files",                     # 微信接收的文件
    "wechat files",
    # 凭据与配置
    "\\.ssh\\",
    "\\.gnupg\\",
]


def format_size(size_bytes):
    """格式化文件大小"""
    if size_bytes >= 1024 ** 3:
        return f"{size_bytes / (1024 ** 3):.2f} GB"
    elif size_bytes >= 1024 ** 2:
        return f"{size_bytes / (1024 ** 2):.2f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KB"
    return f"{size_bytes} B"


def classify_path(path):
    """判断扫描项更像文件还是目录"""
    if path.endswith("\\") or path.endswith("/"):
        return "Directory"
    return "File"


def _is_under(child, parent):
    """Windows-aware path containment, including case and trailing separators."""
    child_key = _path_key(child)
    parent_key = _path_key(parent)
    return child_key != parent_key and child_key.startswith(parent_key.rstrip("\\") + "\\")


def _path_key(path):
    return ntpath.normcase(ntpath.normpath(path.replace("/", "\\")))


def _is_local_drive_path(path):
    normalized = path.replace("/", "\\")
    drive, tail = ntpath.splitdrive(normalized)
    return (len(drive) == 2 and drive[0].isalpha() and drive[1] == ":" and
            tail.startswith("\\") and not normalized.startswith("\\\\") and
            ntpath.normpath(normalized) == normalized.rstrip("\\") and
            ntpath.normpath(normalized) != drive + "\\")


def _ps_literal(value):
    """Encode untrusted data as a PowerShell single-quoted string literal."""
    return "'" + str(value).replace("'", "''") + "'"


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


def analyze_csv(csv_path, min_size_mb=50):
    """分析 CSV 文件"""
    results = {
        "scan_file": csv_path,
        "scan_time": datetime.now().isoformat(),
        "total_size": 0,
        "free_space": 0,
        "used_space": 0,
        "categories": {
            "high": {"name": "High priority — lower risk (review each path)", "items": [], "total_size": 0},
            "medium": {"name": "Medium priority — review carefully", "items": [], "total_size": 0},
            "low": {"name": "Low priority — confirm the impact first", "items": [], "total_size": 0},
        }
    }

    if min_size_mb < 0:
        raise ValueError("min_size_mb must be zero or greater")
    min_size = min_size_mb * 1024 * 1024

    with open(csv_path, 'r', encoding='utf-8-sig') as f:
        # 兼容 GUI 导出：首行可能是 "Generated by WizTree..." 说明行（命令行导出没有），需要跳过
        pos = f.tell()
        first_line = f.readline()
        if ('文件名称' in first_line) or ('File Name' in first_line):
            f.seek(pos)
        reader = csv.DictReader(f)

        for row in reader:
            try:
                # 兼容中英文界面导出的列名
                path = row.get('文件名称') or row.get('File Name') or ''
                logical_size = int(row.get('大小') or row.get('Size') or 0)
                allocated_raw = row.get('Allocated') or row.get('已分配') or row.get('分配大小') or row.get('占用空间')
                if allocated_raw is None or allocated_raw == "":
                    size = logical_size
                else:
                    allocated_raw = str(allocated_raw).strip()
                    # WizTree prefixes hard-link allocated values with 0.
                    size = 0 if len(allocated_raw) > 1 and allocated_raw.startswith("0") else int(allocated_raw or 0)

                # 获取驱动器信息（只有根目录有）
                if path.rstrip("\\/").endswith(":"):
                    results["total_size"] = int(row.get('DRIVECAPACITY', 0))
                    results["free_space"] = int(row.get('FREESPACE', 0))
                    results["used_space"] = int(row.get('USEDSPACE', 0))

                # Imported CSVs are data, not authority. Only accept ordinary
                # absolute drive paths and reject roots, traversal, UNC, and
                # device paths before any item can become executable.
                if not _is_local_drive_path(path):
                    continue

                # 跳过小文件和排除目录
                if size <= 0 or size < min_size:
                    continue

                path_lower = path.replace("/", "\\").lower()

                # 检查是否在排除列表中
                is_excluded = any(os.path.normcase(exc) in _path_key(path) for exc in EXCLUDE_PATTERNS)
                if is_excluded:
                    continue

                # 检查匹配的清理类别
                for priority, category in CLEANABLE_PATTERNS.items():
                    for pattern_info in category["patterns"]:
                        if pattern_info["pattern"] in path_lower:
                            # 检查是否已经有父目录在列表中
                            existing_paths = [item["path"] for item in results["categories"][priority]["items"]]
                            is_subdir = any(_is_under(path, p) for p in existing_paths)

                            if not is_subdir:
                                # 移除已有的子目录
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

    # 计算每个类别的总大小并排序
    for priority in results["categories"]:
        items = results["categories"][priority]["items"]
        items.sort(key=lambda x: x["size"], reverse=True)
        results["categories"][priority]["total_size"] = sum(item["size"] for item in items)
        results["categories"][priority]["total_size_formatted"] = format_size(
            results["categories"][priority]["total_size"]
        )

    return results


def print_category_items(category, show_all=False, item_limit=10):
    """打印单个类别下的候选项"""
    items = category["items"]
    if not items:
        return

    visible_items = items if show_all else items[:item_limit]
    for item in visible_items:
        print(f"  {item['size_formatted']:>10}  {item.get('kind', '项目')}  {item['name']}")
        print(f"             {item['path']}")

    if not show_all and len(items) > item_limit:
        print(f"  ... 还有 {len(items) - item_limit} 个项目")


def print_report(results, show_all_items=False, item_limit=10):
    """打印分析报告"""
    print("=" * 60)
    print("           Disk Cleanup Analysis Report")
    print("=" * 60)
    print()

    if results["total_size"] > 0:
        print(f"Total capacity: {format_size(results['total_size'])}")
        print(f"Used space:     {format_size(results['used_space'])}")
        print(f"Free space:     {format_size(results['free_space'])}")
        print()

    total_cleanable = 0

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
    print("Protected: Windows system stores and installers, restore data, personal folders, messaging data, and credential folders.")
    print("Estimate uses allocated size when WizTree provides it; hard links are excluded. Actual free space may differ.")
    print("=" * 60)


def generate_clean_script(results, output_path, priority="high"):
    """生成清理脚本"""
    if priority == "all":
        items = []
        for key in ["high", "medium", "low"]:
            items.extend(results["categories"][key]["items"])
        # 去重并按大小排序，避免同一路径在不同优先级下重复进入脚本
        deduped = {}
        for item in items:
            deduped[_path_key(item["path"])] = item
        items = list(deduped.values())
        priority_name = "All priorities (high / medium / low)"
    else:
        items = results["categories"][priority]["items"]
        priority_name = results["categories"][priority]["name"]

    # A parent candidate covers descendants even when rules put them in
    # different tiers. Emit a non-overlapping plan to prevent double counting.
    items = _non_overlapping_items(items)
    if not items:
        raise ValueError("No cleanup candidates were found for the selected priority")

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

$cleanTargets = @(
{targets}
)

$available = @()
Write-Host "Choose exactly which items to clean:" -ForegroundColor White
for ($i = 0; $i -lt $cleanTargets.Count; $i++) {{
    $target = $cleanTargets[$i]
    if (Test-Path -LiteralPath $target.Path) {{
        $target | Add-Member -NotePropertyName Index -NotePropertyValue ($available.Count + 1) -Force | Out-Null
        $available += $target
        Write-Host "  [$($target.Index)] $($target.Name) - $($target.Size) - $($target.Path)" -ForegroundColor White
    }} else {{
        Write-Host "  [Missing] $($target.Name) - $($target.Path)" -ForegroundColor Gray
    }}
}}
if ($available.Count -eq 0) {{ Write-Host "No existing targets are available." -ForegroundColor Yellow; exit 0 }}

if ($Select.Count -gt 0) {{
    $invalid = @($Select | Where-Object {{ $_ -lt 1 -or $_ -gt $available.Count }})
    if ($invalid.Count -gt 0) {{ throw "Selection index is out of range. Valid indexes are 1 through $($available.Count)." }}
    $cleanTargets = @($Select | Select-Object -Unique | ForEach-Object {{ $available[$_ - 1] }})
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
        $invalid = @($numbers | Where-Object {{ $_ -lt 1 -or $_ -gt $available.Count }})
        if ($invalid.Count -gt 0) {{ throw "Selection index is out of range. Valid indexes are 1 through $($available.Count)." }}
        $cleanTargets = @($numbers | Select-Object -Unique | ForEach-Object {{ $available[$_ - 1] }})
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
            # Preserve every claude* item and its subtree at any depth.
            $claudePaths = @($entries | Where-Object {{ $_.Name -like 'claude*' }} | ForEach-Object {{ $_.FullName }})
            $deletable = @($entries | Where-Object {{
                $relative = $_.FullName.Substring($target.Path.TrimEnd('\\').Length).TrimStart('\\')
                $entryPrefix = $_.FullName.TrimEnd('\\') + '\\'
                $isClaude = [bool]($relative.Split([IO.Path]::DirectorySeparatorChar) | Where-Object {{ $_ -like 'claude*' }})
                $hasClaudeChild = [bool]($claudePaths | Where-Object {{ $_.StartsWith($entryPrefix, [System.StringComparison]::OrdinalIgnoreCase) }})
                -not $isClaude -and -not $hasClaudeChild
            }})
            $before = ($deletable | Where-Object {{ -not $_.PSIsContainer }} | Measure-Object -Property Length -Sum).Sum
            $deletable | Sort-Object {{ $_.FullName.Length }} -Descending | Remove-Item -Force -EA Stop
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

    # 生成目标列表
    targets_str = ""
    for item in items:
        path = _ps_literal(item["path"])
        targets_str += f'''    @{{
        Name = {_ps_literal(item['name'])}
        Path = {path}
        Size = {_ps_literal(item['size_formatted'])}
        IsDirectory = ${str(item.get('kind', '').lower() in ('directory', 'folder', '目录')).lower()}
    }},
'''

    script = script.format(
        priority_name=priority_name,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        targets=targets_str.rstrip(",\n"),
        priority_arg=priority if priority != "all" else "low"
    )

    # The BOM lets Windows PowerShell 5.1 read Unicode paths correctly.
    with open(output_path, 'w', encoding='utf-8-sig') as f:
        f.write(script)

    return output_path


def write_item_list_report(results, output_path):
    """把按类别整理的候选项写成文本文件"""
    lines = []
    lines.append("Disk Cleanup Candidate List")
    lines.append(f"Generated at: {datetime.now().isoformat()}")
    lines.append("")

    total_cleanable = 0
    for priority in ["high", "medium", "low"]:
        category = results["categories"][priority]
        lines.append("=" * 60)
        lines.append(f"[{category['name']}] - {category['total_size_formatted']} total")
        lines.append("=" * 60)
        if not category["items"]:
            lines.append("(none)")
        else:
            for item in category["items"]:
                lines.append(f"- {item['size_formatted']}  {item.get('kind', 'item')}  {item['name']}")
                lines.append(f"  {item['path']}")
                lines.append(f"  Safe: {'yes' if item.get('safe') else 'no'}")
        lines.append("")
        total_cleanable += category["total_size"]

    lines.append("=" * 60)
    lines.append(f"Potential cleanable space: {format_size(total_cleanable)}")
    lines.append("=" * 60)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    return output_path


def clear_screen():
    """清屏，给 TUI 用"""
    os.system("cls" if os.name == "nt" else "clear")


def prompt_choice(prompt, choices, default=None):
    """读取一个带默认值的菜单选择"""
    suffix = f" [{default}]" if default is not None else ""
    while True:
        value = input(f"{prompt}{suffix}: ").strip()
        if not value and default is not None:
            return default
        if value in choices:
            return value
        print(f"Please enter one of: {', '.join(choices)}")


def prompt_existing_csv(initial_csv=None):
    """选择或输入一个可用的 CSV 文件"""
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
    """交互式终端界面"""
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

        results = analyze_csv(csv_file, current_min_size)

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
                write_item_list_report(results, output_path)
                print(f"Candidate list written to: {output_path}")
                input("Press Enter to continue...")
            elif choice == "3":
                default_name = f"{Path(csv_file).stem}.clean.ps1"
                output_path = input(f"Cleanup script path [{default_name}]: ").strip().strip('"') or default_name
                priority = prompt_choice("Priority", ["high", "medium", "low", "all"], default="high")
                generate_clean_script(results, output_path, priority)
                print(f"Cleanup script written to: {output_path}")
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

    results = analyze_csv(args.csv_file, args.min_size)

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        print_report(results, show_all_items=args.list_items, item_limit=args.item_limit)

    if args.output:
        generate_clean_script(results, args.output, args.priority)
        print(f"\nCleanup script written to: {args.output}")

    if args.list_output:
        write_item_list_report(results, args.list_output)
        print(f"\nCandidate list written to: {args.list_output}")


if __name__ == "__main__":
    main()
