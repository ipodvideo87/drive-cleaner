"""Run read-only previews and reviewed cleanup plans in PowerShell."""

import shutil
import subprocess

import scan
from error_messages import describe_error


def _find_powershell():
    return shutil.which("pwsh") or shutil.which("powershell")


def offer_to_preview_cleanup_script(script_path):
    """Run a guided preview; return True on success, False on failure, None if skipped."""
    print("A read-only preview lists every eligible file and folder in this plan.")
    print("It repeats safety checks and may take time for large selections; it creates no backup and removes nothing.")
    try:
        while True:
            answer = input("Show the full cleanup preview now? [Y/n]: ").strip().casefold()
            if answer in {"", "y", "yes"}:
                break
            if answer in {"n", "no"}:
                print("Preview skipped; the saved plan is unchanged and nothing was removed.")
                return None
            print("Enter Y or N.")
    except (EOFError, KeyboardInterrupt):
        print("Preview cancelled; the saved plan is unchanged and nothing was removed.")
        return None

    powershell = _find_powershell()
    if not powershell:
        print("PowerShell was not found. The plan is saved; no files were changed.")
        return False

    print("Starting the read-only cleanup preview.")
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-PreviewOnly"],
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"Could not start the preview: {describe_error(exc)}. No files were changed.")
        return False
    if result.returncode != 0:
        print(f"The preview stopped with status {result.returncode}. No files were removed.")
        return False
    return True


def offer_to_run_cleanup_script(script_path):
    """Offer to launch a new plan when this window is already running as Administrator."""
    if not scan.check_admin():
        return False

    print("This window is running as Administrator.")
    print("The plan will show these entries again so you can choose which to clean and confirm.")
    try:
        while True:
            answer = input("Run the new cleanup plan now? [y/N]: ").strip().casefold()
            if answer in {"", "n", "no"}:
                print("Cleanup plan saved for later; nothing has been removed.")
                return False
            if answer in {"y", "yes"}:
                break
            print("Enter Y or N.")
    except (EOFError, KeyboardInterrupt):
        print("Launch cancelled; the cleanup plan is saved and nothing has been removed.")
        return False

    powershell = _find_powershell()
    if not powershell:
        print("PowerShell was not found. The cleanup plan is saved and can be run later.")
        return False

    print("Starting the cleanup plan in this administrator session.")
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"Could not start the cleanup plan: {describe_error(exc)}")
        return False
    if result.returncode != 0:
        print(f"The cleanup plan exited with status {result.returncode}.")
    return True
