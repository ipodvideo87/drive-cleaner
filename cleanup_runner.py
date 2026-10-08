"""Run read-only previews and reviewed cleanup plans in PowerShell."""

import shutil
import subprocess

import scan
from error_messages import describe_error


def _find_powershell():
    return shutil.which("pwsh") or shutil.which("powershell")


def offer_to_preview_cleanup_script(script_path):
    """Run a guided preview; return True on success, False on failure, None if skipped."""
    print("A read-only preview shows every file and folder this plan could remove after its safety checks.")
    print("It repeats safety checks and may take time for large selections; it creates no backup and removes nothing.")
    try:
        while True:
            answer = input(
                "Show the full cleanup preview now? "
                "[Y/n] (Enter or Y = preview every selected path; N = skip preview): "
            ).strip().casefold()
            if answer in {"", "y", "yes"}:
                break
            if answer in {"n", "no"}:
                print("Preview skipped; the saved plan is unchanged and nothing was removed.")
                return None
            print("Enter Y to preview the selected paths or N to skip the preview.")
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
    admin_status = scan.check_admin_status()
    if admin_status is None:
        print(
            "Could not determine whether this window is running as Administrator. "
            "The cleanup plan is saved; no files were changed."
        )
        return False
    if not admin_status:
        print("This window is not running as Administrator. The cleanup plan is saved; no files were changed.")
        return False

    print("This window is running as Administrator.")
    print("The plan will show your saved selection again, then ask about a backup and final confirmation.")
    try:
        while True:
            answer = input(
                "Run the saved cleanup plan now? "
                "[y/N] (Y = open the plan and continue its confirmations; Enter or N = save for later): "
            ).strip().casefold()
            if answer in {"", "n", "no"}:
                print("Cleanup plan saved for later; nothing has been removed.")
                return False
            if answer in {"y", "yes"}:
                break
            print("Enter Y to open the plan now or N to save it for later.")
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
