import csv
import io
import json
import os
import shutil
import subprocess
import struct
import sys
import tempfile
import time
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import analyze
import backup
import scan
import drive_cleaner
from error_messages import describe_error


class ErrorMessageTests(unittest.TestCase):
    def test_localized_os_error_text_is_replaced_with_english_summary(self):
        error = PermissionError(13, "localized access-denied text", "private-path")
        message = describe_error(error)
        self.assertIn("Access was denied", message)
        self.assertNotIn("localized access-denied text", message)
        self.assertNotIn("private-path", message)

    def test_unknown_os_errors_keep_a_stable_error_code(self):
        message = describe_error(OSError(12345, "localized operating-system text"))
        self.assertIn("error code 12345", message)
        self.assertNotIn("localized operating-system text", message)

    def test_scan_validation_uses_the_english_os_error_summary(self):
        with mock.patch("builtins.open", side_effect=PermissionError(
                13, "localized access-denied text", "private-scan.csv")):
            valid, message = scan.validate_scan_export("private-scan.csv")
        self.assertFalse(valid)
        self.assertIn("CSV could not be read: Access was denied", message)
        self.assertNotIn("localized access-denied text", message)
        self.assertNotIn("private-scan.csv", message)


class KnowledgeBaseConsistencyTests(unittest.TestCase):
    def test_automated_tiers_and_manual_only_examples_are_distinguished(self):
        knowledge_path = Path(__file__).resolve().parent.parent / "references" / "knowledge.md"
        knowledge = knowledge_path.read_text(encoding="utf-8")
        automated_section = knowledge.split("## What Drive Cleanr suggests automatically", 1)[1]
        automated_section = automated_section.split("## Path patterns to review", 1)[0]

        for phrase in (
            "Puppeteer", "Electron", "npm", "Yarn", "Windows crash dumps",
            "Chocolatey staging", "generic cache, log, GPU, shader, and code-cache",
            "Gradle", "Cargo registry", "NuGet", "Go module", "Scoop",
            "NVIDIA App", "Playwright", "Chrome/Edge profile IndexedDB",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, automated_section)

        for phrase in (
            "manual guidance rather than automatic Drive Cleanr cleanup candidates",
            "the Recycle Bin", "DISM component cleanup", "MyDrivers",
            "Maven `.m2`", "GoogleUpdater `crx_cache`", "WER reports",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, knowledge)


class AnalyzeSafetyTests(unittest.TestCase):
    @staticmethod
    def _install_complete_mock_backup(plan_dir):
        """Provide a tiny CLI stub so cleanup tests never create real backups."""
        plan_root = Path(plan_dir)
        calls = plan_root / "backup-calls.txt"
        helper = plan_root / "backup.py"
        helper.write_text(
            "import json, sys\nfrom pathlib import Path\n"
            f"calls = Path({str(calls)!r})\n"
            "with calls.open('a', encoding='utf-8') as stream: stream.write(sys.argv[1] + '\\n')\n"
            "if sys.argv[1] == 'verify':\n"
            "    print(json.dumps({'status': 'verified'}))\n"
            "    raise SystemExit(0)\n"
            "start = sys.argv.index('--paths') + 1\n"
            "end = sys.argv.index('--json')\n"
            "paths = sys.argv[start:end]\n"
            "print(json.dumps({'status': 'completed', 'id': 'mock-backup', "
            "'items': [{'path': path} for path in paths]}))\n",
            encoding="utf-8",
        )
        return calls

    @staticmethod
    def _install_mock_backup_that_changes_stream_on_verify(
        plan_dir, stream_path, replacement, base_path
    ):
        """Simulate a named stream changing after its recovery copy was verified."""
        helper = Path(plan_dir) / "backup.py"
        helper.write_text(
            "import json, os, sys\n"
            f"stream_path = {str(stream_path)!r}\n"
            f"base_path = {str(base_path)!r}\n"
            f"replacement = {replacement!r}\n"
            "if sys.argv[1] == 'verify':\n"
            "    before = os.stat(base_path)\n"
            "    with open(stream_path, 'wb') as stream: stream.write(replacement)\n"
            "    os.utime(base_path, ns=(before.st_atime_ns, before.st_mtime_ns))\n"
            "    print(json.dumps({'status': 'verified'}))\n"
            "    raise SystemExit(0)\n"
            "start = sys.argv.index('--paths') + 1\n"
            "end = sys.argv.index('--json')\n"
            "items = [{'path': path} for path in sys.argv[start:end]]\n"
            "print(json.dumps({'status': 'completed', 'id': 'mock-backup', 'items': items}))\n",
            encoding="utf-8",
        )
        return helper

    def test_cleanup_selection_parser_requires_an_explicit_selection(self):
        self.assertIsNone(analyze.parse_cleanup_selection("", 3))
        self.assertIsNone(analyze.parse_cleanup_selection("q", 3))
        self.assertEqual(analyze.parse_cleanup_selection("2, 1;2", 3), [2, 1])
        self.assertEqual(analyze.parse_cleanup_selection("A", 3), [1, 2, 3])
        for answer in ("0", "4", "1,x"):
            with self.subTest(answer=answer), self.assertRaises(ValueError):
                analyze.parse_cleanup_selection(answer, 3)

    def test_cleanup_picker_labels_files_and_folders_and_limits_selection_to_listed_entries(self):
        results = {"categories": {
            "high": {"name": "High", "items": [
                {"path": r"C:\Users\A\AppData\Local\Temp\large-file.tmp", "size": 10,
                 "size_formatted": "10 B", "kind": "File", "name": "Temporary file"},
                {"path": r"C:\Users\A\AppData\Local\Temp\cache", "size": 20,
                 "size_formatted": "20 B", "kind": "Directory", "name": "Temporary files"},
            ]},
            "medium": {"name": "Medium", "items": []},
            "low": {"name": "Low", "items": []},
        }}
        output = io.StringIO()
        with mock.patch("builtins.input", return_value="1,2"), redirect_stdout(output):
            selected = analyze.select_cleanup_candidates(results, "high")
        self.assertEqual(selected, [
            r"C:\Users\A\AppData\Local\Temp\large-file.tmp",
            r"C:\Users\A\AppData\Local\Temp\cache",
        ])
        self.assertIn("| File |", output.getvalue())
        self.assertIn("| Folder |", output.getvalue())
        self.assertIn("Each row is labeled File or Folder.", output.getvalue())
        self.assertIn("Choose individual files, folders, or both by number.", output.getvalue())
        self.assertIn("Choosing a folder includes files and folders inside it, even when they are not separate scan suggestions.", output.getvalue())
        self.assertIn("Higher-risk candidates inside selected folders are kept unless you explicitly select their listed entries too.", output.getvalue())
        self.assertIn("Only listed entries can be selected.", output.getvalue())

    def test_generated_plan_contains_only_explicitly_selected_candidates(self):
        first_path = r"C:\Users\A\AppData\Local\Temp\selected-cache"
        second_path = r"C:\Users\A\AppData\Local\Temp\unselected-cache"
        label = "Temporary files (check for installers or builds in progress)"
        results = {"categories": {
            "high": {"items": [
                {"path": first_path, "name": label, "size": 100,
                 "size_formatted": "100 B", "kind": "Directory"},
                {"path": second_path, "name": label, "size": 200,
                 "size_formatted": "200 B", "kind": "Directory"},
            ]},
            "medium": {"items": []},
            "low": {"items": []},
        }}
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "selected.ps1"
            with mock.patch.object(analyze, "_is_local_drive_path", return_value=True), \
                 mock.patch.object(scan, "_path_has_reparse_component", return_value=False), \
                 mock.patch.object(analyze, "_is_excluded_path", return_value=False), \
                 mock.patch.object(analyze, "_matches_cleanup_rule", return_value=True), \
                 mock.patch.object(analyze, "_inside_project_tree", return_value=False), \
                 mock.patch.object(analyze, "_ensure_output_outside_targets"):
                analyze.generate_clean_script(
                    results, str(output_path), "high", selected_paths=[first_path]
                )
            script = output_path.read_text(encoding="utf-8-sig")
            self.assertIn(f"Path = '{first_path}'", script)
            self.assertNotIn("unselected-cache", script)
            self.assertIn("[int[]]$Select = @(1)", script)
            self.assertIn("ItemType = 'Folder'", script)
            self.assertIn("$($target.ItemType) | $($target.Path)", script)
            self.assertIn("Drive Cleanr Cleanup Plan", script)
            self.assertIn("Files and folders already selected for this plan:", script)
            self.assertIn("Selected targets (folder contents are included, except protected and project data and higher-risk candidates you did not explicitly select):", script)
            self.assertIn("higher-risk candidates you did not explicitly select", script)

            with self.assertRaisesRegex(ValueError, "not in the chosen candidate list"):
                analyze.generate_clean_script(
                    results, str(Path(temp_dir) / "unknown.ps1"), "high",
                    selected_paths=[r"C:\Users\A\AppData\Local\Temp\not-listed"],
                )
            with self.assertRaisesRegex(ValueError, "Select at least one"):
                analyze.generate_clean_script(
                    results, str(Path(temp_dir) / "empty.ps1"), "high", selected_paths=[]
                )

    def test_review_menu_builds_plan_from_only_numbered_selection(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            csv_path = root / "scan.csv"
            csv_path.write_text("placeholder", encoding="utf-8")
            selected_path = r"C:\Users\A\AppData\Local\Temp\selected-cache"
            other_path = r"C:\Users\A\AppData\Local\Temp\other-cache"
            label = "Temporary files (check for installers or builds in progress)"
            selected_item = {
                "path": selected_path, "size": 100, "size_formatted": "100 B",
                "kind": "Directory", "name": label, "safe": True,
            }
            other_item = {
                "path": other_path, "size": 200, "size_formatted": "200 B",
                "kind": "Directory", "name": label, "safe": True,
            }
            results = {
                "scan_file": str(csv_path), "scan_time": "now", "total_size": 0,
                "free_space": 0, "used_space": 0, "space_source": None,
                "categories": {
                    "high": {"name": "High", "items": [selected_item, other_item]},
                    "medium": {"name": "Medium", "items": []},
                    "low": {"name": "Low", "items": []},
                },
            }
            plan_path = root / "reviewed.ps1"
            output = io.StringIO()
            with mock.patch.object(analyze, "analyze_csv", return_value=results), \
                 mock.patch.object(analyze, "clear_screen"), \
                 mock.patch("builtins.input", side_effect=[
                     "3", "high", "1", str(plan_path), "", "0",
                 ]), \
                 mock.patch.object(analyze, "generate_clean_script") as generate, \
                 mock.patch.object(analyze, "offer_to_run_cleanup_script") as offer, \
                 redirect_stdout(output):
                analyze.run_tui(initial_csv=str(csv_path))
            generate.assert_called_once_with(
                results, str(plan_path), "high", selected_paths=[selected_path]
            )
            offer.assert_called_once_with(str(plan_path))
            self.assertIn("Minimum item size shown: 50 MB", output.getvalue())
            self.assertIn("3) Choose individual files, folders, or both for a cleanup plan", output.getvalue())
            self.assertIn("| Folder |", output.getvalue())

    def test_cleanup_script_run_offer_is_hidden_without_admin_token(self):
        with mock.patch.object(analyze.scan, "check_admin", return_value=False), \
             mock.patch("builtins.input") as prompt, \
             mock.patch.object(analyze.subprocess, "run") as run_script:
            self.assertFalse(analyze.offer_to_run_cleanup_script("reviewed.ps1"))
        prompt.assert_not_called()
        run_script.assert_not_called()

    def test_admin_cleanup_script_run_offer_defaults_to_saved_plan(self):
        with mock.patch.object(analyze.scan, "check_admin", return_value=True), \
             mock.patch("builtins.input", return_value=""), \
             mock.patch.object(analyze.subprocess, "run") as run_script:
            self.assertFalse(analyze.offer_to_run_cleanup_script("reviewed.ps1"))
        run_script.assert_not_called()

    def test_admin_cleanup_script_run_offer_launches_power_shell_without_force(self):
        completed = SimpleNamespace(returncode=0)
        with mock.patch.object(analyze.scan, "check_admin", return_value=True), \
             mock.patch("builtins.input", return_value="y"), \
             mock.patch.object(analyze.shutil, "which", side_effect=["pwsh.exe"]), \
             mock.patch.object(analyze.subprocess, "run", return_value=completed) as run_script:
            self.assertTrue(analyze.offer_to_run_cleanup_script("C:\\Reviewed Plan.ps1"))
        run_script.assert_called_once_with(
            ["pwsh.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "C:\\Reviewed Plan.ps1"],
            check=False,
        )

    def test_admin_cleanup_script_run_offer_uses_powershell_fallback(self):
        completed = SimpleNamespace(returncode=0)
        with mock.patch.object(analyze.scan, "check_admin", return_value=True), \
             mock.patch("builtins.input", return_value="yes"), \
             mock.patch.object(analyze.shutil, "which", side_effect=[None, "powershell.exe"]), \
             mock.patch.object(analyze.subprocess, "run", return_value=completed) as run_script:
            self.assertTrue(analyze.offer_to_run_cleanup_script("reviewed.ps1"))
        self.assertEqual(run_script.call_args.args[0][0], "powershell.exe")

    def test_review_menu_blank_selection_creates_no_plan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "scan.csv"
            csv_path.write_text("placeholder", encoding="utf-8")
            results = {
                "scan_file": str(csv_path), "scan_time": "now", "total_size": 0,
                "free_space": 0, "used_space": 0, "space_source": None,
                "categories": {
                    "high": {"name": "High", "items": [{
                        "path": r"C:\Users\A\AppData\Local\Temp\candidate",
                        "size": 100, "size_formatted": "100 B",
                        "kind": "Directory", "name": "Temporary files",
                    }]},
                    "medium": {"name": "Medium", "items": []},
                    "low": {"name": "Low", "items": []},
                },
            }
            with mock.patch.object(analyze, "analyze_csv", return_value=results), \
                 mock.patch.object(analyze, "clear_screen"), \
                 mock.patch("builtins.input", side_effect=["3", "high", "", "", "0"]), \
                 mock.patch.object(analyze, "generate_clean_script") as generate:
                analyze.run_tui(initial_csv=str(csv_path))
            generate.assert_not_called()

    def analyze_rows(self, rows):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "scan.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["File Name", "Size", "Allocated", "DRIVECAPACITY", "FREESPACE", "USEDSPACE"])
                writer.writeheader()
                writer.writerows(rows)
            with mock.patch("analyze.os.path.exists", return_value=True):
                with mock.patch("analyze.os.path.isdir", side_effect=self._synthetic_isdir(rows)):
                    with mock.patch("analyze.os.path.isfile", side_effect=self._synthetic_isfile(rows)):
                        return analyze.analyze_csv(str(csv_path), min_size_mb=0)

    @staticmethod
    def _synthetic_types(rows):
        types = {}
        for row in rows:
            path = next((value for key, value in row.items() if key.casefold() in {
                "file name", "name", "path"
            }), "")
            if not path:
                continue
            normalized = path.rstrip("\\/").casefold()
            is_directory = path.endswith(("\\", "/"))
            keys = {key.casefold().replace(" ", "") for key in row}
            if not is_directory and any("windirstat" in key for key in keys):
                is_directory = analyze._is_directory_row({
                    "attributes": row.get("Attributes", ""),
                    "windirstatattributes": row.get("WinDirStat Attributes", ""),
                    "files": row.get("Files", ""),
                    "folders": row.get("Folders", ""),
                }) is True
            types[normalized] = "directory" if is_directory else "file"
        return types

    @classmethod
    def _synthetic_isdir(cls, rows):
        types = cls._synthetic_types(rows)
        return lambda path: types.get(path.rstrip("\\/").casefold()) == "directory"

    @classmethod
    def _synthetic_isfile(cls, rows):
        types = cls._synthetic_types(rows)
        return lambda path: types.get(path.rstrip("\\/").casefold()) == "file"

    def test_scan_export_with_missing_required_columns_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "bad.csv"
            csv_path.write_text("Date,Count\n2026-01-01,2\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing required columns"):
                analyze.analyze_csv(str(csv_path), min_size_mb=0)

    def test_reports_disclose_when_the_scan_export_was_last_modified(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "scan.csv"
            csv_path.write_text("File Name,Size\n", encoding="utf-8")
            fixed_timestamp = 1_767_325_445
            os.utime(csv_path, (fixed_timestamp, fixed_timestamp))
            expected = datetime.fromtimestamp(fixed_timestamp).astimezone().isoformat(timespec="seconds")
            results = analyze.analyze_csv(str(csv_path), min_size_mb=0)

            report = io.StringIO()
            with redirect_stdout(report):
                analyze.print_report(results)
            self.assertIn(f"Scan file last changed: {expected}", report.getvalue())
            self.assertIn("Scan again before cleanup", report.getvalue())

            candidate_list = Path(temp_dir) / "candidates.txt"
            analyze.write_item_list_report(results, str(candidate_list))
            self.assertIn(f"Source scan last modified: {expected}", candidate_list.read_text(encoding="utf-8"))

    def test_generated_cleanup_script_discloses_normalized_scan_timestamp(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = {
                "scan_file_time": "2026-01-02T03:04:05-08:00\nWrite-Host 'not a timestamp'",
                "categories": {"high": {"name": "High", "items": [{
                    "path": r"C:\Users\A\AppData\Local\Temp\cache.bin",
                    "name": "Temporary files (check for installers or builds in progress)",
                    "size": 100, "size_formatted": "100 B", "kind": "File",
                }]}, "medium": {"name": "Medium", "items": []}, "low": {"name": "Low", "items": []}},
            }
            output_path = Path(temp_dir) / "clean.ps1"
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(result, str(output_path))
            script = output_path.read_text(encoding="utf-8-sig")
        self.assertIn("# Source scan last modified: Unknown", script)
        self.assertNotIn("Write-Host 'not a timestamp'", script)

    def test_wiztree_export_with_generated_note_line_is_analyzed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            export_path = Path(temp_dir) / "gui-export.csv"
            export_path.write_text(
                "Generated by WizTree 4.x\n"
                '"File Name","Size","Allocated"\n'
                '"C:\\Users\\A\\AppData\\Local\\Temp\\large.tmp","104857600","104857600"\n',
                encoding="utf-8",
            )
            with mock.patch("analyze.os.path.exists", return_value=True):
                with mock.patch("analyze.os.path.isdir", return_value=False), \
                     mock.patch("analyze.os.path.isfile", return_value=True):
                    results = analyze.analyze_csv(str(export_path), min_size_mb=0)
        self.assertEqual(len(results["categories"]["high"]["items"]), 1)
        self.assertTrue(results["categories"]["high"]["items"][0]["path"].endswith("large.tmp"))

    def test_candidate_paths_inside_detected_project_folders_are_omitted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project = Path(temp_dir) / "project"
            cache = project / "pip" / "cache"
            (project / ".git").mkdir(parents=True)
            cache.mkdir(parents=True)
            csv_path = Path(temp_dir) / "scan.csv"
            csv_path.write_text(
                "File Name,Size\n" + f'"{cache}\\","104857600"\n', encoding="utf-8"
            )
            results = analyze.analyze_csv(str(csv_path), min_size_mb=0)
            imported_results = {
                "categories": {key: {"name": key, "items": []} for key in ("high", "medium", "low")}
            }
            imported_results["categories"]["high"]["items"] = [{
                "path": str(cache) + "\\", "size": 100, "size_formatted": "100 B",
                "name": "pip cache", "kind": "Directory",
            }]
            with self.assertRaisesRegex(ValueError, "project folder"):
                analyze.generate_clean_script(imported_results, str(Path(temp_dir) / "project-cache.ps1"))
        self.assertEqual(results["project_candidate_count"], 1)
        self.assertEqual(results["project_roots"], [{"path": str(project), "marker": ".git"}])
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))
        report_output = io.StringIO()
        with redirect_stdout(report_output):
            analyze.print_report(results)
        self.assertIn(str(project), report_output.getvalue())
        self.assertIn("project marker: .git", report_output.getvalue())
        with tempfile.TemporaryDirectory() as report_dir:
            candidate_list = Path(report_dir) / "candidates.txt"
            analyze.write_item_list_report(results, str(candidate_list))
            exported_report = candidate_list.read_text(encoding="utf-8")
        self.assertIn(str(project), exported_report)
        self.assertIn("project marker: .git", exported_report)

    def test_solution_project_and_requirements_files_protect_project_caches(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            rows = []
            markers = ("DriveCleanr.sln", "Worker.csproj", "dev-requirements.txt")
            for index, marker in enumerate(markers):
                project = Path(temp_dir) / f"project-{index}"
                cache = project / "pip" / "cache"
                cache.mkdir(parents=True)
                (project / marker).touch()
                rows.append({"File Name": str(cache) + "\\", "Size": "104857600"})
            results = self.analyze_rows(rows)
        self.assertEqual(results["project_candidate_count"], len(markers))
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))

    def test_git_ide_and_agent_settings_markers_protect_project_caches(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            rows = []
            markers = (
                ".gitignore", ".gitattributes", ".editorconfig", ".idea", ".vscode", ".vs",
                ".claude", ".cursor", ".gemini", ".github", ".opencode", ".windsurf",
                "DriveCleanr.code-workspace",
            )
            for index, marker in enumerate(markers):
                project = Path(temp_dir) / f"project-{index}"
                cache = project / "cache"
                cache.mkdir(parents=True)
                marker_path = project / marker
                if marker in {
                        ".idea", ".vscode", ".vs", ".claude", ".cursor", ".gemini",
                        ".github", ".opencode", ".windsurf"}:
                    marker_path.mkdir()
                else:
                    marker_path.touch()
                rows.append({"File Name": str(cache) + "\\", "Size": "104857600"})
            results = self.analyze_rows(rows)
        self.assertEqual(results["project_candidate_count"], len(markers))
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))

    def test_ai_project_guidance_files_protect_project_caches(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            rows = []
            markers = (
                "AGENTS.md", "AGENTS.override.md", "CLAUDE.md", "GEMINI.md",
                "SKILL.md", ".cursorrules", "copilot-instructions.md",
            )
            for index, marker in enumerate(markers):
                project = Path(temp_dir) / f"project-{index}"
                cache = project / "cache"
                cache.mkdir(parents=True)
                (project / marker).touch()
                rows.append({"File Name": str(cache) + "\\", "Size": "104857600"})
            results = self.analyze_rows(rows)
        self.assertEqual(results["project_candidate_count"], len(markers))
        self.assertEqual(
            {Path(root["path"]).name for root in results["project_roots"]},
            {f"project-{index}" for index in range(len(markers))},
        )
        self.assertEqual(
            {root["marker"].casefold() for root in results["project_roots"]},
            {marker.casefold() for marker in markers},
        )
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))

    def test_unreal_godot_and_unity_project_markers_protect_cache_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            rows = []
            marker_types = (
                ("unreal-project", "Project.uproject", "file"),
                ("unreal-plugin", "Plugin.uplugin", "file"),
                ("godot", "project.godot", "file"),
                ("unity", "ProjectSettings", "directory"),
            )
            for project_name, marker, marker_type in marker_types:
                project = Path(temp_dir) / project_name
                cache = project / "Cache"
                cache.mkdir(parents=True)
                marker_path = project / marker
                if marker_type == "directory":
                    marker_path.mkdir()
                else:
                    marker_path.touch()
                rows.append({"File Name": str(cache) + "\\", "Size": "104857600"})
            results = self.analyze_rows(rows)
        self.assertEqual(results["project_candidate_count"], len(marker_types))
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))

    def test_project_marker_at_user_profile_root_is_checked_before_walking_stops(self):
        profile = r"C:\Users\ExampleUser"
        cache_path = profile + r"\AppData\Local\Temp\pip\cache"
        is_profile = lambda path: os.path.normcase(path) == os.path.normcase(profile)
        with mock.patch.object(analyze, "_directory_has_project_marker", side_effect=is_profile):
            self.assertTrue(analyze._inside_project_tree(cache_path, True, {}))

    def test_shared_tool_metadata_at_profile_root_does_not_hide_other_cleanup_locations(self):
        entries = []
        for name in (
                "package.json", "package-lock.json", "bun.lock", ".editorconfig", ".vscode",
                "Work.code-workspace", "AGENTS.md", "AGENTS.override.md", "CLAUDE.md",
                "GEMINI.md", "SKILL.md", ".cursorrules", "copilot-instructions.md",
                ".claude", ".cursor", ".gemini", ".github", ".opencode", ".windsurf"):
            entry = mock.Mock()
            entry.name = name
            entry.is_file.return_value = True
            entries.append(entry)
        scan_context = mock.MagicMock()
        scan_context.__enter__.return_value = entries
        with mock.patch.object(analyze.os, "scandir", return_value=scan_context):
            self.assertFalse(analyze._directory_has_project_marker(r"C:\Users\ExampleUser"))
        self.assertTrue(analyze._is_excluded_path(
            r"C:\Users\ExampleUser\.vscode\extensions\publisher.example\Cache"
        ))
        self.assertFalse(analyze._is_excluded_path(
            r"C:\Users\ExampleUser\AppData\Local\npm-cache"
        ))

    def test_temp_named_paths_outside_known_temp_roots_are_caution_candidates(self):
        results = self.analyze_rows([{
            "File Name": "C:\\Games\\Temp\\game-assets\\", "Size": "104857600",
        }])
        self.assertEqual(results["categories"]["high"]["items"], [])
        items = results["categories"]["medium"]["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "Folder named Temp (inspect its owner and contents; the name alone does not prove it is temporary)")

        imported_item = dict(items[0])
        promoted = {"categories": {
            "high": {"name": "High", "items": [imported_item]},
            "medium": {"name": "Medium", "items": []},
            "low": {"name": "Low", "items": []},
        }}
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(ValueError, "does not match its priority and cleanup label"):
                analyze.generate_clean_script(promoted, str(Path(temp_dir) / "unsafe.ps1"))
            safe_plan = Path(temp_dir) / "caution.ps1"
            analyze.generate_clean_script({"categories": {
                "high": {"name": "High", "items": []},
                "medium": {"name": "Medium", "items": items},
                "low": {"name": "Low", "items": []},
            }}, str(safe_plan), priority="medium")
            self.assertIn("Folder named Temp", safe_plan.read_text(encoding="utf-8-sig"))

    def test_standard_windows_temp_root_remains_a_lower_risk_candidate(self):
        results = self.analyze_rows([{
            "File Name": r"C:\Users\A\AppData\Local\Temp\cache.bin", "Size": "104857600",
        }])
        items = results["categories"]["high"]["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "Temporary files (check for installers or builds in progress)")
        self.assertEqual(results["categories"]["medium"]["items"], [])

    def test_equal_specificity_cache_labels_override_broad_known_temp_label(self):
        rows = [
            {"File Name": r"C:\Users\A\AppData\Local\Temp\Cache" + "\\", "Size": "104857600"},
            {"File Name": r"C:\Users\A\AppData\Local\Temp\Logs" + "\\", "Size": "104857600"},
            {"File Name": r"C:\Users\A\AppData\Local\Temp\GPUCache" + "\\", "Size": "104857600"},
        ]
        results = self.analyze_rows(rows)
        self.assertEqual(results["categories"]["high"]["items"], [])
        labels = {item["path"]: item["name"] for item in results["categories"]["medium"]["items"]}
        self.assertEqual(labels, {
            r"C:\Users\A\AppData\Local\Temp\Cache" + "\\": "Cache-named data (inspect its location and contents; the name alone does not prove it is disposable)",
            r"C:\Users\A\AppData\Local\Temp\Logs" + "\\": "Logs data (review contents; may include user or diagnostic history)",
            r"C:\Users\A\AppData\Local\Temp\GPUCache" + "\\": "GPU cache data (review which application owns it before cleanup)",
        })
        mislabeled = dict(results["categories"]["medium"]["items"][0])
        mislabeled["name"] = "Temporary files (check for installers or builds in progress)"
        invalid_plan = {"categories": {
            "high": {"name": "High", "items": [mislabeled]},
            "medium": {"name": "Medium", "items": []},
            "low": {"name": "Low", "items": []},
        }}
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(
                ValueError, "does not match its priority and cleanup label"):
            analyze.generate_clean_script(invalid_plan, str(Path(temp_dir) / "mislabelled-temp-cache.ps1"))

    def test_known_temp_root_is_skipped_so_nested_items_can_be_selected(self):
        temp_root = "C:\\Users\\A\\AppData\\Local\\Temp\\"
        work_folder = temp_root + "cargo-install\\"
        large_file = work_folder + "payload.bin"
        results = self.analyze_rows([
            {"File Name": large_file, "Size": "200000000"},
            {"File Name": work_folder, "Size": "250000000"},
            {"File Name": temp_root, "Size": "300000000"},
        ])
        items = results["categories"]["high"]["items"]
        self.assertEqual([item["path"] for item in items], [work_folder])
        self.assertEqual(results["temp_root_candidate_count"], 1)

        report_output = io.StringIO()
        with redirect_stdout(report_output):
            analyze.print_report(results)
        self.assertIn("Known temporary folders skipped: 1", report_output.getvalue())
        self.assertIn("files and folders inside are shown separately when they match the cleanup rules", report_output.getvalue())

        with tempfile.TemporaryDirectory() as temp_dir:
            candidate_report = Path(temp_dir) / "candidates.txt"
            analyze.write_item_list_report(results, str(candidate_report))
            report_text = candidate_report.read_text(encoding="utf-8")
            self.assertIn("Known temporary folders skipped: 1", report_text)
            plan_path = Path(temp_dir) / "selected-child.ps1"
            analyze.generate_clean_script(results, str(plan_path))
            plan = plan_path.read_text(encoding="utf-8-sig")
        self.assertIn(work_folder, plan)

        imported_root = {
            "path": temp_root,
            "name": "Temporary files (check for installers or builds in progress)",
            "size": 300_000_000, "size_formatted": "286.10 MB", "kind": "Directory",
        }
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(
                ValueError, "does not match its priority and cleanup label"):
            analyze.generate_clean_script(
                {"categories": {"high": {"name": "High", "items": [imported_root]}}},
                str(Path(temp_dir) / "unsafe-temp-root.ps1"),
            )

    def test_configured_temp_root_remains_a_lower_risk_candidate(self):
        with mock.patch.dict(os.environ, {"TEMP": r"D:\Scratch\Session"}):
            results = self.analyze_rows([{
                "File Name": "D:\\Scratch\\Session\\build-output\\", "Size": "104857600",
            }])
        self.assertEqual(len(results["categories"]["high"]["items"]), 1)
        self.assertEqual(results["categories"]["medium"]["items"], [])

    def test_project_marker_lookup_failure_is_conservative(self):
        with mock.patch.object(analyze.os, "scandir", side_effect=PermissionError):
            self.assertTrue(analyze._directory_has_project_marker(r"C:\Users\PrivateProject"))

    def test_custom_project_protection_marker_hides_unrecognized_project_trees(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            project = Path(temp_dir) / "personal-project"
            cache = project / "Temp" / "pip" / "cache"
            cache.mkdir(parents=True)
            (project / ".drive-cleanr-protect").touch()
            csv_path = Path(temp_dir) / "scan.csv"
            csv_path.write_text(
                "File Name,Size\n" + f'"{cache}\\","104857600"\n', encoding="utf-8"
            )
            results = analyze.analyze_csv(str(csv_path), min_size_mb=0)
        self.assertEqual(results["project_candidate_count"], 1)
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))

    def test_candidate_list_deduplicates_overlapping_risk_tiers(self):
        results = {
            "total_size": 0,
            "categories": {
                "high": {"name": "High", "total_size_formatted": "100 B", "total_size": 100, "items": [
                    {"path": "C:\\Temp\\cache\\", "size": 100, "size_formatted": "100 B", "kind": "Directory", "name": "Temp", "safe": True},
                ]},
                "medium": {"name": "Medium", "total_size_formatted": "50 B", "total_size": 50, "items": [
                    {"path": "C:\\Temp\\cache\\nested\\", "size": 50, "size_formatted": "50 B", "kind": "Directory", "name": "Cache", "safe": False},
                ]},
                "low": {"name": "Low", "total_size_formatted": "50 B", "total_size": 50, "items": [
                    {"path": "C:\\Temp\\cache\\nested\\deep\\", "size": 25, "size_formatted": "25 B", "kind": "Directory", "name": "Cache", "safe": False},
                    {"path": "C:\\Temp\\other\\", "size": 25, "size_formatted": "25 B", "kind": "Directory", "name": "Temp", "safe": False},
                ]},
            }
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "candidates.txt"
            analyze.write_item_list_report(results, str(report_path))
            report = report_path.read_text(encoding="utf-8")
        self.assertIn("Estimated space in listed files and folders (counted once): 125 B", report)
        self.assertIn("Some listed items are inside a listed folder. Each row is shown separately, but the same space is counted only once in the total.", report)
        self.assertIn(
            "50 B at C:\\Temp\\cache\\nested\\ is inside 100 B at C:\\Temp\\cache\\",
            report,
        )
        self.assertIn(
            "25 B at C:\\Temp\\cache\\nested\\deep\\ is inside "
            "50 B at C:\\Temp\\cache\\nested\\",
            report,
        )
        self.assertIn("The same space is counted once in the total, even when items appear in different review groups.", report)
        self.assertIn("[High] - Estimated space: 50 B", report)
        self.assertIn("[Medium] - Estimated space: 25 B", report)
        self.assertIn("[Low] - Estimated space: 50 B", report)
        self.assertIn("Folder totals can include nested protected data", report)
        self.assertIn("Risk level: lower risk; review first", report)
        self.assertIn("Risk level: caution; review carefully", report)
        self.assertNotIn("Safe: yes", report)

        console = io.StringIO()
        with redirect_stdout(console):
            analyze.print_report(results)
        console_report = console.getvalue()
        self.assertIn(
            "50 B at C:\\Temp\\cache\\nested\\ is inside "
            "100 B at C:\\Temp\\cache\\",
            console_report,
        )
        self.assertIn(
            "25 B at C:\\Temp\\cache\\nested\\deep\\ is inside "
            "50 B at C:\\Temp\\cache\\nested\\",
            console_report,
        )
        self.assertIn("[High] - Estimated space: 50 B", console_report)
        self.assertIn("[Medium] - Estimated space: 25 B", console_report)
        self.assertIn("Estimated space in listed files and folders (counted once): 125 B", console_report)

    def test_standard_wiztree_report_discloses_possible_access_gaps(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "scan_wiztree_standard_mock.csv"
            csv_path.write_text("File Name,Size\n", encoding="utf-8")
            results = analyze.analyze_csv(str(csv_path), min_size_mb=0)
            with mock.patch("builtins.print") as output:
                analyze.print_report(results)
        report_text = " ".join(str(call.args[0]) for call in output.call_args_list if call.args)
        self.assertEqual(results["scan_mode"], "wiztree_standard")
        self.assertIn("files inaccessible to this account may be missing", report_text)

    def test_review_menu_returns_cleanly_after_an_invalid_export(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "bad.csv"
            csv_path.write_text("Date,Count\n2026-01-01,2\n", encoding="utf-8")
            with mock.patch.object(analyze, "prompt_existing_csv", side_effect=[str(csv_path), None]) as picker, \
                 mock.patch("builtins.input", return_value=""), \
                 mock.patch("builtins.print"):
                analyze.run_tui()
            self.assertEqual(picker.call_count, 2)

    def test_review_menu_recovers_if_scan_becomes_unreadable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "scan.csv"
            csv_path.write_text("File Name,Size\n", encoding="utf-8")
            with mock.patch.object(analyze, "prompt_existing_csv", side_effect=[str(csv_path), None]) as picker, \
                 mock.patch.object(analyze, "analyze_csv", side_effect=PermissionError(13, "denied")), \
                 mock.patch.object(analyze, "clear_screen"), \
                 mock.patch("builtins.input", return_value=""), \
                 redirect_stdout(io.StringIO()) as output:
                analyze.run_tui()

        self.assertEqual(picker.call_count, 2)
        self.assertIn("Could not review this scan", output.getvalue())
        self.assertIn("Access was denied", output.getvalue())

    def test_scan_picker_rejects_missing_paths_and_directories(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            for invalid_path in (str(Path(temp_dir) / "missing.csv"), temp_dir):
                with self.subTest(path_kind="directory" if Path(invalid_path).is_dir() else "missing"):
                    output = io.StringIO()
                    with mock.patch.object(analyze, "get_latest_scan", return_value=None), \
                         mock.patch.object(analyze, "clear_screen"), \
                         mock.patch("builtins.input", side_effect=["2", invalid_path, "", "0"]), \
                         redirect_stdout(output):
                        selected = analyze.prompt_existing_csv()

                    self.assertIsNone(selected)
                    self.assertIn("not a file", output.getvalue())

    def test_analyzer_cli_reports_unreadable_scan_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "scan.csv"
            csv_path.write_text("File Name,Size\n", encoding="utf-8")
            with mock.patch.object(analyze.sys, "argv", ["analyze.py", str(csv_path)]), \
                 mock.patch.object(analyze, "analyze_csv", side_effect=PermissionError(13, "denied")), \
                 redirect_stderr(io.StringIO()) as error_output:
                with self.assertRaises(SystemExit) as exc:
                    analyze.main()

        self.assertEqual(exc.exception.code, 2)
        self.assertIn("could not review scan file: Access was denied", error_output.getvalue())

    def test_analyzer_cli_handles_picker_interrupt_without_traceback(self):
        for interruption in (KeyboardInterrupt, EOFError):
            with self.subTest(interruption=interruption), \
                 mock.patch.object(analyze.sys, "argv", ["analyze.py", "--tui"]), \
                 mock.patch.object(analyze, "clear_screen"), \
                 mock.patch("builtins.input", side_effect=interruption), \
                 redirect_stdout(io.StringIO()) as output:
                analyze.main()
            self.assertIn("Review cancelled.", output.getvalue())

    def test_guided_review_cancels_cleanly_on_keyboard_interrupt_or_eof(self):
        for interruption in (KeyboardInterrupt, EOFError):
            with self.subTest(interruption=interruption), \
                 mock.patch.object(analyze, "prompt_existing_csv", side_effect=interruption), \
                 redirect_stdout(io.StringIO()) as output:
                analyze.run_tui()
            self.assertIn("Review cancelled.", output.getvalue())

    def test_only_absolute_local_non_root_paths_become_candidates(self):
        results = self.analyze_rows([
            {"File Name": "C:\\", "Size": "1000", "DRIVECAPACITY": "1000", "FREESPACE": "200", "USEDSPACE": "800"},
            {"File Name": "C:\\Users\\A\\AppData\\Local\\Temp\\candidate\\", "Size": "90"},
            {"File Name": "C:\\Windows\\SoftwareDistribution\\", "Size": "100"},
            {"File Name": "C:\\Windows\\SoftwareDistribution\\Download\\package\\", "Size": "80"},
            {"File Name": "\\\\server\\share\\Temp\\", "Size": "90"},
            {"File Name": "C:\\Users\\A\\Temp\\..\\Documents\\", "Size": "90"},
            {"File Name": "C:\\Temp\\..\\", "Size": "90"},
        ])
        candidates = results["categories"]["high"]["items"]
        self.assertEqual({item["path"] for item in candidates}, {
            "C:\\Users\\A\\AppData\\Local\\Temp\\candidate\\",
        })
        self.assertFalse(results["categories"]["medium"]["items"])
        self.assertEqual(results["total_size"], 1000)

    def test_cleanup_patterns_match_path_components_not_embedded_names(self):
        results = self.analyze_rows([
            {"File Name": "C:\\Users\\A\\AppData\\Local\\CacheInspector\\large.bin", "Size": "104857600"},
            {"File Name": "C:\\Users\\A\\AppData\\Local\\GPUCache\\large.bin", "Size": "104857600"},
            {"File Name": "C:\\Users\\A\\Projects\\CrashDumpManager\\large.bin", "Size": "104857600"},
            {"File Name": "C:\\Users\\A\\OneDriveBackup\\AppData\\Local\\Temp\\build.tmp", "Size": "104857600"},
            {"File Name": "C:\\Users\\A\\AppData\\Local\\Temp.archive\\large.bin", "Size": "104857600"},
            {"File Name": "C:\\Windows\\MEMORY.DMP", "Size": "104857600"},
            {"File Name": "C:\\Windows\\CrashDump.dmp", "Size": "104857600"},
        ])
        candidates = [item["path"] for category in results["categories"].values()
                      for item in category["items"]]
        self.assertEqual(set(candidates), {
            "C:\\Users\\A\\AppData\\Local\\GPUCache\\large.bin",
            "C:\\Users\\A\\OneDriveBackup\\AppData\\Local\\Temp\\build.tmp",
            "C:\\Windows\\MEMORY.DMP",
            "C:\\Windows\\CrashDump.dmp",
        })

    def test_generic_cache_and_log_labels_explain_the_uncertainty(self):
        rows = [
            r"C:\Users\A\AppData\Local\App\Cache\settings.db",
            r"C:\Users\A\AppData\Local\App\Caches\plugin-data.bin",
            r"C:\Users\A\AppData\Local\App\Logs\account-history.log",
            r"C:\Users\A\AppData\Local\App\GPUCache\shader.bin",
            r"C:\Users\A\AppData\Local\App\ShaderCache\compiled.bin",
            r"C:\Users\A\AppData\Local\App\Code Cache\index.bin",
        ]
        results = self.analyze_rows([{"File Name": path, "Size": "104857600"} for path in rows])
        items = results["categories"]["medium"]["items"]
        self.assertEqual({item["path"] for item in items}, set(rows))
        self.assertTrue(all(not item["safe"] for item in items))
        descriptions = " ".join(item["name"] for item in items)
        self.assertIn("name alone does not prove it is disposable", descriptions)
        self.assertIn("may include user or diagnostic history", descriptions)
        self.assertIn("review which application owns it before cleanup", descriptions)
        self.assertTrue(analyze._matches_cleanup_rule(
            r"C:\Users\A\AppData\Local\App\Cache\settings.db",
            ("medium",),
            "Cache-named data (inspect its location and contents; the name alone does not prove it is disposable)",
        ))
        self.assertFalse(analyze._matches_cleanup_rule(
            r"C:\Users\A\AppData\Local\App\Cache\settings.db",
            ("medium",),
            "Application cache",
        ))

    def test_cargo_install_build_outputs_inside_temp_are_caution_candidates(self):
        path = r"C:\Users\A\AppData\Local\Temp\cargo-installABC\debug\example.exe"
        label = "Cargo install build output (confirm the install completed and review its compiled files)"
        results = self.analyze_rows([{"File Name": path, "Size": "104857600"}])
        items = results["categories"]["medium"]["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["path"], path)
        self.assertEqual(items[0]["name"], label)
        self.assertFalse(results["categories"]["high"]["items"])
        self.assertTrue(analyze._matches_cleanup_rule(path, ("medium",), label))
        self.assertFalse(analyze._matches_cleanup_rule(
            r"C:\Users\A\Downloads\cargo-installABC\debug\example.exe", ("medium",), label
        ))
        stale_plan = {"categories": {"high": {"name": "High", "items": [{
            "path": path,
            "name": "Temporary files (check for installers or builds in progress)",
            "size": 104857600, "size_formatted": "100 MB", "kind": "File",
        }]}}}
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(
                ValueError, "does not match its priority and cleanup label"):
            analyze.generate_clean_script(stale_plan, str(Path(temp_dir) / "stale.ps1"), priority="high")

    def test_chocolatey_staging_inside_temp_is_a_caution_candidate(self):
        path = r"C:\Users\A\AppData\Local\Temp\chocolatey\windirstat\2.9.0\payload.exe"
        label = "Chocolatey package staging (confirm installs are complete and review contents)"
        results = self.analyze_rows([{"File Name": path, "Size": "104857600"}])
        items = results["categories"]["medium"]["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["path"], path)
        self.assertEqual(items[0]["name"], label)
        self.assertFalse(results["categories"]["high"]["items"])
        self.assertTrue(analyze._matches_cleanup_rule(path, ("medium",), label))
        self.assertFalse(analyze._matches_cleanup_rule(
            r"C:\Users\A\Downloads\chocolatey\windirstat\2.9.0\payload.exe", ("medium",), label
        ))
        stale_plan = {"categories": {"high": {"name": "High", "items": [{
            "path": path,
            "name": "Temporary files (check for installers or builds in progress)",
            "size": 104857600, "size_formatted": "100 MB", "kind": "File",
        }]}}}
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(
                ValueError, "does not match its priority and cleanup label"):
            analyze.generate_clean_script(stale_plan, str(Path(temp_dir) / "stale.ps1"), priority="high")

    def test_known_vscode_cache_paths_get_specific_caution_labels(self):
        known_paths = [
            r"C:\Users\A\AppData\Roaming\Code\CachedExtensionVSIXs",
            r"C:\Users\A\AppData\Roaming\Code\CachedData",
            r"C:\Users\A\AppData\Roaming\Code\Cache",
            r"C:\Users\A\AppData\Roaming\Code\Crashpad",
        ]
        other_paths = [
            r"C:\Users\A\Projects\Code\Cache",
            r"C:\Users\A\AppData\Roaming\Code\User",
            r"C:\Users\A\AppData\Roaming\Code\WebStorage",
            r"C:\Users\A\AppData\Roaming\Code\User\globalStorage\Cache",
        ]
        results = self.analyze_rows([
            {"File Name": path, "Size": "104857600"}
            for path in known_paths + other_paths
        ])
        candidates = results["categories"]["medium"]["items"]
        by_path = {item["path"].rstrip("\\"): item for item in candidates}
        for path in known_paths:
            with self.subTest(path=path):
                item = by_path[path.rstrip("\\")]
                self.assertIn("VS Code", item["name"])
                self.assertFalse(item["safe"])
        self.assertIn("Cache-named data", by_path[other_paths[0].rstrip("\\")]["name"])
        self.assertNotIn(other_paths[1].rstrip("\\"), by_path)
        self.assertNotIn(other_paths[2].rstrip("\\"), by_path)
        self.assertIn("Cache-named data", by_path[other_paths[3].rstrip("\\")]["name"])
        outdated = {"categories": {"medium": {"name": "Medium", "items": [{
            "path": known_paths[2],
            "name": "Cache-named data (inspect its location and contents; the name alone does not prove it is disposable)",
            "size": 100, "size_formatted": "100 B", "kind": "Directory",
        }]}}}
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(
                ValueError, "does not match its priority and cleanup label"):
            analyze.generate_clean_script(
                outdated, str(Path(temp_dir) / "old-cache-label.ps1"), priority="medium"
            )

    def test_chrome_and_nvidia_labels_require_their_known_parent_paths(self):
        results = self.analyze_rows([
            {"File Name": r"C:\Users\A\AppData\Local\Google\Chrome\User Data\OptGuideOnDeviceModel" + "\\", "Size": "104857600"},
            {"File Name": r"C:\Users\A\BuildArtifacts\OptGuideOnDeviceModel" + "\\", "Size": "104857600"},
            {"File Name": r"C:\ProgramData\NVIDIA Corporation\NVIDIA App\UpdateFramework\ota-artifacts" + "\\", "Size": "104857600"},
            {"File Name": r"C:\ProgramData\NVIDIA Corporation\NvApp-UpdateFramework\ota-artifacts" + "\\", "Size": "104857600"},
            {"File Name": r"D:\Archive\ota-artifacts" + "\\", "Size": "104857600"},
        ])
        high = results["categories"]["high"]["items"]
        medium = results["categories"]["medium"]["items"]
        low = results["categories"]["low"]["items"]
        self.assertEqual(high, [])
        chrome_model = [item for item in medium if "OptGuideOnDeviceModel" in item["path"]]
        self.assertEqual([item["path"] for item in chrome_model], [
            r"C:\Users\A\AppData\Local\Google\Chrome\User Data\OptGuideOnDeviceModel" + "\\",
        ])
        self.assertIn("Chrome on-device AI model", chrome_model[0]["name"])
        self.assertIn("may be downloaded again", chrome_model[0]["name"])
        self.assertFalse(chrome_model[0]["safe"])
        self.assertEqual({item["path"] for item in low}, {
            r"C:\ProgramData\NVIDIA Corporation\NVIDIA App\UpdateFramework\ota-artifacts" + "\\",
            r"C:\ProgramData\NVIDIA Corporation\NvApp-UpdateFramework\ota-artifacts" + "\\",
        })
        self.assertTrue(all(not item["safe"] for item in low))
        self.assertTrue(all("driver-update files" in item["name"] for item in low))

    def test_generated_plan_rejects_old_lower_risk_chrome_model_label(self):
        results = {"categories": {"high": {"name": "High", "items": [{
            "path": r"C:\Users\A\AppData\Local\Google\Chrome\User Data\OptGuideOnDeviceModel",
            "name": "Chrome on-device AI model (after deleting, consider disabling optimization-guide-on-device-model in chrome://flags to prevent re-download)",
            "size": 100, "size_formatted": "100 B", "kind": "Directory",
        }]}}}
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(
                ValueError, "does not match its priority and cleanup label"):
            analyze.generate_clean_script(results, str(Path(temp_dir) / "clean.ps1"))

    def test_indexeddb_candidates_require_a_browser_profile_parent(self):
        results = self.analyze_rows([
            {"File Name": r"C:\Users\A\AppData\Local\Google\Chrome\User Data\Default\IndexedDB\https_example_0.indexeddb.leveldb" + "\\", "Size": "104857600"},
            {"File Name": r"C:\Users\A\AppData\Local\Microsoft\Edge\User Data\Profile 1\IndexedDB\https_example_0.indexeddb.leveldb" + "\\", "Size": "104857600"},
            {"File Name": r"C:\Users\A\AppData\Local\SomeApp\IndexedDB\store" + "\\", "Size": "104857600"},
            {"File Name": r"C:\Users\A\IndexedDB\Archive\Chrome\User Data\store" + "\\", "Size": "104857600"},
        ])
        candidates = results["categories"]["low"]["items"]
        self.assertEqual({item["path"] for item in candidates}, {
            r"C:\Users\A\AppData\Local\Google\Chrome\User Data\Default\IndexedDB\https_example_0.indexeddb.leveldb" + "\\",
            r"C:\Users\A\AppData\Local\Microsoft\Edge\User Data\Profile 1\IndexedDB\https_example_0.indexeddb.leveldb" + "\\",
        })
        self.assertTrue(all("Chrome/Edge profile IndexedDB data" in item["name"] for item in candidates))

    def test_generated_plan_revalidates_indexeddb_browser_path(self):
        results = {"categories": {"low": {"name": "Low", "items": [{
            "path": r"C:\Users\A\AppData\Local\SomeApp\IndexedDB\store",
            "name": "Chrome/Edge profile IndexedDB data (offline web-app data or login state; deleting it can sign you out or lose data)",
            "size": 100, "size_formatted": "100 B", "kind": "File",
        }]}}}
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(
                ValueError, "does not match its priority and cleanup label"):
            analyze.generate_clean_script(results, str(Path(temp_dir) / "clean.ps1"), priority="low")

    def test_crash_dump_rules_are_limited_to_windows_locations(self):
        with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
            results = self.analyze_rows([
                {"File Name": r"C:\Windows\LiveKernelReports\WATCHDOG\WATCHDOG-2026.dmp", "Size": "104857600"},
                {"File Name": r"C:\Windows\Minidump\memory.dmp", "Size": "104857600"},
                {"File Name": r"C:\Windows\MEMORY.DMP", "Size": "104857600"},
                {"File Name": r"D:\Windows\Minidump\system.dmp", "Size": "104857600"},
                {"File Name": r"C:\Windows\Archives\Minidump\project.dmp", "Size": "104857600"},
                {"File Name": r"C:\Windows\Logs\CrashDumps\old.zip", "Size": "104857600"},
                {"File Name": r"C:\Users\A\Archives\CrashDumps\customer-data.zip", "Size": "104857600"},
                {"File Name": r"C:\Users\A\Projects\Minidump\sample.dmp", "Size": "104857600"},
                {"File Name": r"C:\Users\A\Archives\CrashDump.dmp", "Size": "104857600"},
            ])
        medium = results["categories"]["medium"]["items"]
        crash_dump_items = [item for item in medium if "memory data" in item["name"]]
        self.assertEqual({item["path"] for item in crash_dump_items}, {
            r"C:\Windows\LiveKernelReports\WATCHDOG\WATCHDOG-2026.dmp",
            r"C:\Windows\Minidump\memory.dmp",
            r"C:\Windows\MEMORY.DMP",
            r"D:\Windows\Minidump\system.dmp",
        })
        self.assertTrue(all(not item["safe"] for item in crash_dump_items))
        self.assertTrue(any(item["path"] == r"C:\Windows\Logs\CrashDumps\old.zip" and
                            "Logs data" in item["name"] for item in medium))
        self.assertFalse(analyze._matches_cleanup_rule(
            r"C:\Users\A\Archives\CrashDumps\customer-data.zip", ("medium",),
            "Windows crash diagnostics (keep if troubleshooting; may contain memory data)"
        ))
        self.assertFalse(analyze._matches_cleanup_rule(
            r"C:\Windows\Archives\Minidump\project.dmp", ("medium",),
            "Windows crash diagnostics (keep if troubleshooting; may contain memory data)"
        ))
        self.assertFalse(analyze._matches_cleanup_rule(
            r"C:\Windows\Logs\CrashDumps\old.zip", ("medium",),
            "Windows crash diagnostics (keep if troubleshooting; may contain memory data)"
        ))
        arbitrary_dump = {
            "categories": {key: {"name": key, "items": []} for key in ("high", "medium", "low")}
        }
        arbitrary_dump["categories"]["high"]["items"] = [{
            "path": r"C:\Users\A\Archives\CrashDumps\customer-data.zip",
            "name": "Windows crash diagnostics (keep if troubleshooting; may contain memory data)", "size": 104857600,
            "size_formatted": "100 MB", "kind": "File",
        }]
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(
                ValueError, "does not match its priority and cleanup label"):
            analyze.generate_clean_script(arbitrary_dump, str(Path(temp_dir) / "unsafe.ps1"))

    def test_specific_package_cache_rules_beat_generic_cache_rules(self):
        results = self.analyze_rows([
            {"File Name": r"C:\Users\A\.gradle\caches" + "\\", "Size": "100000000"},
            {"File Name": r"C:\Users\A\.cargo\registry\cache\download\package.crate", "Size": "90000000"},
            {"File Name": r"C:\Users\A\scoop\cache\temurin20-jdk.zip", "Size": "85000000"},
            {"File Name": r"C:\Users\A\AppData\Local\OtherApp\caches\state.bin", "Size": "80000000"},
        ])
        high = results["categories"]["high"]["items"]
        medium = results["categories"]["medium"]["items"]
        low = results["categories"]["low"]["items"]
        self.assertFalse(high)
        self.assertEqual([item["path"] for item in medium], [
            r"C:\Users\A\AppData\Local\OtherApp\caches\state.bin",
        ])
        self.assertEqual({item["path"] for item in low}, {
            r"C:\Users\A\.gradle\caches" + "\\",
            r"C:\Users\A\.cargo\registry\cache\download\package.crate",
            r"C:\Users\A\scoop\cache\temurin20-jdk.zip",
        })
        self.assertEqual({item["name"] for item in low}, {
            "Gradle cache", "Cargo cache",
            "Scoop downloaded installers (may be needed for offline reinstall; prefer Scoop cache management)",
        })
        self.assertTrue(analyze._matches_cleanup_rule(
            r"C:\Users\A\scoop\cache\temurin20-jdk.zip", ("low",),
            "Scoop downloaded installers (may be needed for offline reinstall; prefer Scoop cache management)",
        ))
        self.assertFalse(analyze._matches_cleanup_rule(
            r"C:\Users\A\scoop\cache\temurin20-jdk.zip", ("medium",),
            "Scoop downloaded installers (may be needed for offline reinstall; prefer Scoop cache management)",
        ))

    def test_exclusions_match_complete_path_components(self):
        self.assertTrue(analyze._is_excluded_path("C:\\Users\\A\\OneDrive\\Documents\\file.dat"))
        self.assertTrue(analyze._is_excluded_path("C:\\Users\\A\\OneDrive - Contoso\\AppData\\Local\\Temp\\file.dat"))
        self.assertFalse(analyze._is_excluded_path("C:\\Users\\A\\OneDriveBackup\\Temp\\file.dat"))

    def test_codex_store_package_and_roaming_state_are_protected(self):
        report_paths = [
            "C:\\Users\\TestUser\\AppData\\Local\\Packages\\OpenAI.Codex_2p2nqsd0c76g0\\LocalCache\\Local\\npm-cache",
            "C:\\Users\\TestUser\\AppData\\Local\\Packages\\OpenAI.Codex_2p2nqsd0c76g0\\LocalCache\\Roaming\\Codex\\web\\Codex\\Default\\Partitions\\codex-browser-app\\Cache\\Cache_Data",
            "C:\\Users\\TestUser\\AppData\\Roaming\\Codex\\web\\Codex\\Default\\Partitions\\codex-browser-app\\Cache\\Cache_Data",
            "C:\\Users\\TestUser\\.codex\\plugins\\cache\\openai-curated-remote",
            "C:\\Users\\TestUser\\.codex-old\\plugins\\cache\\openai-curated-remote",
        ]
        for path in report_paths:
            with self.subTest(path=path):
                self.assertTrue(analyze._is_excluded_path(path))
        results = self.analyze_rows([
            {"File Name": path, "Size": "104857600"} for path in report_paths
        ])
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))
        self.assertFalse(analyze._is_excluded_path(
            "C:\\Users\\TestUser\\AppData\\Local\\Temp\\OpenAI.CodexBackup\\build.tmp"
        ))

    def test_scan_paths_reject_windows_devices_streams_and_invalid_names(self):
        for path in (
            r"C:\Temp\cache:alternate-stream", r"C:\Temp\CON.txt",
            "C:\\Temp\\COM¹.txt", "C:\\Temp\\LPT³.log",
            r"C:\Temp\bad*name", r"C:\Temp\trailing.\cache",
            "C:\\Temp\\bad\x00name",
        ):
            with self.subTest(path=path):
                self.assertFalse(analyze._is_local_drive_path(path))

    def test_recovery_data_update_staging_logs_and_service_workers_are_protected(self):
        rows = [
            {"File Name": r"C:\Users\A\Recovered-WindowsOld\Previous-settings\.gradle\caches", "Size": "6000000"},
            {"File Name": "C:\\$WinREAgent\\", "Size": "1500000"},
            {"File Name": r"C:\ProgramData\USOShared\Logs\System", "Size": "90000"},
            {"File Name": r"C:\Users\A\AppData\Local\Microsoft\Edge\User Data\Default\Service Worker", "Size": "50000"},
            {"File Name": r"C:\Windows\SoftwareDistribution\Download\package", "Size": "5000000"},
            {"File Name": r"C:\Users\A\.codex\plugins\cache\extension", "Size": "5000000"},
            {"File Name": r"C:\Users\A\.agents\cache\skills", "Size": "5000000"},
            {"File Name": r"C:\Users\A\.local\share\containers\podman\cache\machine.tar", "Size": "5000000"},
            {"File Name": r"C:\Users\A\Downloads\ExampleProject\Workbench\ExampleProject\Temp\dotnet", "Size": "5000000"},
        ]
        # These were false positives in an earlier real report. Stub all
        # filesystem metadata so the regression test never inspects local data.
        with mock.patch.object(analyze.scan, "_path_has_reparse_component", return_value=False), \
             mock.patch.object(analyze, "_directory_has_project_marker", return_value=False), \
             mock.patch.object(analyze.shutil, "disk_usage", side_effect=OSError):
            results = self.analyze_rows(rows)
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))

    def test_virtual_memory_and_hibernation_files_are_protected_from_candidates_and_plans(self):
        paths = (
            r"C:\pagefile.sys",
            r"C:\swapfile.sys",
            r"C:\hiberfil.sys",
            r"C:\Users\A\AppData\Local\Temp\pagefile.sys",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(analyze._is_excluded_path(path))

        results = self.analyze_rows([
            {"File Name": path, "Size": "100000000"}
            for path in paths
        ])
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))

        imported = {"categories": {"high": {"name": "High", "items": [{
            "path": paths[-1],
            "name": "Temporary files (check for installers or builds in progress)",
            "size": 100_000_000, "size_formatted": "95.37 MB", "kind": "File",
        }]}}}
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(ValueError, "protected path"):
            analyze.generate_clean_script(imported, str(Path(temp_dir) / "clean.ps1"))

    def test_store_app_package_data_is_excluded_from_candidates_and_imported_plans(self):
        paths = (
            r"C:\Users\A\AppData\Local\Packages\Microsoft.Windows.Photos_8wekyb3d8bbwe\LocalCache\Temp\pending.dat",
            r"C:\Users\A\AppData\Local\Packages\Microsoft.Windows.Photos_8wekyb3d8bbwe\LocalCache\Cache\state.bin",
        )
        results = self.analyze_rows([
            {"File Name": path, "Size": "100000000"} for path in paths
        ])
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))

        item = {
            "path": paths[0],
            "name": "Temporary files (check for installers or builds in progress)",
            "size": 100_000_000, "size_formatted": "95.37 MB", "kind": "File",
        }
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(
                ValueError, "protected path"):
            analyze.generate_clean_script(
                {"categories": {"high": {"name": "High", "items": [item]}}},
                str(Path(temp_dir) / "store-app-cleanup.ps1"),
            )

    def test_windows_personal_folders_are_excluded_from_candidates_and_imported_plans(self):
        paths = (
            r"C:\Users\ExampleUser\Music\Temp\unfinished-recording.wav",
            r"C:\Users\ExampleUser\Saved Games\Logs\game-session.log",
            r"C:\Users\ExampleUser\Contacts\Cache\contacts.db",
            r"C:\Users\ExampleUser\Camera Roll\Cache\photo-index.db",
            r"C:\Users\ExampleUser\Saved Pictures\Temp\edited-photo.tmp",
            r"C:\Users\ExampleUser\Favorites\Cache\links.dat",
            r"C:\Users\ExampleUser\Links\Temp\project-link.lnk",
            r"C:\Users\ExampleUser\Searches\Logs\search-history.log",
            r"C:\Users\ExampleUser\3D Objects\Cache\model-index.db",
        )
        results = self.analyze_rows([
            {"File Name": path, "Size": "100000000"} for path in paths
        ])
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))
        self.assertTrue(all(analyze._is_excluded_path(path) for path in paths))

        item = {
            "path": paths[0],
            "name": "Temporary files (check for installers or builds in progress)",
            "size": 100_000_000, "size_formatted": "95.37 MB", "kind": "File",
        }
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(
                ValueError, "protected path"):
            analyze.generate_clean_script(
                {"categories": {"high": {"name": "High", "items": [item]}}},
                str(Path(temp_dir) / "personal-folder-cleanup.ps1"),
            )

    def test_credential_bearing_cli_profiles_are_excluded_from_candidates_and_plans(self):
        paths = (
            r"C:\Users\A\.aws\sso\cache\access-token.json",
            r"C:\Users\A\.azure\cache\token.json",
            r"C:\Users\A\.kube\cache\discovery\cluster.json",
            r"C:\Users\A\.docker\cache\auth.json",
            r"C:\Users\A\.config\gcloud\cache\credentials.db",
            r"C:\Users\A\.config\gh\cache\auth.json",
        )
        results = self.analyze_rows([
            {"File Name": path, "Size": "100000000"} for path in paths
        ])
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))
        self.assertTrue(all(analyze._is_excluded_path(path) for path in paths))

        item = {
            "path": paths[0],
            "name": "Cache-named data (inspect its location and contents; the name alone does not prove it is disposable)",
            "size": 100_000_000, "size_formatted": "95.37 MB", "kind": "File",
        }
        categories = {key: {"name": key, "items": []} for key in ("high", "medium", "low")}
        categories["medium"]["items"] = [item]
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(
                ValueError, "protected path"):
            analyze.generate_clean_script(
                {"categories": categories},
                str(Path(temp_dir) / "credential-profile-cleanup.ps1"),
                priority="medium",
            )

    def test_agent_and_editor_settings_data_is_protected_but_lookalikes_are_not(self):
        settings_paths = tuple(
            f"C:\\Users\\TestUser\\{folder}\\Cache\\"
            for folder in (".claude", ".cursor", ".gemini", ".github", ".opencode", ".windsurf")
        )
        results = self.analyze_rows([
            {"File Name": path, "Size": "100000000"} for path in settings_paths
        ])
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))
        self.assertTrue(all(analyze._is_excluded_path(path) for path in settings_paths))
        self.assertFalse(analyze._is_excluded_path(
            "C:\\Users\\TestUser\\AppData\\Local\\Temp\\.cursorBackup\\Cache\\"
        ))

        item = {
            "path": settings_paths[0],
            "name": "Cache-named data (inspect its location and contents; the name alone does not prove it is disposable)",
            "size": 100_000_000, "size_formatted": "95.37 MB", "kind": "Directory",
        }
        categories = {key: {"name": key, "items": []} for key in ("high", "medium", "low")}
        categories["medium"]["items"] = [item]
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(
                ValueError, "protected path"):
            analyze.generate_clean_script(
                {"categories": categories},
                str(Path(temp_dir) / "agent-settings-cleanup.ps1"),
                priority="medium",
            )

    def test_windows_case_and_separator_aware_parent_deduplication(self):
        self.assertTrue(analyze._is_under(r"C:\Temp\nested", r"c:/temp/"))
        self.assertFalse(analyze._is_under(r"C:\Temp-old\item", r"C:\Temp"))

    def test_downloaded_projects_and_installers_are_not_cleanup_candidates(self):
        results = self.analyze_rows([
            {"File Name": r"C:\Users\ExampleUser\Downloads\ExampleProject\Workbench\ExampleProject\Temp\dotnet", "Size": "700000000"},
            {"File Name": r"C:\Users\ExampleUser\Downloads\ExampleProject\Workbench\ExampleProject\Cache\Hives", "Size": "200000000"},
            {"File Name": "C:\\Users\\ExampleUser\\Downloads\\", "Size": "100000000"},
            {"File Name": r"C:\Users\ExampleUser\Downloads\installer.exe", "Size": "100000000"},
        ])
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))

    def test_hard_link_rows_do_not_count_as_reclaimable_bytes(self):
        results = self.analyze_rows([
            {"File Name": "C:\\Users\\A\\AppData\\Local\\Temp\\hardlink.tmp", "Size": "90000000", "Allocated": "090000000"},
            {"File Name": "C:\\Users\\A\\AppData\\Local\\Temp\\normal.tmp", "Size": "90000000", "Allocated": "89000000"},
        ])
        items = results["categories"]["high"]["items"]
        self.assertEqual([item["path"] for item in items], ["C:\\Users\\A\\AppData\\Local\\Temp\\normal.tmp"])
        self.assertEqual(items[0]["size"], 89_000_000)

    def test_windirstat_export_uses_physical_size_and_directory_attributes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "windirstat.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=[
                    "Name", "Files", "Folders", "Logical Size", "Physical Size", "Attributes",
                    "WinDirStat Attributes",
                ])
                writer.writeheader()
                writer.writerow({
                    "Name": r"C:\Users\A\AppData\Local\Temp\Candidate", "Files": "4", "Folders": "1",
                    "Logical Size": "125000000", "Physical Size": "120000000", "Attributes": "",
                    "WinDirStat Attributes": "0x20000004",
                })
                writer.writerow({
                    "Name": r"C:\Users\A\AppData\Local\Temp\Candidate\large.bin", "Files": "0", "Folders": "0",
                    "Logical Size": "125000000", "Physical Size": "120000000", "Attributes": "Archive",
                    "WinDirStat Attributes": "0x20000008",
                })
            with mock.patch("analyze.os.path.exists", return_value=True), \
                 mock.patch("analyze.os.path.isdir", side_effect=lambda path: path.endswith("Candidate")), \
                 mock.patch("analyze.os.path.isfile", side_effect=lambda path: path.endswith("large.bin")):
                results = analyze.analyze_csv(str(csv_path), min_size_mb=0)
        items = results["categories"]["high"]["items"]
        self.assertEqual(len(items), 1)  # parent folder prevents double-counting its file
        self.assertEqual(items[0]["path"], "C:\\Users\\A\\AppData\\Local\\Temp\\Candidate\\")
        self.assertEqual(items[0]["size"], 120_000_000)
        self.assertEqual(items[0]["kind"], "Directory")
        with tempfile.TemporaryDirectory() as temp_dir:
            script_path = Path(temp_dir) / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            self.assertIn("IsDirectory = $true", script_path.read_text(encoding="utf-8-sig"))

    def test_localized_windirstat_headers_are_parsed_from_verified_export_layout(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "imported-scan.csv"
            headers = [
                "\u540d\u79f0", "\u6587\u4ef6\u6570", "\u6587\u4ef6\u5939\u6570",
                "\u903b\u8f91\u5927\u5c0f", "\u7269\u7406\u5927\u5c0f", "\u5c5e\u6027",
                "\u6700\u540e\u4fee\u6539", "\u5185\u90e8\u5c5e\u6027", "\u7d22\u5f15",
            ]
            folder_path = "C:\\Users\\A\\AppData\\Local\\Temp\\Candidate\\"
            file_path = folder_path + "cache.bin"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(headers)
                writer.writerow([folder_path, "1", "0", "125000000", "120000000", "", "", "0x20000004", "00000001"])
                writer.writerow([file_path, "0", "0", "125000000", "120000000", "Archive", "", "0x20000008", "00000002"])

            with mock.patch("analyze.os.path.exists", return_value=True), \
                 mock.patch("analyze.os.path.isdir", side_effect=lambda path: path.endswith("Candidate")), \
                 mock.patch("analyze.os.path.isfile", side_effect=lambda path: path.endswith("cache.bin")):
                results = analyze.analyze_csv(str(csv_path), min_size_mb=0)

        candidates = results["categories"]["high"]["items"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["path"], folder_path)
        self.assertEqual(candidates[0]["size"], 120_000_000)
        self.assertEqual(candidates[0]["kind"], "Directory")
        report = io.StringIO()
        with redirect_stdout(report):
            analyze.print_report(results)
        self.assertIn("High priority", report.getvalue())
        for localized_header in headers:
            self.assertNotIn(localized_header, report.getvalue())

    def test_unrecognized_nine_column_csv_is_not_guessed_as_windirstat(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "unrecognized.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow([f"Column {index}" for index in range(9)])
                writer.writerow([
                    r"C:\Users\A\AppData\Local\Temp\cache.bin", "0", "0", "125000000", "120000000",
                    "Archive", "", "0x20000001", "not-an-index",
                ])
            with self.assertRaisesRegex(ValueError, "missing required columns"):
                analyze.analyze_csv(str(csv_path), min_size_mb=0)

    def test_windirstat_rows_without_type_metadata_are_not_mislabeled_as_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "windirstat-ambiguous.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["Name", "Logical Size", "Physical Size"])
                writer.writeheader()
                writer.writerow({
                    "Name": r"C:\Users\A\AppData\Local\Temp\known-directory" + "\\",
                    "Logical Size": "125000000", "Physical Size": "120000000",
                })
                writer.writerow({
                    "Name": r"C:\Users\A\AppData\Local\Temp\unknown-item",
                    "Logical Size": "130000000", "Physical Size": "125000000",
                })
            with mock.patch("analyze.os.path.exists", return_value=True):
                with mock.patch("analyze.os.path.isdir", side_effect=lambda path: path.endswith("known-directory")), \
                     mock.patch("analyze.os.path.isfile", return_value=False):
                    results = analyze.analyze_csv(str(csv_path), min_size_mb=0)
        candidates = results["categories"]["high"]["items"]
        self.assertEqual([item["path"] for item in candidates], [
            r"C:\Users\A\AppData\Local\Temp\known-directory" + "\\",
        ])
        self.assertEqual(candidates[0]["kind"], "Directory")
        self.assertEqual(results["unclassified_candidate_count"], 1)
        with mock.patch("builtins.print") as output:
            analyze.print_report(results)
        report = " ".join(str(call.args[0]) for call in output.call_args_list if call.args)
        self.assertIn("file or folder type could not be confirmed", report)

    def test_display_item_type_keeps_localized_folder_metadata_in_english(self):
        localized_folder_label = "\u76ee\u5f55"
        self.assertEqual(analyze.display_item_type({"kind": localized_folder_label}), "Folder")
        self.assertEqual(analyze.display_item_type({"kind": "directory"}), "Folder")

    def test_windirstat_type_metadata_is_checked_against_current_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "windirstat-types.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["Name", "Logical Size", "Physical Size", "WinDirStat Attributes"])
                writer.writeheader()
                writer.writerow({
                    "Name": r"C:\Users\A\AppData\Local\Temp\changed-to-file",
                    "Logical Size": "125000000", "Physical Size": "120000000",
                    "WinDirStat Attributes": "0x20000004",
                })
                writer.writerow({
                    "Name": r"C:\Users\A\AppData\Local\Temp\current-file",
                    "Logical Size": "130000000", "Physical Size": "125000000",
                })
            with mock.patch("analyze.os.path.exists", return_value=True), \
                 mock.patch("analyze.os.path.isdir", return_value=False), \
                 mock.patch("analyze.os.path.isfile", return_value=True):
                results = analyze.analyze_csv(str(csv_path), min_size_mb=0)
        candidates = results["categories"]["high"]["items"]
        self.assertEqual([item["path"] for item in candidates], [r"C:\Users\A\AppData\Local\Temp\current-file"])
        self.assertEqual(candidates[0]["kind"], "File")
        self.assertEqual(results["type_mismatch_count"], 1)
        with mock.patch("builtins.print") as output:
            analyze.print_report(results)
        report = " ".join(str(call.args[0]) for call in output.call_args_list if call.args)
        self.assertIn("type changed since the scan", report)

    def test_candidate_analysis_skips_reparse_paths_and_discloses_them(self):
        with mock.patch.object(analyze.scan, "_path_has_reparse_component", return_value=True):
            results = self.analyze_rows([{
                "File Name": r"C:\Users\A\AppData\Local\Temp\redirected-cache.bin",
                "Size": "104857600",
            }])

        self.assertEqual(results["categories"]["high"]["items"], [])
        self.assertEqual(results["reparse_candidate_count"], 1)
        with mock.patch("builtins.print") as output:
            analyze.print_report(results)
        report = " ".join(str(call.args[0]) for call in output.call_args_list if call.args)
        self.assertIn("pass through a link or could not be checked", report)

        with tempfile.TemporaryDirectory() as temp_dir:
            candidate_file = Path(temp_dir) / "candidates.txt"
            analyze.write_item_list_report(results, str(candidate_file))
            self.assertIn("pass through a link or could not be checked", candidate_file.read_text(encoding="utf-8"))

    def test_windirstat_without_volume_metadata_uses_labeled_current_space(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "windirstat.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["Name", "Logical Size", "Physical Size"])
                writer.writeheader()
                writer.writerow({
                    "Name": r"C:\Users\A\AppData\Local\Temp\cache.bin",
                    "Logical Size": "100", "Physical Size": "100",
                })
            usage = SimpleNamespace(total=1000, used=700, free=300)
            with mock.patch("analyze.os.path.exists", return_value=True), \
                 mock.patch("analyze.os.path.isdir", return_value=False), \
                 mock.patch("analyze.os.path.isfile", return_value=True), \
                 mock.patch("analyze.shutil.disk_usage", return_value=usage) as disk_usage:
                results = analyze.analyze_csv(str(csv_path), min_size_mb=0)
                with mock.patch("builtins.print") as output:
                    analyze.print_report(results)
        self.assertEqual(results["space_source"], "current")
        self.assertEqual((results["total_size"], results["used_space"], results["free_space"]), (1000, 700, 300))
        disk_usage.assert_called_once_with("C:\\")
        output_text = " ".join(str(call.args[0]) for call in output.call_args_list if call.args)
        self.assertIn("Current capacity", output_text)
        self.assertIn("Volume space was checked now", output_text)

    def test_localized_wiztree_headers_remain_supported_with_english_ui(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "localized.csv"
            path_header = "\u6587\u4ef6\u540d\u79f0"
            size_header = "\u5927\u5c0f"
            allocated_header = "\u5df2\u5206\u914d"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=[path_header, size_header, allocated_header])
                writer.writeheader()
                writer.writerow({
                    path_header: r"C:\Users\A\AppData\Local\Temp\cache.bin",
                    size_header: "120000000", allocated_header: "120000000",
                })
            with mock.patch("analyze.os.path.exists", return_value=True):
                with mock.patch("analyze.os.path.isdir", return_value=False), \
                     mock.patch("analyze.os.path.isfile", return_value=True):
                    results = analyze.analyze_csv(str(csv_path), min_size_mb=0)
        items = results["categories"]["high"]["items"]
        self.assertEqual([item["path"] for item in items], [r"C:\Users\A\AppData\Local\Temp\cache.bin"])
        output = io.StringIO()
        with redirect_stdout(output):
            analyze.print_report(results)
        report = output.getvalue()
        self.assertIn("High priority", report)
        self.assertIn("lower risk (review each path)", report)
        self.assertIn("Temporary files (check for installers or builds in progress)", report)
        for localized_header in (path_header, size_header, allocated_header):
            self.assertNotIn(localized_header, report)

    def test_generated_script_quotes_untrusted_path_and_backs_up_first(self):
        path = "C:\\Users\\O'Brien\\AppData\\Local\\Temp\\$(not-a-command)\\"
        results = {"categories": {"high": {"name": "High", "items": [{
            "path": path, "name": "Temporary files (check for installers or builds in progress)", "size": 100,
            "size_formatted": "100 B", "kind": "Directory",
        }]}}}
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "clean.ps1"
            analyze.generate_clean_script(results, str(output))
            script = output.read_text(encoding="utf-8-sig")
        self.assertIn("'C:\\Users\\O''Brien\\AppData\\Local\\Temp\\$(not-a-command)\\'", script)
        self.assertIn("--json", script)
        self.assertIn("A Rust/Cargo process is running", script)
        self.assertIn("A Conda, Mamba, or Pixi operation is running", script)
        self.assertIn("A Node.js or package-manager process is running", script)
        self.assertIn("A Go process is running", script)
        self.assertIn("A .NET build process is running", script)
        self.assertIn("Windows installer, updater, or package manager is running", script)
        self.assertLess(script.index("Creating backup before cleanup"), script.index("::DeleteFileIfUnchanged("))
        self.assertIn("::DeleteEmptyDirectoryIfUnchanged(", script)
        self.assertNotIn("Remove-Item -LiteralPath $target.Path", script)
        self.assertIn("$target.IsDirectory", script)
        self.assertIn("Preserve excluded paths and nested projects", script)
        self.assertIn("$protectedPathPattern", script)
        self.assertIn("HashSet[string]", script)
        self.assertIn("$projectMarkers", script)
        self.assertIn(".vscode", script)
        for marker in (
                "agents.md", "agents.override.md", "claude.md", "gemini.md", "skill.md",
                ".cursorrules", ".claude", ".cursor", ".gemini", ".github", ".opencode",
                ".windsurf", "copilot-instructions.md"):
            self.assertIn(f"'{marker}'", script)
        self.assertIn(r"\.code\-workspace", script)
        self.assertIn("$profileRootIgnoredMarkers = @('.editorconfig', '.vscode'", script)
        self.assertIn("'agents.md'", script[script.index("$profileRootIgnoredMarkers"):])
        self.assertIn("$entryName -like '*.code-workspace'", script)
        self.assertIn("$backupScript verify --id $backup.id --paths $target.Path", script)
        self.assertIn("$backupScript = Join-Path $PSScriptRoot 'backup.py'", script)
        expected_backup_tool = str(Path(analyze.__file__).resolve().with_name("backup.py"))
        self.assertIn("$backupScript = " + analyze._ps_literal(expected_backup_tool), script)
        self.assertIn("$backupLocation = Join-Path $backup.backup_root $backup.id", script)
        self.assertIn('Write-Host "Backup saved to: $backupLocation"', script)
        self.assertIn('[Alias("Backup")][switch]$CreateBackup', script)
        self.assertIn('[Alias("NoBackup")][switch]$SkipBackup', script)
        self.assertIn("Choose either -Backup or -NoBackup, not both.", script)
        self.assertIn("} elseif (-not $Force) {", script)
        self.assertNotIn("Noninteractive cleanup keeps the verified backup", script)
        self.assertIn("Create a verified backup of these selected items first? [y/N]", script)
        self.assertIn("A verified recovery backup will be created before cleanup.", script)
        self.assertIn("Type CLEAN to back up and remove", script)
        self.assertIn("Type DELETE WITHOUT BACKUP", script)
        self.assertIn("No backup will be created", script)
        self.assertIn("only the permissions needed for the selected paths", script)
        self.assertIn("$cleanupItemIndex = 0", script)
        self.assertIn('Write-Host "`nChecking selected item $cleanupItemIndex of $($cleanTargets.Count): $($target.ItemType) | $($target.Name) | $($target.Path). $previousItemStatus"', script)
        self.assertIn('"Files from earlier selected items may already have been removed."', script)
        self.assertIn("Checking this item and its parent folders for project files. This can take a while.", script)
        self.assertIn("Reviewing files and folders inside this selection; large folders can take a while. This review does not remove files.", script)
        self.assertIn("Write-Progress -Activity \"Reviewing selected folder contents\"", script)
        entry_guard_start = script.index("function Assert-CleanupEntryPathWithinSelection")
        entry_guard_end = script.index("\n}\n\n$available", entry_guard_start)
        entry_guard = script[entry_guard_start:entry_guard_end]
        self.assertIn("StartsWith($targetRootWithSeparator", entry_guard)
        self.assertNotIn("Get-Item -LiteralPath $entryPath", entry_guard)
        self.assertIn("native removal routine", entry_guard)
        self.assertIn("CleanupLastWriteTimeUtcFileTime", script)
        self.assertIn("RequireFileSnapshot", script)
        self.assertIn("Checking this item and its parent folders for project files.", script)
        self.assertIn("[System.IO.Directory]::EnumerateFileSystemEntries($Directory)", script)
        self.assertIn("Folder review complete", script)
        self.assertIn('Write-Host "  Project check: $projectCheckStatus"', script)
        self.assertIn('Write-Host "  Folder review: $inventoryStatus"', script)
        self.assertIn('Write-Host "  Checked $fileHashIndex of $fileHashTotal selected files; this check does not remove files."', script)
        self.assertIn("Initial checks passed. Now checking and removing selected files one at a time; earlier files may already be removed if a later check fails.", script)
        self.assertIn('Write-Progress -Activity "Removing selected files" -Status "Processing file $fileRecheckIndex of $fileRecheckTotal; earlier files may already be removed"', script)
        self.assertIn("Removed $targetFilesRemoved of $fileRecheckTotal selected files from this item.", script)
        self.assertIn("FileStream(handle, FileAccess.Read, 131072, false)", script)
        self.assertNotIn("Run with administrator privileges", script)

    def test_generated_script_parses_in_powershell_when_available(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        results = {"categories": {"high": {"name": "High", "items": [{
            "path": "C:\\Users\\TestUser\\AppData\\Local\\Temp\\candidate-folder\\", "name": "Temporary files (check for installers or builds in progress)",
            "size": 100, "size_formatted": "100 B", "kind": "Directory",
        }]}}}
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "clean.ps1"
            analyze.generate_clean_script(results, str(output))
            ps_literal = "'" + str(output).replace("'", "''") + "'"
            command = (
                "$tokens=$null;$errors=$null;"
                f"[System.Management.Automation.Language.Parser]::ParseFile({ps_literal},[ref]$tokens,[ref]$errors)|Out-Null;"
                "if($errors.Count){$errors|Format-List;exit 1}"
            )
            result = subprocess.run([powershell, "-NoProfile", "-Command", command], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_cleanup_runs_in_windows_powershell_51(self):
        powershell = shutil.which("powershell")
        if not powershell:
            self.skipTest("Windows PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        if not temp_root.is_dir():
            self.skipTest("Windows temporary folder is unavailable")
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            root = Path(temp_dir)
            target = root / "candidate-cache.tmp"
            target.write_bytes(b"PowerShell 5.1 fixture")
            label = "Temporary files (check for installers or builds in progress)"
            results = {"categories": {
                "high": {"name": "High", "items": [{
                    "path": str(target), "name": label,
                    "size": target.stat().st_size,
                    "size_formatted": f"{target.stat().st_size} B", "kind": "File",
                }]},
                "medium": {"name": "Medium", "items": []},
                "low": {"name": "Low", "items": []},
            }}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                 "-Select", "1", "-NoBackup", "-Force"],
                capture_output=True, text=True, timeout=120,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(target.exists(), result.stdout + result.stderr)
            self.assertIn(
                f"Checking selected item 1 of 1: File | {label} | {target}. Nothing has been removed yet.",
                result.stdout,
            )

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_cleanup_removes_unchanged_file_and_directory_named_streams(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        if not temp_root.is_dir():
            self.skipTest("Windows temporary folder is unavailable")
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            root = Path(temp_dir)
            target = root / "candidate-cache"
            nested = target / "nested"
            nested.mkdir(parents=True)
            payload = nested / "payload.bin"
            payload.write_bytes(b"ordinary cached file")
            streams = (
                (str(target) + ":DriveCleanrRootTest:$DATA", b"root stream"),
                (str(nested) + ":DriveCleanrNestedTest:$DATA", b"nested directory stream"),
                (str(payload) + ":DriveCleanrFileTest:$DATA", b"file stream payload"),
            )
            try:
                for stream_path, contents in streams:
                    with open(stream_path, "wb") as stream:
                        stream.write(contents)
            except OSError as exc:
                self.skipTest(f"Temporary volume does not support named streams: {exc}")
            if any(not backup._named_data_streams(stream_path.split(":DriveCleanr", 1)[0])
                   for stream_path, _contents in streams):
                self.skipTest("Temporary volume does not expose named data streams")

            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target) + "\\",
                "name": "Temporary files (check for installers or builds in progress)",
                "size": payload.stat().st_size,
                "size_formatted": f"{payload.stat().st_size} B",
                "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                 "-Select", "1", "-NoBackup", "-Force"],
                capture_output=True, text=True, timeout=120,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(target.exists(), result.stdout + result.stderr)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_cleanup_preserves_file_when_named_stream_changes_after_review(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        if not temp_root.is_dir():
            self.skipTest("Windows temporary folder is unavailable")
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            root = Path(temp_dir)
            target = root / "candidate-cache.bin"
            target.write_bytes(b"ordinary file payload")
            stream_path = str(target) + ":DriveCleanrMutationTest:$DATA"
            original_stream = b"original ADS"
            replacement_stream = b"changed ADS!"
            self.assertEqual(len(original_stream), len(replacement_stream))
            with open(stream_path, "wb") as stream:
                stream.write(original_stream)
            if not backup._named_data_streams(str(target)):
                self.skipTest("Temporary volume does not expose named data streams")

            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target),
                "name": "Temporary files (check for installers or builds in progress)",
                "size": target.stat().st_size,
                "size_formatted": f"{target.stat().st_size} B",
                "kind": "File",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            self._install_mock_backup_that_changes_stream_on_verify(
                root, stream_path, replacement_stream, target
            )
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                 "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=120,
            )

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(target.exists(), result.stdout + result.stderr)
            self.assertEqual(target.read_bytes(), b"ordinary file payload")
            with open(stream_path, "rb") as stream:
                self.assertEqual(stream.read(), replacement_stream)
            self.assertIn("contents changed after backup verification", result.stdout + result.stderr)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_cleanup_preserves_folder_contents_when_folder_stream_changes(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        if not temp_root.is_dir():
            self.skipTest("Windows temporary folder is unavailable")
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            root = Path(temp_dir)
            target = root / "candidate-cache"
            target.mkdir()
            payload = target / "payload.bin"
            payload.write_bytes(b"preserve until review completes")
            stream_path = str(target) + ":DriveCleanrDirectoryMutationTest:$DATA"
            original_stream = b"original directory stream"
            replacement_stream = b"changed directory stream!"
            self.assertEqual(len(original_stream), len(replacement_stream))
            with open(stream_path, "wb") as stream:
                stream.write(original_stream)
            if not backup._named_data_streams(str(target)):
                self.skipTest("Temporary volume does not expose directory named streams")

            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target) + "\\",
                "name": "Temporary files (check for installers or builds in progress)",
                "size": payload.stat().st_size,
                "size_formatted": f"{payload.stat().st_size} B",
                "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            self._install_mock_backup_that_changes_stream_on_verify(
                root, stream_path, replacement_stream, target
            )
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                 "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=120,
            )

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(target.is_dir(), result.stdout + result.stderr)
            self.assertEqual(payload.read_bytes(), b"preserve until review completes")
            with open(stream_path, "rb") as stream:
                self.assertEqual(stream.read(), replacement_stream)
            self.assertIn("named data streams changed after review", result.stdout + result.stderr)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_creates_and_verifies_backup_before_cleaning_selected_fixture(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        with (
            tempfile.TemporaryDirectory(dir=temp_root) as target_temp,
            tempfile.TemporaryDirectory(dir=temp_root) as plan_temp,
        ):
            target = Path(target_temp) / "candidate.tmp"
            target.write_bytes(b"synthetic disposable cache")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target),
                "name": "Temporary files (check for installers or builds in progress)",
                "size": target.stat().st_size,
                "size_formatted": f"{target.stat().st_size} B",
                "kind": "File",
            }]}}}
            script_path = Path(plan_temp) / "clean.ps1"
            backup_calls = self._install_complete_mock_backup(plan_temp)
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(results, str(script_path))

            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                 "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(target.exists(), result.stdout + result.stderr)
            self.assertIn("Files and folders already selected for this plan:", result.stdout)
            self.assertIn("File | Temporary files", result.stdout)
            self.assertIn("A verified recovery backup will be created before cleanup.", result.stdout)
            self.assertIn("Backup created: mock-backup", result.stdout)
            self.assertEqual(backup_calls.read_text(encoding="utf-8").splitlines(), ["create", "verify"])

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_handles_selected_child_inside_selected_folder(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        with (
            tempfile.TemporaryDirectory(dir=temp_root) as target_temp,
            tempfile.TemporaryDirectory(dir=temp_root) as plan_temp,
        ):
            root = Path(target_temp)
            selected_folder = root / "selected-folder"
            selected_cache = selected_folder / "Cache"
            selected_cache.mkdir(parents=True)
            nested_file = selected_cache / "payload.bin"
            nested_file.write_bytes(b"explicitly selected nested cache")
            unrelated_file = root / "outside.bin"
            unrelated_file.write_bytes(b"must stay in place")
            results = {"categories": {
                "high": {"name": "High", "items": [{
                    "path": str(selected_folder) + "\\",
                    "name": "Temporary files (check for installers or builds in progress)",
                    "size": 32, "size_formatted": "32 B", "kind": "Directory",
                }]},
                "medium": {"name": "Medium", "items": [{
                    "path": str(selected_cache) + "\\",
                    "name": "Cache-named data (inspect its location and contents; the name alone does not prove it is disposable)",
                    "size": 32, "size_formatted": "32 B", "kind": "Directory",
                }]},
                "low": {"name": "Low", "items": []},
            }}
            script_path = Path(plan_temp) / "clean.ps1"
            analyze.generate_clean_script(
                results, str(script_path), priority="all",
                selected_paths=[str(selected_folder) + "\\", str(selected_cache) + "\\"],
            )
            backup_log = Path(plan_temp) / "backup-targets.txt"
            (Path(plan_temp) / "backup.py").write_text(
                "import json, ntpath, os, sys\n"
                "start = sys.argv.index('--paths') + 1\n"
                "end = sys.argv.index('--json') if '--json' in sys.argv else len(sys.argv)\n"
                "paths = sys.argv[start:end]\n"
                "with open(os.environ['CLEANR_TEST_BACKUP_LOG'], 'a', encoding='utf-8') as log:\n"
                "    log.write(sys.argv[1] + '|' + '|'.join(paths) + '\\n')\n"
                "if sys.argv[1] == 'verify': sys.exit(0)\n"
                "keys = [ntpath.normcase(ntpath.normpath(path)).rstrip('\\\\') for path in paths]\n"
                "for index, path in enumerate(keys):\n"
                "    if any(path == earlier or path.startswith(earlier + '\\\\') or earlier.startswith(path + '\\\\') for earlier in keys[:index]):\n"
                "        print('Backup paths must not duplicate or overlap', file=sys.stderr)\n"
                "        sys.exit(2)\n"
                "print(json.dumps({'status': 'completed', 'id': 'mock-backup', 'items': [{'path': path} for path in paths]}))\n",
                encoding="utf-8",
            )
            env = dict(os.environ, CLEANR_TEST_BACKUP_LOG=str(backup_log))
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                 "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=120, env=env,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(selected_folder.exists(), result.stdout + result.stderr)
            self.assertFalse(nested_file.exists(), result.stdout + result.stderr)
            self.assertEqual(unrelated_file.read_bytes(), b"must stay in place")
            calls = backup_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(calls), 2, result.stdout + result.stderr)
            self.assertEqual(calls[0].rstrip("\\"), f"create|{selected_folder}")
            self.assertEqual(calls[1].rstrip("\\"), f"verify|{selected_folder}")
            self.assertIn("Explicitly selected nested items included with this folder:", result.stdout)
            self.assertIn(str(selected_cache), result.stdout)
            script_text = script_path.read_text(encoding="utf-8-sig")
            self.assertIn("higher-risk candidates you did not explicitly select", script_text)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_shows_progress_while_inventorying_large_fixture_folder(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        # Use a private temporary root so project checks do not scan the user's
        # actual Temp directory. Empty child folders isolate inventory cost.
        with (
            tempfile.TemporaryDirectory(dir=Path.home()) as isolated_temp,
            mock.patch.dict(os.environ, {"TEMP": isolated_temp, "TMP": isolated_temp}),
            mock.patch.object(tempfile, "tempdir", isolated_temp),
            tempfile.TemporaryDirectory(dir=isolated_temp) as target_temp,
            tempfile.TemporaryDirectory(dir=isolated_temp) as plan_temp,
        ):
            target = Path(target_temp) / "candidate-cache"
            target.mkdir()
            entry_count = 3809
            for index in range(entry_count):
                (target / f"item-{index:04d}.cache").write_bytes(b"")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target) + "\\",
                "name": "Temporary files (check for installers or builds in progress)",
                "size": 0,
                "size_formatted": "0 B",
                "kind": "Directory",
            }]}}}
            script_path = Path(plan_temp) / "clean.ps1"
            self._install_complete_mock_backup(plan_temp)
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(results, str(script_path))
            script_text = script_path.read_text(encoding="utf-8-sig")
            # Keep this progress-only fixture inside its synthetic temp root;
            # production plans still check all real parent folders.
            profile_scan_prefix = "if ($normalizedCurrent -match "
            self.assertIn(profile_scan_prefix, script_text)
            script_text = script_text.replace(
                profile_scan_prefix,
                "if ($normalizedCurrent -eq ([System.IO.Path]::GetFullPath($env:TEMP).TrimEnd('\\')) -or $normalizedCurrent -match ",
                1,
            )
            inventory_complete = 'Write-Host "Folder review complete; $($entries.Count) files and folders found." -ForegroundColor Gray'
            protected_content_complete = 'Write-Host "Protected-data check complete; $protectedContentCheckIndex items reviewed." -ForegroundColor Gray'
            self.assertIn(inventory_complete, script_text)
            self.assertIn(protected_content_complete, script_text)
            self.assertIn("if ($entries.Count -eq 1 -or ($entries.Count % 100) -eq 0", script_text)
            # Stop after both unbounded classification passes, before hashing
            # files or reaching any removal code.
            script_path.write_text(
                script_text.replace(
                    protected_content_complete,
                    protected_content_complete + "\n            exit 0",
                    1,
                ),
                encoding="utf-8-sig",
            )

            try:
                result = subprocess.run(
                    [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                     "-Select", "1", "-Force"],
                    capture_output=True, text=True, timeout=120,
                )
            except subprocess.TimeoutExpired as exc:
                output = exc.stdout or ""
                if isinstance(output, bytes):
                    output = output.decode("utf-8", errors="replace")
                self.fail(f"cleanup exceeded 120 seconds; output so far:\n{output}")

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Reviewing files and folders inside this selection", result.stdout)
            self.assertIn("Project check: First entry checked for project files.", result.stdout)
            self.assertIn("Project check: 100 entries checked for project files.", result.stdout)
            self.assertIn("Project marker check complete; 3809 entries checked in this folder.", result.stdout)
            self.assertIn("Folder review: First item listed; this review does not remove files.", result.stdout)
            self.assertIn("Folder review: 3800 files and folders listed; this review does not remove files.", result.stdout)
            self.assertIn("Folder review complete; 3809 files and folders found.", result.stdout)
            self.assertIn("Project file check: 3800 of 3809 items checked for project files; this check does not remove files.", result.stdout)
            self.assertIn("Project file check complete; 3809 items reviewed.", result.stdout)
            self.assertIn("Protected-data check: 3800 of 3809 items checked for protected data; this check does not remove files.", result.stdout)
            self.assertIn("Protected-data check complete; 3809 items reviewed.", result.stdout)
            self.assertNotIn("Checking the contents of", result.stdout)
            self.assertTrue(target.is_dir(), result.stdout + result.stderr)
            self.assertEqual(entry_count, sum(1 for _ in target.iterdir()))

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_reports_byte_progress_while_hashing_a_large_file(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with (
            tempfile.TemporaryDirectory(dir=Path.home()) as isolated_temp,
            mock.patch.dict(os.environ, {"TEMP": isolated_temp, "TMP": isolated_temp}),
            mock.patch.object(tempfile, "tempdir", isolated_temp),
            tempfile.TemporaryDirectory(dir=isolated_temp) as target_temp,
            tempfile.TemporaryDirectory(dir=isolated_temp) as plan_temp,
        ):
            target = Path(target_temp) / "large-cache.bin"
            with target.open("wb") as stream:
                stream.truncate(128 * 1024 * 1024)
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target),
                "name": "Temporary files (check for installers or builds in progress)",
                "size": target.stat().st_size,
                "size_formatted": "128.00 MB",
                "kind": "File",
            }]}}}
            script_path = Path(plan_temp) / "clean.ps1"
            self._install_complete_mock_backup(plan_temp)
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(results, str(script_path))
            script_text = script_path.read_text(encoding="utf-8-sig")
            profile_scan_prefix = "if ($normalizedCurrent -match "
            self.assertIn(profile_scan_prefix, script_text)
            script_text = script_text.replace(
                profile_scan_prefix,
                "if ($normalizedCurrent -eq ([System.IO.Path]::GetFullPath($env:TEMP).TrimEnd('\\')) -or $normalizedCurrent -match ",
                1,
            )
            script_path.write_text(script_text, encoding="utf-8-sig")

            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                 "-Select", "1", "-Force"],
                capture_output=True, text=True, timeout=180,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(target.exists(), result.stdout + result.stderr)

        self.assertIn("File 1 of 1: 64.0 MB of 128.0 MB checked (50%).", result.stdout)
        self.assertIn("File 1 of 1: 128.0 MB of 128.0 MB checked (100%).", result.stdout)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_cleanup_modes_still_reject_stale_and_project_targets(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        with tempfile.TemporaryDirectory(dir=temp_root) as fixture_root:
            root = Path(fixture_root)
            for case in ("stale", "project"):
                with self.subTest(case=case):
                    case_root = root / case
                    case_root.mkdir()
                    project_root = case_root / "project"
                    project_root.mkdir()
                    target = project_root / "candidate.tmp"
                    target.write_bytes(b"synthetic cleanup fixture")
                    results = {"categories": {"high": {"name": "High", "items": [{
                        "path": str(target),
                        "name": "Temporary files (check for installers or builds in progress)",
                        "size": target.stat().st_size,
                        "size_formatted": f"{target.stat().st_size} B",
                        "kind": "File",
                    }]}}}
                    script_path = case_root / "clean.ps1"
                    with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                        analyze.generate_clean_script(results, str(script_path))

                    if case == "stale":
                        target.unlink()
                        target.mkdir()
                        sentinel = target / "preserve.txt"
                        sentinel.write_text("preserve", encoding="utf-8")
                    else:
                        (project_root / ".git").mkdir()
                        sentinel = target

                    result = subprocess.run(
                        [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                         "-Select", "1", "-Force"],
                        capture_output=True, text=True, timeout=90,
                    )

                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue(sentinel.exists(), result.stdout + result.stderr)
                    self.assertNotIn("Creating backup before cleanup", result.stdout)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_interactive_no_backup_requires_distinct_confirmation(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        with (
            tempfile.TemporaryDirectory(dir=temp_root) as target_temp,
            tempfile.TemporaryDirectory(dir=temp_root) as plan_temp,
        ):
            target = Path(target_temp) / "candidate.tmp"
            target.write_bytes(b"synthetic cleanup fixture")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target),
                "name": "Temporary files (check for installers or builds in progress)",
                "size": target.stat().st_size,
                "size_formatted": f"{target.stat().st_size} B",
                "kind": "File",
            }]}}}
            script_path = Path(plan_temp) / "clean.ps1"
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(results, str(script_path))

            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
                input="1\nn\nDELETE WITHOUT BACKUP\n", capture_output=True, text=True, timeout=90,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(target.exists(), result.stdout + result.stderr)
            generated = script_path.read_text(encoding="utf-8-sig")
            self.assertIn("Create a verified backup of these selected items first? [y/N]", generated)
            self.assertIn("Type DELETE WITHOUT BACKUP", generated)
            self.assertIn("No backup will be created", result.stdout)
            self.assertIn("No recovery backup was created", result.stdout)
            self.assertNotIn("Creating backup before cleanup", result.stdout)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_interactive_user_can_choose_verified_backup(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        with (
            tempfile.TemporaryDirectory(dir=temp_root) as target_temp,
            tempfile.TemporaryDirectory(dir=temp_root) as plan_temp,
        ):
            target = Path(target_temp) / "candidate.tmp"
            target.write_bytes(b"synthetic cleanup fixture")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target),
                "name": "Temporary files (check for installers or builds in progress)",
                "size": target.stat().st_size,
                "size_formatted": f"{target.stat().st_size} B",
                "kind": "File",
            }]}}}
            script_path = Path(plan_temp) / "clean.ps1"
            calls = Path(plan_temp) / "backup-calls.txt"
            backup_helper = Path(plan_temp) / "backup.py"
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(results, str(script_path))
            backup_helper.write_text(
                "import json, sys\nfrom pathlib import Path\n"
                f"calls = Path({str(calls)!r})\n"
                "with calls.open('a', encoding='utf-8') as stream: stream.write(sys.argv[1] + '\\n')\n"
                "if sys.argv[1] == 'verify': sys.exit(0)\n"
                "start = sys.argv.index('--paths') + 1; end = sys.argv.index('--json')\n"
                "print(json.dumps({'status':'completed','id':'mock-backup','items':[{} for _ in sys.argv[start:end]]}))\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
                input="1\ny\nCLEAN\n", capture_output=True, text=True, timeout=90,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(target.exists(), result.stdout + result.stderr)
            self.assertIn("Backup created: mock-backup", result.stdout)
            self.assertEqual(calls.read_text(encoding="utf-8").splitlines(), ["create", "verify"])

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_blank_backup_choice_defaults_to_no_and_clean_phrase_cancels(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        with (
            tempfile.TemporaryDirectory(dir=temp_root) as target_temp,
            tempfile.TemporaryDirectory(dir=temp_root) as plan_temp,
        ):
            target = Path(target_temp) / "candidate.tmp"
            target.write_bytes(b"must remain after wrong confirmation")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target),
                "name": "Temporary files (check for installers or builds in progress)",
                "size": target.stat().st_size,
                "size_formatted": f"{target.stat().st_size} B",
                "kind": "File",
            }]}}}
            script_path = Path(plan_temp) / "clean.ps1"
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(results, str(script_path))

            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
                input="1\n\nCLEAN\n", capture_output=True, text=True, timeout=90,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(target.is_file(), result.stdout + result.stderr)
            self.assertIn("Cancelled; nothing was changed.", result.stdout)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_noninteractive_cleanup_does_not_create_backup_without_opt_in(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        with (
            tempfile.TemporaryDirectory(dir=temp_root) as target_temp,
            tempfile.TemporaryDirectory(dir=temp_root) as plan_temp,
        ):
            target = Path(target_temp) / "candidate.tmp"
            target.write_bytes(b"temporary fixture selected without backup")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target), "name": "Temporary files (check for installers or builds in progress)", "size": target.stat().st_size,
                "size_formatted": f"{target.stat().st_size} B", "kind": "File",
            }]}}}
            script_path = Path(plan_temp) / "clean.ps1"
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(results, str(script_path))
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                 "-Select", "1", "-Force"],
                capture_output=True, text=True, timeout=90,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(target.exists(), result.stdout + result.stderr)
            self.assertIn("No backup will be created", result.stdout)
            self.assertIn("No recovery backup was created", result.stdout)
            self.assertNotIn("Creating backup before cleanup", result.stdout)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_file_checks_report_visible_progress_during_large_folder_cleanup(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with (
            tempfile.TemporaryDirectory(dir=Path.home()) as isolated_temp,
            mock.patch.dict(os.environ, {"TEMP": isolated_temp, "TMP": isolated_temp}),
            mock.patch.object(tempfile, "tempdir", isolated_temp),
            tempfile.TemporaryDirectory(dir=isolated_temp) as target_temp,
            tempfile.TemporaryDirectory(dir=isolated_temp) as plan_temp,
        ):
            target = Path(target_temp) / "candidate-cache"
            target.mkdir()
            for index in range(101):
                (target / f"item-{index:04d}.bin").write_bytes(b"cache entry")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target) + "\\", "name": "Temporary files (check for installers or builds in progress)", "size": 101 * 11,
                "size_formatted": "1.1 KB", "kind": "Directory",
            }]}}}
            script_path = Path(plan_temp) / "clean.ps1"
            self._install_complete_mock_backup(plan_temp)
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(results, str(script_path))
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                 "-Select", "1", "-Force"],
                capture_output=True, text=True, timeout=120,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(target.exists(), result.stdout + result.stderr)
            self.assertIn("Checking selected file 1 of 101; this check does not remove files.", result.stdout)
            self.assertIn("Checked 100 of 101 selected files; this check does not remove files.", result.stdout)
            self.assertIn("Checked 101 of 101 selected files; this check does not remove files.", result.stdout)
            self.assertIn("Initial checks passed. Now checking and removing selected files one at a time; earlier files may already be removed if a later check fails.", result.stdout)
            self.assertIn("Removed 100 of 101 selected files from this item.", result.stdout)
            self.assertIn("Removed 101 of 101 selected files from this item.", result.stdout)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_partial_folder_failure_reports_only_files_successfully_removed(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with (
            tempfile.TemporaryDirectory(dir=Path.home()) as isolated_temp,
            mock.patch.dict(os.environ, {"TEMP": isolated_temp, "TMP": isolated_temp}),
            mock.patch.object(tempfile, "tempdir", isolated_temp),
            tempfile.TemporaryDirectory(dir=isolated_temp) as target_temp,
            tempfile.TemporaryDirectory(dir=isolated_temp) as plan_temp,
        ):
            target = Path(target_temp) / "candidate-cache"
            target.mkdir()
            selected_files = [target / "cache-a.tmp", target / "cache-b.tmp"]
            for selected_file in selected_files:
                selected_file.write_bytes(b"fixture-9")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target) + "\\",
                "name": "Temporary files (check for installers or builds in progress)",
                "size": sum(selected_file.stat().st_size for selected_file in selected_files),
                "size_formatted": "18 B", "kind": "Directory",
            }]}}}
            script_path = Path(plan_temp) / "clean.ps1"
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(results, str(script_path))

            lines = script_path.read_text(encoding="utf-8-sig").splitlines()
            loop_index = next(
                index for index, line in enumerate(lines)
                if line.strip() == "foreach ($entry in $orderedDeletable) {"
            )
            loop_indent = lines[loop_index][:len(lines[loop_index]) - len(lines[loop_index].lstrip())]
            lines.insert(loop_index, f"{loop_indent}$deleteAttempt = 0")
            call_index = next(
                index for index, line in enumerate(lines[:-1])
                if "::DeleteFileIfUnchanged(" in line and "$entry.FullName" in lines[index + 1]
            )
            call_indent = lines[call_index][:len(lines[call_index]) - len(lines[call_index].lstrip())]
            lines[call_index:call_index] = [
                f"{call_indent}$deleteAttempt++",
                f"{call_indent}if ($deleteAttempt -eq 2) {{ throw 'simulated failure after the first file' }}",
            ]
            script_path.write_text("\n".join(lines) + "\n", encoding="utf-8-sig")
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                 "-Select", "1", "-NoBackup", "-Force"],
                capture_output=True, text=True, timeout=120,
            )

            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertEqual(sum(not selected_file.exists() for selected_file in selected_files), 1)
            self.assertIn("Cleanup finished with errors. Removed 1 file and 0 folders (9 bytes of file data; about 0.00 GB); some items may remain.", result.stdout)
            self.assertIn("Removed 1 of 2 selected files and 0 folders from this item before the error (9 bytes of file data).", result.stdout)
            self.assertIn("No backup was created", result.stdout)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_normalizes_unknown_runtime_errors_to_english(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            root = Path(temp_dir)
            target = root / "candidate.tmp"
            target.write_bytes(b"localized error fixture")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target),
                "name": "Temporary files (check for installers or builds in progress)",
                "size": target.stat().st_size,
                "size_formatted": f"{target.stat().st_size} B",
                "kind": "File",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            script_text = script_path.read_text(encoding="utf-8-sig")
            insertion_point = "            $targetFilesPlanned = 1\n"
            self.assertIn(insertion_point, script_text)
            script_path.write_text(
                script_text.replace(
                    insertion_point,
                    insertion_point + "            throw 'Zugriff verweigert'\n",
                    1,
                ),
                encoding="utf-8-sig",
            )

            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                 "-Select", "1", "-NoBackup", "-Force"],
                capture_output=True, text=True, timeout=90,
            )

            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertTrue(target.exists(), result.stdout + result.stderr)
            self.assertIn("A cleanup check failed; no more files will be removed from this item.", result.stdout)
            self.assertNotIn("Zugriff verweigert", result.stdout + result.stderr)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_selected_item_progress_uses_processing_order_and_tracks_prior_removals(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with (
            tempfile.TemporaryDirectory(dir=Path.home()) as isolated_temp,
            mock.patch.dict(os.environ, {"TEMP": isolated_temp, "TMP": isolated_temp}),
            mock.patch.object(tempfile, "tempdir", isolated_temp),
            tempfile.TemporaryDirectory(dir=isolated_temp) as target_temp,
            tempfile.TemporaryDirectory(dir=isolated_temp) as plan_temp,
        ):
            targets = [Path(target_temp) / f"candidate-{index}.tmp" for index in range(3)]
            for index, target in enumerate(targets):
                target.write_bytes(f"fixture {index}".encode("ascii"))
            label = "Temporary files (check for installers or builds in progress)"
            results = {"categories": {"high": {"name": "High", "items": [
                {"path": str(target), "name": label, "size": target.stat().st_size,
                 "size_formatted": f"{target.stat().st_size} B", "kind": "File"}
                for target in targets
            ]}}}
            script_path = Path(plan_temp) / "clean.ps1"
            self._install_complete_mock_backup(plan_temp)
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(results, str(script_path))
            command = f"& {analyze._ps_literal(str(script_path))} -Select 1,3 -Force"
            result = subprocess.run(
                [powershell, "-NoProfile", "-Command", command],
                capture_output=True, text=True, timeout=120,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(f"Checking selected item 1 of 2: File | {label} | {targets[0]}. Nothing has been removed yet.", result.stdout)
            self.assertIn(f"Checking selected item 2 of 2: File | {label} | {targets[2]}. Files from earlier selected items may already have been removed.", result.stdout)
            self.assertFalse(targets[0].exists(), result.stdout + result.stderr)
            self.assertTrue(targets[1].exists(), "The unselected middle file must remain untouched")
            self.assertFalse(targets[2].exists(), result.stdout + result.stderr)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_rejects_changed_item_type_before_backup(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        with (
            tempfile.TemporaryDirectory(dir=temp_root) as target_temp,
            tempfile.TemporaryDirectory(dir=temp_root) as plan_temp,
        ):
            target = Path(target_temp) / "candidate.tmp"
            target.write_text("scanned as a file", encoding="utf-8")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target),
                "name": "Temporary files (check for installers or builds in progress)",
                "size": target.stat().st_size,
                "size_formatted": f"{target.stat().st_size} B",
                "kind": "File",
            }]}}}
            script_path = Path(plan_temp) / "clean.ps1"
            sentinel = Path(plan_temp) / "backup_called.txt"
            backup_helper = Path(plan_temp) / "backup.py"
            helper_contents = (
                "import json\nfrom pathlib import Path\n"
                f"Path({str(sentinel)!r}).write_text('called', encoding='utf-8')\n"
                "print(json.dumps({'status':'completed','id':'backup_20260928_123456_123456',"
                "'items':[{}]}))\n"
            )
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(results, str(script_path))
            backup_helper.write_text(helper_contents, encoding="utf-8")

            target.unlink()
            target.mkdir()
            (target / "keep.txt").write_text("preserve", encoding="utf-8")
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90,
            )

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("item type changed since the scan", result.stdout + result.stderr)
            self.assertFalse(sentinel.exists(), "Backup should not start for a stale candidate type")
            self.assertEqual((target / "keep.txt").read_text(encoding="utf-8"), "preserve")

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_rechecks_target_type_after_backup_before_cleanup(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        with (
            tempfile.TemporaryDirectory(dir=temp_root) as target_temp,
            tempfile.TemporaryDirectory(dir=temp_root) as plan_temp,
        ):
            target = Path(target_temp) / "candidate.tmp"
            target.write_text("scanned as a file", encoding="utf-8")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target),
                "name": "Temporary files (check for installers or builds in progress)",
                "size": target.stat().st_size,
                "size_formatted": f"{target.stat().st_size} B",
                "kind": "File",
            }]}}}
            script_path = Path(plan_temp) / "clean.ps1"
            call_log = Path(plan_temp) / "backup_calls.txt"
            backup_helper = Path(plan_temp) / "backup.py"
            helper_contents = (
                "import json, sys\nfrom pathlib import Path\n"
                f"candidate = Path({str(target)!r})\n"
                f"log = Path({str(call_log)!r})\n"
                "with log.open('a', encoding='utf-8') as stream: stream.write(sys.argv[1] + '\\n')\n"
                "if sys.argv[1] == 'create':\n"
                "    candidate.unlink(); candidate.mkdir()\n"
                "    (candidate / 'keep.txt').write_text('preserve', encoding='utf-8')\n"
                "    print(json.dumps({'status':'completed','id':'backup_20260928_123456_123456','items':[{}]}))\n"
            )
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(results, str(script_path))
            backup_helper.write_text(helper_contents, encoding="utf-8")

            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90,
            )

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("item type changed since the scan", result.stdout + result.stderr)
            self.assertEqual(call_log.read_text(encoding="utf-8").splitlines(), ["create"])
            self.assertEqual((target / "keep.txt").read_text(encoding="utf-8"), "preserve")

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_mocked_scan_candidate_flows_through_cleanup_and_real_restore(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        with (
            tempfile.TemporaryDirectory(dir=temp_root) as target_temp,
            tempfile.TemporaryDirectory(dir=temp_root) as plan_temp,
        ):
            target = Path(target_temp) / "candidate.tmp"
            target.write_bytes(b"synthetic cache data")
            scan_data = Path(plan_temp) / "scan-data"
            scan_command = []

            class CompletedMockScanner:
                def poll(self):
                    return 0

                def wait(self, timeout=None):
                    return 0

            def write_mock_scan_export(command, **_kwargs):
                scan_command.extend(command)
                export_arg = next(arg for arg in command if arg.startswith("/export="))
                csv_path = Path(export_arg.split("=", 1)[1])
                with csv_path.open("w", newline="", encoding="utf-8") as export:
                    writer = csv.writer(export)
                    writer.writerow(["File Name", "Size", "Allocated"])
                    writer.writerow([str(target), str(target.stat().st_size), str(target.stat().st_size)])
                return CompletedMockScanner()

            with (
                mock.patch.object(scan, "DATA_DIR", str(scan_data)),
                mock.patch.object(scan, "find_wiztree", return_value="mock-WizTree64.exe"),
                mock.patch.object(scan, "check_admin", return_value=False),
                mock.patch.object(scan, "_path_has_reparse_component", return_value=False),
                mock.patch.object(scan.subprocess, "Popen", side_effect=write_mock_scan_export),
                mock.patch.object(scan.time, "sleep", return_value=None),
                mock.patch.object(analyze, "_directory_has_project_marker", return_value=False),
                mock.patch.object(analyze.shutil, "disk_usage", side_effect=OSError),
            ):
                csv_path = scan.scan(
                    drive=target_temp,
                    app="wiztree",
                    wiztree_mode="standard",
                    timeout=30,
                )
                self.assertTrue(csv_path)
                self.assertIn("mock-WizTree64.exe", scan_command)
                self.assertIn(target_temp, scan_command)
                self.assertIn("/exportfiles=1", scan_command)
                results = analyze.analyze_csv(str(csv_path), min_size_mb=0)
            candidate = results["categories"]["high"]["items"][0]
            self.assertEqual(candidate["path"], str(target))

            script_path = Path(plan_temp) / "reviewed-cleanup.ps1"
            backup_root = Path(plan_temp) / "mock-backups"
            backup_helper = Path(plan_temp) / "backup.py"
            repository_root = Path(backup.__file__).resolve().parent
            helper_contents = (
                "import sys\n"
                f"sys.path.insert(0, {str(repository_root)!r})\n"
                "import backup as implementation\n"
                f"backup_root = {str(backup_root)!r}\n"
                "implementation.find_backup_drive = lambda exclude_drives=None, required_space_bytes=0: backup_root\n"
                "implementation._existing_backup_roots = lambda: [backup_root]\n"
                "implementation._get_drive_free_space = lambda _root: 10**10\n"
                "implementation.main()\n"
            )
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(results, str(script_path))
            backup_helper.write_text(helper_contents, encoding="utf-8")

            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(target.exists(), result.stdout + result.stderr)
            self.assertIn("Backup created:", result.stdout)
            self.assertIn("Cleanup complete!", result.stdout)
            self.assertIn("Copying backup file complete.", result.stderr)
            backup_dirs = list(backup_root.glob("backup_*"))
            self.assertEqual(len(backup_dirs), 1)
            backup_id = backup_dirs[0].name
            with (
                mock.patch.object(backup, "_existing_backup_roots", return_value=[str(backup_root)]),
                mock.patch.object(backup, "_get_drive_free_space", return_value=10**10),
            ):
                self.assertTrue(backup.restore_backup(backup_id))
            self.assertEqual(target.read_bytes(), b"synthetic cache data")

    @unittest.skipUnless(os.name == "nt", "WinDirStat scan/review flow targets Windows")
    def test_mocked_windirstat_scan_flows_through_review_and_plan_generation(self):
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        if not temp_root.is_dir():
            self.skipTest("Windows temporary folder is unavailable")
        with (
            tempfile.TemporaryDirectory(dir=temp_root) as target_temp,
            tempfile.TemporaryDirectory(dir=temp_root) as plan_temp,
        ):
            target_root = Path(target_temp) / "app-cache"
            target_root.mkdir()
            target = target_root / "candidate.tmp"
            target.write_bytes(b"synthetic WinDirStat candidate")
            scan_data = Path(plan_temp) / "scan-data"
            plan_path = Path(plan_temp) / "reviewed-windirstat-cleanup.ps1"
            command = []

            class CompletedMockScanner:
                def poll(self):
                    return 0

                def wait(self, timeout=None):
                    return 0

            def write_mock_scan_export(arguments, **_kwargs):
                command.extend(arguments)
                export_path = Path(arguments[2])
                export_path.parent.mkdir(parents=True, exist_ok=True)
                with export_path.open("w", newline="", encoding="utf-8") as export:
                    writer = csv.writer(export)
                    writer.writerow([
                        "Name", "Files", "Folders", "Logical Size", "Physical Size",
                        "Attributes", "WinDirStat Attributes",
                    ])
                    writer.writerow([
                        str(target), "0", "0", str(target.stat().st_size),
                        str(target.stat().st_size), "Archive", "0x20000008",
                    ])
                return CompletedMockScanner()

            clock = [0.0]

            def advance_scan_clock(seconds):
                clock[0] += seconds

            output = io.StringIO()
            with (
                mock.patch.object(scan, "DATA_DIR", str(scan_data)),
                mock.patch.object(scan, "find_windirstat", return_value="mock-WinDirStat.exe"),
                mock.patch.object(scan, "_get_windows_file_version", return_value=(2, 6, 0, 0)),
                mock.patch.object(scan, "_path_has_reparse_component", return_value=False),
                mock.patch.object(scan.subprocess, "Popen", side_effect=write_mock_scan_export),
                mock.patch.object(analyze, "_directory_has_project_marker", return_value=False),
                mock.patch.object(analyze.shutil, "disk_usage", return_value=SimpleNamespace(
                    total=10**9, used=5 * 10**8, free=5 * 10**8,
                )),
                mock.patch.object(scan, "check_admin", return_value=False),
                mock.patch.object(analyze, "clear_screen"),
                redirect_stdout(output),
            ):
                with (
                    mock.patch.object(scan.time, "monotonic", side_effect=lambda: clock[0]),
                    mock.patch.object(scan.time, "sleep", side_effect=advance_scan_clock),
                ):
                    csv_path = scan.scan(
                        drive=str(target_root), app="windirstat", timeout=30,
                    )

                self.assertTrue(csv_path)
                self.assertTrue(scan.validate_scan_export(csv_path)[0])
                self.assertEqual(command[:2], ["mock-WinDirStat.exe", "/SaveTo"])
                self.assertEqual(command[-1], str(target_root))
                self.assertEqual(Path(command[2]).parent.name, ".incomplete")
                self.assertTrue(Path(csv_path).is_file())
                self.assertNotEqual(Path(csv_path).parent.name, ".incomplete")

                with mock.patch("builtins.input", side_effect=[
                        "3", "", "1", str(plan_path), "", "0"]):
                    analyze.run_tui(initial_csv=csv_path, min_size_mb=0)

            self.assertTrue(plan_path.is_file(), output.getvalue())
            self.assertIn(str(target), plan_path.read_text(encoding="utf-8-sig"))
            self.assertTrue(target.is_file(), "The generated plan must not be executed by this test")
            self.assertIn("Starting WinDirStat scan", output.getvalue())
            self.assertIn("File |", output.getvalue())
            self.assertIn(str(target), output.getvalue())
            self.assertIn("Cleanup plan saved to:", output.getvalue())
            self.assertNotIn("Starting the cleanup plan", output.getvalue())

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_folder_cleanup_preserves_candidates_from_more_cautious_tiers(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        if not temp_root.is_dir():
            self.skipTest("Windows temporary folder is unavailable")
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            root = Path(temp_dir)
            selected = root / "Temp"
            nested_cache = selected / "Cache"
            nested_gradle_cache = nested_cache / ".gradle" / "caches"
            nested_gradle_cache.mkdir(parents=True)
            (selected / "ordinary.tmp").write_bytes(b"selected temporary fixture")
            (nested_cache / "ordinary-cache.tmp").write_bytes(b"ordinary cache fixture")
            cache_file = nested_cache / "offline-state.bin"
            cache_file.write_bytes(b"caution fixture")
            gradle_file = nested_gradle_cache / "offline-package.bin"
            gradle_file.write_bytes(b"confirm-first fixture")
            results = {"categories": {
                "high": {"name": "High", "items": [{
                    "path": str(selected) + "\\",
                    "name": "Temporary files (check for installers or builds in progress)",
                    "size": 80, "size_formatted": "80 B", "kind": "Directory",
                }]},
                "medium": {"name": "Medium", "items": [{
                    "path": str(nested_cache) + "\\",
                    "name": "Cache-named data (inspect its location and contents; the name alone does not prove it is disposable)",
                    "size": 48, "size_formatted": "48 B", "kind": "Directory",
                }]},
                "low": {"name": "Low", "items": [{
                    "path": str(nested_gradle_cache) + "\\",
                    "name": "Gradle cache",
                    "size": gradle_file.stat().st_size, "size_formatted": "22 B", "kind": "Directory",
                }]},
            }}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path), priority="high")
            (root / "backup.py").write_text(
                "import json, sys\n"
                "if len(sys.argv) > 1 and sys.argv[1] == 'verify': sys.exit(0)\n"
                "print(json.dumps({'status':'completed','items':[{}],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            all_script = root / "clean-all.ps1"
            analyze.generate_clean_script(results, str(all_script), priority="all")
            all_result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(all_script), "-Select", "1", "-Force"],
                capture_output=True, text=True, timeout=90,
            )
            self.assertEqual(all_result.returncode, 0, all_result.stderr or all_result.stdout)
            self.assertTrue(cache_file.exists(), all_result.stdout + all_result.stderr)
            self.assertEqual(cache_file.read_bytes(), b"caution fixture")
            self.assertFalse((selected / "ordinary.tmp").exists(), all_result.stdout + all_result.stderr)
            self.assertIn("Higher-risk files and folders inside this folder will be kept", all_result.stdout)

            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Force"],
                capture_output=True, text=True, timeout=90,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertTrue(cache_file.exists(), result.stdout + result.stderr)
            self.assertEqual(cache_file.read_bytes(), b"caution fixture")
            self.assertFalse((selected / "ordinary.tmp").exists(), result.stdout + result.stderr)

            medium_script = root / "clean-medium.ps1"
            analyze.generate_clean_script(results, str(medium_script), priority="medium")
            medium_result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(medium_script), "-Select", "1", "-Force"],
                capture_output=True, text=True, timeout=90,
            )
            self.assertEqual(medium_result.returncode, 0, medium_result.stderr or medium_result.stdout)
            self.assertTrue(gradle_file.exists(), medium_result.stdout + medium_result.stderr)
            self.assertEqual(gradle_file.read_bytes(), b"confirm-first fixture")
            self.assertFalse((nested_cache / "ordinary-cache.tmp").exists(), medium_result.stdout + medium_result.stderr)
            self.assertIn("Higher-risk files and folders inside this folder will be kept", medium_result.stdout)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_preserves_nested_protected_and_project_data(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        # Use the long profile path explicitly: Windows' default temp path can
        # use an 8.3 alias that PowerShell expands while enumerating children.
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            root = Path(temp_dir)
            selected = root / "selected"
            unselected = root / "unselected"
            (selected / "nested" / "claude-session").mkdir(parents=True)
            (selected / "nested" / ".codex" / "extensions").mkdir(parents=True)
            codex_old_cache = selected / "nested" / ".codex-old" / "plugins" / "cache"
            codex_old_cache.mkdir(parents=True)
            onedrive_cache = selected / "nested" / "OneDrive - Contoso" / "Cache"
            onedrive_cache.mkdir(parents=True)
            codex_package_cache = (
                selected / "nested" / "Packages" / "OpenAI.Codex_2p2nqsd0c76g0"
                / "LocalCache" / "Local" / "npm-cache"
            )
            codex_package_cache.mkdir(parents=True)
            codex_roaming_cache = selected / "nested" / "AppData" / "Roaming" / "Codex" / "web" / "Cache"
            codex_roaming_cache.mkdir(parents=True)
            personal_music = selected / "nested" / "Music" / "Temp"
            personal_music.mkdir(parents=True)
            project_cache = selected / "nested" / "my-project" / ".cache"
            project_cache.mkdir(parents=True)
            vscode_project = selected / "nested" / "vscode-project"
            vscode_project_cache = vscode_project / "Cache"
            (vscode_project / ".vscode").mkdir(parents=True)
            vscode_project_cache.mkdir()
            workspace_project = selected / "nested" / "workspace-file-project"
            workspace_project_cache = workspace_project / "Cache"
            workspace_project.mkdir(parents=True)
            workspace_project_cache.mkdir()
            (workspace_project / "DriveCleanr.code-workspace").touch()
            visual_project_cache = selected / "nested" / "visual-studio-project" / "packages" / "cache"
            visual_project_cache.mkdir(parents=True)
            (visual_project_cache.parents[1] / "DriveCleanrSample.csproj").touch()
            unselected.mkdir()
            (selected / "remove-me.bin").write_bytes(b"remove")
            (selected / "nested" / "claude-session" / "keep.bin").write_bytes(b"keep")
            (selected / "nested" / ".codex" / "extensions" / "keep.bin").write_bytes(b"keep")
            (codex_old_cache / "keep.bin").write_bytes(b"keep")
            (onedrive_cache / "keep.bin").write_bytes(b"keep")
            (codex_package_cache / "keep.bin").write_bytes(b"keep")
            (codex_roaming_cache / "keep.bin").write_bytes(b"keep")
            (personal_music / "keep.bin").write_bytes(b"keep")
            (selected / "nested" / "my-project" / "package.json").write_text("{}", encoding="utf-8")
            (project_cache / "keep.bin").write_bytes(b"keep")
            (vscode_project_cache / "keep.bin").write_bytes(b"keep")
            (workspace_project_cache / "keep.bin").write_bytes(b"keep")
            (visual_project_cache / "keep.bin").write_bytes(b"keep")
            (selected / "nested" / "regular-cache").mkdir()
            (selected / "nested" / "regular-cache" / "remove.bin").write_bytes(b"remove")
            (unselected / "keep.bin").write_bytes(b"untouched")
            results = {"categories": {"high": {"name": "High", "items": [
                {"path": str(selected) + "\\", "name": "Temporary files (check for installers or builds in progress)", "size": 6, "size_formatted": "6 B", "kind": "Directory"},
                {"path": str(unselected) + "\\", "name": "Temporary files (check for installers or builds in progress)", "size": 9, "size_formatted": "9 B", "kind": "Directory"},
            ]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            backup_log = root / "backup-targets.txt"
            fake_backup = root / "backup.py"
            fake_backup.write_text(
                "import json, os, sys\n"
                "if len(sys.argv) > 1 and sys.argv[1] == 'verify': sys.exit(0)\n"
                "start=sys.argv.index('--paths')+1\n"
                "end=sys.argv.index('--json')\n"
                "paths=sys.argv[start:end]\n"
                "open(os.environ['CLEANR_TEST_BACKUP_LOG'],'w',encoding='utf-8').write('\\n'.join(paths))\n"
                "print(json.dumps({'status':'completed','items':[{} for _ in paths],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            env = dict(os.environ, CLEANR_TEST_BACKUP_LOG=str(backup_log))
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "2", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90, env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertFalse((selected / "remove-me.bin").exists(), result.stdout + result.stderr)
            self.assertEqual((selected / "nested" / "claude-session" / "keep.bin").read_bytes(), b"keep")
            self.assertEqual((selected / "nested" / ".codex" / "extensions" / "keep.bin").read_bytes(), b"keep")
            self.assertEqual((codex_old_cache / "keep.bin").read_bytes(), b"keep")
            self.assertEqual((onedrive_cache / "keep.bin").read_bytes(), b"keep")
            self.assertEqual((codex_package_cache / "keep.bin").read_bytes(), b"keep")
            self.assertEqual((codex_roaming_cache / "keep.bin").read_bytes(), b"keep")
            self.assertEqual((personal_music / "keep.bin").read_bytes(), b"keep")
            self.assertEqual((project_cache / "keep.bin").read_bytes(), b"keep")
            self.assertEqual((vscode_project_cache / "keep.bin").read_bytes(), b"keep")
            self.assertEqual((workspace_project_cache / "keep.bin").read_bytes(), b"keep")
            self.assertEqual((visual_project_cache / "keep.bin").read_bytes(), b"keep")
            self.assertFalse((selected / "nested" / "regular-cache" / "remove.bin").exists())
            self.assertEqual((unselected / "keep.bin").read_bytes(), b"untouched")
            self.assertEqual(backup_log.read_text(encoding="utf-8"), str(selected) + "\\")
            self.assertIn("protected data was preserved", result.stdout)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_removes_empty_selected_folder_after_verified_backup(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            selected = root / "selected-cache"
            selected.mkdir()
            (selected / "remove-me.bin").write_bytes(b"temporary data")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(selected) + "\\", "name": "Temporary files (check for installers or builds in progress)",
                "size": 14, "size_formatted": "14 B", "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            fake_backup = root / "backup.py"
            fake_backup.write_text(
                "import json, sys\n"
                "if len(sys.argv) > 1 and sys.argv[1] == 'verify': sys.exit(0)\n"
                "start=sys.argv.index('--paths')+1; end=sys.argv.index('--json')\n"
                "paths=sys.argv[start:end]\n"
                "print(json.dumps({'status':'completed','items':[{} for _ in paths],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertFalse(selected.exists(), result.stdout + result.stderr)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_can_remove_a_read_only_selected_file(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        if not temp_root.is_dir():
            self.skipTest("Windows temporary folder is unavailable")
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            root = Path(temp_dir)
            selected = root / "readonly-cache.bin"
            selected.write_bytes(b"read only fixture")
            os.chmod(selected, 0o444)
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(selected),
                "name": "Temporary files (check for installers or builds in progress)",
                "size": selected.stat().st_size, "size_formatted": "17 B", "kind": "File",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            (root / "backup.py").write_text(
                "import json, sys\n"
                "if len(sys.argv) > 1 and sys.argv[1] == 'verify': sys.exit(0)\n"
                "print(json.dumps({'status':'completed','items':[{}],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            try:
                try:
                    result = subprocess.run(
                        [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Force"],
                        capture_output=True, text=True, timeout=90,
                    )
                except subprocess.TimeoutExpired as exc:
                    output = exc.stdout or ""
                    if isinstance(output, bytes):
                        output = output.decode("utf-8", errors="replace")
                    self.fail(f"read-only cleanup exceeded 90 seconds; output so far:\n{output}")
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
                self.assertFalse(selected.exists(), result.stdout + result.stderr)
            finally:
                if selected.exists():
                    os.chmod(selected, 0o666)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_preserves_file_with_conflicting_write_lock(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        if not temp_root.is_dir():
            self.skipTest("Windows temporary folder is unavailable")
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            root = Path(temp_dir)
            selected = root / "locked-cache.bin"
            selected.write_bytes(b"locked fixture")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(selected),
                "name": "Temporary files (check for installers or builds in progress)",
                "size": selected.stat().st_size, "size_formatted": "14 B", "kind": "File",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            (root / "backup.py").write_text(
                "import json, sys\n"
                "if len(sys.argv) > 1 and sys.argv[1] == 'verify': sys.exit(0)\n"
                "print(json.dumps({'status':'completed','items':[{}],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            generated_script = script_path.read_text(encoding="utf-8-sig")
            delete_call = next(
                line for line in reversed(generated_script.splitlines())
                if "::DeleteFileIfUnchanged(" in line
            )
            trigger = root / "lock-trigger"
            lock_ready = root / "lock-ready"
            lock_release = root / "lock-release"
            ps_literal = lambda path: "'" + str(path).replace("'", "''") + "'"
            indent = delete_call[:len(delete_call) - len(delete_call.lstrip())]
            injection = (
                f"{indent}[System.IO.File]::WriteAllText({ps_literal(trigger)}, 'lock')\n"
                f"{indent}$lockDeadline = (Get-Date).AddSeconds(10)\n"
                f"{indent}while (-not (Test-Path -LiteralPath {ps_literal(lock_ready)}) -and (Get-Date) -lt $lockDeadline) {{ Start-Sleep -Milliseconds 20 }}\n"
                f"{indent}if (-not (Test-Path -LiteralPath {ps_literal(lock_ready)})) {{ throw 'The mock lock process did not start' }}\n"
                + delete_call
            )
            call_line = "\n" + delete_call + "\n"
            self.assertEqual(generated_script.count(call_line), 1)
            script_path.write_text(
                generated_script.replace(call_line, "\n" + injection + "\n", 1),
                encoding="utf-8-sig",
            )
            lock_script = root / "hold-lock.ps1"
            lock_script.write_text(
                "$target = $args[0]\n"
                "$trigger = $args[1]\n"
                "$ready = $args[2]\n"
                "$release = $args[3]\n"
                "while (-not [System.IO.File]::Exists($trigger)) { Start-Sleep -Milliseconds 20 }\n"
                "$share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete\n"
                "$stream = [System.IO.File]::Open($target, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)\n"
                "$stream.Lock(0, [long]::MaxValue)\n"
                "[System.IO.File]::WriteAllText($ready, 'locked')\n"
                "while (-not [System.IO.File]::Exists($release)) { Start-Sleep -Milliseconds 20 }\n"
                "$stream.Unlock(0, [long]::MaxValue)\n"
                "$stream.Dispose()\n",
                encoding="utf-8",
            )
            lock_process = subprocess.Popen(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(lock_script),
                 str(selected), str(trigger), str(lock_ready), str(lock_release)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                result = subprocess.run(
                    [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Force"],
                    capture_output=True, text=True, timeout=90,
                )
                self.assertTrue(lock_ready.exists(), result.stdout + result.stderr)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertRegex(result.stdout + result.stderr, r"in use|unavailable")
            finally:
                lock_release.write_text("release", encoding="utf-8")
                try:
                    lock_process.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    lock_process.kill()
                    lock_process.communicate(timeout=5)
            self.assertTrue(selected.exists(), result.stdout + result.stderr)
            self.assertEqual(selected.read_bytes(), b"locked fixture")

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_keeps_new_child_added_after_backup_verification(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            selected = root / "selected-cache"
            selected.mkdir()
            (selected / "remove-me.bin").write_bytes(b"temporary data")
            new_project = selected / "new-project"
            keep_file = new_project / "keep.bin"
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(selected) + "\\", "name": "Temporary files (check for installers or builds in progress)",
                "size": 14, "size_formatted": "14 B", "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            fake_backup = root / "backup.py"
            fake_backup.write_text(
                "import json, sys\nfrom pathlib import Path\n"
                f"project = Path({str(new_project)!r})\n"
                f"keep_file = Path({str(keep_file)!r})\n"
                "if len(sys.argv) > 1 and sys.argv[1] == 'verify':\n"
                "    project.mkdir()\n"
                "    (project / 'package.json').write_text('{}', encoding='utf-8')\n"
                "    keep_file.write_bytes(b'created after backup verification')\n"
                "    sys.exit(0)\n"
                "start=sys.argv.index('--paths')+1; end=sys.argv.index('--json')\n"
                "paths=sys.argv[start:end]\n"
                "print(json.dumps({'status':'completed','items':[{} for _ in paths],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(new_project.is_dir(), result.stdout + result.stderr)
            self.assertEqual(keep_file.read_bytes(), b"created after backup verification")
            self.assertIn("Cleanup finished with errors", result.stdout + result.stderr)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_refuses_directory_tree_with_nested_reparse_point(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            selected = root / "selected"
            outside = root / "outside"
            selected.mkdir()
            outside.mkdir()
            (selected / "keep.bin").write_bytes(b"keep")
            (outside / "keep.bin").write_bytes(b"outside")
            try:
                (selected / "linked-outside").symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Could not create a temporary directory symlink: {exc}")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(selected) + "\\", "name": "Temporary files (check for installers or builds in progress)", "size": 4,
                "size_formatted": "4 B", "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            (root / "backup.py").write_text(
                "import json, sys\nif len(sys.argv) > 1 and sys.argv[1] == 'verify': sys.exit(0)\n"
                "print(json.dumps({'status':'completed','items':[{}],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90,
            )
            self.assertEqual((selected / "keep.bin").read_bytes(), b"keep")
            self.assertEqual((outside / "keep.bin").read_bytes(), b"outside")
            self.assertTrue((selected / "linked-outside").exists())
            self.assertIn("containing a reparse point", result.stdout)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_rechecks_nested_paths_after_backup_verification(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        if not temp_root.is_dir():
            self.skipTest("Windows temporary folder is unavailable")
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            root = Path(temp_dir)
            selected = root / "selected"
            nested = selected / "nested"
            moved_original = selected / "nested-original"
            outside = root / "outside"
            nested.mkdir(parents=True)
            outside.mkdir()
            (nested / "cache.tmp").write_bytes(b"selected fixture")
            # Match the enumerated child name so the stale cleanup path would
            # resolve through the newly-created junction if it is not checked.
            outside_sentinel = outside / "cache.tmp"
            outside_sentinel.write_bytes(b"outside sentinel")
            source_attributes = (nested / "cache.tmp").stat()
            os.utime(outside_sentinel, ns=(source_attributes.st_atime_ns, source_attributes.st_mtime_ns))
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(selected) + "\\",
                "name": "Temporary files (check for installers or builds in progress)",
                "size": 16, "size_formatted": "16 B", "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            (root / "backup.py").write_text(
                "import json, pathlib, subprocess, sys\n"
                f"nested = pathlib.Path({str(nested)!r})\n"
                f"moved_original = pathlib.Path({str(moved_original)!r})\n"
                f"outside = pathlib.Path({str(outside)!r})\n"
                "if len(sys.argv) > 1 and sys.argv[1] == 'verify':\n"
                "    nested.rename(moved_original)\n"
                "    link_result = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(nested), str(outside)], capture_output=True)\n"
                "    if link_result.returncode:\n"
                "        sys.exit(2)\n"
                "    sys.exit(0)\n"
                "print(json.dumps({'status':'completed','items':[{}],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90,
            )
            self.assertTrue(outside_sentinel.exists(), result.stdout + result.stderr)
            self.assertEqual(outside_sentinel.read_bytes(), b"outside sentinel")
            self.assertTrue((moved_original / "cache.tmp").exists(), result.stdout + result.stderr)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("reparse point", result.stdout + result.stderr)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_detects_junction_swap_at_file_removal_boundary(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        if not temp_root.is_dir():
            self.skipTest("Windows temporary folder is unavailable")
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            root = Path(temp_dir)
            selected = root / "selected"
            nested = selected / "nested"
            moved_original = selected / "nested-original"
            outside = root / "outside"
            nested.mkdir(parents=True)
            outside.mkdir()
            selected_file = nested / "cache.tmp"
            selected_file.write_bytes(b"selected fixture")
            outside_sentinel = outside / selected_file.name
            outside_sentinel.write_bytes(b"outside sentinel")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(selected) + "\\",
                "name": "Temporary files (check for installers or builds in progress)",
                "size": selected_file.stat().st_size, "size_formatted": "16 B", "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            (root / "backup.py").write_text(
                "import json, sys\n"
                "if len(sys.argv) > 1 and sys.argv[1] == 'verify': sys.exit(0)\n"
                "print(json.dumps({'status':'completed','items':[{}],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )

            def ps_literal(value):
                return "'" + str(value).replace("'", "''") + "'"

            generated_script = script_path.read_text(encoding="utf-8-sig")
            delete_call = next(
                line.strip() for line in generated_script.splitlines()
                if "::DeleteFileIfUnchanged(" in line
            )
            injection = (
                f"Move-Item -LiteralPath {ps_literal(nested)} -Destination {ps_literal(moved_original)}\n"
                f"New-Item -ItemType Junction -Path {ps_literal(nested)} -Target {ps_literal(outside)} | Out-Null\n"
                + delete_call
            )
            self.assertEqual(generated_script.count(delete_call), 2)
            script_path.write_text(
                generated_script.replace(delete_call, injection, 1), encoding="utf-8-sig")
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Force"],
                capture_output=True, text=True, timeout=90,
            )
            self.assertTrue(outside_sentinel.exists(), result.stdout + result.stderr)
            self.assertEqual(outside_sentinel.read_bytes(), b"outside sentinel")
            self.assertTrue((moved_original / selected_file.name).exists(), result.stdout + result.stderr)
            nested_attributes = (selected / "nested").lstat().st_file_attributes
            self.assertTrue(
                nested_attributes & 0x00000400,
                result.stdout + result.stderr,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertRegex(result.stdout + result.stderr, r"reparse point|replaced after review")

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_preserves_file_changed_after_backup_verification(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        if not temp_root.is_dir():
            self.skipTest("Windows temporary folder is unavailable")
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            root = Path(temp_dir)
            selected = root / "selected"
            selected.mkdir()
            changed_file = selected / "cache.tmp"
            changed_file.write_bytes(b"original fixture")
            replacement = b"changed fixture!"
            self.assertEqual(len(replacement), changed_file.stat().st_size)
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(selected) + "\\",
                "name": "Temporary files (check for installers or builds in progress)",
                "size": len(b"original fixture"), "size_formatted": "16 B", "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            (root / "backup.py").write_text(
                "import json, os, pathlib, sys\n"
                f"changed_file = pathlib.Path({str(changed_file)!r})\n"
                "if len(sys.argv) > 1 and sys.argv[1] == 'verify':\n"
                "    original_stat = changed_file.stat()\n"
                f"    changed_file.write_bytes({replacement!r})\n"
                "    os.utime(changed_file, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))\n"
                "    sys.exit(0)\n"
                "print(json.dumps({'status':'completed','items':[{}],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(changed_file.read_bytes(), replacement)
            self.assertIn("changed after", result.stdout + result.stderr)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_native_delete_rechecks_file_metadata_after_path_guard(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with (
            tempfile.TemporaryDirectory(dir=Path.home()) as isolated_temp,
            mock.patch.dict(os.environ, {"TEMP": isolated_temp, "TMP": isolated_temp}),
            mock.patch.object(tempfile, "tempdir", isolated_temp),
            tempfile.TemporaryDirectory(dir=isolated_temp) as target_temp,
            tempfile.TemporaryDirectory(dir=isolated_temp) as plan_temp,
        ):
            target = Path(target_temp) / "candidate-cache"
            target.mkdir()
            selected_file = target / "cache.tmp"
            selected_file.write_bytes(b"metadata-only change fixture")
            original_contents = selected_file.read_bytes()
            original_mtime_ns = selected_file.stat().st_mtime_ns
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target) + "\\",
                "name": "Temporary files (check for installers or builds in progress)",
                "size": len(original_contents),
                "size_formatted": f"{len(original_contents)} B",
                "kind": "Directory",
            }]}}}
            script_path = Path(plan_temp) / "clean.ps1"
            with mock.patch.object(analyze, "_directory_has_project_marker", return_value=False):
                analyze.generate_clean_script(results, str(script_path))

            script_text = script_path.read_text(encoding="utf-8-sig")
            path_guard = "                Assert-CleanupEntryPathWithinSelection $target $entry\n"
            self.assertIn(path_guard, script_text)
            script_text = script_text.replace(
                path_guard,
                path_guard +
                "                [System.IO.File]::SetLastWriteTimeUtc($entry.FullName, $entry.LastWriteTimeUtc.AddSeconds(5))\n",
                1,
            )
            script_path.write_text(script_text, encoding="utf-8-sig")
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                 "-Select", "1", "-NoBackup", "-Force"],
                capture_output=True, text=True, timeout=120,
            )

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(selected_file.read_bytes(), original_contents)
            self.assertGreater(selected_file.stat().st_mtime_ns, original_mtime_ns)
            self.assertIn("file or folder is unavailable, in use, or changed", result.stdout.lower())

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_preserves_single_file_changed_with_timestamp_after_backup_verification(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        if not temp_root.is_dir():
            self.skipTest("Windows temporary folder is unavailable")
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            root = Path(temp_dir)
            changed_file = root / "cache.tmp"
            original = b"original file payload"
            replacement = b"replaced file payload"
            self.assertEqual(len(original), len(replacement))
            changed_file.write_bytes(original)
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(changed_file),
                "name": "Temporary files (check for installers or builds in progress)",
                "size": len(original), "size_formatted": f"{len(original)} B", "kind": "File",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            (root / "backup.py").write_text(
                "import json, os, pathlib, sys\n"
                f"changed_file = pathlib.Path({str(changed_file)!r})\n"
                "if len(sys.argv) > 1 and sys.argv[1] == 'verify':\n"
                "    original_stat = changed_file.stat()\n"
                f"    changed_file.write_bytes({replacement!r})\n"
                "    os.utime(changed_file, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))\n"
                "    sys.exit(0)\n"
                "print(json.dumps({'status':'completed','items':[{}],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(changed_file.read_bytes(), replacement)
            self.assertIn("contents changed after backup verification", result.stdout + result.stderr)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_refuses_target_changed_after_backup(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target"
            target.mkdir()
            marker = target / "cache.bin"
            marker.write_bytes(b"before backup")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target) + "\\", "name": "Temporary files (check for installers or builds in progress)",
                "size": 13, "size_formatted": "13 B", "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            (root / "backup.py").write_text(
                "import json, pathlib, sys\n"
                "if sys.argv[1] == 'verify': sys.exit(1)\n"
                "start=sys.argv.index('--paths')+1; end=sys.argv.index('--json')\n"
                "path=pathlib.Path(sys.argv[start])\n"
                "(path/'cache.bin').write_bytes(b'changed after backup')\n"
                "print(json.dumps({'status':'completed','items':[{}],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(marker.read_bytes(), b"changed after backup")
            self.assertIn("refusing cleanup", result.stdout)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_rechecks_file_project_marker_after_backup(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            project = root / "new-project"
            project.mkdir()
            selected = project / "build.tmp"
            selected.write_bytes(b"keep once project marker appears")
            marker = project / "RuntimeAdded.uproject"
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(selected), "name": "Temporary files (check for installers or builds in progress)",
                "size": selected.stat().st_size, "size_formatted": "32 B", "kind": "File",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            (root / "backup.py").write_text(
                "import json, os, pathlib, sys\n"
                "if sys.argv[1] == 'verify':\n"
                "    pathlib.Path(os.environ['CLEANR_TEST_PROJECT_MARKER']).touch()\n"
                "    sys.exit(0)\n"
                "start=sys.argv.index('--paths')+1; end=sys.argv.index('--json')\n"
                "paths=sys.argv[start:end]\n"
                "print(json.dumps({'status':'completed','items':[{} for _ in paths],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            env = dict(os.environ, CLEANR_TEST_PROJECT_MARKER=str(marker))
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90, env=env,
            )
            self.assertTrue(marker.exists(), result.stdout + result.stderr)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(selected.read_bytes(), b"keep once project marker appears")
            self.assertIn("inside a project", result.stdout + result.stderr)
            self.assertIn("Cleanup finished with errors", result.stdout)
            self.assertIn("Backup mock-backup is retained for recovery", result.stdout)
            self.assertNotIn("Cleanup complete!", result.stdout)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_stops_if_project_marker_appears_inside_selected_folder_after_inventory(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            selected = root / "selected-cache"
            nested = selected / "existing-subfolder"
            nested.mkdir(parents=True)
            cached_file = nested / "cache.bin"
            cached_file.write_bytes(b"preserve after the folder becomes a project")
            marker = nested / "package.json"
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(selected) + "\\", "name": "Temporary files (check for installers or builds in progress)",
                "size": cached_file.stat().st_size, "size_formatted": "42 B", "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            (root / "backup.py").write_text(
                "import json, pathlib, sys\n"
                f"marker = pathlib.Path({str(marker)!r})\n"
                "if len(sys.argv) > 1 and sys.argv[1] == 'verify':\n"
                "    marker.write_text('{}', encoding='utf-8')\n"
                "    sys.exit(0)\n"
                "start=sys.argv.index('--paths')+1; end=sys.argv.index('--json')\n"
                "paths=sys.argv[start:end]\n"
                "print(json.dumps({'status':'completed','items':[{} for _ in paths],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90,
            )
            self.assertTrue(marker.exists(), result.stdout + result.stderr)
            self.assertEqual(cached_file.read_bytes(), b"preserve after the folder becomes a project")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("project", result.stdout.lower() + result.stderr.lower())

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_rechecks_agent_settings_folder_after_backup(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            project = root / "new-project"
            project.mkdir()
            selected = project / "build.tmp"
            selected.write_bytes(b"keep once project guidance appears")
            marker = project / ".cursor"
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(selected), "name": "Temporary files (check for installers or builds in progress)",
                "size": selected.stat().st_size, "size_formatted": "32 B", "kind": "File",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            (root / "backup.py").write_text(
                "import json, os, pathlib, sys\n"
                "if sys.argv[1] == 'verify':\n"
                "    pathlib.Path(os.environ['CLEANR_TEST_PROJECT_MARKER']).mkdir()\n"
                "    sys.exit(0)\n"
                "start=sys.argv.index('--paths')+1; end=sys.argv.index('--json')\n"
                "paths=sys.argv[start:end]\n"
                "print(json.dumps({'status':'completed','items':[{} for _ in paths],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            env = dict(os.environ, CLEANR_TEST_PROJECT_MARKER=str(marker))
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90, env=env,
            )
            self.assertTrue(marker.exists(), result.stdout + result.stderr)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(selected.read_bytes(), b"keep once project guidance appears")
            self.assertIn("inside a project", result.stdout + result.stderr)
            self.assertIn("Cleanup finished with errors", result.stdout)
            self.assertIn("Backup mock-backup is retained for recovery", result.stdout)
            self.assertNotIn("Cleanup complete!", result.stdout)


    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_selection_indices_do_not_shift_when_target_disappears(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            missing = root / "missing"
            selected = root / "selected"
            unselected = root / "unselected"
            selected.mkdir()
            unselected.mkdir()
            (selected / "remove-me.bin").write_bytes(b"remove")
            (unselected / "keep.bin").write_bytes(b"keep")
            results = {"categories": {"high": {"name": "High", "items": [
                {"path": str(missing) + "\\", "name": "Temporary files (check for installers or builds in progress)", "size": 10, "size_formatted": "10 B", "kind": "Directory"},
                {"path": str(selected) + "\\", "name": "Temporary files (check for installers or builds in progress)", "size": 6, "size_formatted": "6 B", "kind": "Directory"},
                {"path": str(unselected) + "\\", "name": "Temporary files (check for installers or builds in progress)", "size": 4, "size_formatted": "4 B", "kind": "Directory"},
            ]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            backup_log = root / "backup-targets.txt"
            (root / "backup.py").write_text(
                "import json, os, sys\n"
                "if len(sys.argv) > 1 and sys.argv[1] == 'verify': sys.exit(0)\n"
                "start=sys.argv.index('--paths')+1\n"
                "end=sys.argv.index('--json')\n"
                "paths=sys.argv[start:end]\n"
                "open(os.environ['CLEANR_TEST_BACKUP_LOG'],'w',encoding='utf-8').write('\\n'.join(paths))\n"
                "print(json.dumps({'status':'completed','items':[{} for _ in paths],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            env = dict(os.environ, CLEANR_TEST_BACKUP_LOG=str(backup_log))
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "2", "-Backup", "-Force"],
                capture_output=True, text=True, timeout=90, env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertFalse((selected / "remove-me.bin").exists())
            self.assertEqual((unselected / "keep.bin").read_bytes(), b"keep")
            self.assertEqual(backup_log.read_text(encoding="utf-8"), str(selected) + "\\")

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_generated_script_treats_wildcard_characters_in_paths_literally(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        temp_root = Path.home() / "AppData" / "Local" / "Temp"
        with tempfile.TemporaryDirectory(dir=temp_root) as temp_dir:
            root = Path(temp_dir)
            selected = root / "selected[1]"
            selected.mkdir()
            marker = selected / "remove-me.bin"
            marker.write_bytes(b"temporary fixture")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(selected) + "\\", "name": "Temporary files (check for installers or builds in progress)",
                "size": marker.stat().st_size, "size_formatted": "17 B", "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            (root / "backup.py").write_text(
                "import json, sys\n"
                "if sys.argv[1] == 'verify': sys.exit(0)\n"
                "start=sys.argv.index('--paths')+1; end=sys.argv.index('--json')\n"
                "paths=sys.argv[start:end]\n"
                "print(json.dumps({'status':'completed','items':[{} for _ in paths],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Force"],
                capture_output=True, text=True, timeout=90,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertFalse(marker.exists(), result.stdout + result.stderr)
            self.assertIn("[Done -", result.stdout)

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_cancelling_generated_plan_performs_no_backup_or_deletion(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target"
            target.mkdir()
            marker = target / "keep.bin"
            marker.write_bytes(b"keep")
            (target / "visible-cache.bin").write_bytes(b"preview")
            for index in range(20):
                (target / f"preview-{index:02d}.tmp").write_bytes(b"preview")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target) + "\\", "name": "Temporary files (check for installers or builds in progress)", "size": 4,
                "size_formatted": "4 B", "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            backup_log = root / "backup-targets.txt"
            (root / "backup.py").write_text("raise SystemExit('backup must not run after cancel')\n", encoding="utf-8")
            env = dict(os.environ, CLEANR_TEST_BACKUP_LOG=str(backup_log))
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
                input="1\nQ\n", capture_output=True, text=True, timeout=90, env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertTrue(marker.exists())
            self.assertIn("Preview of files and folders inside each selected folder", result.stdout)
            self.assertIn("keep.bin", result.stdout)
            self.assertIn("Preview limited to 12 direct items. Other contents may also be removed unless they are protected, project data, or higher-risk candidates.", result.stdout)
            preview_rows = [line for line in result.stdout.splitlines() if "preview-" in line or "visible-cache.bin" in line]
            self.assertLessEqual(len(preview_rows), 12)
            self.assertFalse(backup_log.exists())

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_cleanup_rejects_partial_or_incomplete_backup_even_if_helper_exits_zero(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target"
            target.mkdir()
            marker = target / "keep.bin"
            marker.write_bytes(b"must remain")
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target) + "\\", "name": "Temporary files (check for installers or builds in progress)", "size": 11,
                "size_formatted": "11 B", "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            backup_helper = root / "backup.py"
            for status, items in (("partial", "[]"), ("completed", "[]")):
                with self.subTest(status=status, items=items):
                    backup_helper.write_text(
                        "import json\n"
                        f"print(json.dumps({{'status': {status!r}, 'items': {items}, 'id': 'mock-backup'}}))\n",
                        encoding="utf-8",
                    )
                    result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Backup", "-Force"],
                        capture_output=True, text=True, timeout=90,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("Backup was incomplete. No cleanup was performed.", result.stderr + result.stdout)
                    self.assertNotIn("Starting cleanup...", result.stdout)
                    self.assertTrue(marker.exists())

    def test_generating_empty_plan_is_an_error(self):
        results = {"categories": {"high": {"name": "High", "items": []}}}
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ValueError):
                analyze.generate_clean_script(results, str(Path(temp_dir) / "empty.ps1"))

    def test_generated_plan_rejects_protected_downloads_even_from_imported_data(self):
        results = {"categories": {"high": {"name": "High", "items": [{
            "path": "C:\\Users\\ExampleUser\\Downloads\\ExampleProject\\Temp\\dotnet\\",
            "name": "Temporary files (check for installers or builds in progress)", "size": 100, "size_formatted": "100 B", "kind": "Directory",
        }]}}}
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(ValueError, "protected path"):
                analyze.generate_clean_script(results, str(Path(temp_dir) / "clean.ps1"))

    def test_generated_plan_rejects_unmatched_or_mislabeled_candidates(self):
        invalid_items = [
            {
                "path": r"C:\Users\ExampleUser\OneDriveBackup\Important",
                "name": "Temporary files (check for installers or builds in progress)",
                "size": 100, "size_formatted": "100 B", "kind": "File",
            },
            {
                "path": r"C:\Users\ExampleUser\AppData\Local\Temp\ordinary.tmp",
                "name": "Crash dumps",
                "size": 100, "size_formatted": "100 B", "kind": "File",
            },
            {
                "path": r"C:\Users\ExampleUser\.gradle\caches\modules",
                "name": "Gradle cache",
                "size": 100, "size_formatted": "100 B", "kind": "Directory",
            },
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            for item in invalid_items:
                results = {"categories": {"high": {"name": "High", "items": [item]}}}
                with self.subTest(path=item["path"]), self.assertRaisesRegex(
                        ValueError, "does not match its priority and cleanup label"):
                    analyze.generate_clean_script(results, str(Path(temp_dir) / "clean.ps1"))

    def test_generated_plan_rejects_old_generic_cache_label(self):
        results = {"categories": {"medium": {"name": "Medium", "items": [{
            "path": r"C:\Users\A\AppData\Local\App\Cache\settings.db",
            "name": "Application cache", "size": 100, "size_formatted": "100 B", "kind": "File",
        }]}}}
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(
                ValueError, "does not match its priority and cleanup label"):
            analyze.generate_clean_script(results, str(Path(temp_dir) / "clean.ps1"), priority="medium")

    def test_bcut_cache_is_only_a_caution_candidate(self):
        path = r"C:\Users\A\AppData\Roaming\BCUT\Cache\Material\asset.bin"
        results = self.analyze_rows([{"File Name": path, "Size": "104857600"}])
        high_items = results["categories"]["high"]["items"]
        medium_items = results["categories"]["medium"]["items"]
        self.assertFalse(any(item["path"] == path for item in high_items))
        bcut_items = [item for item in medium_items if item["path"] == path]
        self.assertEqual(len(bcut_items), 1)
        self.assertIn("name alone does not prove", bcut_items[0]["name"])

    def test_generated_plan_rejects_old_bcut_safe_label(self):
        results = {"categories": {key: {"name": key, "items": []} for key in ("high", "medium", "low")}}
        results["categories"]["high"]["items"] = [{
            "path": r"C:\Users\A\AppData\Roaming\BCUT\Cache\Material\asset.bin",
            "name": "BCUT cache", "size": 100, "size_formatted": "100 B", "kind": "File",
        }]
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaisesRegex(
                ValueError, "does not match its priority and cleanup label"):
            analyze.generate_clean_script(results, str(Path(temp_dir) / "clean.ps1"))

    def test_all_priority_plan_accepts_valid_lower_tier_candidate(self):
        categories = {key: {"name": key, "items": []} for key in ("high", "medium", "low")}
        path = r"Z:\DriveCleanrTest\.gradle\caches\modules"
        categories["low"]["items"] = [{
            "path": path, "name": "Gradle cache", "size": 100,
            "size_formatted": "100 B", "kind": "Directory",
        }]
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "clean-all.ps1"
            analyze.generate_clean_script({"categories": categories}, str(output), priority="all")
            self.assertIn(path, output.read_text(encoding="utf-8-sig"))

    def test_generated_plan_rejects_unsafe_paths_and_priority_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            for path in (r"\\server\share\cache", "C:\\", r"C:\Temp\..\Windows\Temp\cache"):
                results = {"categories": {key: {"name": key, "items": []} for key in ("high", "medium", "low")}}
                results["categories"]["high"]["items"] = [{
                    "path": path, "size": 100, "size_formatted": "100 B", "name": "Cache", "kind": "Directory",
                }]
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unsafe path"):
                    analyze.generate_clean_script(results, str(Path(temp_dir) / "unsafe.ps1"))

            results = {"categories": {key: {"name": key, "items": []} for key in ("high", "medium", "low")}}
            results["categories"]["high"]["items"] = [{
                "path": r"C:\Temp\cache", "size": 100, "size_formatted": "100 B", "name": "Cache", "kind": "File",
            }]
            with self.assertRaisesRegex(ValueError, "priority"):
                analyze.generate_clean_script(
                    results, str(Path(temp_dir) / "unsafe.ps1"),
                    priority="high'; Remove-Item C:\\ -Recurse",
                )

    def test_generated_plan_rejects_paths_that_became_reparse_points(self):
        results = {"categories": {"high": {"name": "High", "items": [{
            "path": r"C:\Users\A\AppData\Local\Temp\cache.bin",
            "name": "Temporary files (check for installers or builds in progress)",
            "size": 100, "size_formatted": "100 B", "kind": "File",
        }]}}}
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "clean.ps1"
            with mock.patch.object(analyze.scan, "_path_has_reparse_component", return_value=True):
                with self.assertRaisesRegex(ValueError, "crosses a junction or symbolic link"):
                    analyze.generate_clean_script(results, str(output))
            self.assertFalse(output.exists())

    def test_generated_reports_never_overwrite_existing_files(self):
        results = self.analyze_rows([{
            "File Name": r"C:\Users\A\AppData\Local\Temp\cache.tmp", "Size": "104857600",
        }])
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "existing.ps1"
            output_path.write_text("keep this existing file", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                analyze.generate_clean_script(results, str(output_path))
            self.assertEqual(output_path.read_text(encoding="utf-8"), "keep this existing file")
            list_path = Path(temp_dir) / "existing.txt"
            list_path.write_text("keep this list", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                analyze.write_item_list_report(results, str(list_path))
            self.assertEqual(list_path.read_text(encoding="utf-8"), "keep this list")

    def test_generated_outputs_cannot_be_placed_inside_cleanup_targets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "cache"
            target.mkdir()
            results = {"categories": {key: {"name": key, "items": []} for key in ("high", "medium", "low")}}
            results["categories"]["medium"]["items"] = [{
                "path": str(target) + "\\", "size": 100, "size_formatted": "100 B",
                "name": "Cache-named data (inspect its location and contents; the name alone does not prove it is disposable)",
                "kind": "Directory", "safe": False,
            }]
            with self.assertRaisesRegex(ValueError, "outside the selected cleanup targets"):
                analyze.generate_clean_script(results, str(target / "plan.ps1"), priority="medium")
            with self.assertRaisesRegex(ValueError, "outside the selected cleanup targets"):
                analyze.write_item_list_report(results, str(target / "items.txt"))

    def test_review_menu_handles_refused_candidate_list_destination(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "scan.csv"
            csv_path.write_text("placeholder", encoding="utf-8")
            target = Path(temp_dir) / "cache"
            target.mkdir()
            item = {"path": str(target) + "\\", "size": 100, "size_formatted": "100 B",
                    "kind": "Directory", "name": "Cache", "safe": False}
            results = {
                "scan_file": str(csv_path), "scan_time": "now", "total_size": 0,
                "free_space": 0, "used_space": 0, "space_source": None,
                "stale_candidate_count": 0,
                "categories": {
                    "high": {"name": "High", "items": [item], "total_size": 100, "total_size_formatted": "100 B"},
                    "medium": {"name": "Medium", "items": [], "total_size": 0, "total_size_formatted": "0 B"},
                    "low": {"name": "Low", "items": [], "total_size": 0, "total_size_formatted": "0 B"},
                },
            }
            with mock.patch.object(analyze, "analyze_csv", return_value=results), \
                 mock.patch.object(analyze, "clear_screen"), \
                 mock.patch("builtins.input", side_effect=["2", str(target / "items.txt"), "", "0"]), \
                 mock.patch("builtins.print") as output:
                analyze.run_tui(initial_csv=str(csv_path))
        self.assertIn("Could not save the review list", " ".join(str(call) for call in output.call_args_list))
        self.assertFalse((target / "items.txt").exists())

    def test_negative_minimum_size_is_rejected(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as handle:
            handle.write("File Name,Size\n")
            csv_path = handle.name
        try:
            with self.assertRaises(ValueError):
                analyze.analyze_csv(csv_path, min_size_mb=-1)
        finally:
            os.unlink(csv_path)

    def test_analyzer_reports_csv_byte_percentage_progress(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "scan.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["File Name", "Size"])
                writer.writeheader()
                writer.writerows([
                    {"File Name": r"C:\Users\A\file-one.bin", "Size": "100"},
                    {"File Name": r"C:\Users\A\file-two.bin", "Size": "100"},
                ])
            progress = []
            with mock.patch.object(analyze, "ANALYSIS_PROGRESS_INTERVAL", 1):
                analyze.analyze_csv(str(csv_path), min_size_mb=0, progress_callback=progress.append)
        self.assertGreater(progress[0], 0)
        self.assertLess(progress[0], 100)
        self.assertEqual(progress[-1], 100)
        self.assertEqual(progress, sorted(progress))
        self.assertTrue(all(0 <= value <= 100 for value in progress))

    def test_analyzer_skips_paths_missing_since_the_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "scan.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["File Name", "Size"])
                writer.writeheader()
                writer.writerow({
                    "File Name": r"C:\Users\A\AppData\Local\Temp\gone\candidate.bin",
                    "Size": "100000000",
                })
            with mock.patch("analyze.os.path.exists", return_value=False):
                results = analyze.analyze_csv(str(csv_path), min_size_mb=0)
        self.assertEqual(results["stale_candidate_count"], 1)
        self.assertTrue(all(not category["items"] for category in results["categories"].values()))


class ScanSafetyTests(unittest.TestCase):
    def test_scan_reparse_checks_fail_closed_when_metadata_is_unreadable(self):
        with mock.patch.object(scan.os.path, "islink", return_value=False), \
             mock.patch.object(scan.os.path, "isjunction", return_value=False, create=True), \
             mock.patch.object(scan.os, "stat", side_effect=PermissionError("access denied")):
            self.assertTrue(scan._is_reparse_point("unreadable-path"))
            self.assertTrue(scan._path_has_reparse_component(r"C:\blocked\data"))

    def test_missing_scan_storage_components_are_not_treated_as_reparse_points(self):
        with mock.patch.object(scan.os.path, "islink", return_value=False), \
             mock.patch.object(scan.os.path, "isjunction", return_value=False, create=True), \
             mock.patch.object(scan.os, "stat", side_effect=FileNotFoundError("not found")):
            self.assertFalse(scan._is_reparse_point("missing-path"))
            self.assertFalse(scan._path_has_reparse_component(r"C:\missing\data"))

    def test_wiztree_discovery_prefers_64_bit_worker_for_configured_launcher(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            launcher = Path(temp_dir) / "WizTree.exe"
            worker = Path(temp_dir) / "WizTree64.exe"
            launcher.touch()
            worker.touch()
            with mock.patch.dict(os.environ, {"WIZTREE_PATH": str(launcher)}):
                self.assertEqual(scan.find_wiztree(), str(worker))

    def test_custom_executable_paths_support_portable_scanners(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            portable_dir = Path(temp_dir) / "portable tools"
            portable_dir.mkdir()
            wiztree = portable_dir / "WizTree64.exe"
            windirstat = portable_dir / "WinDirStat.exe"
            wiztree.touch()
            windirstat.touch()

            with mock.patch.dict(os.environ, {"WIZTREE_PATH": str(wiztree)}):
                self.assertEqual(scan.find_wiztree(), str(wiztree))
            with mock.patch.dict(os.environ, {"WINDIRSTAT_PATH": str(windirstat)}):
                self.assertEqual(scan.find_windirstat(), str(windirstat))

    def test_scan_target_accepts_drive_roots_and_existing_local_folders(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertEqual(scan._normalize_scan_target("d:"), "D:")
            self.assertEqual(scan._normalize_scan_target("C:\\"), "C:\\")
            self.assertTrue(scan._is_whole_drive_target("C:\\"))
            self.assertEqual(scan._normalize_scan_target(temp_dir), os.path.normpath(temp_dir))
            self.assertFalse(scan._is_whole_drive_target(temp_dir))

    def test_scan_target_rejects_missing_relative_and_network_folders(self):
        for target in ("relative\\folder", r"\\server\share", "Z:\\missing\\folder"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                scan._normalize_scan_target(target)

    def test_scanner_choice_accepts_windirstat_alias(self):
        with mock.patch("builtins.input", side_effect=["x", "2"]):
            self.assertEqual(scan.choose_scanner(), "windirstat")

    def test_scanner_and_mode_prompts_accept_explicit_cancellation(self):
        with mock.patch("builtins.input", return_value="q"), redirect_stdout(io.StringIO()):
            self.assertIsNone(scan.choose_scanner())
            self.assertIsNone(scan.choose_wiztree_mode())

    def test_wiztree_mode_picker_accepts_automatic_fast_and_standard(self):
        for answer, expected in (("", "auto"), ("2", "fast"), ("standard", "standard")):
            with self.subTest(answer=answer), mock.patch("builtins.input", return_value=answer):
                self.assertEqual(scan.choose_wiztree_mode(), expected)

    def test_wiztree_auto_mode_uses_mft_only_for_elevated_drive_scans(self):
        for elevated, expected_flag in ((False, "/admin=0"), (True, "/admin=1")):
            with self.subTest(elevated=elevated), tempfile.TemporaryDirectory() as temp_dir:
                old_data_dir = scan.DATA_DIR
                scan.DATA_DIR = str(Path(temp_dir) / "data")
                captured = {}

                def fake_popen(command, **_kwargs):
                    captured["command"] = command
                    export_arg = next(arg for arg in command if arg.startswith("/export="))
                    export_path = Path(export_arg.split("=", 1)[1])
                    export_path.parent.mkdir(parents=True, exist_ok=True)
                    export_path.write_text("File Name,Size\n", encoding="utf-8")
                    return object()

                try:
                    with mock.patch.object(scan, "check_admin", return_value=elevated), \
                         mock.patch.object(scan, "find_wiztree", return_value="/mock/WizTree64.exe"), \
                         mock.patch.object(scan.subprocess, "Popen", side_effect=fake_popen), \
                         mock.patch.object(scan, "wait_for_scan_process", return_value=True), \
                         mock.patch("builtins.print"):
                        result = scan.scan("D:", app="wiztree")
                finally:
                    scan.DATA_DIR = old_data_dir
                self.assertTrue(result.endswith(".csv"))
                self.assertIn(expected_flag, captured["command"])
                expected_mode = "standard" if expected_flag == "/admin=0" else "fast"
                self.assertTrue(Path(result).name.startswith(f"scan_wiztree_{expected_mode}_"))

    def test_wiztree_auto_mode_uses_standard_for_folders_even_when_elevated(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as temp_dir:
            old_data_dir = scan.DATA_DIR
            scan.DATA_DIR = str(Path(temp_dir) / "data")
            captured = {}

            def fake_popen(command, **_kwargs):
                captured["command"] = command
                export_arg = next(arg for arg in command if arg.startswith("/export="))
                export_path = Path(export_arg.split("=", 1)[1])
                export_path.parent.mkdir(parents=True, exist_ok=True)
                export_path.write_text("File Name,Size\n", encoding="utf-8")
                return object()

            try:
                with mock.patch.object(scan, "check_admin", return_value=True), \
                     mock.patch.object(scan, "find_wiztree", return_value="/mock/WizTree64.exe"), \
                     mock.patch.object(scan.subprocess, "Popen", side_effect=fake_popen), \
                     mock.patch.object(scan, "wait_for_scan_process", return_value=True), \
                     mock.patch("builtins.print"):
                    result = scan.scan(folder, app="wiztree", wiztree_mode="auto")
            finally:
                scan.DATA_DIR = old_data_dir
        self.assertTrue(result.endswith(".csv"))
        self.assertIn("/admin=0", captured["command"])
        self.assertIn("scan_wiztree_standard_", Path(result).name)

    def test_wiztree_fast_mode_refuses_non_admin_before_launch(self):
        with mock.patch.object(scan, "check_admin", return_value=False), \
             mock.patch.object(scan.subprocess, "Popen") as launch, \
             mock.patch("builtins.print") as output:
            self.assertIsNone(scan.scan("D:", app="wiztree", wiztree_mode="fast"))
        launch.assert_not_called()
        self.assertIn("requires an Administrator terminal", " ".join(str(c) for c in output.call_args_list))

    def test_wiztree_fast_mode_refuses_folder_targets_before_launch(self):
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch.object(scan, "check_admin", return_value=True), \
             mock.patch.object(scan.subprocess, "Popen") as launch, \
             mock.patch("builtins.print") as output:
            self.assertIsNone(scan.scan(folder, app="wiztree", wiztree_mode="fast"))
        launch.assert_not_called()
        self.assertIn("only available for drives", " ".join(str(c) for c in output.call_args_list))

    @unittest.skipUnless(os.name == "nt", "WinDirStat version checks target Windows")
    def test_windirstat_old_version_is_rejected_before_launch(self):
        output = io.StringIO()
        with mock.patch.object(scan, "find_windirstat", return_value="/mock/WinDirStat.exe"), \
             mock.patch.object(scan, "_get_windows_file_version", return_value=(2, 5, 9, 0)), \
             mock.patch.object(scan.subprocess, "Popen") as launch, \
             redirect_stdout(output):
            self.assertIsNone(scan.scan("D:", app="windirstat"))

        self.assertIn("WinDirStat 2.5.9.0 is too old", output.getvalue())
        self.assertIn("Update to WinDirStat 2.6.0 or newer", output.getvalue())
        launch.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows executable version resources are platform-specific")
    def test_windows_executable_version_reader_returns_four_numeric_parts(self):
        version = scan._get_windows_file_version(sys.executable)
        self.assertIsNotNone(version)
        self.assertEqual(len(version), 4)
        self.assertTrue(all(isinstance(part, int) and part >= 0 for part in version))

    def test_windirstat_launches_documented_save_to_csv_command(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_data_dir = scan.DATA_DIR
            scan.DATA_DIR = str(Path(temp_dir) / "data")
            captured = {}

            def fake_popen(command, **kwargs):
                captured["command"] = command
                export_path = Path(command[2])
                export_path.parent.mkdir(parents=True, exist_ok=True)
                export_path.write_text("File Name,Size\n", encoding="utf-8")
                return object()

            try:
                with mock.patch.object(scan, "find_windirstat", return_value="/mock/WinDirStat.exe"), \
                     mock.patch.object(scan, "_get_windows_file_version", return_value=(2, 6, 0, 0)), \
                     mock.patch.object(scan.subprocess, "Popen", side_effect=fake_popen), \
                     mock.patch.object(scan, "wait_for_scan_process", return_value=True), \
                     mock.patch("builtins.print") as output:
                    result = scan.scan("D:", app="windirstat")
                    output_text = " ".join(str(call.args[0]) for call in output.call_args_list if call.args)
            finally:
                scan.DATA_DIR = old_data_dir
        self.assertTrue(result.endswith(".csv"))
        self.assertEqual(captured["command"][:2], ["/mock/WinDirStat.exe", "/SaveTo"])
        self.assertEqual(captured["command"][-1], "D:")
        self.assertNotEqual(captured["command"][2], result)
        self.assertEqual(Path(captured["command"][2]).name, Path(result).name)
        self.assertEqual(Path(captured["command"][2]).parent.name, ".incomplete")
        self.assertNotIn("Command:", output_text)
        self.assertNotIn("python scan.py --cleanup", output_text)
        self.assertIn("applies its saved filters and scan exclusions", output_text)
        self.assertIn("Earlier scans and cleanup plans were kept.", output_text)

    def test_windirstat_rejects_wiztree_only_export_options(self):
        for options in ({"max_depth": 3}, {"include_files": False}, {"wiztree_mode": "standard"}):
            with self.subTest(options=options), mock.patch("builtins.print") as output, \
                 mock.patch.object(scan.subprocess, "Popen") as launch:
                self.assertIsNone(scan.scan("D:", app="windirstat", **options))
                launch.assert_not_called()
                message = " ".join(str(c) for c in output.call_args_list)
                if not options.get("include_files", True):
                    self.assertIn("use WizTree to scan folders only", message)
                else:
                    self.assertIn("supported only by WizTree", message)

    def test_guided_scan_runs_chosen_scanner_then_opens_review(self):
        output = io.StringIO()
        with mock.patch.object(scan, "choose_scanner", return_value="windirstat"), \
             mock.patch.object(scan, "scan", return_value="data/scan_test.csv") as run_scan, \
             mock.patch.object(analyze, "run_tui") as run_review, \
             mock.patch("builtins.input", side_effect=["D:", "", ""]) as input_mock, \
             redirect_stdout(output):
            drive_cleaner._scan_flow()
        run_scan.assert_called_once_with(drive="D:", include_files=True, max_depth=0, timeout=1800, app="windirstat")
        run_review.assert_called_once_with(initial_csv="data/scan_test.csv")
        prompts = [call.args[0] for call in input_mock.call_args_list]
        self.assertFalse(any("individual files" in prompt for prompt in prompts))
        self.assertNotIn("python scan.py", output.getvalue())
        self.assertNotIn("python analyze.py", output.getvalue())

    def test_direct_scan_cli_points_back_to_review_menu_without_extra_command(self):
        output = io.StringIO()
        with mock.patch.object(sys, "argv", [
                "scan.py", "C:", "--app", "wiztree", "--wiztree-mode", "standard"]), \
             mock.patch.object(scan, "scan", return_value=r"C:\Drive Cleanr\data\scan_example.csv"), \
             redirect_stdout(output):
            with self.assertRaises(SystemExit) as exit_result:
                scan.main()

        self.assertEqual(exit_result.exception.code, 0)
        self.assertIn("Review a previous scan", output.getvalue())
        self.assertNotIn("python analyze.py", output.getvalue())

    def test_guided_wiztree_scan_keeps_the_file_rows_choice(self):
        with mock.patch.object(scan, "choose_scanner", return_value="wiztree"), \
             mock.patch.object(scan, "scan", return_value="data/scan_test.csv") as run_scan, \
             mock.patch.object(analyze, "run_tui"), \
             mock.patch("builtins.input", side_effect=["D:", "1", "n", "0", "30", "n"]) as input_mock:
            drive_cleaner._scan_flow()
        run_scan.assert_called_once_with(drive="D:", include_files=False, max_depth=0, timeout=1800,
                                         app="wiztree", wiztree_mode="auto")
        self.assertTrue(any("individual files" in call.args[0] for call in input_mock.call_args_list))

    def test_guided_wiztree_scan_passes_requested_export_depth(self):
        with mock.patch.object(scan, "choose_scanner", return_value="wiztree"), \
             mock.patch.object(scan, "scan", return_value="data/scan_test.csv") as run_scan, \
             mock.patch.object(analyze, "run_tui"), \
             mock.patch("builtins.input", side_effect=["C:", "", "", "4", "30", "n"]):
            drive_cleaner._scan_flow()
        run_scan.assert_called_once_with(drive="C:", include_files=True, max_depth=4,
                                         timeout=1800, app="wiztree", wiztree_mode="auto")

    def test_guided_folder_scan_skips_fast_mft_mode_picker(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch.object(scan, "choose_scanner", return_value="wiztree"), \
             mock.patch.object(scan, "choose_wiztree_mode") as choose_mode, \
             mock.patch.object(scan, "scan", return_value=None) as run_scan, \
             mock.patch.object(drive_cleaner, "_pause"), \
             mock.patch("builtins.input", side_effect=[folder, "n", "0", "30"]), \
             redirect_stdout(output):
            drive_cleaner._scan_flow()
        choose_mode.assert_not_called()
        run_scan.assert_called_once_with(drive=folder, include_files=False, max_depth=0,
                                         timeout=1800, app="wiztree", wiztree_mode="standard")
        self.assertIn("this folder will use standard scanning", output.getvalue())

    def test_guided_wiztree_prompts_retry_invalid_values(self):
        output = io.StringIO()
        with mock.patch.object(scan, "choose_scanner", return_value="wiztree"), \
             mock.patch.object(scan, "choose_wiztree_mode", return_value="auto"), \
             mock.patch.object(scan, "scan", return_value="data/scan_test.csv") as run_scan, \
             mock.patch.object(analyze, "run_tui"), \
             mock.patch("builtins.input", side_effect=["D:", "maybe", "y", "-1", "2", "oops", "0", "30", "n"]), \
             redirect_stdout(output):
            drive_cleaner._scan_flow()
        run_scan.assert_called_once_with(drive="D:", include_files=True, max_depth=2,
                                         timeout=1800, app="wiztree", wiztree_mode="auto")
        self.assertIn("Enter Y or N, or Q to cancel.", output.getvalue())
        self.assertIn("Enter a whole number, or Q to cancel.", output.getvalue())
        self.assertIn("Folder depth cannot be negative.", output.getvalue())
        self.assertIn("Enter a positive number of minutes.", output.getvalue())

    def test_guided_scan_can_cancel_during_option_prompts(self):
        output = io.StringIO()
        with mock.patch.object(scan, "choose_scanner", return_value="wiztree"), \
             mock.patch.object(scan, "choose_wiztree_mode", return_value="auto"), \
             mock.patch.object(scan, "scan") as run_scan, \
             mock.patch("builtins.input", side_effect=["D:", "q"]), \
             redirect_stdout(output):
            drive_cleaner._scan_flow()
        run_scan.assert_not_called()
        self.assertIn("Scan cancelled.", output.getvalue())

    def test_guided_entry_point_has_simple_exit(self):
        output = io.StringIO()
        with mock.patch("builtins.input", return_value="0"), redirect_stdout(output):
            drive_cleaner.main_menu()
        welcome = output.getvalue()
        self.assertIn("FIND SPACE. KEEP CONTROL.", welcome)
        self.assertNotRegex(welcome, r"[\u3400-\u9fff]")
        self.assertIn("Scan -> Review -> Choose files/folders -> Optional backup -> Confirm -> Clean", welcome)
        self.assertIn("Scanning and review never remove anything.", welcome)
        self.assertIn("Choose individual files, folders, or both from the review list.", welcome)
        self.assertIn("Higher-risk candidates inside a folder are kept unless you explicitly select their listed entries too.", welcome)
        self.assertIn("The preview shows up to 12 direct items; other contents may also be removed.", welcome)
        self.assertIn("The saved plan lets you choose the final items again before cleanup.", welcome)
        self.assertIn("Without a backup, removed items cannot be restored by Drive Cleanr.", welcome)
        self.assertLess(welcome.index("FIND SPACE."), welcome.index("1) Scan a drive"))

    def test_main_menu_opens_the_previous_scan_picker(self):
        output = io.StringIO()
        with mock.patch("builtins.input", side_effect=["2", "0"]), \
             mock.patch.object(analyze, "run_tui") as review_scan, \
             redirect_stdout(output):
            drive_cleaner.main_menu()
        review_scan.assert_called_once_with()
        self.assertEqual(output.getvalue().count("FIND SPACE. KEEP CONTROL."), 1)

    def test_backup_menu_can_merge_without_overwriting(self):
        manifests = [{"id": "backup_test", "items": [{"original_path": r"C:\Users\ExampleUser\cache.bin"}]}]
        with mock.patch("builtins.input", side_effect=["3", "backup_test", "MERGE", "0"]), \
             mock.patch.object(backup, "list_backups", return_value=manifests), \
             mock.patch.object(backup, "print_backups_table"), \
             mock.patch.object(backup, "restore_backup", return_value=True) as restore, \
             mock.patch.object(drive_cleaner, "_pause"):
            drive_cleaner._backup_menu()
        restore.assert_called_once_with("backup_test", overwrite=False)

    def test_backup_menu_requires_explicit_overwrite_choice(self):
        manifests = [{"id": "backup_test", "items": [{"original_path": r"C:\Users\ExampleUser\cache.bin"}]}]
        with mock.patch("builtins.input", side_effect=["3", "backup_test", "OVERWRITE", "0"]), \
             mock.patch.object(backup, "list_backups", return_value=manifests), \
             mock.patch.object(backup, "print_backups_table"), \
             mock.patch.object(backup, "restore_backup", return_value=True) as restore, \
             mock.patch.object(drive_cleaner, "_pause"):
            drive_cleaner._backup_menu()
        restore.assert_called_once_with("backup_test", overwrite=True)

    def test_scan_cleanup_deletes_only_plans_paired_with_pruned_exports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_data_dir = scan.DATA_DIR
            scan.DATA_DIR = str(Path(temp_dir) / "data")
            data = Path(scan.DATA_DIR)
            data.mkdir()
            old_export = data / "scan_older.csv"
            new_export = data / "scan_newer.csv"
            old_export.write_text("old")
            new_export.write_text("new")
            os.utime(old_export, (1, 1))
            os.utime(new_export, (2, 2))
            old_plan = Path(temp_dir) / "scan_older.clean.ps1"
            new_plan = Path(temp_dir) / "scan_newer.clean.ps1"
            unrelated_plan = Path(temp_dir) / "clean_reviewed.ps1"
            custom_plan = Path(temp_dir) / "manual-review.ps1"
            for script in (old_plan, new_plan, unrelated_plan, custom_plan):
                script.write_text("reviewed")
            try:
                scan.cleanup_old_scans(keep_latest=1)
                self.assertTrue(old_plan.exists())
                self.assertTrue(unrelated_plan.exists())
                # The default helper call does not delete plans. Restore its
                # old CSV fixture to model the explicit CLI cleanup action,
                # which prunes the export and its paired plan together.
                old_export.write_text("old")
                os.utime(old_export, (1, 1))
                scan.cleanup_old_scans(keep_latest=1, include_scripts=True)
                self.assertFalse(old_export.exists())
                self.assertFalse(old_plan.exists())
                self.assertTrue(new_export.exists())
                self.assertTrue(new_plan.exists())
                self.assertTrue(unrelated_plan.exists())
                self.assertTrue(custom_plan.exists())
            finally:
                scan.DATA_DIR = old_data_dir

    def test_scan_cleanup_keeps_plan_when_its_export_cannot_be_pruned(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_data_dir = scan.DATA_DIR
            scan.DATA_DIR = str(Path(temp_dir) / "data")
            data = Path(scan.DATA_DIR)
            data.mkdir()
            old_export = data / "scan_older.csv"
            new_export = data / "scan_newer.csv"
            old_export.write_text("old")
            new_export.write_text("new")
            os.utime(old_export, (1, 1))
            os.utime(new_export, (2, 2))
            old_plan = Path(temp_dir) / "scan_older.clean.ps1"
            old_plan.write_text("reviewed")
            original_unlink = Path.unlink

            def fail_old_export(path, *args, **kwargs):
                if path == old_export:
                    raise OSError("simulated export deletion failure")
                return original_unlink(path, *args, **kwargs)

            try:
                with mock.patch.object(Path, "unlink", autospec=True, side_effect=fail_old_export):
                    scan.cleanup_old_scans(keep_latest=1, include_scripts=True)
                self.assertTrue(old_export.exists())
                self.assertTrue(old_plan.exists())
            finally:
                scan.DATA_DIR = old_data_dir

    def test_scan_storage_reparse_path_blocks_launch_and_retention_cleanup(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_data_dir = scan.DATA_DIR
            scan.DATA_DIR = str(Path(temp_dir) / "data")
            data = Path(scan.DATA_DIR)
            data.mkdir()
            older = data / "old.csv"
            newer = data / "new.csv"
            older.write_text("old", encoding="utf-8")
            newer.write_text("new", encoding="utf-8")
            try:
                with mock.patch.object(scan, "find_windirstat", return_value="/mock/WinDirStat.exe"), \
                     mock.patch.object(scan, "_path_has_reparse_component", return_value=True), \
                     mock.patch.object(scan.subprocess, "Popen") as launch, \
                     mock.patch("builtins.print"):
                    self.assertIsNone(scan.scan("D:", app="windirstat"))
                    self.assertEqual(scan.cleanup_old_scans(keep_latest=1), 0)
                launch.assert_not_called()
                self.assertTrue(older.exists())
                self.assertTrue(newer.exists())
            finally:
                scan.DATA_DIR = old_data_dir

    def test_scan_export_collision_preserves_existing_scans(self):
        fixed_time = datetime(2026, 9, 28, 12, 0, 0)
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir) / "data"
            data_dir.mkdir()
            base = data_dir / "scan_windirstat_20260928120000000000.csv"
            first_suffix = data_dir / "scan_windirstat_20260928120000000000_1.csv"
            base.write_text("keep original scan", encoding="utf-8")
            first_suffix.write_text("keep earlier collision", encoding="utf-8")
            with mock.patch.object(scan, "DATA_DIR", str(data_dir)), \
                 mock.patch.object(scan, "datetime", SimpleNamespace(now=lambda: fixed_time)), \
                 mock.patch.object(scan, "find_windirstat", return_value="WinDirStat.exe"), \
                 mock.patch.object(scan, "wait_for_scan_process", return_value=True), \
                 mock.patch.object(scan.subprocess, "Popen") as launch:
                def write_export(command, **_kwargs):
                    export_path = Path(command[2])
                    export_path.parent.mkdir(parents=True, exist_ok=True)
                    export_path.write_text("File Name,Size\n", encoding="utf-8")
                    return object()

                launch.side_effect = write_export
                output = scan.scan("D:", app="windirstat")

            self.assertEqual(output, str(data_dir / "scan_windirstat_20260928120000000000_2.csv"))
            self.assertEqual(base.read_text(encoding="utf-8"), "keep original scan")
            self.assertEqual(first_suffix.read_text(encoding="utf-8"), "keep earlier collision")
            launch.assert_called_once()

    def test_wait_uses_process_exit_after_a_quiet_export(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            export_path = Path(temp_dir) / "scan.csv"
            export_path.write_text("File Name,Size\n", encoding="utf-8")

            class QuietProcess:
                def __init__(self):
                    self.calls = 0
                    self.returncode = 0
                    self.terminated = False

                def poll(self):
                    self.calls += 1
                    return None if self.calls < 4 else 0

                def terminate(self):
                    self.terminated = True

                def wait(self, timeout=None):
                    return 0

            process = QuietProcess()
            with mock.patch.object(scan.time, "monotonic", return_value=0), \
                 mock.patch.object(scan.time, "sleep", return_value=None):
                self.assertTrue(scan.wait_for_scan_process(process, str(export_path), timeout=10))
            self.assertFalse(process.terminated)

    def test_transient_export_stat_error_does_not_abort_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            export_path = Path(temp_dir) / "scan.csv"
            export_path.write_text("File Name,Size\n", encoding="utf-8")

            class FinishingProcess:
                calls = 0

                def poll(self):
                    self.calls += 1
                    return None if self.calls == 1 else 0

                def wait(self, timeout=None):
                    return 0

            original_getsize = scan.os.path.getsize
            stat_calls = []

            def fail_once(path):
                if not stat_calls:
                    stat_calls.append(path)
                    raise PermissionError("temporary sharing violation")
                return original_getsize(path)

            output = io.StringIO()
            with mock.patch.object(scan.os.path, "getsize", side_effect=fail_once), \
                 mock.patch.object(scan.time, "sleep", return_value=None), \
                 redirect_stdout(output):
                self.assertTrue(scan.wait_for_scan_process(
                    FinishingProcess(), str(export_path), timeout=10
                ))
            self.assertIn("Checking scan file", output.getvalue())
            self.assertIn("Scan complete", output.getvalue())

    def test_wait_for_file_does_not_swallow_unexpected_errors_or_interrupts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            export_path = Path(temp_dir) / "scan.csv"
            export_path.write_text("File Name,Size\n", encoding="utf-8")
            with mock.patch.object(scan.os.path, "getsize", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    scan.wait_for_file(str(export_path), timeout=1)
            with mock.patch.object(scan.os.path, "getsize", side_effect=RuntimeError("unexpected")):
                with self.assertRaisesRegex(RuntimeError, "unexpected"):
                    scan.wait_for_file(str(export_path), timeout=1)

    def test_wait_for_file_separates_progress_from_completion_message(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            export_path = Path(temp_dir) / "scan.csv"
            export_path.write_text("File Name,Size\n", encoding="utf-8")
            clock = [0.0]

            def advance_time(_seconds):
                clock[0] += 1

            output = io.StringIO()
            with mock.patch.object(scan.time, "monotonic", side_effect=lambda: clock[0]), \
                 mock.patch.object(scan.time, "sleep", side_effect=advance_time), \
                 redirect_stdout(output):
                self.assertTrue(scan.wait_for_file(str(export_path), timeout=10, stable_time=2))

            self.assertRegex(
                output.getvalue(),
                r"Saved so far: [0-9.]+ MB\nScan complete! Results file size:",
            )

    def test_wait_for_file_timeout_uses_monotonic_clock(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_export = Path(temp_dir) / "not-created.csv"
            clock = [0.0]

            def advance_time(_seconds):
                clock[0] += 1

            output = io.StringIO()
            with mock.patch.object(scan.time, "monotonic", side_effect=lambda: clock[0]), \
                 mock.patch.object(scan.time, "time", side_effect=AssertionError("wall clock used for timeout")), \
                 mock.patch.object(scan.time, "sleep", side_effect=advance_time), \
                 redirect_stdout(output):
                self.assertFalse(scan.wait_for_file(str(missing_export), timeout=3))

            self.assertIn("did not finish within 3 seconds", output.getvalue())

    def test_scan_export_validation_accepts_supported_headers_and_wiztree_note(self):
        localized_windirstat_header = ",".join((
            "\u540d\u79f0", "\u6587\u4ef6\u6570", "\u6587\u4ef6\u5939\u6570",
            "\u903b\u8f91\u5927\u5c0f", "\u7269\u7406\u5927\u5c0f", "\u5c5e\u6027",
            "\u6700\u540e\u4fee\u6539", "\u5185\u90e8\u5c5e\u6027", "\u7d22\u5f15",
        ))
        localized_windirstat_row = (
            r"C:\Users\A\Temp\cache.bin,0,0,125000000,120000000,Archive,,"
            "0x20000008,00000002\n"
        )
        cases = (
            ("File Name,Size\n", True, "scan.csv"),
            ("Name,Logical Size,Physical Size\n", True, "scan.csv"),
            ("Generated by WizTree 4.x\nFile Name,Size\n", True, "scan.csv"),
            ("Generated by WizTree 4.x\nnot-a-scan,columns\n", False, "scan.csv"),
            ('"unterminated,header\n', False, "scan.csv"),
            (f"{localized_windirstat_header}\n{localized_windirstat_row}", True,
             "scan_windirstat_fixture.csv"),
            (f"WinDirStat export\n{localized_windirstat_header}\n{localized_windirstat_row}", True,
             "scan_windirstat_fixture.csv"),
            (f"{localized_windirstat_header}\n", True, "scan_windirstat_fixture.csv"),
            (f"{localized_windirstat_header}\n"
             r"C:\Users\A\Temp\cache.bin,0,0,125000000,120000000,Archive,,0x20000001,not-an-index\n",
             False, "unrecognized.csv"),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            for contents, expected, filename in cases:
                with self.subTest(contents=contents):
                    export_path = Path(temp_dir) / filename
                    export_path.write_text(contents, encoding="utf-8")
                    valid, _reason = scan.validate_scan_export(str(export_path))
                    self.assertEqual(valid, expected)

    def test_scan_process_rejects_an_invalid_stable_export(self):
        class FinishedProcess:
            def poll(self):
                return 0

            def wait(self):
                return 0

        with tempfile.TemporaryDirectory() as temp_dir:
            export_path = Path(temp_dir) / "scan.csv"
            export_path.write_text("scanner failed but exited 0\n", encoding="utf-8")
            with mock.patch.object(scan, "wait_for_file", return_value=True), \
                 mock.patch("builtins.print"):
                self.assertFalse(scan.wait_for_scan_process(FinishedProcess(), str(export_path)))

    def test_timeout_terminates_a_stuck_scan(self):
        class StuckProcess:
            terminated = False

            def poll(self):
                return None

            def terminate(self):
                self.terminated = True

            def wait(self, timeout=None):
                return 0

        process = StuckProcess()
        ticks = iter([0.0, 2.0])
        with mock.patch.object(scan.time, "monotonic", side_effect=lambda: next(ticks)), \
             mock.patch.object(scan.time, "sleep", return_value=None):
            self.assertFalse(scan.wait_for_scan_process(process, "missing.csv", timeout=1))
        self.assertTrue(process.terminated)

    def test_timeout_escalates_to_kill_when_scanner_ignores_terminate(self):
        class UnstoppableProcess:
            terminated = False
            killed = False

            def poll(self):
                return 0 if self.killed else None

            def terminate(self):
                self.terminated = True

            def wait(self, timeout=None):
                if not self.killed:
                    raise subprocess.TimeoutExpired("mock-scanner", timeout)
                return 0

            def kill(self):
                self.killed = True

        process = UnstoppableProcess()
        ticks = iter([0.0, 2.0])
        with mock.patch.object(scan.time, "monotonic", side_effect=lambda: next(ticks)), \
             mock.patch.object(scan.time, "sleep", return_value=None):
            self.assertFalse(scan.wait_for_scan_process(process, "missing.csv", timeout=1))
        self.assertTrue(process.terminated)
        self.assertTrue(process.killed)

    def test_unstoppable_scanner_keeps_partial_export(self):
        class UnstoppableProcess:
            def poll(self):
                return None

            def terminate(self):
                pass

            def wait(self, timeout=None):
                raise subprocess.TimeoutExpired("mock-scanner", timeout)

            def kill(self):
                pass

        with tempfile.TemporaryDirectory() as temp_dir:
            old_data_dir = scan.DATA_DIR
            data_dir = Path(temp_dir) / "data"
            scan.DATA_DIR = str(data_dir)
            process = UnstoppableProcess()

            def fake_popen(command, **kwargs):
                Path(command[2]).write_text("partial scan", encoding="utf-8")
                return process

            ticks = iter([0.0, 2.0])
            output = io.StringIO()
            try:
                with mock.patch.object(scan, "find_windirstat", return_value="WinDirStat.exe"), \
                     mock.patch.object(scan.subprocess, "Popen", side_effect=fake_popen), \
                     mock.patch.object(scan.time, "monotonic", side_effect=lambda: next(ticks)), \
                     mock.patch.object(scan.time, "sleep", return_value=None), \
                     redirect_stdout(output):
                    self.assertIsNone(scan.scan("D:", app="windirstat", timeout=1))

                partial_exports = list((data_dir / ".incomplete").glob("*.csv"))
                self.assertEqual(len(partial_exports), 1)
                self.assertEqual(partial_exports[0].read_text(encoding="utf-8"), "partial scan")
                self.assertIn("could not be confirmed stopped", output.getvalue())
                self.assertIsNone(scan.get_latest_scan())
                self.assertEqual(scan.cleanup_old_scans(keep_latest=1), 0)
                self.assertTrue(partial_exports[0].exists())
            finally:
                scan.DATA_DIR = old_data_dir

    def test_interrupted_or_failed_scan_stops_process_and_removes_partial_export(self):
        for failure in (KeyboardInterrupt(), RuntimeError("mock scan failure")):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as temp_dir:
                old_data_dir = scan.DATA_DIR
                scan.DATA_DIR = str(Path(temp_dir) / "data")

                class FakeProcess:
                    terminated = False
                    exited = False

                    def poll(self):
                        return 0 if self.exited else None

                    def terminate(self):
                        self.terminated = True

                    def wait(self, timeout=None):
                        self.exited = True
                        return 0

                    def kill(self):
                        self.exited = True

                process = FakeProcess()

                def fake_popen(command, **kwargs):
                    Path(command[2]).write_text("partial scan", encoding="utf-8")
                    return process

                try:
                    with mock.patch.object(scan, "find_windirstat", return_value="/mock/WinDirStat.exe"), \
                         mock.patch.object(scan.subprocess, "Popen", side_effect=fake_popen), \
                         mock.patch.object(scan, "wait_for_scan_process", side_effect=failure), \
                         mock.patch("builtins.print"):
                        self.assertIsNone(scan.scan("D:", app="windirstat"))
                    self.assertTrue(process.terminated)
                    self.assertEqual(list(Path(scan.DATA_DIR).rglob("*.csv")), [])
                finally:
                    scan.DATA_DIR = old_data_dir


class BackupSafetyTests(unittest.TestCase):
    def test_backup_json_mode_keeps_progress_off_json_stdout(self):
        manifest = {"status": "completed", "id": "backup_20261003_123456", "items": []}
        stdout = io.StringIO()
        stderr = io.StringIO()

        def create_with_progress(_paths, _priority, progress_stream=None):
            print("Copying backup file: payload.bin (50%).", file=progress_stream)
            return manifest

        with mock.patch.object(
                backup.sys, "argv",
                ["backup.py", "create", "--paths", r"C:\Temp\payload.bin", "--json"]), \
             mock.patch.object(backup, "create_backup", side_effect=create_with_progress) as create, \
             redirect_stdout(stdout), redirect_stderr(stderr):
            backup.main()

        create.assert_called_once()
        self.assertIs(create.call_args.kwargs["progress_stream"], stderr)
        self.assertEqual(json.loads(stdout.getvalue()), manifest)
        self.assertIn("payload.bin (50%)", stderr.getvalue())

    def test_backup_cleanup_requires_exact_confirmation(self):
        backups = [{
            "id": "backup_20260928_123456_000001",
            "timestamp": "2026-09-28T12:34:56",
            "items": [],
            "backup_root": r"D:\CleanBackups",
            "total_size_formatted": "0 B",
        }]
        with mock.patch.object(backup.sys, "argv", ["backup.py", "cleanup", "--all"]), \
             mock.patch.object(backup, "list_backups", return_value=backups), \
             mock.patch("builtins.input", return_value="delete"), \
             mock.patch.object(backup, "cleanup_all_backups") as cleanup, \
             redirect_stdout(io.StringIO()) as output:
            backup.main()
        cleanup.assert_not_called()
        self.assertIn("Backup cleanup cancelled", output.getvalue())

    def test_backup_cleanup_interrupt_cancels_without_deleting(self):
        backups = [{
            "id": "backup_20260928_123456_000001",
            "timestamp": "2026-09-28T12:34:56",
            "items": [],
            "backup_root": r"D:\CleanBackups",
            "total_size_formatted": "0 B",
        }]
        with mock.patch.object(backup.sys, "argv", ["backup.py", "cleanup", "--all"]), \
             mock.patch.object(backup, "list_backups", return_value=backups), \
             mock.patch("builtins.input", side_effect=KeyboardInterrupt), \
             mock.patch.object(backup, "cleanup_all_backups") as cleanup, \
             redirect_stdout(io.StringIO()) as output:
            backup.main()
        cleanup.assert_not_called()
        self.assertIn("Backup cleanup cancelled", output.getvalue())

    def test_backup_cleanup_uses_the_displayed_snapshot_after_confirmation(self):
        backups = [{
            "id": "backup_20260928_123456_000001",
            "timestamp": "2026-09-28T12:34:56",
            "items": [],
            "backup_root": r"D:\CleanBackups",
            "total_size_formatted": "0 B",
        }]
        with mock.patch.object(backup.sys, "argv", ["backup.py", "cleanup", "--all"]), \
             mock.patch.object(backup, "list_backups", return_value=backups), \
             mock.patch("builtins.input", return_value="DELETE") as prompt, \
             mock.patch.object(backup, "cleanup_all_backups", return_value=1) as cleanup, \
             redirect_stdout(io.StringIO()) as output:
            backup.main()
        prompt.assert_called_once()
        self.assertIn("Permanently delete all 1 listed backups", prompt.call_args.args[0])
        cleanup.assert_called_once_with(backups)
        self.assertIn("Deleted 1 of 1 listed backups", output.getvalue())

    def test_backup_cleanup_yes_skips_prompt_but_uses_displayed_snapshot(self):
        backups = [{
            "id": "backup_20260928_123456_000001",
            "timestamp": "2026-09-28T12:34:56",
            "items": [],
            "backup_root": r"D:\CleanBackups",
            "total_size_formatted": "0 B",
        }]
        with mock.patch.object(backup.sys, "argv", ["backup.py", "cleanup", "--all", "--yes"]), \
             mock.patch.object(backup, "list_backups", return_value=backups), \
             mock.patch("builtins.input") as prompt, \
             mock.patch.object(backup, "cleanup_all_backups", return_value=1) as cleanup, \
             redirect_stdout(io.StringIO()):
            backup.main()
        prompt.assert_not_called()
        cleanup.assert_called_once_with(backups)

    def test_backup_cli_confirmation_interrupts_cancel_without_running_operation(self):
        for command, expected_message, operation in (
                ("restore", "Restore cancelled", "restore_backup"),
                ("delete", "Backup deletion cancelled", "delete_backup")):
            with self.subTest(command=command), \
                 mock.patch.object(backup.sys, "argv", ["backup.py", command, "--id", "backup_test"]), \
                 mock.patch("builtins.input", side_effect=KeyboardInterrupt), \
                 mock.patch.object(backup, operation) as run_operation, \
                 redirect_stdout(io.StringIO()) as output:
                backup.main()
            run_operation.assert_not_called()
            self.assertIn(expected_message, output.getvalue())

    def test_backup_list_skips_malformed_manifest_shapes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            malformed_id = "backup_20260928_123456_000001"
            wrong_fields_id = "backup_20260928_123456_000002"
            valid_id = "backup_20260928_123456_000003"
            for backup_id in (malformed_id, wrong_fields_id, valid_id):
                (root / backup_id).mkdir()
            (root / malformed_id / "manifest.json").write_text("[]", encoding="utf-8")
            (root / wrong_fields_id / "manifest.json").write_text(json.dumps({
                "id": wrong_fields_id, "timestamp": {}, "items": [],
            }), encoding="utf-8")
            (root / valid_id / "manifest.json").write_text(json.dumps({
                "id": valid_id, "timestamp": "2026-09-28T12:34:56", "items": [],
            }), encoding="utf-8")

            with mock.patch.object(backup, "_existing_backup_roots", return_value=[temp_dir]):
                backups = backup.list_backups()

        self.assertEqual([valid_id], [entry["id"] for entry in backups])

    def test_backup_list_skips_reparse_paths_at_each_level(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            backup_id = "backup_20260928_123456_123456"
            backup_dir = root / backup_id
            backup_dir.mkdir()
            manifest_path = backup_dir / "manifest.json"
            manifest_path.write_text(json.dumps({
                "id": backup_id, "timestamp": "2026-09-28T12:34:56", "items": [],
            }), encoding="utf-8")
            for redirected_path in (root, backup_dir, manifest_path):
                redirected = os.path.normcase(os.path.abspath(redirected_path))

                def is_redirected(path, redirected=redirected):
                    return os.path.normcase(os.path.abspath(path)) == redirected

                with self.subTest(path=redirected_path), mock.patch.object(backup, "_existing_backup_roots", return_value=[temp_dir]), mock.patch.object(backup, "_path_has_reparse_component", side_effect=is_redirected):
                    self.assertEqual([], backup.list_backups())

    def test_get_backup_rejects_corrupt_and_mismatched_manifests(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            backup_id = "backup_20260928_123456_123456"
            manifest_path = Path(temp_dir) / "manifest.json"
            invalid_manifests = (
                "{invalid json",
                "[]",
                json.dumps({
                    "id": "backup_20260928_123456_000001",
                    "timestamp": "2026-09-28T12:34:56",
                    "items": [],
                }),
            )
            with mock.patch.object(backup, "_find_backup_dir", return_value=temp_dir):
                for contents in invalid_manifests:
                    with self.subTest(contents=contents):
                        manifest_path.write_text(contents, encoding="utf-8")
                        self.assertIsNone(backup.get_backup(backup_id))

    def test_backup_list_shows_the_restore_location(self):
        manifest = {
            "id": "backup_20260928_123456_123456",
            "timestamp": "2026-09-28T12:34:56",
            "backup_root": r"D:\CleanBackups",
            "total_size_formatted": "12 MB",
            "status": "completed",
            "items": [{"original_path": r"C:\Users\A\cache.bin"}],
        }
        output = io.StringIO()
        with redirect_stdout(output):
            backup.print_backups_table([manifest])
        self.assertIn(r"Saved to: D:\CleanBackups\backup_20260928_123456_123456", output.getvalue())
        self.assertIn("Completed", output.getvalue())

    def test_backup_list_shows_partial_status_and_escapes_manifest_controls(self):
        manifests = [
            {
                "id": "backup_20260928_123456_000001",
                "timestamp": "2026-09-28T12:34:56",
                "backup_root": "D:\\CleanBackups\x1b[31m",
                "total_size_formatted": "12 MB\nInjected output",
                "status": "partial",
                "items": [],
            },
        ]
        output = io.StringIO()
        with redirect_stdout(output):
            backup.print_backups_table(manifests)
        rendered = output.getvalue()
        self.assertIn("Partial", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("Injected output\n", rendered)
        self.assertIn(r"\x1b[31m", rendered)
        self.assertIn(r"\x0aInjected output", rendered)

    def test_delete_refuses_backup_tree_with_reparse_point(self):
        output = io.StringIO()
        with mock.patch.object(backup, "_find_backup_dir", return_value="D:\\CleanBackups\\backup_20260928_123456_123456"), \
             mock.patch.object(backup, "_tree_has_reparse_point", return_value=True), \
             mock.patch.object(backup.shutil, "rmtree") as remove_tree, \
             redirect_stdout(output):
            self.assertFalse(backup.delete_backup("backup_20260928_123456_123456"))
        remove_tree.assert_not_called()
        self.assertIn("containing a reparse point or junction", output.getvalue())

    def test_reparse_point_lookup_fails_closed_but_allows_missing_paths(self):
        with mock.patch.object(backup.os, "lstat", side_effect=PermissionError("access denied")):
            self.assertTrue(backup._is_reparse_point("unreadable-path"))
            self.assertTrue(backup._path_has_reparse_component("unreadable-path"))

        with mock.patch.object(backup.os, "lstat", side_effect=FileNotFoundError("missing")):
            self.assertFalse(backup._is_reparse_point("missing-path"))

    def test_backup_creation_rejects_drive_roots_and_unc_before_creating_storage(self):
        for unsafe_path in ("C:\\", "\\\\server\\share\\folder", "C:relative"):
            with self.subTest(path=unsafe_path), mock.patch.object(backup, "get_backup_root") as get_root:
                with self.assertRaisesRegex(ValueError, "unsafe backup path"):
                    backup.create_backup([unsafe_path])
                get_root.assert_not_called()

    def test_backup_creation_rejects_duplicate_and_nested_paths_before_storage(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = str(Path(temp_dir) / "selected")
            child = str(Path(parent) / "nested" / "cache.bin")
            for paths in ([parent, parent], [parent, child]):
                with self.subTest(paths=paths), mock.patch.object(backup, "get_backup_root") as get_root:
                    with self.assertRaisesRegex(ValueError, "duplicate or overlap"):
                        backup.create_backup(paths)
                    get_root.assert_not_called()

    def test_backup_verification_rejects_overlapping_manifest_sources(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = str(Path(temp_dir) / "selected")
            manifest = {
                "status": "completed",
                "items": [
                    {"original_path": parent},
                    {"original_path": str(Path(parent) / "nested" / "cache.bin")},
                ],
            }
            with mock.patch.object(backup, "get_backup", return_value=manifest), \
                 mock.patch.object(backup, "_find_backup_dir", return_value=temp_dir), \
                 mock.patch("builtins.print") as output:
                self.assertFalse(backup.verify_backup("backup_test"))
            message = " ".join(str(call.args[0]) for call in output.call_args_list if call.args)
            self.assertIn("duplicate or overlapping source paths", message)

    def test_backup_source_beneath_a_reparse_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "linked-parent" / "cache.bin"
            source.parent.mkdir()
            source.write_bytes(b"keep")
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_path_has_reparse_component", return_value=True), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10):
                result = backup.create_backup([str(source)])
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["items"], [])
            self.assertTrue(any("reparse point" in error for error in result["errors"]))
            self.assertEqual(source.read_bytes(), b"keep")

    def test_backup_root_refuses_an_existing_reparse_path_before_writing(self):
        with mock.patch.object(backup, "find_backup_drive", return_value=r"D:\CleanBackups"), \
             mock.patch.object(backup, "_path_has_reparse_component", return_value=True), \
             mock.patch.object(backup.os, "makedirs") as make_directory:
            with self.assertRaisesRegex(RuntimeError, "reparse point or junction"):
                backup.get_backup_root()
        make_directory.assert_not_called()

    def test_backup_id_collision_never_reuses_an_existing_backup_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cache.bin"
            source.write_bytes(b"new source")
            fixed_now = datetime(2026, 9, 27, 12, 34, 56, 123456)
            existing = Path(temp_dir) / "backup_20260927_123456_123456"
            existing.mkdir()
            marker = existing / "preserve.txt"
            marker.write_text("existing backup", encoding="utf-8")
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "datetime") as mocked_datetime:
                mocked_datetime.now.return_value = fixed_now
                with self.assertRaises(FileExistsError):
                    backup.create_backup([str(source)])
            self.assertEqual(marker.read_text(encoding="utf-8"), "existing backup")

    def test_missing_path_makes_backup_partial_not_successful(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10_000_000):
                output = io.StringIO()
                with redirect_stdout(output):
                    result = backup.create_backup([str(Path(temp_dir) / "missing")])
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["items"], [])
            self.assertTrue(result["errors"])
            self.assertIn("Backup incomplete:", output.getvalue())
            self.assertNotIn("Backup complete!", output.getvalue())

    def test_directory_copy_failure_has_machine_readable_manifest_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "small-directory"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"mock data")
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 mock.patch.object(backup, "_run_robocopy_with_progress", side_effect=RuntimeError("mock robocopy failure")):
                result = backup.create_backup([str(source)])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["items"], [])
        self.assertTrue(any("Directory copy backup failed" in error and "mock robocopy failure" in error
                            for error in result["errors"]))

    def test_directory_archive_failure_has_machine_readable_manifest_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "large-directory"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"mock data")
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 mock.patch.object(backup, "_path_size_and_named_streams",
                                   return_value=(backup.SIZE_THRESHOLD, False)), \
                 mock.patch.object(backup, "_create_zip_backup", side_effect=OSError("mock archive failure")):
                result = backup.create_backup([str(source)])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["items"], [])
        self.assertTrue(any("Directory archive backup failed" in error and "Operating-system error" in error
                            for error in result["errors"]))

    def test_zip64_directory_backup_manifest_verification_and_restore_round_trip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source-data"
            nested = source / "nested"
            nested.mkdir(parents=True)
            expected = bytes(range(64))
            (nested / "payload.bin").write_bytes(expected)
            output = io.StringIO()

            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 mock.patch.object(backup, "SIZE_THRESHOLD", 1), \
                 mock.patch.object(zipfile, "ZIP64_LIMIT", 16), \
                 redirect_stdout(output):
                manifest = backup.create_backup([str(source)])

            self.assertEqual(manifest["status"], "completed")
            self.assertEqual(manifest["items"][0]["format"], "zip")
            self.assertIn("Backup complete!", output.getvalue())
            with zipfile.ZipFile(manifest["items"][0]["backup_path"]) as archive:
                self.assertGreaterEqual(archive.getinfo("nested/payload.bin").extract_version, 45)

            with mock.patch.object(backup, "_existing_backup_roots", return_value=[temp_dir]), \
                 redirect_stdout(io.StringIO()):
                self.assertTrue(backup.verify_backup(manifest["id"]))

            shutil.rmtree(source)
            with mock.patch.object(backup, "_existing_backup_roots", return_value=[temp_dir]), \
                 redirect_stdout(io.StringIO()):
                self.assertTrue(backup.restore_backup(manifest["id"]))
            self.assertEqual((nested / "payload.bin").read_bytes(), expected)

    def test_file_backup_is_copied_and_verified(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cache-file.bin"
            source.write_bytes(b"mock cache data")
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10):
                result = backup.create_backup([str(source)])
            self.assertEqual(result["status"], "completed")
            item = result["items"][0]
            self.assertEqual(item["format"], "file")
            self.assertEqual(Path(item["backup_path"]).read_bytes(), b"mock cache data")

    def test_file_backup_reports_progress_during_copy_and_verification(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cache-file.bin"
            with source.open("wb") as stream:
                stream.truncate(128 * 1024 * 1024)
            output = io.StringIO()
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 redirect_stdout(output):
                result = backup.create_backup([str(source)])

        self.assertEqual(result["status"], "completed")
        self.assertIn("Checking backup contents", output.getvalue())
        self.assertIn("Copying backup file", output.getvalue())
        self.assertIn("Verifying backup contents", output.getvalue())
        self.assertIn("64.00 MB of 128.00 MB copied (50%).", output.getvalue())
        self.assertIn("64.00 MB of 128.00 MB checked (50%).", output.getvalue())

    def test_zip_backup_reports_progress_while_compressing_and_checking(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "large-directory"
            source.mkdir()
            with (source / "payload.bin").open("wb") as stream:
                stream.truncate(2 * 1024 * 1024)
            output = io.StringIO()
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 mock.patch.object(backup, "SIZE_THRESHOLD", 1), \
                 mock.patch.object(backup, "BACKUP_PROGRESS_BYTES_INTERVAL", 1024 * 1024), \
                 redirect_stdout(output):
                result = backup.create_backup([str(source)])

        self.assertEqual(result["status"], "completed")
        self.assertIn("Compressing backup folder: payload.bin: 1.00 MB of 2.00 MB added to archive (50%).", output.getvalue())
        self.assertIn("Verifying compressed backup: payload.bin: 1.00 MB of 2.00 MB verified (50%).", output.getvalue())

    def test_folder_backup_size_scan_reports_periodic_item_progress(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "many-files"
            source.mkdir()
            for index in range(105):
                (source / f"item-{index:03}.bin").write_bytes(b"temporary")

            def mock_copy(command, **_kwargs):
                shutil.copytree(command[1], command[2])
                return 1

            output = io.StringIO()
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 mock.patch.object(backup, "_run_robocopy_with_progress", side_effect=mock_copy), \
                 redirect_stdout(output):
                result = backup.create_backup([str(source)])

        self.assertEqual(result["status"], "completed")
        self.assertIn("Checking backup contents: 100 items checked", output.getvalue())
        self.assertIn("1 item checked", output.getvalue())
        self.assertNotIn("1 items checked", output.getvalue())
        self.assertIn("Verifying backup contents", output.getvalue())

    def test_robocopy_backup_emits_a_progress_heartbeat(self):
        command = ["robocopy", "source", "destination"]

        class MockProcess:
            def __init__(self):
                self.wait_calls = 0

            def wait(self, timeout=None):
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired(command, timeout)
                return 1

        process = MockProcess()
        output = io.StringIO()
        with mock.patch.object(backup.subprocess, "Popen", return_value=process) as launch, \
             redirect_stdout(output):
            return_code = backup._run_robocopy_with_progress(
                command, progress=backup._BackupProgress("Copying backup folder")
            )

        self.assertEqual(return_code, 1)
        self.assertIn("Still working after", output.getvalue())
        launch.assert_called_once_with(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    def test_large_directory_with_named_streams_uses_verified_copy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "large-directory"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"fixture")
            backup_root = root / "backups"
            backup_root.mkdir()
            fingerprint = {
                "payload.bin": ("file", 7, "a" * 64),
                "payload.bin\0:metadata:$DATA": ("stream", 12, "b" * 64),
            }

            def mock_robocopy(command, **_kwargs):
                Path(command[2]).mkdir()
                return 1

            with mock.patch.object(backup, "get_backup_root", return_value=str(backup_root)), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 mock.patch.object(backup, "SIZE_THRESHOLD", 1), \
                 mock.patch.object(backup, "_path_size_and_named_streams", return_value=(19, True)), \
                 mock.patch.object(backup, "get_dir_size", return_value=19), \
                 mock.patch.object(backup, "_directory_fingerprint", return_value=fingerprint), \
                 mock.patch.object(backup, "_create_zip_backup") as create_zip, \
                 mock.patch.object(backup, "_run_robocopy_with_progress", side_effect=mock_robocopy):
                manifest = backup.create_backup([str(source)])

            self.assertEqual(manifest["version"], 2)
            self.assertEqual(manifest["status"], "completed")
            self.assertEqual(manifest["items"][0]["format"], "copy")
            create_zip.assert_not_called()

    def test_directory_backup_fails_if_named_stream_is_missing_from_copy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "large-directory"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"fixture")
            backup_root = root / "backups"
            backup_root.mkdir()
            source_fingerprint = {
                "payload.bin": ("file", 7, "a" * 64),
                "payload.bin\0:metadata:$DATA": ("stream", 12, "b" * 64),
            }
            copied_without_stream = {"payload.bin": ("file", 7, "a" * 64)}

            def fingerprint(path, include_named_streams=True, **_kwargs):
                return source_fingerprint if os.path.normcase(path) == os.path.normcase(str(source)) else copied_without_stream

            def mock_robocopy(command, **_kwargs):
                Path(command[2]).mkdir()
                return 1

            with mock.patch.object(backup, "get_backup_root", return_value=str(backup_root)), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 mock.patch.object(backup, "SIZE_THRESHOLD", 1), \
                 mock.patch.object(backup, "_path_size_and_named_streams", return_value=(19, True)), \
                 mock.patch.object(backup, "get_dir_size", return_value=19), \
                 mock.patch.object(backup, "_directory_fingerprint", side_effect=fingerprint), \
                 mock.patch.object(backup, "_run_robocopy_with_progress", side_effect=mock_robocopy):
                manifest = backup.create_backup([str(source)])

            self.assertEqual(manifest["status"], "partial")
            self.assertEqual(manifest["items"], [])
            self.assertTrue(any("different file contents" in error for error in manifest["errors"]))

    @unittest.skipUnless(os.name == "nt", "named data stream backup requires Windows")
    def test_file_backup_verifies_and_restores_named_ntfs_stream(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "cache-file.bin"
            source.write_bytes(b"main file data")
            stream_suffix = ":DriveCleanrTest:$DATA"
            stream_path = str(source) + stream_suffix
            expected_stream = b"restore the named stream"
            try:
                with open(stream_path, "wb") as stream:
                    stream.write(expected_stream)
            except OSError as exc:
                self.skipTest(f"Temporary volume does not support named streams: {exc}")
            if not any(name.casefold() == stream_suffix.casefold()
                       for name, _size in backup._named_data_streams(str(source))):
                self.skipTest("Temporary volume does not expose NTFS named streams")

            backup_root = root / "backups"
            backup_root.mkdir()

            def copy_default_stream_only(source_path, backup_path, **_kwargs):
                # Reproduce the Windows copy behavior used by Python 3.10,
                # which does not include NTFS named streams in shutil.copy2.
                with open(source_path, "rb") as source_file, \
                     open(backup_path, "wb") as backup_file:
                    shutil.copyfileobj(source_file, backup_file)
                return backup_path

            with mock.patch.object(backup, "get_backup_root", return_value=str(backup_root)), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 mock.patch.object(backup, "_copy_file_with_progress", side_effect=copy_default_stream_only):
                manifest = backup.create_backup([str(source)])

            self.assertEqual(manifest["status"], "completed")
            item = manifest["items"][0]
            self.assertEqual(item["size"], len(b"main file data") + len(expected_stream))
            self.assertEqual(Path(item["backup_path"]).read_bytes(), b"main file data")
            with open(item["backup_path"] + stream_suffix, "rb") as stream:
                self.assertEqual(stream.read(), expected_stream)

            with mock.patch.object(backup, "_existing_backup_roots", return_value=[str(backup_root)]):
                self.assertTrue(backup.verify_backup(manifest["id"], [str(source)]))
                with open(stream_path, "wb") as stream:
                    stream.write(b"X" * len(expected_stream))
                self.assertFalse(backup.verify_backup(manifest["id"], [str(source)]))

                source.unlink()
                with redirect_stdout(io.StringIO()), \
                     mock.patch.object(backup.shutil, "copy2", side_effect=copy_default_stream_only):
                    self.assertTrue(backup.restore_backup(manifest["id"]))
            with open(stream_path, "rb") as stream:
                self.assertEqual(stream.read(), expected_stream)

    @unittest.skipUnless(os.name == "nt", "named data stream backup requires Windows")
    def test_large_directory_named_stream_survives_mocked_direct_copy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "large-directory"
            source.mkdir()
            payload = source / "payload.bin"
            payload.write_bytes(b"directory data")
            stream_suffix = ":DriveCleanrFolderTest:$DATA"
            stream_path = str(payload) + stream_suffix
            expected_stream = b"folder stream data"
            try:
                with open(stream_path, "wb") as stream:
                    stream.write(expected_stream)
            except OSError as exc:
                self.skipTest(f"Temporary volume does not support named streams: {exc}")
            if not backup._named_data_streams(str(payload)):
                self.skipTest("Temporary volume does not expose NTFS named streams")

            backup_root = root / "backups"
            backup_root.mkdir()

            def copy_file_with_named_streams(source_file, backup_file):
                result = shutil.copy2(source_file, backup_file)
                backup._copy_named_data_streams(source_file, backup_file)
                return result

            def mock_robocopy(command, **_kwargs):
                # Model Robocopy's /COPY:DAT behavior independently of the
                # Python version running the test.
                shutil.copytree(command[1], command[2], copy_function=copy_file_with_named_streams)
                return 1

            with mock.patch.object(backup, "get_backup_root", return_value=str(backup_root)), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 mock.patch.object(backup, "SIZE_THRESHOLD", 1), \
                 mock.patch.object(backup, "_run_robocopy_with_progress", side_effect=mock_robocopy):
                manifest = backup.create_backup([str(source)])

            self.assertEqual(manifest["status"], "completed")
            self.assertEqual(manifest["items"][0]["format"], "copy")
            saved_stream = manifest["items"][0]["backup_path"] + "\\payload.bin" + stream_suffix
            with open(saved_stream, "rb") as stream:
                self.assertEqual(stream.read(), expected_stream)
            with mock.patch.object(backup, "_existing_backup_roots", return_value=[str(backup_root)]):
                self.assertTrue(backup.verify_backup(manifest["id"]))

    @unittest.skipUnless(os.name == "nt", "Robocopy named-stream integration requires Windows")
    def test_large_directory_backup_and_restore_preserve_directory_named_stream(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "large-directory"
            nested = source / "nested"
            nested.mkdir(parents=True)
            (nested / "payload.bin").write_bytes(b"directory file data")
            stream_suffix = ":DriveCleanrDirectoryTest:$DATA"
            stream_path = str(nested) + stream_suffix
            expected_stream = b"directory stream payload"
            try:
                with open(stream_path, "wb") as stream:
                    stream.write(expected_stream)
            except OSError as exc:
                self.skipTest(f"Temporary volume does not support named streams on directories: {exc}")
            if not backup._named_data_streams(str(nested)):
                self.skipTest("Temporary volume does not expose directory named streams")

            backup_root = root / "backups"
            backup_root.mkdir()
            with mock.patch.object(backup, "get_backup_root", return_value=str(backup_root)), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 mock.patch.object(backup, "SIZE_THRESHOLD", 1):
                manifest = backup.create_backup([str(source)])

            self.assertEqual(manifest["status"], "completed")
            item = manifest["items"][0]
            self.assertEqual(item["format"], "copy")
            self.assertEqual(
                item["size"], len(b"directory file data") + len(expected_stream)
            )
            saved_nested = Path(item["backup_path"]) / "nested"
            with open(str(saved_nested) + stream_suffix, "rb") as stream:
                self.assertEqual(stream.read(), expected_stream)

            with mock.patch.object(backup, "_existing_backup_roots", return_value=[str(backup_root)]):
                self.assertTrue(backup.verify_backup(manifest["id"]))
                shutil.rmtree(source)
                with redirect_stdout(io.StringIO()):
                    self.assertTrue(backup.restore_backup(manifest["id"]))

            with open(stream_path, "rb") as stream:
                self.assertEqual(stream.read(), expected_stream)

    @unittest.skipUnless(os.name == "nt", "backup manifests use Windows local paths")
    def test_legacy_backup_cannot_claim_verification_for_unrecorded_named_streams(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            backup_id = "backup_20261003_123456_000001"
            backup_dir = root / backup_id
            backup_dir.mkdir()
            source = root / "cache-file.bin"
            saved = backup_dir / "cache-file.bin"
            source.write_bytes(b"same main data")
            saved.write_bytes(b"same main data")
            digest = backup._sha256_file(str(source))
            manifest = {
                "id": backup_id,
                "timestamp": "2026-10-03T12:34:56",
                "status": "completed",
                "items": [{
                    "original_path": str(source),
                    "backup_path": str(saved),
                    "format": "file",
                    "size": source.stat().st_size,
                    "source_integrity_sha256": digest,
                    "integrity_sha256": digest,
                }],
            }
            (backup_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            output = io.StringIO()
            with mock.patch.object(backup, "_existing_backup_roots", return_value=[str(root)]), \
                 mock.patch.object(backup, "_path_size_and_named_streams",
                                   return_value=(source.stat().st_size + 4, True)), \
                 redirect_stdout(output):
                self.assertFalse(backup.verify_backup(backup_id))
            self.assertIn("cannot verify the named data streams", output.getvalue())

    def test_backup_verification_detects_source_changes_after_backup(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cache-file.bin"
            source.write_bytes(b"mock cache data")
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10):
                result = backup.create_backup([str(source)])
            self.assertEqual(result["status"], "completed")
            with mock.patch.object(backup, "_existing_backup_roots", return_value=[temp_dir]):
                self.assertTrue(backup.verify_backup(result["id"], [str(source)]))
                source.write_bytes(b"changed after backup")
                self.assertFalse(backup.verify_backup(result["id"], [str(source)]))

    def test_file_backup_rejects_same_size_corruption(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cache-file.bin"
            source.write_bytes(b"original payload")

            def corrupt_copy(_source, destination, **_kwargs):
                Path(destination).write_bytes(b"X" * source.stat().st_size)

            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 mock.patch.object(backup, "_copy_file_with_progress", side_effect=corrupt_copy):
                result = backup.create_backup([str(source)])
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["items"], [])
            self.assertTrue(any("different file contents" in error for error in result["errors"]))

    def test_directory_backup_rejects_same_size_corruption(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cache-directory"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"original payload")

            def corrupt_robocopy(command, **_kwargs):
                copy_source = Path(command[1])
                destination = Path(command[2])
                destination.mkdir(parents=True)
                relative_file = Path("payload.bin")
                (destination / relative_file).write_bytes(b"X" * (copy_source / relative_file).stat().st_size)
                return 1

            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 mock.patch.object(backup, "_run_robocopy_with_progress", side_effect=corrupt_robocopy):
                result = backup.create_backup([str(source)])
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["items"], [])
            self.assertTrue(any("different file contents" in error for error in result["errors"]))

    def test_zip_backup_rejects_content_that_differs_from_source_snapshot(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "large-directory"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"good")
            source_snapshot = {"payload.bin": ("file", 4, "a" * 64)}
            archived_snapshot = {"payload.bin": ("file", 4, "b" * 64)}

            def write_changed_archive(source_path, archive_path, **_kwargs):
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.write(Path(source_path) / "payload.bin", "payload.bin")
                return archived_snapshot

            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 mock.patch.object(backup, "_path_size_and_named_streams",
                                   return_value=(backup.SIZE_THRESHOLD, False)), \
                 mock.patch.object(backup, "_directory_fingerprint", return_value=source_snapshot), \
                 mock.patch.object(backup, "_create_zip_backup", side_effect=write_changed_archive):
                result = backup.create_backup([str(source)])

            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["items"], [])
            self.assertTrue(any("Source changed while" in error for error in result["errors"]))

    def test_file_backup_restores_after_the_original_is_missing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cache-file.bin"
            source.write_bytes(b"recoverable data")
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10):
                manifest = backup.create_backup([str(source)])
            source.unlink()
            with mock.patch.object(backup, "_existing_backup_roots", return_value=[temp_dir]):
                self.assertTrue(backup.restore_backup(manifest["id"]))
            self.assertEqual(source.read_bytes(), b"recoverable data")

    def test_file_restore_preserves_existing_destination_without_explicit_overwrite(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cache-file.bin"
            source.write_bytes(b"saved data")
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10):
                manifest = backup.create_backup([str(source)])
            source.write_bytes(b"newer user data")
            with mock.patch.object(backup, "_existing_backup_roots", return_value=[temp_dir]):
                self.assertFalse(backup.restore_backup(manifest["id"]))
                self.assertTrue(backup.restore_backup(manifest["id"], overwrite=True))
            self.assertEqual(source.read_bytes(), b"saved data")

    def test_file_restore_copy_failure_preserves_overwrite_destination(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cache-file.bin"
            source.write_bytes(b"saved data")
            with (
                mock.patch.object(backup, "get_backup_root", return_value=temp_dir),
                mock.patch.object(backup, "_get_drive_free_space", return_value=10**10),
            ):
                manifest = backup.create_backup([str(source)])
            source.write_bytes(b"keep this current data")

            output = io.StringIO()
            with (
                mock.patch.object(backup, "_existing_backup_roots", return_value=[temp_dir]),
                mock.patch.object(backup.shutil, "copy2", side_effect=OSError("simulated disk full")),
                redirect_stdout(output),
            ):
                self.assertFalse(backup.restore_backup(manifest["id"], overwrite=True))

            self.assertEqual(source.read_bytes(), b"keep this current data")
            self.assertEqual([], list(Path(temp_dir).glob(".drive-cleanr-restore-*.tmp")))
            self.assertIn("Restore incomplete", output.getvalue())

    def test_file_restore_copy_failure_leaves_missing_destination_missing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cache-file.bin"
            source.write_bytes(b"saved data")
            with (
                mock.patch.object(backup, "get_backup_root", return_value=temp_dir),
                mock.patch.object(backup, "_get_drive_free_space", return_value=10**10),
            ):
                manifest = backup.create_backup([str(source)])
            source.unlink()

            def write_partial_then_fail(_backup_path, staged_path):
                Path(staged_path).write_bytes(b"partial")
                raise OSError("simulated interrupted copy")

            output = io.StringIO()
            with (
                mock.patch.object(backup, "_existing_backup_roots", return_value=[temp_dir]),
                mock.patch.object(backup.shutil, "copy2", side_effect=write_partial_then_fail),
                redirect_stdout(output),
            ):
                self.assertFalse(backup.restore_backup(manifest["id"]))

            self.assertFalse(source.exists())
            self.assertEqual([], list(Path(temp_dir).glob(".drive-cleanr-restore-*.tmp")))
            self.assertIn("Restore incomplete", output.getvalue())

    def test_file_restore_rejects_corrupted_staged_copy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cache-file.bin"
            source.write_bytes(b"saved data")
            with (
                mock.patch.object(backup, "get_backup_root", return_value=temp_dir),
                mock.patch.object(backup, "_get_drive_free_space", return_value=10**10),
            ):
                manifest = backup.create_backup([str(source)])
            source.unlink()

            def copy_corrupt_data(_backup_path, staged_path):
                Path(staged_path).write_bytes(b"corrupted")

            with (
                mock.patch.object(backup, "_existing_backup_roots", return_value=[temp_dir]),
                mock.patch.object(backup.shutil, "copy2", side_effect=copy_corrupt_data),
            ):
                self.assertFalse(backup.restore_backup(manifest["id"]))

            self.assertFalse(source.exists())
            self.assertEqual([], list(Path(temp_dir).glob(".drive-cleanr-restore-*.tmp")))

    def test_file_restore_preserves_destination_created_during_staging(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cache-file.bin"
            source.write_bytes(b"saved data")
            with (
                mock.patch.object(backup, "get_backup_root", return_value=temp_dir),
                mock.patch.object(backup, "_get_drive_free_space", return_value=10**10),
            ):
                manifest = backup.create_backup([str(source)])
            source.unlink()

            def create_destination(_backup_path, staged_path):
                source.write_bytes(b"new user file")
                Path(staged_path).write_bytes(b"saved data")

            output = io.StringIO()
            with (
                mock.patch.object(backup, "_existing_backup_roots", return_value=[temp_dir]),
                mock.patch.object(backup.shutil, "copy2", side_effect=create_destination),
                redirect_stdout(output),
            ):
                self.assertFalse(backup.restore_backup(manifest["id"]))

            self.assertEqual(source.read_bytes(), b"new user file")
            self.assertEqual([], list(Path(temp_dir).glob(".drive-cleanr-restore-*.tmp")))
            self.assertIn("destination appeared during restore and was preserved", output.getvalue())

    def test_directory_restore_merges_without_replacing_existing_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            backup_root = root / "backup"
            saved = backup_root / "saved-directory"
            saved.mkdir(parents=True)
            (saved / "changed.bin").write_bytes(b"original")
            (saved / "removed.bin").write_bytes(b"restore me")
            destination = root / "restored-directory"
            destination.mkdir()
            (destination / "changed.bin").write_bytes(b"newer user data")
            manifest = {
                "id": "backup_20260927_123456_123456",
                "status": "completed",
                "timestamp": "2026-09-27T12:34:56",
                "items": [{
                    "original_path": str(destination),
                    "backup_path": str(saved),
                    "format": "copy",
                    "size": backup.get_dir_size(str(saved)),
                }],
            }

            def copy_missing_files(command, **_kwargs):
                self.assertIn("/XC", command)
                self.assertIn("/XN", command)
                self.assertIn("/XO", command)
                source_root, destination_root = Path(command[1]), Path(command[2])
                for source_file in source_root.rglob("*"):
                    if source_file.is_file():
                        target = destination_root / source_file.relative_to(source_root)
                        if not target.exists():
                            target.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(source_file, target)
                return subprocess.CompletedProcess(command, 1)

            with mock.patch.object(backup, "get_backup", return_value=manifest), \
                 mock.patch.object(backup, "_find_backup_dir", return_value=str(backup_root)), \
                 mock.patch.object(backup.subprocess, "run", side_effect=copy_missing_files):
                self.assertFalse(backup.restore_backup(manifest["id"]))
            self.assertEqual((destination / "changed.bin").read_bytes(), b"newer user data")
            self.assertEqual((destination / "removed.bin").read_bytes(), b"restore me")

    @unittest.skipUnless(os.name == "nt", "Robocopy and Windows file attributes are required")
    def test_windows_directory_backup_restore_preserves_hidden_and_system_files(self):
        import ctypes

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            source.mkdir()
            backup_root = root / "backups"
            backup_root.mkdir()
            hidden_file = source / "hidden.dat"
            system_file = source / "system.dat"
            hidden_file.write_bytes(b"hidden fixture")
            system_file.write_bytes(b"system fixture")

            set_attributes = ctypes.windll.kernel32.SetFileAttributesW
            set_attributes.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
            set_attributes.restype = ctypes.c_int
            get_attributes = ctypes.windll.kernel32.GetFileAttributesW
            get_attributes.argtypes = [ctypes.c_wchar_p]
            get_attributes.restype = ctypes.c_uint32
            hidden_flag = 0x2
            system_flag = 0x4
            normal_flag = 0x80
            self.assertTrue(set_attributes(str(hidden_file), hidden_flag))
            self.assertTrue(set_attributes(str(system_file), system_flag))

            with (
                mock.patch.object(backup, "get_backup_root", return_value=str(backup_root)),
                mock.patch.object(backup, "_get_drive_free_space", return_value=10**10),
                redirect_stdout(io.StringIO()),
            ):
                manifest = backup.create_backup([str(source)])
            self.assertEqual(manifest["status"], "completed")
            self.assertEqual(manifest["items"][0]["format"], "copy")

            for fixture_file in (hidden_file, system_file):
                self.assertTrue(set_attributes(str(fixture_file), normal_flag))
                fixture_file.unlink()

            with (
                mock.patch.object(backup, "_existing_backup_roots", return_value=[str(backup_root)]),
                mock.patch.object(backup, "_get_drive_free_space", return_value=10**10),
                redirect_stdout(io.StringIO()),
            ):
                self.assertTrue(backup.restore_backup(manifest["id"]))

            self.assertEqual(hidden_file.read_bytes(), b"hidden fixture")
            self.assertEqual(system_file.read_bytes(), b"system fixture")
            self.assertNotEqual(get_attributes(str(hidden_file)) & hidden_flag, 0)
            self.assertNotEqual(get_attributes(str(system_file)) & system_flag, 0)

    def test_directory_restore_rechecks_destination_before_robocopy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            backup_root = root / "backup"
            saved = backup_root / "saved-directory"
            saved.mkdir(parents=True)
            (saved / "payload.bin").write_bytes(b"saved data")
            destination = root / "restored-directory"
            destination.mkdir()
            protected = destination / "keep.bin"
            protected.write_bytes(b"existing user data")
            manifest = {
                "id": "backup_20260927_123456_123456",
                "status": "completed",
                "timestamp": "2026-09-27T12:34:56",
                "items": [{
                    "original_path": str(destination),
                    "backup_path": str(saved),
                    "format": "copy",
                    "size": backup.get_dir_size(str(saved)),
                }],
            }
            destination_key = os.path.normcase(os.path.abspath(destination))
            destination_checks = 0

            def destination_becomes_linked(path):
                nonlocal destination_checks
                if os.path.normcase(os.path.abspath(path)) == destination_key:
                    destination_checks += 1
                    return destination_checks >= 3
                return False

            output = io.StringIO()
            with (
                mock.patch.object(backup, "get_backup", return_value=manifest),
                mock.patch.object(backup, "_find_backup_dir", return_value=str(backup_root)),
                mock.patch.object(backup, "_path_has_reparse_component", side_effect=destination_becomes_linked),
                mock.patch.object(backup.subprocess, "run") as robocopy,
                redirect_stdout(output),
            ):
                self.assertFalse(backup.restore_backup(manifest["id"]))

            robocopy.assert_not_called()
            self.assertEqual(protected.read_bytes(), b"existing user data")
            self.assertIn("Restore source or destination changed to a reparse point", output.getvalue())

    def test_restore_rejects_same_size_corrupted_file_backup_before_writing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cache-file.bin"
            source.write_bytes(b"original payload")
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10):
                manifest = backup.create_backup([str(source)])
            item = manifest["items"][0]
            Path(item["backup_path"]).write_bytes(b"X" * len(b"original payload"))
            source.write_bytes(b"keep this destination")
            with mock.patch.object(backup, "_existing_backup_roots", return_value=[temp_dir]):
                self.assertFalse(backup.restore_backup(manifest["id"]))
            self.assertEqual(source.read_bytes(), b"keep this destination")

    def test_restore_rejects_corrupted_directory_backup_before_writing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "cache-directory"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"original payload")

            def mock_robocopy(command, **_kwargs):
                copy_source = Path(command[1])
                destination = Path(command[2])
                shutil.copytree(copy_source, destination)
                return 1

            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10), \
                 mock.patch.object(backup, "_run_robocopy_with_progress", side_effect=mock_robocopy):
                manifest = backup.create_backup([str(source)])
            item = manifest["items"][0]
            (Path(item["backup_path"]) / "payload.bin").write_bytes(b"X" * len(b"original payload"))
            (source / "payload.bin").write_bytes(b"keep this destination")
            with mock.patch.object(backup, "_existing_backup_roots", return_value=[temp_dir]):
                self.assertFalse(backup.restore_backup(manifest["id"]))
            self.assertEqual((source / "payload.bin").read_bytes(), b"keep this destination")

    def test_incomplete_backup_cannot_be_restored(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10**10):
                manifest = backup.create_backup([str(Path(temp_dir) / "missing")])
            with mock.patch.object(backup, "_existing_backup_roots", return_value=[temp_dir]):
                self.assertFalse(backup.restore_backup(manifest["id"]))

    def test_zip_backup_includes_hidden_files_and_restores_them(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source"
            (source / ".hidden-folder").mkdir(parents=True)
            hidden_dir = source / ".hidden-folder"
            hidden_file = hidden_dir / "secret-cache.bin"
            hidden_file.write_bytes(b"hidden payload")
            (source / "normal.bin").write_bytes(b"visible payload")
            if os.name == "nt":
                import ctypes
                self.assertTrue(ctypes.windll.kernel32.SetFileAttributesW(str(hidden_dir), 0x12))
                self.assertTrue(ctypes.windll.kernel32.SetFileAttributesW(str(hidden_file), 0x2))
            archive_path = Path(temp_dir) / "backup.zip"
            destination = Path(temp_dir) / "restored"
            archived_fingerprint = backup._create_zip_backup(str(source), str(archive_path))
            self.assertEqual(archived_fingerprint, backup._directory_fingerprint(str(source)))
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(archive.testzip(), None)
                self.assertIn(".hidden-folder/secret-cache.bin", archive.namelist())
                file_info = archive.getinfo("normal.bin")
                with archive_path.open("rb") as archive_file:
                    archive_file.seek(file_info.header_offset)
                    local_header = archive_file.read(30)
                self.assertEqual(struct.unpack_from("<H", local_header, 4)[0], 20)
                self.assertNotEqual(struct.unpack_from("<II", local_header, 18), (0xFFFFFFFF, 0xFFFFFFFF))
                self.assertEqual(archive.read("normal.bin"), b"visible payload")
                if os.name == "nt":
                    attrs = {entry.filename: entry.external_attr & 0xFF for entry in archive.infolist()}
                    self.assertTrue(attrs[".hidden-folder/"] & 0x2)
                    self.assertTrue(attrs[".hidden-folder/secret-cache.bin"] & 0x2)
            backup._extract_zip_backup(str(archive_path), str(destination))
            self.assertEqual((destination / ".hidden-folder" / "secret-cache.bin").read_bytes(), b"hidden payload")
            self.assertEqual((destination / "normal.bin").read_bytes(), b"visible payload")
            if os.name == "nt":
                self.assertTrue(ctypes.windll.kernel32.GetFileAttributesW(str(destination / ".hidden-folder")) & 0x2)
                self.assertTrue(ctypes.windll.kernel32.GetFileAttributesW(str(destination / ".hidden-folder" / "secret-cache.bin")) & 0x2)

    def test_zip_backup_and_restore_use_zip64_for_large_members(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source"
            source.mkdir()
            payload = bytes(range(64))
            (source / "large.bin").write_bytes(payload)
            archive_path = Path(temp_dir) / "backup.zip"
            # Lower the threshold only in this test so a real, valid archive
            # crosses it without creating a multi-gigabyte fixture.
            with mock.patch.object(zipfile, "ZIP64_LIMIT", 16):
                backup._create_zip_backup(str(source), str(archive_path))

            with zipfile.ZipFile(archive_path) as archive:
                info = archive.getinfo("large.bin")
                with archive_path.open("rb") as archive_file:
                    archive_file.seek(info.header_offset)
                    local_header = archive_file.read(30)
                self.assertEqual(struct.unpack_from("<H", local_header, 4)[0], 45)
                self.assertGreaterEqual(info.extract_version, 45)
                self.assertEqual(archive.read("large.bin"), payload)

            destination = Path(temp_dir) / "restored"
            backup._extract_zip_backup(str(archive_path), str(destination))
            self.assertEqual((destination / "large.bin").read_bytes(), payload)

    def test_zip_restore_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "unsafe.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../outside.txt", "must not extract")
            with self.assertRaises(RuntimeError):
                backup._extract_zip_backup(str(archive_path), str(Path(temp_dir) / "restore"))

    def test_zip_restore_preflights_reparse_paths_before_writing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            destination = root / "restore"
            linked_dir = destination / "linked"
            linked_dir.mkdir(parents=True)
            archive_path = root / "link-redirect.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("first.txt", "must not be partially restored")
                archive.writestr("linked/escape.txt", "must not follow a link")
            linked_key = os.path.normcase(os.path.abspath(linked_dir))
            is_link = lambda path: os.path.normcase(os.path.abspath(path)) == linked_key
            with mock.patch.object(backup, "_is_reparse_point", side_effect=is_link):
                with self.assertRaisesRegex(RuntimeError, "reparse point"):
                    backup._extract_zip_backup(str(archive_path), str(destination))
            self.assertFalse((destination / "first.txt").exists())
            self.assertFalse((linked_dir / "escape.txt").exists())

    def test_zip_restore_preserves_existing_files_unless_overwrite_is_explicit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "saved.zip"
            destination = root / "restore"
            destination.mkdir()
            (destination / "existing.txt").write_text("newer user data", encoding="utf-8")
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("existing.txt", "saved data")
                archive.writestr("missing.txt", "also restore")

            conflicts = backup._extract_zip_backup(str(archive_path), str(destination))
            self.assertEqual(conflicts, [str(destination / "existing.txt")])
            self.assertEqual((destination / "existing.txt").read_text(encoding="utf-8"), "newer user data")
            self.assertEqual((destination / "missing.txt").read_text(encoding="utf-8"), "also restore")

            self.assertEqual(backup._extract_zip_backup(str(archive_path), str(destination), overwrite=True), [])
            self.assertEqual((destination / "existing.txt").read_text(encoding="utf-8"), "saved data")

    def test_zip_restore_write_failure_preserves_overwrite_destination(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "saved.zip"
            destination = root / "restore"
            destination.mkdir()
            target = destination / "existing.txt"
            target.write_bytes(b"keep current data")
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("existing.txt", "restored data")

            def partial_write_then_fail(_source, output, length):
                output.write(b"partial")
                raise OSError("simulated write failure")

            with mock.patch.object(backup.shutil, "copyfileobj", side_effect=partial_write_then_fail):
                with self.assertRaisesRegex(OSError, "simulated write failure"):
                    backup._extract_zip_backup(str(archive_path), str(destination), overwrite=True)

            self.assertEqual(target.read_bytes(), b"keep current data")
            self.assertEqual([], list(destination.glob(".drive-cleanr-restore-*.tmp")))

    def test_zip_restore_write_failure_does_not_leave_partial_new_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "saved.zip"
            destination = root / "restore"
            destination.mkdir()
            target = destination / "missing.txt"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("missing.txt", "restored data")

            def partial_write_then_fail(_source, output, length):
                output.write(b"partial")
                raise OSError("simulated write failure")

            with mock.patch.object(backup.shutil, "copyfileobj", side_effect=partial_write_then_fail):
                with self.assertRaisesRegex(OSError, "simulated write failure"):
                    backup._extract_zip_backup(str(archive_path), str(destination))

            self.assertFalse(target.exists())
            self.assertEqual([], list(destination.glob(".drive-cleanr-restore-*.tmp")))

    def test_zip_restore_preflights_non_directory_parent_conflicts_before_writing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            destination = root / "restore"
            destination.mkdir()
            (destination / "blocker").write_text("preserve me", encoding="utf-8")
            archive_path = root / "nested-without-directory-entry.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("first.txt", "must not be partially restored")
                archive.writestr("blocker/nested.txt", "cannot restore here")

            with self.assertRaisesRegex(RuntimeError, "non-directory path component"):
                backup._extract_zip_backup(str(archive_path), str(destination))
            self.assertFalse((destination / "first.txt").exists())
            self.assertEqual((destination / "blocker").read_text(encoding="utf-8"), "preserve me")

    def test_zip_restore_rejects_case_colliding_paths_before_writing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "case-collision.zip"
            destination = root / "restore"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("cache.bin", "first copy")
                archive.writestr("CACHE.BIN", "second copy")

            with self.assertRaisesRegex(RuntimeError, "duplicate or case-colliding"):
                backup._extract_zip_backup(str(archive_path), str(destination))
            self.assertFalse(destination.exists())

    def test_zip_restore_rejects_file_directory_path_conflicts_before_writing(self):
        conflicting_orders = (
            ("blocked", "blocked/child.txt"),
            ("blocked/child.txt", "blocked"),
        )
        for names in conflicting_orders:
            with self.subTest(names=names), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                archive_path = root / "path-conflict.zip"
                destination = root / "restore"
                with zipfile.ZipFile(archive_path, "w") as archive:
                    for name in names:
                        archive.writestr(name, "payload")

                with self.assertRaisesRegex(RuntimeError, "file/directory path conflict"):
                    backup._extract_zip_backup(str(archive_path), str(destination))
                self.assertFalse(destination.exists())

    @unittest.skipUnless(os.name == "nt", "backup restore targets Windows paths")
    def test_restore_rejects_corrupt_later_zip_member_before_writing_any_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            backup_dir = root / "backup_20260927_123456_123456"
            backup_dir.mkdir()
            archive_path = backup_dir / "payload.zip"
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("first.txt", b"restored data")
                archive.writestr("later.txt", b"damaged data")

            with zipfile.ZipFile(archive_path) as archive:
                info = archive.getinfo("later.txt")
                data_offset = info.header_offset + 30 + len(info.filename.encode("utf-8")) + len(info.extra)
            with archive_path.open("r+b") as archive_file:
                archive_file.seek(data_offset)
                original_byte = archive_file.read(1)
                archive_file.seek(data_offset)
                archive_file.write(bytes([original_byte[0] ^ 0x01]))

            destination = root / "restore-target"
            manifest = {
                "status": "completed",
                "timestamp": "2026-09-27T12:34:56",
                "items": [{
                    "original_path": str(destination),
                    "backup_path": str(archive_path),
                    "format": "zip",
                    "integrity_sha256": backup._sha256_file(str(archive_path)),
                    "size": len(b"restored data") + len(b"damaged data"),
                }],
            }
            with mock.patch.object(backup, "get_backup", return_value=manifest), \
                 mock.patch.object(backup, "_find_backup_dir", return_value=str(backup_dir)):
                with mock.patch("builtins.print") as output:
                    self.assertFalse(backup.restore_backup("backup_20260927_123456_123456"))
            self.assertFalse(destination.exists())
            restore_summary = " ".join(str(call.args[0]) for call in output.call_args_list if call.args)
            self.assertIn("Restore incomplete: 0/1 items; 1 failed", restore_summary)
            self.assertNotIn("Restore complete", restore_summary)

    def test_zip_restore_preflights_timestamps_before_writing_any_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = root / "invalid-timestamp.zip"
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("first.txt", b"must not be partially restored")
                archive.writestr("later.txt", b"invalid timestamp")

            archive_bytes = bytearray(archive_path.read_bytes())
            offset = archive_bytes.find(b"PK\x01\x02")
            while offset >= 0:
                name_length = struct.unpack_from("<H", archive_bytes, offset + 28)[0]
                extra_length = struct.unpack_from("<H", archive_bytes, offset + 30)[0]
                comment_length = struct.unpack_from("<H", archive_bytes, offset + 32)[0]
                name_start = offset + 46
                name = bytes(archive_bytes[name_start:name_start + name_length]).decode("utf-8")
                if name == "later.txt":
                    # DOS date month 15 is structurally readable by zipfile,
                    # but datetime.timestamp() rejects it during extraction.
                    invalid_dos_date = (15 << 5) | 1
                    struct.pack_into("<H", archive_bytes, offset + 14, invalid_dos_date)
                    break
                offset = archive_bytes.find(
                    b"PK\x01\x02", name_start + name_length + extra_length + comment_length
                )
            else:
                self.fail("Could not find the later ZIP central directory entry")
            archive_path.write_bytes(archive_bytes)

            destination = root / "restore"
            with self.assertRaises((RuntimeError, ValueError, OSError)):
                backup._extract_zip_backup(str(archive_path), str(destination))
            self.assertFalse((destination / "first.txt").exists())
            self.assertFalse((destination / "later.txt").exists())

    def test_zip_restore_rejects_windows_alternate_stream_names(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "ads.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("ordinary.txt:alternate", "unsafe stream")
            with self.assertRaisesRegex(RuntimeError, "Unsafe path"):
                backup._extract_zip_backup(str(archive_path), str(Path(temp_dir) / "restore"))

    def test_zip_restore_rejects_windows_reserved_device_names(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            for index, name in enumerate(("CON.txt", "COM¹.txt", "LPT³.log")):
                with self.subTest(name=name):
                    archive_path = Path(temp_dir) / f"device-name-{index}.zip"
                    with zipfile.ZipFile(archive_path, "w") as archive:
                        archive.writestr(f"nested/{name}", "must not target a device")
                    destination = Path(temp_dir) / f"restore-{index}"
                    with self.assertRaisesRegex(RuntimeError, "Unsafe path"):
                        backup._extract_zip_backup(str(archive_path), str(destination))
                    self.assertFalse(destination.exists())

    def test_restore_manifest_rejects_traversal_before_restoring_anything(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            backup_dir = root / "backup_20260927_123456_123456"
            backup_dir.mkdir()
            payload = backup_dir / "payload"
            payload.write_bytes(b"safe backup payload")
            manifest = {
                "status": "completed",
                "timestamp": "2026-09-27T12:34:56",
                "items": [
                    {
                        "original_path": str(root / "first-target.bin"),
                        "backup_path": str(payload),
                        "format": "file",
                    },
                    {
                        "original_path": r"C:\Users\..\Windows\system32\target.bin",
                        "backup_path": str(payload),
                        "format": "file",
                    },
                ],
            }
            with mock.patch.object(backup, "get_backup", return_value=manifest), \
                 mock.patch.object(backup, "_find_backup_dir", return_value=str(backup_dir)):
                self.assertFalse(backup.restore_backup("backup_20260927_123456_123456"))
            self.assertEqual(payload.read_bytes(), b"safe backup payload")
            self.assertFalse((root / "first-target.bin").exists())

    def test_restore_manifest_rejects_duplicate_and_nested_destinations_before_writing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            backup_dir = root / "backup_20260927_123456_123456"
            backup_dir.mkdir()
            payloads = [backup_dir / "payload-1", backup_dir / "payload-2"]
            payloads[0].write_bytes(b"first payload")
            payloads[1].write_bytes(b"second payload")

            for index in range(2):
                with self.subTest(overlap=index):
                    destination = root / f"restore-target-{index}.bin"
                    destinations = (
                        [str(destination), str(destination)] if index == 0 else
                        [str(destination), str(destination) + r"\nested.bin"]
                    )
                    manifest = {
                        "status": "completed",
                        "timestamp": "2026-09-27T12:34:56",
                        "items": [{
                            "original_path": target,
                            "backup_path": str(payload),
                            "format": "file",
                            "size": payload.stat().st_size,
                        } for target, payload in zip(destinations, payloads)],
                    }
                    with mock.patch.object(backup, "get_backup", return_value=manifest), \
                         mock.patch.object(backup, "_find_backup_dir", return_value=str(backup_dir)), \
                         mock.patch("builtins.print") as output:
                        self.assertFalse(backup.restore_backup(
                            "backup_20260927_123456_123456", overwrite=True
                        ))
                    self.assertFalse(destination.exists())
                    message = " ".join(str(call.args[0]) for call in output.call_args_list if call.args)
                    self.assertIn("duplicate or overlapping restore destinations", message)

    def test_restore_manifest_refuses_directory_destinations_with_links(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            backup_dir = root / "backup_20260927_123456_123456"
            backup_copy = backup_dir / "saved-directory"
            backup_copy.mkdir(parents=True)
            destination = root / "restore-target"
            linked_child = destination / "linked-child"
            linked_child.mkdir(parents=True)
            manifest = {
                "status": "completed",
                "timestamp": "2026-09-27T12:34:56",
                "items": [{
                    "original_path": str(destination),
                    "backup_path": str(backup_copy),
                    "format": "copy",
                }],
            }
            linked_key = os.path.normcase(os.path.abspath(linked_child))
            is_link = lambda path: os.path.normcase(os.path.abspath(path)) == linked_key
            with mock.patch.object(backup, "get_backup", return_value=manifest), \
                 mock.patch.object(backup, "_find_backup_dir", return_value=str(backup_dir)), \
                 mock.patch.object(backup, "_is_reparse_point", side_effect=is_link), \
                 mock.patch.object(backup.subprocess, "run") as run_process:
                self.assertFalse(backup.restore_backup("backup_20260927_123456_123456"))
            run_process.assert_not_called()

    def test_restore_target_accepts_local_paths_and_rejects_unsafe_forms(self):
        self.assertTrue(backup._valid_restore_target(r"C:\Users\ExampleUser\file.bin"))
        for path in (
            "C:\\", r"\\server\share\file.bin", r"\??\C:\file.bin",
            r"C:\Users\..\Windows\file.bin", r"C:\Users\file.bin:stream",
            r"C:\Users\*.bin", r"C:\Users\CON.txt", "C:\\Users\\COM¹.txt",
            "C:\\Users\\LPT³.log", "C:\\Users\\trailing. ",
        ):
            with self.subTest(path=path):
                self.assertFalse(backup._valid_restore_target(path))

    def test_backup_id_validation_blocks_path_traversal(self):
        self.assertFalse(backup._valid_backup_id(".."))
        self.assertFalse(backup._valid_backup_id("backup_../victim"))
        self.assertTrue(backup._valid_backup_id("backup_20260927_123456_123456"))
        self.assertTrue(backup._valid_backup_id("backup_20260717_123456"))


if __name__ == "__main__":
    unittest.main()
