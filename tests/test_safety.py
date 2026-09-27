import csv
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import analyze
import backup
import scan
import drive_cleaner


class AnalyzeSafetyTests(unittest.TestCase):
    def analyze_rows(self, rows):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "scan.csv"
            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["File Name", "Size", "Allocated", "DRIVECAPACITY", "FREESPACE", "USEDSPACE"])
                writer.writeheader()
                writer.writerows(rows)
            return analyze.analyze_csv(str(csv_path), min_size_mb=0)

    def test_only_absolute_local_non_root_paths_become_candidates(self):
        results = self.analyze_rows([
            {"File Name": "C:\\", "Size": "1000", "DRIVECAPACITY": "1000", "FREESPACE": "200", "USEDSPACE": "800"},
            {"File Name": "C:\\Users\\A\\AppData\\Local\\Temp\\", "Size": "90"},
            {"File Name": "C:\\Windows\\SoftwareDistribution\\", "Size": "100"},
            {"File Name": "C:\\Windows\\SoftwareDistribution\\Download\\", "Size": "80"},
            {"File Name": "\\\\server\\share\\Temp\\", "Size": "90"},
            {"File Name": "C:\\Users\\A\\Temp\\..\\Documents\\", "Size": "90"},
            {"File Name": "C:\\Temp\\..\\", "Size": "90"},
        ])
        candidates = results["categories"]["high"]["items"]
        self.assertEqual({item["path"] for item in candidates}, {
            "C:\\Users\\A\\AppData\\Local\\Temp\\",
            "C:\\Windows\\SoftwareDistribution\\Download\\",
        })
        self.assertEqual(results["total_size"], 1000)

    def test_windows_case_and_separator_aware_parent_deduplication(self):
        self.assertTrue(analyze._is_under(r"C:\Temp\nested", r"c:/temp/"))
        self.assertFalse(analyze._is_under(r"C:\Temp-old\item", r"C:\Temp"))

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
                ])
                writer.writeheader()
                writer.writerow({
                    "Name": r"C:\Users\A\AppData\Local\Temp", "Files": "4", "Folders": "1",
                    "Logical Size": "125000000", "Physical Size": "120000000", "Attributes": "Directory",
                })
                writer.writerow({
                    "Name": r"C:\Users\A\AppData\Local\Temp\large.bin", "Files": "0", "Folders": "0",
                    "Logical Size": "125000000", "Physical Size": "120000000", "Attributes": "Archive",
                })
            results = analyze.analyze_csv(str(csv_path), min_size_mb=0)
        items = results["categories"]["high"]["items"]
        self.assertEqual(len(items), 1)  # parent folder prevents double-counting its file
        self.assertEqual(items[0]["path"], "C:\\Users\\A\\AppData\\Local\\Temp\\")
        self.assertEqual(items[0]["size"], 120_000_000)
        self.assertEqual(items[0]["kind"], "Directory")

    def test_generated_script_quotes_untrusted_path_and_backs_up_first(self):
        path = "C:\\Users\\O'Brien\\$(not-a-command)\\AppData\\Local\\Temp\\"
        results = {"categories": {"high": {"name": "High", "items": [{
            "path": path, "name": "Temporary files", "size": 100,
            "size_formatted": "100 B", "kind": "目录",
        }]}}}
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "clean.ps1"
            analyze.generate_clean_script(results, str(output))
            script = output.read_text(encoding="utf-8-sig")
        self.assertIn("'C:\\Users\\O''Brien\\$(not-a-command)\\AppData\\Local\\Temp\\'", script)
        self.assertIn("--json", script)
        self.assertLess(script.index("Creating backup before cleanup"), script.index("Remove-Item -LiteralPath"))
        self.assertIn("$target.IsDirectory", script)
        self.assertIn("Preserve every claude* item and its subtree at any depth", script)

    def test_generated_script_parses_in_powershell_when_available(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        results = {"categories": {"high": {"name": "High", "items": [{
            "path": "C:\\Users\\名\\AppData\\Local\\Temp\\", "name": "Temporary files",
            "size": 100, "size_formatted": "100 B", "kind": "目录",
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
    def test_generated_script_cleans_only_the_selected_item_and_keeps_claude_data(self):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if not powershell:
            self.skipTest("PowerShell is not installed")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            selected = root / "selected"
            unselected = root / "unselected"
            (selected / "nested" / "claude-session").mkdir(parents=True)
            unselected.mkdir()
            (selected / "remove-me.bin").write_bytes(b"remove")
            (selected / "nested" / "claude-session" / "keep.bin").write_bytes(b"keep")
            (unselected / "keep.bin").write_bytes(b"untouched")
            results = {"categories": {"high": {"name": "High", "items": [
                {"path": str(selected) + "\\", "name": "Temporary files", "size": 6, "size_formatted": "6 B", "kind": "Directory"},
                {"path": str(unselected) + "\\", "name": "Temporary files", "size": 9, "size_formatted": "9 B", "kind": "Directory"},
            ]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            backup_log = root / "backup-targets.txt"
            fake_backup = root / "backup.py"
            fake_backup.write_text(
                "import json, os, sys\n"
                "start=sys.argv.index('--paths')+1\n"
                "end=sys.argv.index('--json')\n"
                "paths=sys.argv[start:end]\n"
                "open(os.environ['CLEANR_TEST_BACKUP_LOG'],'w',encoding='utf-8').write('\\n'.join(paths))\n"
                "print(json.dumps({'status':'completed','items':[{} for _ in paths],'id':'mock-backup'}))\n",
                encoding="utf-8",
            )
            env = dict(os.environ, CLEANR_TEST_BACKUP_LOG=str(backup_log))
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "2", "-Force"],
                capture_output=True, text=True, timeout=45, env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertFalse((selected / "remove-me.bin").exists())
            self.assertEqual((selected / "nested" / "claude-session" / "keep.bin").read_bytes(), b"keep")
            self.assertEqual((unselected / "keep.bin").read_bytes(), b"untouched")
            self.assertEqual(backup_log.read_text(encoding="utf-8"), str(selected) + "\\")

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
            results = {"categories": {"high": {"name": "High", "items": [{
                "path": str(target) + "\\", "name": "Temporary files", "size": 4,
                "size_formatted": "4 B", "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            backup_log = root / "backup-targets.txt"
            (root / "backup.py").write_text("raise SystemExit('backup must not run after cancel')\n", encoding="utf-8")
            env = dict(os.environ, CLEANR_TEST_BACKUP_LOG=str(backup_log))
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
                input="Q\n", capture_output=True, text=True, timeout=45, env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertTrue(marker.exists())
            self.assertFalse(backup_log.exists())

    @unittest.skipUnless(os.name == "nt", "generated cleanup scripts target Windows")
    def test_partial_backup_aborts_generated_cleanup(self):
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
                "path": str(target) + "\\", "name": "Temporary files", "size": 11,
                "size_formatted": "11 B", "kind": "Directory",
            }]}}}
            script_path = root / "clean.ps1"
            analyze.generate_clean_script(results, str(script_path))
            (root / "backup.py").write_text(
                "import json, sys\n"
                "print(json.dumps({'status':'partial','items':[],'id':'mock-backup'}))\n"
                "sys.exit(1)\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path), "-Select", "1", "-Force"],
                capture_output=True, text=True, timeout=45,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(marker.exists())

    def test_generating_empty_plan_is_an_error(self):
        results = {"categories": {"high": {"name": "High", "items": []}}}
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ValueError):
                analyze.generate_clean_script(results, str(Path(temp_dir) / "empty.ps1"))

    def test_negative_minimum_size_is_rejected(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as handle:
            handle.write("File Name,Size\n")
            csv_path = handle.name
        try:
            with self.assertRaises(ValueError):
                analyze.analyze_csv(csv_path, min_size_mb=-1)
        finally:
            os.unlink(csv_path)


class ScanSafetyTests(unittest.TestCase):
    def test_scanner_choice_accepts_windirstat_alias(self):
        with mock.patch("builtins.input", side_effect=["x", "2"]):
            self.assertEqual(scan.choose_scanner(), "windirstat")

    def test_windirstat_launches_documented_save_to_csv_command(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_data_dir = scan.DATA_DIR
            scan.DATA_DIR = str(Path(temp_dir) / "data")
            captured = {}

            def fake_popen(command, **kwargs):
                captured["command"] = command
                return object()

            try:
                with mock.patch.object(scan, "find_windirstat", return_value="/mock/WinDirStat.exe"), \
                     mock.patch.object(scan.subprocess, "Popen", side_effect=fake_popen), \
                     mock.patch.object(scan, "wait_for_scan_process", return_value=True):
                    result = scan.scan("D:", app="windirstat")
            finally:
                scan.DATA_DIR = old_data_dir
        self.assertTrue(result.endswith(".csv"))
        self.assertEqual(captured["command"][:2], ["/mock/WinDirStat.exe", "/SaveTo"])
        self.assertEqual(captured["command"][-1], "D:")
        self.assertEqual(captured["command"][2], result)

    def test_guided_scan_runs_chosen_scanner_then_opens_review(self):
        with mock.patch.object(scan, "choose_scanner", return_value="windirstat"), \
             mock.patch.object(scan, "scan", return_value="data/scan_test.csv") as run_scan, \
             mock.patch.object(analyze, "run_tui") as run_review, \
             mock.patch("builtins.input", side_effect=["D:", "", "", ""]):
            drive_cleaner._scan_flow()
        run_scan.assert_called_once_with(drive="D:", include_files=True, timeout=1800, app="windirstat")
        run_review.assert_called_once_with(initial_csv="data/scan_test.csv")

    def test_guided_entry_point_has_simple_exit(self):
        with mock.patch("builtins.input", return_value="0"):
            drive_cleaner.main_menu()

    def test_scan_does_not_delete_reviewed_scripts_as_a_side_effect(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_data_dir = scan.DATA_DIR
            scan.DATA_DIR = str(Path(temp_dir) / "data")
            data = Path(scan.DATA_DIR)
            data.mkdir()
            (data / "old.csv").write_text("x")
            (data / "new.csv").write_text("x")
            script = Path(temp_dir) / "clean_reviewed.ps1"
            script.write_text("reviewed")
            try:
                scan.cleanup_old_scans(keep_latest=1)
                self.assertTrue(script.exists())
                scan.cleanup_old_scans(keep_latest=1, include_scripts=True)
                self.assertFalse(script.exists())
            finally:
                scan.DATA_DIR = old_data_dir

    def test_wait_uses_process_exit_after_a_quiet_export(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            export_path = Path(temp_dir) / "scan.csv"
            export_path.write_text("header")

            class QuietProcess:
                calls = 0
                returncode = 0

                def poll(self):
                    self.calls += 1
                    return None if self.calls < 4 else 0

                def wait(self, timeout=None):
                    return 0

            self.assertTrue(scan.wait_for_scan_process(QuietProcess(), str(export_path), timeout=10))

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


class BackupSafetyTests(unittest.TestCase):
    def test_missing_path_makes_backup_partial_not_successful(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch.object(backup, "get_backup_root", return_value=temp_dir), \
                 mock.patch.object(backup, "_get_drive_free_space", return_value=10_000_000):
                result = backup.create_backup([str(Path(temp_dir) / "missing")])
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["items"], [])
            self.assertTrue(result["errors"])

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
            backup._create_zip_backup(str(source), str(archive_path))
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(archive.testzip(), None)
                self.assertIn(".hidden-folder/secret-cache.bin", archive.namelist())
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

    def test_zip_restore_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "unsafe.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../outside.txt", "must not extract")
            with self.assertRaises(RuntimeError):
                backup._extract_zip_backup(str(archive_path), str(Path(temp_dir) / "restore"))

    def test_backup_id_validation_blocks_path_traversal(self):
        self.assertFalse(backup._valid_backup_id(".."))
        self.assertFalse(backup._valid_backup_id("backup_../victim"))
        self.assertTrue(backup._valid_backup_id("backup_20260927_123456_123456"))
        self.assertTrue(backup._valid_backup_id("backup_20260717_123456"))


if __name__ == "__main__":
    unittest.main()
