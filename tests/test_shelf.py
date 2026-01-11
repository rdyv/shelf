#!/usr/bin/env python3
"""Unit tests for shelf backup tool."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import shelf


class TestFileManagerShouldExclude(unittest.TestCase):
    """Tests for FileManager.should_exclude() pattern matching."""

    def setUp(self):
        self.logger = MagicMock()
        self.fm = shelf.FileManager(self.logger)

    def test_exact_match(self):
        patterns = ["*.log", "node_modules/"]
        self.assertTrue(self.fm.should_exclude("test.log", patterns))
        self.assertTrue(self.fm.should_exclude("node_modules/", patterns))

    def test_wildcard_extension(self):
        patterns = ["*.pyc", "*.tmp"]
        self.assertTrue(self.fm.should_exclude("module.pyc", patterns))
        self.assertTrue(self.fm.should_exclude("cache.tmp", patterns))
        self.assertFalse(self.fm.should_exclude("module.py", patterns))

    def test_directory_pattern(self):
        patterns = ["__pycache__", ".git"]
        self.assertTrue(self.fm.should_exclude("__pycache__", patterns))
        self.assertTrue(self.fm.should_exclude(".git", patterns))
        self.assertFalse(self.fm.should_exclude(".gitignore", patterns))

    def test_nested_path_matches_basename(self):
        patterns = ["*.log"]
        self.assertTrue(self.fm.should_exclude("logs/app.log", patterns))
        self.assertTrue(self.fm.should_exclude("/var/log/test.log", patterns))

    def test_empty_patterns(self):
        self.assertFalse(self.fm.should_exclude("anything.txt", []))

    def test_double_wildcard(self):
        # fnmatch doesn't support ** like glob, but *.bak works
        patterns = ["*.bak"]
        self.assertTrue(self.fm.should_exclude("test.bak", patterns))
        self.assertTrue(self.fm.should_exclude("dir/test.bak", patterns))


class TestFileManagerFormatSize(unittest.TestCase):
    """Tests for FileManager.format_size() size formatting."""

    def setUp(self):
        self.logger = MagicMock()
        self.fm = shelf.FileManager(self.logger)

    def test_zero_bytes(self):
        self.assertEqual(self.fm.format_size(0), "0 B")

    def test_bytes(self):
        self.assertEqual(self.fm.format_size(500), "500.0 B")

    def test_kilobytes(self):
        self.assertEqual(self.fm.format_size(1024), "1.0 KB")
        self.assertEqual(self.fm.format_size(1536), "1.5 KB")

    def test_megabytes(self):
        self.assertEqual(self.fm.format_size(1024 * 1024), "1.0 MB")
        self.assertEqual(self.fm.format_size(5 * 1024 * 1024), "5.0 MB")

    def test_gigabytes(self):
        self.assertEqual(self.fm.format_size(1024**3), "1.0 GB")

    def test_terabytes(self):
        self.assertEqual(self.fm.format_size(1024**4), "1.0 TB")


class TestShelfParseSize(unittest.TestCase):
    """Tests for Shelf.parse_size() size parsing."""

    def test_integer_input(self):
        self.assertEqual(shelf.Shelf.parse_size(1024), 1024)

    def test_bytes_string(self):
        self.assertEqual(shelf.Shelf.parse_size("100B"), 100)
        self.assertEqual(shelf.Shelf.parse_size("100 B"), 100)

    def test_kilobytes_string(self):
        self.assertEqual(shelf.Shelf.parse_size("1KB"), 1024)
        self.assertEqual(shelf.Shelf.parse_size("2KB"), 2048)

    def test_megabytes_string(self):
        self.assertEqual(shelf.Shelf.parse_size("1MB"), 1024**2)
        self.assertEqual(shelf.Shelf.parse_size("10MB"), 10 * 1024**2)

    def test_gigabytes_string(self):
        self.assertEqual(shelf.Shelf.parse_size("1GB"), 1024**3)

    def test_terabytes_string(self):
        self.assertEqual(shelf.Shelf.parse_size("1TB"), 1024**4)

    def test_case_insensitive(self):
        self.assertEqual(shelf.Shelf.parse_size("1kb"), 1024)
        self.assertEqual(shelf.Shelf.parse_size("1Kb"), 1024)
        self.assertEqual(shelf.Shelf.parse_size("1KB"), 1024)

    def test_float_values(self):
        self.assertEqual(shelf.Shelf.parse_size("1.5KB"), 1536)
        self.assertEqual(shelf.Shelf.parse_size("2.5MB"), int(2.5 * 1024**2))

    def test_invalid_returns_default(self):
        # Invalid strings return default of 10MB
        self.assertEqual(shelf.Shelf.parse_size("invalid"), 10 * 1024 * 1024)

    def test_plain_number_string(self):
        self.assertEqual(shelf.Shelf.parse_size("1024"), 1024)


class TestShelfMergeConfig(unittest.TestCase):
    """Tests for Shelf.merge_config() deep merge functionality."""

    def setUp(self):
        # Mock the Shelf init to avoid file system operations
        with patch.object(shelf.Shelf, "__init__", lambda x: None):
            self.shelf = shelf.Shelf()

    def test_simple_merge(self):
        loaded = {"key1": "value1"}
        defaults = {"key1": "default1", "key2": "default2"}
        result = self.shelf.merge_config(loaded, defaults)
        self.assertEqual(result["key1"], "value1")
        self.assertEqual(result["key2"], "default2")

    def test_nested_merge(self):
        loaded = {"section": {"nested_key": "loaded_value"}}
        defaults = {"section": {"nested_key": "default", "other_key": "other"}}
        result = self.shelf.merge_config(loaded, defaults)
        self.assertEqual(result["section"]["nested_key"], "loaded_value")
        self.assertEqual(result["section"]["other_key"], "other")

    def test_loaded_overrides_defaults(self):
        loaded = {"key": "loaded"}
        defaults = {"key": "default"}
        result = self.shelf.merge_config(loaded, defaults)
        self.assertEqual(result["key"], "loaded")

    def test_defaults_preserved_when_not_in_loaded(self):
        loaded = {}
        defaults = {"key": "default"}
        result = self.shelf.merge_config(loaded, defaults)
        self.assertEqual(result["key"], "default")

    def test_deeply_nested_merge(self):
        loaded = {"a": {"b": {"c": "loaded"}}}
        defaults = {"a": {"b": {"c": "default", "d": "preserved"}}}
        result = self.shelf.merge_config(loaded, defaults)
        self.assertEqual(result["a"]["b"]["c"], "loaded")
        self.assertEqual(result["a"]["b"]["d"], "preserved")


class TestShelfDictToToml(unittest.TestCase):
    """Tests for Shelf._dict_to_toml() TOML serialization."""

    def setUp(self):
        with patch.object(shelf.Shelf, "__init__", lambda x: None):
            self.shelf = shelf.Shelf()

    def test_simple_string(self):
        data = {"key": "value"}
        result = self.shelf._dict_to_toml(data)
        self.assertIn('key = "value"', result)

    def test_integer_value(self):
        data = {"count": 42}
        result = self.shelf._dict_to_toml(data)
        self.assertIn("count = 42", result)

    def test_boolean_values(self):
        data = {"enabled": True, "disabled": False}
        result = self.shelf._dict_to_toml(data)
        self.assertIn("enabled = true", result)
        self.assertIn("disabled = false", result)

    def test_list_value(self):
        data = {"items": ["a", "b", "c"]}
        result = self.shelf._dict_to_toml(data)
        self.assertIn('items = ["a", "b", "c"]', result)

    def test_nested_table(self):
        data = {"section": {"key": "value"}}
        result = self.shelf._dict_to_toml(data)
        self.assertIn("[section]", result)
        self.assertIn('key = "value"', result)

    def test_path_key_quoted(self):
        data = {"~/path/to/file": "value"}
        result = self.shelf._dict_to_toml(data)
        self.assertIn('"~/path/to/file"', result)


class TestSystemUtils(unittest.TestCase):
    """Tests for SystemUtils static methods."""

    def test_get_platform_darwin(self):
        with patch("platform.system", return_value="Darwin"):
            self.assertEqual(shelf.SystemUtils.get_platform(), "macos")

    def test_get_platform_linux(self):
        with patch("platform.system", return_value="Linux"):
            self.assertEqual(shelf.SystemUtils.get_platform(), "linux")

    def test_get_platform_windows(self):
        with patch("platform.system", return_value="Windows"):
            self.assertEqual(shelf.SystemUtils.get_platform(), "windows")

    def test_which_found(self):
        with patch("shutil.which", return_value="/usr/bin/git"):
            self.assertTrue(shelf.SystemUtils.which("git"))

    def test_which_not_found(self):
        with patch("shutil.which", return_value=None):
            self.assertFalse(shelf.SystemUtils.which("nonexistent"))

    def test_path_to_relative_unix(self):
        # Unix absolute path
        result = shelf.SystemUtils.path_to_relative(Path("/etc/hosts"))
        self.assertEqual(str(result), "etc/hosts")

    def test_path_to_relative_windows(self):
        # Windows absolute path
        result = shelf.SystemUtils.path_to_relative(Path("C:/Users/test"))
        self.assertEqual(str(result), "Users/test")

    def test_path_to_relative_already_relative(self):
        # Already relative path
        result = shelf.SystemUtils.path_to_relative(Path("some/path"))
        self.assertEqual(str(result), "some/path")


class TestShelfValidateBackupPath(unittest.TestCase):
    """Tests for Shelf._validate_backup_path() validation."""

    def setUp(self):
        with patch.object(shelf.Shelf, "__init__", lambda x: None):
            self.shelf = shelf.Shelf()

    def test_root_directory_rejected(self):
        error = self.shelf._validate_backup_path(Path("/"))
        self.assertIsNotNone(error)
        self.assertIn("root directory", error)

    def test_system_directories_rejected(self):
        system_paths = ["/System/Library", "/usr/local", "/bin", "/sbin", "/var/log", "/etc/hosts", "/lib", "/opt"]
        for path_str in system_paths:
            error = self.shelf._validate_backup_path(Path(path_str))
            self.assertIsNotNone(error, f"Expected error for {path_str}")

    def test_home_directory_rejected(self):
        error = self.shelf._validate_backup_path(Path.home())
        self.assertIsNotNone(error)
        self.assertIn("home directory", error)

    def test_valid_paths_accepted(self):
        valid_paths = [
            Path.home() / "backups",
            Path.home() / ".backup",
            Path("/tmp/backup"),
        ]
        for path in valid_paths:
            error = self.shelf._validate_backup_path(path)
            self.assertIsNone(error, f"Unexpected error for {path}: {error}")


class TestGitManager(unittest.TestCase):
    """Tests for GitManager git operations."""

    def setUp(self):
        self.logger = MagicMock()
        self.config = {"branch": "main", "auto_commit": True}
        self.temp_dir = tempfile.mkdtemp()
        self.repo_path = Path(self.temp_dir)
        self.git_manager = shelf.GitManager(self.repo_path, self.logger, self.config)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("subprocess.run")
    def test_run_git_success(self, mock_run):
        mock_run.return_value = MagicMock(stdout="output", stderr="", returncode=0)
        result = self.git_manager.run_git(["status"])
        mock_run.assert_called_once()
        self.assertEqual(result.stdout, "output")

    @patch("subprocess.run")
    def test_run_git_failure_logs_error(self, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.CalledProcessError(1, "git", stderr="error msg")
        with self.assertRaises(subprocess.CalledProcessError):
            self.git_manager.run_git(["invalid"])
        self.logger.error.assert_called()

    @patch("subprocess.run")
    def test_has_changes_true(self, mock_run):
        mock_run.return_value = MagicMock(stdout="M file.txt\n", returncode=0)
        self.assertTrue(self.git_manager.has_changes())

    @patch("subprocess.run")
    def test_has_changes_false(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        self.assertFalse(self.git_manager.has_changes())

    @patch("subprocess.run")
    def test_has_remote_true(self, mock_run):
        mock_run.return_value = MagicMock(stdout="origin\thttps://...", returncode=0)
        self.assertTrue(self.git_manager.has_remote())

    @patch("subprocess.run")
    def test_has_remote_false(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        self.assertFalse(self.git_manager.has_remote())

    def test_commit_message_template(self):
        config = {"commit_message": "Backup: {timestamp}"}
        gm = shelf.GitManager(self.repo_path, self.logger, config)
        self.assertEqual(gm.commit_message_template, "Backup: {timestamp}")


class TestPasswordsProvider(unittest.TestCase):
    """Tests for PasswordsProvider password management."""

    def setUp(self):
        self.logger = MagicMock()
        self.file_manager = MagicMock()
        self.provider = shelf.PasswordsProvider(self.logger, self.file_manager)
        self.temp_dir = tempfile.mkdtemp()
        self.store_path = Path(self.temp_dir)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_password_file_simple_name(self):
        result = self.provider._get_password_file(self.store_path, "mypassword")
        self.assertEqual(result, self.store_path / "mypassword.gpg")

    def test_get_password_file_sanitizes_special_chars(self):
        result = self.provider._get_password_file(self.store_path, "my/pass@word!")
        expected_name = "my_pass_word_.gpg"
        self.assertEqual(result.name, expected_name)

    def test_get_password_file_allows_safe_chars(self):
        result = self.provider._get_password_file(self.store_path, "my-pass.word_123")
        self.assertEqual(result.name, "my-pass.word_123.gpg")

    def test_list_passwords_empty(self):
        passwords = self.provider.list_passwords(self.store_path)
        self.assertEqual(passwords, [])

    def test_list_passwords_with_files(self):
        (self.store_path / "pass1.gpg").touch()
        (self.store_path / "pass2.gpg").touch()
        (self.store_path / "notapass.txt").touch()
        passwords = self.provider.list_passwords(self.store_path)
        self.assertEqual(passwords, ["pass1", "pass2"])


class TestFilesProvider(unittest.TestCase):
    """Tests for FilesProvider file backup functionality."""

    def setUp(self):
        self.logger = MagicMock()
        self.file_manager = shelf.FileManager(self.logger)
        self.provider = shelf.FilesProvider(self.logger, self.file_manager)
        self.temp_dir = tempfile.mkdtemp()
        self.backup_path = Path(self.temp_dir) / "backup"
        self.backup_path.mkdir()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_backup_disabled_returns_skipped(self):
        config = {"enabled": False}
        result = self.provider.backup(config, self.backup_path)
        self.assertTrue(result["skipped"])
        self.assertTrue(result["success"])

    def test_backup_nonexistent_path_warns(self):
        config = {"enabled": True, "paths": ["/nonexistent/path/12345"]}
        self.provider.backup(config, self.backup_path)
        self.logger.warn.assert_called()


class TestHomebrewProvider(unittest.TestCase):
    """Tests for HomebrewProvider homebrew backup."""

    def setUp(self):
        self.logger = MagicMock()
        self.file_manager = MagicMock()
        self.provider = shelf.HomebrewProvider(self.logger, self.file_manager)

    def test_backup_disabled_returns_skipped(self):
        config = {"enabled": False}
        result = self.provider.backup(config, Path("/tmp"))
        self.assertTrue(result["skipped"])

    @patch.object(shelf.SystemUtils, "which", return_value=False)
    def test_backup_no_brew_returns_skipped(self, mock_which):
        config = {"enabled": True}
        result = self.provider.backup(config, Path("/tmp"))
        self.assertTrue(result["skipped"])


class TestFontsProvider(unittest.TestCase):
    """Tests for FontsProvider font inventory."""

    def setUp(self):
        self.logger = MagicMock()
        self.file_manager = MagicMock()
        self.provider = shelf.FontsProvider(self.logger, self.file_manager)

    def test_backup_disabled_returns_skipped(self):
        config = {"enabled": False}
        result = self.provider.backup(config, Path("/tmp"))
        self.assertTrue(result["skipped"])


class TestJSONFormatter(unittest.TestCase):
    """Tests for JSONFormatter log formatting."""

    def test_format_produces_valid_json(self):
        import logging

        formatter = shelf.JSONFormatter("test_session")
        # Create a real LogRecord instead of mocking
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.event_type = "test"

        result = formatter.format(record)
        parsed = json.loads(result)

        self.assertEqual(parsed["level"], "INFO")
        self.assertEqual(parsed["message"], "Test message")
        self.assertEqual(parsed["session_id"], "test_session")
        self.assertEqual(parsed["v"], shelf.LOG_VERSION)


class TestLogger(unittest.TestCase):
    """Tests for Logger functionality."""

    def test_logger_creates_session_id(self):
        logger = shelf.Logger()
        self.assertIsNotNone(logger.session_id)
        self.assertRegex(logger.session_id, r"\d{8}_\d{6}")

    def test_logger_with_file_creates_handler(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "test.log"
            logger = shelf.Logger(log_file)
            self.assertTrue(log_file.exists())
            # Should have console + file handlers
            self.assertEqual(len(logger.logger.handlers), 2)


class TestFileManagerCopy(unittest.TestCase):
    """Tests for FileManager copy operations."""

    def setUp(self):
        self.logger = MagicMock()
        self.fm = shelf.FileManager(self.logger)
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_copy_file(self):
        src = Path(self.temp_dir) / "source.txt"
        dest = Path(self.temp_dir) / "dest.txt"
        src.write_text("test content")

        result = self.fm.copy_item(src, dest)
        self.assertTrue(result)
        self.assertTrue(dest.exists())
        self.assertEqual(dest.read_text(), "test content")

    def test_copy_directory(self):
        src_dir = Path(self.temp_dir) / "src_dir"
        src_dir.mkdir()
        (src_dir / "file.txt").write_text("content")
        dest_dir = Path(self.temp_dir) / "dest_dir"

        result = self.fm.copy_item(src_dir, dest_dir)
        self.assertTrue(result)
        self.assertTrue(dest_dir.exists())
        self.assertTrue((dest_dir / "file.txt").exists())

    def test_copy_nonexistent_returns_false(self):
        src = Path(self.temp_dir) / "nonexistent"
        dest = Path(self.temp_dir) / "dest"

        result = self.fm.copy_item(src, dest)
        self.assertFalse(result)

    def test_get_file_checksum(self):
        test_file = Path(self.temp_dir) / "test.txt"
        test_file.write_text("hello")
        checksum = self.fm.get_file_checksum(test_file)
        self.assertIsNotNone(checksum)
        self.assertEqual(len(checksum), 64)  # SHA256 hex length

    def test_files_differ_same_content(self):
        file1 = Path(self.temp_dir) / "file1.txt"
        file2 = Path(self.temp_dir) / "file2.txt"
        file1.write_text("same")
        file2.write_text("same")

        self.assertFalse(self.fm.files_differ(file1, file2))

    def test_files_differ_different_content(self):
        file1 = Path(self.temp_dir) / "file1.txt"
        file2 = Path(self.temp_dir) / "file2.txt"
        file1.write_text("content1")
        file2.write_text("content2")

        self.assertTrue(self.fm.files_differ(file1, file2))


class TestBackupProviderBase(unittest.TestCase):
    """Tests for BackupProvider base class."""

    def test_default_backup_returns_failure(self):
        logger = MagicMock()
        fm = MagicMock()
        provider = shelf.BackupProvider("test", logger, fm)
        result = provider.backup({}, Path("/tmp"))
        self.assertFalse(result["success"])

    def test_default_restore_returns_false(self):
        logger = MagicMock()
        fm = MagicMock()
        provider = shelf.BackupProvider("test", logger, fm)
        result = provider.restore(Path("/tmp"), {})
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
