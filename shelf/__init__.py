#!/usr/bin/env python3

import os
import sys
import json
import tomllib
import shutil
import subprocess
import platform
import fnmatch
import logging
import stat
import hashlib
import getpass
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

__version__ = "0.4.0"

# Configuration
CONFIG_DIR = ".config/shelf"
BACKUP_DIR = ".local/share/shelf"

# Logging configuration
LOG_VERSION = 1
LOG_FILE_FORMAT = "backup_%Y%m%d_%H%M%S.ndjson"
LOG_TIME_FORMAT = "%H:%M:%S"
SESSION_ID_FORMAT = "%Y%m%d_%H%M%S"

# Font configuration
FONT_EXTENSIONS = {".ttf", ".otf", ".woff", ".woff2", ".eot"}
FONT_LIST_FILE = "custom-fonts.txt"
MACOS_FONTS_DIR = "Library/Fonts"
LINUX_FONTS_DIR = ".fonts"

# Subprocess configuration
DEFAULT_SUBPROCESS_TIMEOUT = 60  # seconds

# Backup configuration
BACKUP_SUCCESS_THRESHOLD = 0.8  # 80% success rate considered acceptable
DEFAULT_BACKUP_LIST_LIMIT = 20  # default number of backups to show in list


class JSONFormatter(logging.Formatter):
    SKIP_FIELDS = {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "getMessage",
        "exc_info",
        "exc_text",
        "stack_info",
        "event_type",
    }

    def __init__(self, session_id: str):
        super().__init__()
        self.session_id = session_id

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "v": LOG_VERSION,
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "session_id": self.session_id,
            "type": "event",
            "level": record.levelname,
            "message": record.getMessage(),
            "event_type": getattr(record, "event_type", "general"),
        }
        log_entry.update({k: v for k, v in record.__dict__.items() if k not in self.SKIP_FIELDS})
        return json.dumps(log_entry)


class ColoredConsoleHandler(logging.StreamHandler):
    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[31m",
        "RESET": "\033[0m",
    }

    def emit(self, record: logging.LogRecord) -> None:
        try:
            color = self.COLORS.get(record.levelname, "")
            timestamp = datetime.now().strftime(LOG_TIME_FORMAT)
            print(f"{color}[{timestamp}] {record.levelname}: {record.getMessage()}{self.COLORS['RESET']}")
        except Exception:
            self.handleError(record)


class Logger:
    def __init__(self, log_file: Optional[Path] = None):
        self.session_id = datetime.now().strftime(SESSION_ID_FORMAT)
        self.logger = logging.getLogger(f"shelf_{self.session_id}")
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()

        console_handler = ColoredConsoleHandler()
        console_handler.setLevel(logging.INFO)
        self.logger.addHandler(console_handler)

        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(JSONFormatter(self.session_id))
            self.logger.addHandler(file_handler)

    def log_metadata(self, operation: str, profile: str, **kwargs) -> None:
        metadata = {
            "v": LOG_VERSION,
            "timestamp": datetime.now().isoformat(),
            "session_id": self.session_id,
            "type": "metadata",
            "operation": operation,
            "profile": profile,
            "platform": platform.system().lower(),
            "hostname": platform.node(),
            **kwargs,
        }
        for handler in self.logger.handlers:
            if isinstance(handler, logging.FileHandler):
                with open(handler.baseFilename, "a") as f:
                    f.write(json.dumps(metadata) + "\n")

    def info(self, message: str, event_type: str = "general", **kwargs) -> None:
        self.logger.info(message, extra={"event_type": event_type, **kwargs})

    def warn(self, message: str, event_type: str = "warning", **kwargs) -> None:
        self.logger.warning(message, extra={"event_type": event_type, **kwargs})

    def error(self, message: str, event_type: str = "error", **kwargs) -> None:
        self.logger.error(message, extra={"event_type": event_type, **kwargs})

    def debug(self, message: str, event_type: str = "debug", **kwargs) -> None:
        self.logger.debug(message, extra={"event_type": event_type, **kwargs})


class GitManager:
    def __init__(self, repo_path: Path, logger: Logger, config: Dict[str, Any]):
        self.repo_path = repo_path
        self.logger = logger
        self.config = config
        self.commit_message_template = config.get("commit_message", "Backup: {timestamp}")
        self.branch = config.get("branch", "main")
        self.auto_commit = config.get("auto_commit", True)
        self.auto_push = config.get("auto_push", False)

    def run_git(self, args: List[str], timeout: int = DEFAULT_SUBPROCESS_TIMEOUT) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                ["git"] + args,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            self.logger.error(f"Git command timed out after {timeout}s: {' '.join(args)}")
            raise
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Git command failed: {' '.join(args)}")
            if e.stderr:
                self.logger.error(f"Git error: {e.stderr.strip()}")
            raise

    def init(self) -> None:
        if (self.repo_path / ".git").exists():
            return
        self.repo_path.mkdir(parents=True, exist_ok=True)
        self.run_git(["init"])
        self.logger.debug(f"Initialized git repo: {self.repo_path}")

    def add_all(self) -> None:
        self.run_git(["add", "."])

    def commit(self, message: str) -> bool:
        try:
            self.run_git(["commit", "-m", message])
            return True
        except subprocess.CalledProcessError:
            return False

    def checkout(self, commit_hash: str) -> None:
        self.run_git(["checkout", commit_hash])

    def log(self, limit: int = 10) -> str:
        try:
            return self.run_git(["log", "--oneline", f"-{limit}"]).stdout
        except subprocess.CalledProcessError:
            return ""

    def get_current_commit(self) -> str:
        try:
            return self.run_git(["rev-parse", "HEAD"]).stdout.strip()
        except subprocess.CalledProcessError:
            return ""

    def push(self) -> bool:
        try:
            self.run_git(["push"])
            self.logger.info("Pushed changes to remote")
            return True
        except subprocess.CalledProcessError:
            return False

    def has_changes(self) -> bool:
        try:
            return bool(self.run_git(["status", "--porcelain"]).stdout.strip())
        except subprocess.CalledProcessError:
            return False

    def has_remote(self) -> bool:
        """Check if git repository has a remote configured"""
        try:
            result = self.run_git(["remote", "-v"])
            return bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            return False


class FileManager:
    def __init__(self, logger: Logger, ignore_patterns: Optional[List[str]] = None):
        self.logger = logger
        self.ignore_patterns = ignore_patterns or []

    def get_file_checksum(self, file_path: Path) -> Optional[str]:
        try:
            with open(file_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return None

    def files_differ(self, file1: Path, file2: Path) -> bool:
        if not file1.exists() or not file2.exists():
            return True
        if file1.is_file() and file2.is_file():
            return self.get_file_checksum(file1) != self.get_file_checksum(file2)
        return file1.stat().st_mtime != file2.stat().st_mtime

    def copy_item(self, src: Path, dest: Path) -> bool:
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)

            if src.is_file():
                shutil.copy2(src, dest)
                self.logger.debug(f"Copied file: {src} → {dest}")
            elif src.is_dir():
                if dest.exists():
                    shutil.rmtree(dest)
                self._copy_directory_safe(src, dest)
                if not dest.exists():
                    self.logger.warn(f"Failed to create directory: {dest}")
                    return False
                self.logger.debug(f"Copied directory: {src} → {dest}")
            else:
                self.logger.warn(f"Source not found: {src}")
                return False
            return True
        except Exception as e:
            self.logger.error(f"Failed to copy {src} → {dest}: {e}")
            return False

    def _copy_directory_safe(self, src: Path, dest: Path) -> None:
        def ignore_problematic_files(src_dir: str, names: List[str]) -> List[str]:
            ignored = []
            for name in names:
                full_path = Path(src_dir) / name
                if self.should_exclude(name, self.ignore_patterns):
                    ignored.append(name)
                    self.logger.debug(f"Skipping (ignore pattern): {name}")
                    continue

                try:
                    stat_result = full_path.stat()
                    if stat.S_ISSOCK(stat_result.st_mode):
                        ignored.append(name)
                        self.logger.debug(f"Skipping socket: {full_path}")
                    elif stat.S_ISFIFO(stat_result.st_mode):
                        ignored.append(name)
                        self.logger.debug(f"Skipping FIFO: {full_path}")
                    elif full_path.is_file() and not os.access(full_path, os.R_OK):
                        ignored.append(name)
                        self.logger.debug(f"Skipping unreadable: {full_path}")
                except (OSError, PermissionError):
                    ignored.append(name)
                    self.logger.debug(f"Skipping inaccessible: {full_path}")
            return ignored

        try:
            shutil.copytree(src, dest, symlinks=True, ignore=ignore_problematic_files)
        except Exception as e:
            self.logger.debug(f"Some files in {src} could not be copied: {type(e).__name__}")
            dest.mkdir(parents=True, exist_ok=True)

    def should_exclude(self, path_str: str, exclude_patterns: List[str]) -> bool:
        return any(fnmatch.fnmatch(path_str, p) or fnmatch.fnmatch(Path(path_str).name, p) for p in exclude_patterns)

    def get_file_size(self, path: Path) -> int:
        if path.is_file():
            return path.stat().st_size
        if path.is_dir():
            try:
                return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())
            except (OSError, PermissionError):
                return 0
        return 0

    def format_size(self, size_bytes: int) -> str:
        if size_bytes == 0:
            return "0 B"
        units = ["B", "KB", "MB", "GB", "TB"]
        size = float(size_bytes)
        unit_index = 0
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        return f"{size:.1f} {units[unit_index]}"


class SystemUtils:
    @staticmethod
    def get_platform() -> str:
        system = platform.system().lower()
        return "macos" if system == "darwin" else system

    @staticmethod
    def which(command: str) -> bool:
        return shutil.which(command) is not None

    @staticmethod
    def run_command(cmd: List[str], cwd: Optional[Path] = None, timeout: int = DEFAULT_SUBPROCESS_TIMEOUT) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=True, timeout=timeout)


class BackupProvider:
    def __init__(self, name: str, logger: Logger, file_manager: FileManager):
        self.name = name
        self.logger = logger
        self.file_manager = file_manager

    def backup(self, config: Dict[str, Any], backup_path: Path) -> Dict[str, Any]:
        return {"provider": self.name, "success": False}

    def restore(self, backup_path: Path, config: Dict[str, Any]) -> bool:
        return False


class FilesProvider(BackupProvider):
    def __init__(self, logger: Logger, file_manager: FileManager):
        super().__init__("files", logger, file_manager)
        self.home = Path.home()

    def backup(self, config: Dict[str, Any], backup_path: Path) -> Dict[str, Any]:
        if not config.get("enabled", True):
            return {"provider": self.name, "success": True, "skipped": True}

        paths = config.get("paths", [])
        recursive = config.get("recursive", {})

        stats = {
            "files": 0,
            "dirs": 0,
            "recursive_dirs": 0,
            "errors": 0,
            "total_size": 0,
        }

        for path_pattern in paths:
            src_path = Path(path_pattern).expanduser().resolve()
            if not src_path.exists():
                self.logger.warn(f"Path not found: {path_pattern}")
                continue

            # Create relative path from home directory for cleaner backup structure
            try:
                relative_path = src_path.relative_to(self.home)
                dest_path = backup_path / relative_path
            except ValueError:
                # If path is not relative to home (e.g., /etc/hosts), use full absolute path
                dest_path = backup_path / str(src_path).lstrip("/")

            if self.file_manager.copy_item(src_path, dest_path):
                if src_path.is_file():
                    stats["files"] += 1
                    self.logger.info(f"Backed up file: {path_pattern}")
                elif src_path.is_dir():
                    stats["dirs"] += 1
                    self.logger.info(f"Backed up directory: {path_pattern}")
                stats["total_size"] += self.file_manager.get_file_size(src_path)
            else:
                stats["errors"] += 1

        for parent_path_str, subdirs in recursive.items():
            parent_path = Path(parent_path_str).expanduser()
            if not parent_path.exists():
                self.logger.warn(f"Parent directory does not exist: {parent_path}")
                continue

            for repo in parent_path.iterdir():
                if not repo.is_dir():
                    continue
                for subdir in subdirs:
                    source_path = repo / subdir
                    if not source_path.exists():
                        continue
                    relative_repo_path = repo.relative_to(Path.home())
                    dest_path = backup_path / relative_repo_path / subdir
                    if self.file_manager.copy_item(source_path, dest_path):
                        stats["recursive_dirs"] += 1
                        stats["total_size"] += self.file_manager.get_file_size(source_path)
                        self.logger.info(f"Backed up recursive: {relative_repo_path}/{subdir}")
                    else:
                        stats["errors"] += 1

        total_items = stats["files"] + stats["dirs"] + stats["recursive_dirs"]
        success_rate = total_items / max(1, total_items + stats["errors"])

        return {
            "provider": self.name,
            "success": success_rate >= BACKUP_SUCCESS_THRESHOLD,
            "stats": stats,
            "total_size_formatted": self.file_manager.format_size(stats["total_size"]),
            "success_rate": f"{success_rate:.1%}",
        }

    def restore(self, backup_path: Path, config: Dict[str, Any]) -> bool:
        if not config.get("enabled", True):
            return True

        restored = 0
        for path_pattern in config.get("paths", []):
            dest_path = Path(path_pattern).expanduser().resolve()

            # Find source path using relative path from home
            try:
                relative_path = dest_path.relative_to(self.home)
                src_path = backup_path / relative_path
            except ValueError:
                # If path is not relative to home, use full absolute path
                src_path = backup_path / str(dest_path).lstrip("/")

            if src_path.exists() and self.file_manager.copy_item(src_path, dest_path):
                item_type = "file" if src_path.is_file() else "directory"
                self.logger.info(f"Restored {item_type}: {path_pattern}")
                restored += 1

        self.logger.info(f"Restored {restored} items")
        return True


class HomebrewProvider(BackupProvider):
    def __init__(self, logger: Logger, file_manager: FileManager):
        super().__init__("homebrew", logger, file_manager)

    def backup(self, config: Dict[str, Any], backup_path: Path) -> Dict[str, Any]:
        if not config.get("enabled", True) or not SystemUtils.which("brew"):
            return {"provider": self.name, "success": True, "skipped": True}

        stats = {"brewfile": False, "formulas": 0, "casks": 0, "services": 0}
        success = True

        try:
            # Generate Brewfile
            SystemUtils.run_command(
                [
                    "brew",
                    "bundle",
                    "dump",
                    "--force",
                    "--file",
                    str(backup_path / "Brewfile"),
                ]
            )
            stats["brewfile"] = True
            self.logger.info("Generated Brewfile")

            # Export lists
            result = SystemUtils.run_command(["brew", "list", "--formula"])
            (backup_path / "brew-formulas.txt").write_text(result.stdout)
            stats["formulas"] = len(result.stdout.strip().split("\n")) if result.stdout.strip() else 0

            result = SystemUtils.run_command(["brew", "list", "--cask"])
            (backup_path / "brew-casks.txt").write_text(result.stdout)
            stats["casks"] = len(result.stdout.strip().split("\n")) if result.stdout.strip() else 0

            result = SystemUtils.run_command(["brew", "services", "list"])
            (backup_path / "brew-services.txt").write_text(result.stdout)

            self.logger.info(f"Exported {stats['formulas']} formulas, {stats['casks']} casks")

        except Exception as e:
            self.logger.error(f"Homebrew backup failed: {e}")
            success = False

        return {"provider": self.name, "success": success, "stats": stats}

    def restore(self, backup_path: Path, config: Dict[str, Any]) -> bool:
        if not config.get("enabled", True) or not SystemUtils.which("brew"):
            return True

        brewfile = backup_path / "Brewfile"
        if not brewfile.exists():
            self.logger.warn("No Brewfile found for restore")
            return True

        try:
            self.logger.info("Restoring Homebrew packages...")
            SystemUtils.run_command(["brew", "bundle", "--file", str(brewfile)])
            self.logger.info("Homebrew packages restored")
            return True
        except Exception as e:
            self.logger.error(f"Homebrew restore failed: {e}")
            return False


class FontsProvider(BackupProvider):
    def __init__(self, logger: Logger, file_manager: FileManager):
        super().__init__("fonts", logger, file_manager)
        self.home = Path.home()
        self.fonts_dir = self.home / MACOS_FONTS_DIR if SystemUtils.get_platform() == "macos" else self.home / LINUX_FONTS_DIR

    def backup(self, config: Dict[str, Any], backup_path: Path) -> Dict[str, Any]:
        if not config.get("enabled", True):
            return {"provider": self.name, "success": True, "skipped": True}

        if not self.fonts_dir.exists():
            return {"provider": self.name, "success": True, "stats": {"fonts": 0}}

        stats = {"fonts": 0}
        font_list = []

        for font_file in self.fonts_dir.rglob("*"):
            if font_file.is_file() and font_file.suffix.lower() in FONT_EXTENSIONS:
                font_list.append(font_file.name)
                stats["fonts"] += 1

        if font_list:
            (backup_path / FONT_LIST_FILE).write_text("\n".join(sorted(font_list)))
            self.logger.info(f"Listed {stats['fonts']} custom fonts")

        return {"provider": self.name, "success": True, "stats": stats}

    def restore(self, backup_path: Path, config: Dict[str, Any]) -> bool:
        fonts_list = backup_path / FONT_LIST_FILE
        if fonts_list.exists():
            font_count = len(fonts_list.read_text().strip().split("\n"))
            self.logger.info(f"Font list available: {font_count} fonts (manual restore required)")
        return True


class PasswordsProvider(BackupProvider):
    """Provider for managing passwords encrypted with GPG"""

    def __init__(self, logger: Logger, file_manager: FileManager):
        super().__init__("passwords", logger, file_manager)

    def _run_gpg(self, args: List[str], input_data: Optional[str] = None, timeout: int = DEFAULT_SUBPROCESS_TIMEOUT) -> subprocess.CompletedProcess:
        """Run GPG command"""
        try:
            return subprocess.run(
                ["gpg"] + args,
                input=input_data,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            self.logger.error(f"GPG command timed out after {timeout}s")
            raise
        except subprocess.CalledProcessError as e:
            self.logger.error(f"GPG command failed: {' '.join(args)}")
            if e.stderr:
                self.logger.error(f"GPG error: {e.stderr.strip()}")
            raise

    def _get_password_file(self, store_path: Path, name: str) -> Path:
        """Get the file path for a password entry"""
        # Sanitize name to create safe filename
        safe_name = "".join(c if c.isalnum() or c in ".-_" else "_" for c in name)
        return store_path / f"{safe_name}.gpg"

    def add(self, store_path: Path, gpg_key_id: str, name: str, password: str, force: bool = False) -> bool:
        """Add or update a password"""
        try:
            password_file = self._get_password_file(store_path, name)

            # Check for potential name collision from sanitization
            safe_name = password_file.stem
            if safe_name != name and not force:
                # Name was sanitized, check if this would overwrite existing entry
                if password_file.exists():
                    self.logger.warn(f"Name '{name}' sanitized to '{safe_name}' which already exists")
                    self.logger.error("Use a different name or remove the existing entry first")
                    return False

            self._run_gpg(
                ["-e", "-r", gpg_key_id, "-o", str(password_file), "--batch", "--yes"],
                input_data=password,
            )
            if safe_name != name:
                self.logger.info(f"Password stored: {name} (as {safe_name})")
            else:
                self.logger.info(f"Password stored: {name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to store password: {e}")
            return False

    def show(self, store_path: Path, name: str) -> Optional[str]:
        """Decrypt and show a password"""
        try:
            password_file = self._get_password_file(store_path, name)
            if not password_file.exists():
                self.logger.error(f"Password not found: {name}")
                return None

            result = self._run_gpg(["-d", str(password_file)])
            return result.stdout.strip()
        except Exception as e:
            self.logger.error(f"Failed to decrypt password: {e}")
            return None

    def remove(self, store_path: Path, name: str) -> bool:
        """Remove a password"""
        try:
            password_file = self._get_password_file(store_path, name)
            if not password_file.exists():
                self.logger.error(f"Password not found: {name}")
                return False

            password_file.unlink()
            self.logger.info(f"Password removed: {name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to remove password: {e}")
            return False

    def rename(self, store_path: Path, old_name: str, new_name: str) -> bool:
        """Rename a password"""
        try:
            old_file = self._get_password_file(store_path, old_name)
            if not old_file.exists():
                self.logger.error(f"Password not found: {old_name}")
                return False

            new_file = self._get_password_file(store_path, new_name)
            if new_file.exists():
                self.logger.error(f"Password already exists: {new_name}")
                return False

            old_file.rename(new_file)
            self.logger.info(f"Password renamed: {old_name} -> {new_name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to rename password: {e}")
            return False

    def list_passwords(self, store_path: Path) -> List[str]:
        """List all stored passwords"""
        try:
            passwords = []
            for file in store_path.glob("*.gpg"):
                # Remove .gpg extension
                name = file.stem
                passwords.append(name)
            return sorted(passwords)
        except Exception as e:
            self.logger.error(f"Failed to list passwords: {e}")
            return []

    def backup(self, config: Dict[str, Any], backup_path: Path) -> Dict[str, Any]:
        """Passwords are already in the backup location, nothing to do"""
        return {"provider": self.name, "success": True, "skipped": True}

    def restore(self, backup_path: Path, config: Dict[str, Any]) -> bool:
        """Passwords are already in the backup location, nothing to restore"""
        return True


class Shelf:
    def __init__(self):
        self.home = Path.home()
        self.config_dir = self.home / CONFIG_DIR
        self.os_name = SystemUtils.get_platform()
        self.profile_name = self.os_name

        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.logger = Logger()
        self.file_manager = FileManager(self.logger)
        self.providers = {
            "files": FilesProvider(self.logger, self.file_manager),
            "homebrew": HomebrewProvider(self.logger, self.file_manager),
            "fonts": FontsProvider(self.logger, self.file_manager),
        }

    @staticmethod
    def parse_size(size_str: str) -> int:
        if isinstance(size_str, int):
            return size_str
        size_str = size_str.strip().upper()
        units = {"TB": 1024**4, "GB": 1024**3, "MB": 1024**2, "KB": 1024, "B": 1}
        for unit, multiplier in units.items():
            if size_str.endswith(unit):
                try:
                    return int(float(size_str[: -len(unit)]) * multiplier)
                except ValueError:
                    pass
        try:
            return int(size_str)
        except ValueError:
            return 10 * 1024 * 1024

    def merge_config(self, loaded: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge loaded config with defaults"""
        result = defaults.copy()

        for key, value in loaded.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self.merge_config(value, result[key])
            else:
                result[key] = value

        return result

    def _validate_backup_path(self, path: Path) -> Optional[str]:
        """Validate backup path and return error message if invalid, None if valid"""
        path_str = str(path)

        # Reject root directory
        if path == Path("/"):
            return "Cannot use root directory as backup path"

        # Reject system directories
        forbidden_prefixes = ["/System", "/usr", "/bin", "/sbin", "/var", "/etc", "/lib", "/opt"]
        for prefix in forbidden_prefixes:
            if path_str.startswith(prefix):
                return f"Cannot use system directory '{prefix}' as backup path"

        # Warn about home directory itself
        if path == Path.home():
            return "Cannot use home directory itself as backup path"

        return None

    def _prompt_for_backup_path(self) -> str:
        """Prompt user for backup location path on first run"""
        print("\nPlease specify the backup repository path (The directory will be created if it doesn't exist).")

        while True:
            backup_path = input("\n> ").strip()

            if not backup_path:
                print("Error: Backup path cannot be empty. Please provide a valid path.")
                continue

            expanded_path = Path(backup_path).expanduser().resolve()

            # Validate the path
            validation_error = self._validate_backup_path(expanded_path)
            if validation_error:
                print(f"Error: {validation_error}")
                continue

            # Confirm with user
            print(f"\nBackup repository will be: {expanded_path}")
            confirm = input("Is this correct? (y/n): ").strip().lower()

            if confirm in ("y", "yes"):
                return str(expanded_path)
            else:
                print("Let's try again.")

    def _create_profile_from_template(self) -> Dict[str, Any]:
        script_dir = Path(__file__).parent
        template_file = script_dir / f"{self.profile_name}.toml"

        if not template_file.exists():
            self.logger.error(f"Template file not found: {template_file}")
            self.logger.error("Required template files: macos.toml or linux.toml")
            raise FileNotFoundError(f"Template file required: {template_file}")

        try:
            with open(template_file, "rb") as f:
                profile = tomllib.load(f)
            profile["name"] = self.profile_name
            self.logger.info(f"Using template: {template_file}")
        except Exception as e:
            self.logger.error(f"Failed to load template {template_file}: {e}")
            raise

        self.save_profile(profile)
        self.logger.info(f"Created profile: {self.profile_name}")

        # Prompt for backup path on first run
        backup_path = self._prompt_for_backup_path()
        profile["backup"]["path"] = backup_path
        self.save_profile(profile)
        self.logger.info(f"Saved backup path to profile: {backup_path}")
        print(f"\nBackup path configured: {backup_path}")
        print("You can change this later by editing the config file.\n")

        return profile

    def _load_template(self) -> Dict[str, Any]:
        """Load template file as defaults"""
        script_dir = Path(__file__).parent
        template_file = script_dir / f"{self.profile_name}.toml"

        if not template_file.exists():
            self.logger.error(f"Template file not found: {template_file}")
            self.logger.error("Required template files: macos.toml or linux.toml")
            raise FileNotFoundError(f"Template file required: {template_file}")

        try:
            with open(template_file, "rb") as f:
                return tomllib.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load template {template_file}: {e}")
            raise

    def load_profile(self, name: str) -> Dict[str, Any]:
        profile_path = self.config_dir / f"{name}.toml"

        if not profile_path.exists():
            profile = self._create_profile_from_template()
            return profile

        try:
            with open(profile_path, "rb") as f:
                loaded = tomllib.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load profile {name}: {e}")
            raise

        profile = self.merge_config(loaded, self._load_template())

        # Backward compatibility migrations
        if "providers" not in profile:
            profile["providers"] = {}
        for provider in ["files", "homebrew", "fonts"]:
            if provider in profile:
                profile["providers"][provider] = profile.pop(provider)

        if "backup_path" in profile:
            profile["backup"]["path"] = profile.pop("backup_path")
        if "ignore_patterns" in profile:
            profile["backup"]["ignore_patterns"] = profile.pop("ignore_patterns")

        # Merge old files/directories into paths
        if "files" in profile["providers"]:
            fc = profile["providers"]["files"]
            if "files" in fc or "directories" in fc:
                fc.setdefault("paths", []).extend(fc.pop("files", []) + fc.pop("directories", []))

        return profile

    def save_profile(self, profile: Dict[str, Any]) -> None:
        profile_path = self.config_dir / f"{profile['name']}.toml"
        toml_content = self._dict_to_toml(profile)
        profile_path.write_text(toml_content)

    def _dict_to_toml(self, data: Dict[str, Any], prefix: str = "") -> str:
        lines, tables = [], {}
        for key, value in data.items():
            if isinstance(value, dict):
                tables[key] = value
            elif isinstance(value, bool):
                quoted_key = f'"{key}"' if any(c in key for c in ["/", "~", " ", "."]) else key
                lines.append(f"{quoted_key} = {str(value).lower()}")
            elif isinstance(value, (int, float)):
                quoted_key = f'"{key}"' if any(c in key for c in ["/", "~", " ", "."]) else key
                lines.append(f"{quoted_key} = {value}")
            elif isinstance(value, str):
                quoted_key = f'"{key}"' if any(c in key for c in ["/", "~", " ", "."]) else key
                lines.append(f'{quoted_key} = "{value}"')
            elif isinstance(value, list):
                quoted_key = f'"{key}"' if any(c in key for c in ["/", "~", " ", "."]) else key
                lines.append(f"{quoted_key} = {json.dumps(value)}")
        result = "\n".join(lines)
        for name, data in tables.items():
            result += f"\n\n[{prefix}{name}]\n" if result else f"[{prefix}{name}]\n"
            result += self._dict_to_toml(data, f"{prefix}{name}.")
        return result

    def backup(self, target_path: Optional[str] = None, should_commit: bool = False, should_push: bool = False) -> Dict[str, Any]:
        profile = self.load_profile(self.profile_name)

        if target_path:
            backup_path = Path(target_path).resolve()
            if not profile.get("backup", {}).get("path"):
                profile["backup"]["path"] = str(backup_path)
                self.save_profile(profile)
                self.logger.info(f"Saved backup path to profile: {backup_path}")
        elif profile.get("backup", {}).get("path"):
            backup_path = Path(profile["backup"]["path"]).expanduser().resolve()
        else:
            self.logger.error("No backup path specified. Use shelf backup <path> or set 'backup.path' in config.")
            raise ValueError("Backup path required")

        self.logger.info(f"Backup target: {backup_path}")
        backup_path.mkdir(parents=True, exist_ok=True)
        (backup_path / ".shelf_logs").mkdir(exist_ok=True)

        # Ensure .shelf_logs is gitignored
        gitignore_path = backup_path / ".gitignore"
        if gitignore_path.exists():
            gitignore_content = gitignore_path.read_text()
            if ".shelf_logs" not in gitignore_content and ".shelf_logs/" not in gitignore_content:
                gitignore_path.write_text(gitignore_content.rstrip() + "\n.shelf_logs/\n")
        else:
            gitignore_path.write_text(".shelf_logs/\n")

        log_file = backup_path / ".shelf_logs" / datetime.now().strftime(LOG_FILE_FORMAT)
        self.logger = Logger(log_file)

        self.file_manager = FileManager(
            self.logger,
            profile.get("backup", {}).get("ignore_patterns", []),
        )
        self.providers = {
            "files": FilesProvider(self.logger, self.file_manager),
            "homebrew": HomebrewProvider(self.logger, self.file_manager),
            "fonts": FontsProvider(self.logger, self.file_manager),
        }

        self.logger.log_metadata("backup", self.profile_name, backup_path=str(backup_path))
        self.logger.info(f"Starting backup with profile: {self.profile_name}", "backup_start")

        git_manager = GitManager(backup_path, self.logger, profile.get("git", {}))
        git_manager.init()

        results: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "profile": self.profile_name,
            "success": True,
            "providers": {},
            "log_file": str(log_file),
        }
        providers_results: Dict[str, Any] = results["providers"]

        for provider_name, provider in self.providers.items():
            provider_config = profile.get("providers", {}).get(provider_name, {})
            if provider_config and isinstance(provider_config, dict):
                self.logger.info(f"Running {provider_name} backup...")

                # Get provider-specific subdirectory (default to empty string for root)
                provider_subdirectory = provider_config.get("subdirectory", "")
                provider_backup_path = backup_path / provider_subdirectory if provider_subdirectory else backup_path
                provider_backup_path.mkdir(parents=True, exist_ok=True)

                result = provider.backup(provider_config, provider_backup_path)
                providers_results[provider_name] = result
                if not result.get("success", False) and not result.get("skipped", False):
                    results["success"] = False

        if should_commit:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = git_manager.commit_message_template.format(timestamp=timestamp, date=timestamp.split()[0], time=timestamp.split()[1])

            git_manager.add_all()
            if git_manager.commit(message):
                results["git_commit"] = git_manager.get_current_commit()[:8]
                self.logger.info(f"Git commit: {results['git_commit']}")

                if should_push:
                    if git_manager.has_remote():
                        results["git_push"] = "success" if git_manager.push() else "failed"
                        self.logger.info("Pushed to remote" if results["git_push"] == "success" else "Failed to push")
                    else:
                        self.logger.warn("--push specified but no remote configured")
            else:
                self.logger.info("No changes to commit")
        else:
            self.logger.info("Backup completed (use --commit to create git commit)")

        self.logger.info("Backup completed successfully" if results["success"] else "Backup completed with errors")
        return results

    def restore(
        self,
        commit_hash: Optional[str] = None,
        source_path: Optional[str] = None,
        dry_run: bool = False,
    ) -> bool:
        profile = self.load_profile(self.profile_name)
        backup_path = (
            Path(source_path).resolve()
            if source_path
            else (Path(profile["backup"]["path"]).expanduser().resolve() if profile.get("backup", {}).get("path") else None)
        )
        if not backup_path:
            self.logger.error("No backup path specified. Use shelf restore <commit> <path> or set 'backup.path' in config.")
            raise ValueError("Backup path required")
        if not backup_path.exists():
            self.logger.error(f"No backup found at: {backup_path}")
            return False

        git_manager = GitManager(backup_path, self.logger, profile.get("git", {}))
        if commit_hash:
            try:
                git_manager.checkout(commit_hash)
                self.logger.info(f"Checked out commit: {commit_hash[:8]}")
            except subprocess.CalledProcessError:
                self.logger.error(f"Failed to checkout commit: {commit_hash}")
                return False

        self.logger.info(f"Starting {'dry-run' if dry_run else 'restore'} from profile: {self.profile_name}")
        if dry_run:
            print("\n[DRY-RUN]  DRY RUN MODE, No changes will be made\n")

        success = True
        for provider_name, provider in self.providers.items():
            provider_config = profile.get("providers", {}).get(provider_name, {})
            if provider_config and provider_config.get("enabled", True):
                # Get provider-specific subdirectory (default to empty string for root)
                provider_subdirectory = provider_config.get("subdirectory", "")
                provider_backup_path = backup_path / provider_subdirectory if provider_subdirectory else backup_path

                if dry_run:
                    print(f"[DRY-RUN]  Would restore {provider_name}")
                elif not provider.restore(provider_backup_path, provider_config):
                    success = False

        if dry_run:
            print("\n[DRY-RUN]  Dry-run completed. Run without --dry-run to apply changes.")
        else:
            self.logger.info("Restore completed successfully" if success else "Restore completed with errors")
        return success

    def list_backups(self, source_path: Optional[str] = None, limit: int = DEFAULT_BACKUP_LIST_LIMIT) -> None:
        profile = self.load_profile(self.profile_name)
        backup_path = (
            Path(source_path).resolve()
            if source_path
            else (Path(profile["backup"]["path"]).expanduser().resolve() if profile.get("backup", {}).get("path") else None)
        )
        if not backup_path:
            self.logger.error("No backup path specified. Use shelf list <path> or set 'backup.path' in config.")
            return
        if not backup_path.exists():
            self.logger.info(f"No backups found at: {backup_path}")
            return

        logs_dir = backup_path / ".shelf_logs"
        log_files = sorted(logs_dir.glob("backup_*.ndjson"), reverse=True)[:limit] if logs_dir.exists() else []
        if not log_files:
            self.logger.info("No backup history found")
            return

        self.logger.info(f"Recent backups for profile '{self.profile_name}':")
        print("-" * 80)
        for log_file in log_files:
            try:
                metadata = json.loads(open(log_file).readline())
                if metadata.get("type") == "metadata":
                    try:
                        dt = datetime.fromisoformat(metadata["timestamp"].replace("Z", "+00:00"))
                        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except (ValueError, KeyError):
                        time_str = metadata.get("timestamp", "unknown")
                    print(f"{metadata.get('session_id', 'unknown')}: {metadata.get('operation', 'backup')}: {time_str}")
            except Exception as e:
                self.logger.debug(f"Failed to read {log_file}: {e}")

    def status(self) -> None:
        """Show status information"""
        self.logger.info("Shelf Backup Status")
        print("=" * 50)

        print(f"Config directory: {self.config_dir}")
        print(f"Platform: {SystemUtils.get_platform()}")
        print(f"Profile: {self.profile_name} (auto-detected)")

        # Profile-specific info
        profile_path = self.config_dir / f"{self.profile_name}.toml"

        print(f"\nCurrent Profile: {self.profile_name}")
        print(f"Config: {profile_path}")
        print(f"Exists: {'Yes' if profile_path.exists() else 'No'}")

        if profile_path.exists():
            profile = self.load_profile(self.profile_name)
            configured_backup_path = profile.get("backup", {}).get("path")

            if configured_backup_path:
                print(f"Backup path (git repo): {configured_backup_path}")
                backup_path = Path(configured_backup_path).expanduser().resolve()

                if backup_path.exists():
                    git_manager = GitManager(backup_path, self.logger, profile.get("git", {}))
                    recent_commits = git_manager.log(5)
                    if recent_commits:
                        print("Recent backups:")
                        for line in recent_commits.strip().split("\n"):
                            print(f"  {line}")
                    else:
                        print("No backup history")
                else:
                    print("Backup repository not yet created")
            else:
                print("Backup path not configured yet")
        else:
            print("Run any shelf command to initialize configuration")


def _setup_password_provider(shelf_instance: Shelf) -> tuple:
    """Setup and return password provider configuration"""
    profile = shelf_instance.load_profile(shelf_instance.profile_name)
    pass_config = profile.get("providers", {}).get("passwords", {})

    if not pass_config.get("enabled", False) or not pass_config.get("gpg_key_id"):
        print("\nPassword provider not configured.")
        print("Available GPG keys:")
        try:
            result = subprocess.run(
                ["gpg", "--list-keys", "--keyid-format", "LONG"],
                capture_output=True,
                text=True,
                check=True,
                timeout=DEFAULT_SUBPROCESS_TIMEOUT,
            )
            print(result.stdout)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            print("Error: Could not list GPG keys. Is GPG installed?")
            sys.exit(1)

        gpg_key_id = input("\nEnter GPG key ID to use for password encryption: ").strip()
        if not gpg_key_id:
            print("Error: GPG key ID cannot be empty")
            sys.exit(1)

        if "providers" not in profile:
            profile["providers"] = {}
        if "passwords" not in profile["providers"]:
            profile["providers"]["passwords"] = {}

        profile["providers"]["passwords"]["enabled"] = True
        profile["providers"]["passwords"]["gpg_key_id"] = gpg_key_id
        if "subdirectory" not in profile["providers"]["passwords"]:
            profile["providers"]["passwords"]["subdirectory"] = "passwords"

        shelf_instance.save_profile(profile)
        print(f"Password provider enabled with GPG key: {gpg_key_id}")
        pass_config = profile["providers"]["passwords"]

    gpg_key_id = pass_config.get("gpg_key_id")

    backup_path_str = profile.get("backup", {}).get("path")
    if not backup_path_str:
        print("Error: Backup path not configured. Run 'shelf backup <path>' first.")
        sys.exit(1)

    backup_path = Path(backup_path_str).expanduser().resolve()
    subdirectory = pass_config.get("subdirectory", "passwords")
    store_path = backup_path / subdirectory
    store_path.mkdir(parents=True, exist_ok=True)

    pass_provider = PasswordsProvider(shelf_instance.logger, shelf_instance.file_manager)
    return pass_provider, store_path, gpg_key_id


def _cmd_backup(args) -> None:
    """Handle backup command"""
    shelf = Shelf()
    shelf.backup(args.path, should_commit=args.commit, should_push=args.push)


def _cmd_restore(args) -> None:
    """Handle restore command"""
    shelf = Shelf()
    shelf.restore(args.commit, args.path, dry_run=args.dry_run)


def _cmd_list(args) -> None:
    """Handle list command"""
    shelf = Shelf()
    shelf.list_backups(args.path)


def _cmd_status(args) -> None:
    """Handle status command"""
    shelf = Shelf()
    shelf.status()


def _cmd_pass(args) -> None:
    """Handle pass command"""
    shelf = Shelf()
    pass_provider, store_path, gpg_key_id = _setup_password_provider(shelf)

    if args.action == "list":
        passwords = pass_provider.list_passwords(store_path)
        if passwords:
            print("Stored passwords:")
            for name in passwords:
                print(f"  {name}")
        else:
            print("No passwords stored")

    elif args.action == "add":
        if not args.name:
            print("Error: name is required for 'add' action")
            sys.exit(1)
        password = getpass.getpass("Enter password: ")
        if not password:
            print("Password cannot be empty")
            sys.exit(1)
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match")
            sys.exit(1)
        if pass_provider.add(store_path, gpg_key_id, args.name, password):
            print(f"Password stored: {args.name}")
        else:
            print("Failed to store password")
            sys.exit(1)

    elif args.action == "show":
        if not args.name:
            print("Error: name is required for 'show' action")
            sys.exit(1)
        password = pass_provider.show(store_path, args.name)
        if password:
            print(password)
        else:
            sys.exit(1)

    elif args.action == "rm":
        if not args.name:
            print("Error: name is required for 'rm' action")
            sys.exit(1)
        if pass_provider.remove(store_path, args.name):
            print(f"Password removed: {args.name}")
        else:
            sys.exit(1)

    elif args.action == "rename":
        if not args.name or not args.new_name:
            print("Error: both old_name and new_name are required for 'rename' action")
            sys.exit(1)
        if pass_provider.rename(store_path, args.name, args.new_name):
            print(f"Password renamed: {args.name} -> {args.new_name}")
        else:
            sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="shelf",
        description="A stupidly simple backup tool with zero dependencies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version=f"shelf {__version__}")

    subparsers = parser.add_subparsers(dest="command", title="commands")

    # backup command
    backup_parser = subparsers.add_parser("backup", help="Backup files to repository")
    backup_parser.add_argument("path", nargs="?", help="Backup repository path")
    backup_parser.add_argument("--commit", action="store_true", help="Create git commit after backup")
    backup_parser.add_argument("--push", action="store_true", help="Push changes to remote (requires --commit)")
    backup_parser.set_defaults(func=_cmd_backup)

    # restore command
    restore_parser = subparsers.add_parser("restore", help="Restore files from backup")
    restore_parser.add_argument("commit", nargs="?", help="Git commit hash to restore from")
    restore_parser.add_argument("path", nargs="?", help="Backup repository path")
    restore_parser.add_argument("--dry-run", action="store_true", help="Show what would be restored without making changes")
    restore_parser.set_defaults(func=_cmd_restore)

    # list command
    list_parser = subparsers.add_parser("list", help="List backup history")
    list_parser.add_argument("path", nargs="?", help="Backup repository path")
    list_parser.set_defaults(func=_cmd_list)

    # status command
    status_parser = subparsers.add_parser("status", help="Show system status")
    status_parser.set_defaults(func=_cmd_status)

    # pass command
    pass_parser = subparsers.add_parser("pass", help="Manage GPG-encrypted passwords")
    pass_parser.add_argument("action", choices=["list", "add", "show", "rm", "rename"], help="Password action")
    pass_parser.add_argument("name", nargs="?", help="Password name")
    pass_parser.add_argument("new_name", nargs="?", help="New name (for rename)")
    pass_parser.set_defaults(func=_cmd_pass)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
