#!/usr/bin/env python3

import os
import sys
import json
import shutil
import subprocess
import platform
import fnmatch
import logging
import stat
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Union



class JSONFormatter(logging.Formatter):
    """Custom formatter for JSON logging"""

    def __init__(self, session_id: str):
        super().__init__()
        self.session_id = session_id

    def format(self, record):
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "session_id": self.session_id,
            "type": "event",
            "level": record.levelname,
            "message": record.getMessage(),
            "event_type": getattr(record, 'event_type', 'general')
        }

        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ('name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'lineno', 'funcName', 'created',
                          'msecs', 'relativeCreated', 'thread', 'threadName',
                          'processName', 'process', 'getMessage', 'exc_info',
                          'exc_text', 'stack_info', 'event_type'):
                log_entry[key] = value

        return json.dumps(log_entry)


class ColoredConsoleHandler(logging.StreamHandler):
    """Console handler with colors"""

    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[31m',
        'RESET': '\033[0m'
    }

    def emit(self, record):
        try:
            color = self.COLORS.get(record.levelname, '')
            reset = self.COLORS['RESET']
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"{color}[{timestamp}] {record.levelname}: {record.getMessage()}{reset}")
        except Exception:
            self.handleError(record)


class Logger:
    """Logger using Python's built-in logging with JSON support"""

    def __init__(self, log_file: Optional[Path] = None):
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.logger = logging.getLogger(f"shelf_{self.session_id}")
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()

        # Console handler
        console_handler = ColoredConsoleHandler()
        console_handler.setLevel(logging.INFO)
        self.logger.addHandler(console_handler)

        # File handler for JSON logs
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(JSONFormatter(self.session_id))
            self.logger.addHandler(file_handler)

    def log_metadata(self, operation: str, profile: str, **kwargs):
        """Log session metadata"""
        metadata = {
            "timestamp": datetime.now().isoformat(),
            "session_id": self.session_id,
            "type": "metadata",
            "operation": operation,
            "profile": profile,
            "platform": platform.system().lower(),
            "hostname": platform.node(),
            **kwargs
        }

        # Write metadata directly to file (first line)
        if self.logger.handlers:
            for handler in self.logger.handlers:
                if isinstance(handler, logging.FileHandler):
                    with open(handler.baseFilename, 'a') as f:
                        f.write(json.dumps(metadata) + '\n')

    def info(self, message: str, event_type: str = "general", **kwargs):
        extra = {"event_type": event_type, **kwargs}
        self.logger.info(message, extra=extra)

    def warn(self, message: str, event_type: str = "warning", **kwargs):
        extra = {"event_type": event_type, **kwargs}
        self.logger.warning(message, extra=extra)

    def error(self, message: str, event_type: str = "error", **kwargs):
        extra = {"event_type": event_type, **kwargs}
        self.logger.error(message, extra=extra)

    def debug(self, message: str, event_type: str = "debug", **kwargs):
        extra = {"event_type": event_type, **kwargs}
        self.logger.debug(message, extra=extra)

    def log(self, message: str, level: str = "INFO"):
        """Backwards compatibility"""
        getattr(self.logger, level.lower())(message)


class GitManager:
    """Simple git operations"""

    def __init__(self, repo_path: Path, logger: Logger):
        self.repo_path = repo_path
        self.logger = logger

    def run_git(self, args: List[str]) -> subprocess.CompletedProcess:
        """Run git command"""
        cmd = ["git"] + args
        try:
            result = subprocess.run(
                cmd, cwd=self.repo_path, capture_output=True, text=True, check=True
            )
            return result
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Git command failed: {' '.join(cmd)}")
            if e.stderr:
                self.logger.error(f"Git error: {e.stderr.strip()}")
            raise

    def init(self):
        """Initialize git repository"""
        if (self.repo_path / ".git").exists():
            return

        self.repo_path.mkdir(parents=True, exist_ok=True)
        self.run_git(["init"])
        self.run_git(["config", "user.name", "Shelf Backup System"])
        self.run_git(["config", "user.email", "backup@shelf.local"])
        self.logger.debug(f"Initialized git repo: {self.repo_path}")

    def add_all(self):
        """Add all files to git"""
        self.run_git(["add", "."])

    def commit(self, message: str) -> bool:
        """Commit changes, return True if commit was made"""
        try:
            self.run_git(["commit", "-m", message])
            return True
        except subprocess.CalledProcessError:
            return False

    def checkout(self, commit_hash: str):
        """Checkout specific commit"""
        self.run_git(["checkout", commit_hash])

    def log(self, limit: int = 10) -> str:
        """Get git log"""
        try:
            result = self.run_git(["log", "--oneline", f"-{limit}"])
            return result.stdout
        except subprocess.CalledProcessError:
            return ""

    def get_current_commit(self) -> str:
        """Get current commit hash"""
        try:
            result = self.run_git(["rev-parse", "HEAD"])
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return ""


class FileManager:
    """File operations with logging"""

    def __init__(self, logger: Logger):
        self.logger = logger

    def copy_item(self, src: Path, dest: Path) -> bool:
        """Copy file or directory"""
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)

            if src.is_file():
                shutil.copy2(src, dest)
                self.logger.debug(f"Copied file: {src} → {dest}")
            elif src.is_dir():
                if dest.exists():
                    shutil.rmtree(dest)

                # Use custom copy function to handle socket files gracefully
                self._copy_directory_safe(src, dest)

                # Check if we at least created the destination directory
                if dest.exists():
                    self.logger.debug(f"Copied directory: {src} → {dest}")
                else:
                    self.logger.warn(f"Failed to create directory: {dest}")
                    return False
            else:
                self.logger.warn(f"Source not found: {src}")
                return False

            return True

        except Exception as e:
            self.logger.error(f"Failed to copy {src} → {dest}: {e}")
            return False

    def _copy_directory_safe(self, src: Path, dest: Path):
        """Copy directory, skipping socket files"""
        def ignore_problematic_files(src_dir, names):
            """Skip socket files and other problematic items"""
            ignored = []
            for name in names:
                full_path = Path(src_dir) / name
                try:
                    # Check if it's a socket or FIFO using stat
                    stat_result = full_path.stat()

                    # Skip socket files (common in .gnupg, iTerm2, etc.)
                    if stat.S_ISSOCK(stat_result.st_mode):
                        ignored.append(name)
                        self.logger.debug(f"Skipping socket file: {full_path}")
                        continue

                    # Skip fifos (named pipes)
                    if stat.S_ISFIFO(stat_result.st_mode):
                        ignored.append(name)
                        self.logger.debug(f"Skipping FIFO: {full_path}")
                        continue

                    # Skip files we can't read
                    if full_path.is_file() and not os.access(full_path, os.R_OK):
                        ignored.append(name)
                        self.logger.debug(f"Skipping unreadable file: {full_path}")
                        continue

                except (OSError, PermissionError):
                    # If we can't even check the file type, skip it
                    ignored.append(name)
                    self.logger.debug(f"Skipping inaccessible file: {full_path}")

            return ignored

        try:
            shutil.copytree(src, dest, symlinks=True, ignore=ignore_problematic_files)
        except Exception as e:
            # Some files couldn't be copied (normal for system dirs)
            self.logger.debug(f"Some files in {src} could not be copied: {type(e).__name__}")
            # Create directory structure anyway
            dest.mkdir(parents=True, exist_ok=True)

    def should_exclude(self, path_str: str, exclude_patterns: List[str]) -> bool:
        """Check if path matches exclude patterns"""
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(Path(path_str).name, pattern):
                return True
        return False

    def get_file_size(self, path: Path) -> int:
        """Get file size in bytes"""
        if path.is_file():
            return path.stat().st_size
        elif path.is_dir():
            total = 0
            try:
                for item in path.rglob("*"):
                    if item.is_file():
                        total += item.stat().st_size
            except (OSError, PermissionError):
                pass
            return total
        return 0

    def format_size(self, size_bytes: int) -> str:
        """Format bytes to human readable"""
        if size_bytes == 0:
            return "0 B"

        units = ["B", "KB", "MB", "GB", "TB"]
        unit_index = 0
        size = float(size_bytes)

        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1

        return f"{size:.1f} {units[unit_index]}"


class SystemUtils:
    """System utilities"""

    @staticmethod
    def get_platform() -> str:
        """Get platform name"""
        system = platform.system().lower()
        return "macos" if system == "darwin" else system

    @staticmethod
    def which(command: str) -> bool:
        """Check if command exists"""
        return shutil.which(command) is not None

    @staticmethod
    def run_command(cmd: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
        """Run system command"""
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=True)


class BackupProvider:
    """Base backup provider"""

    def __init__(self, name: str, logger: Logger, file_manager: FileManager):
        self.name = name
        self.logger = logger
        self.file_manager = file_manager

    def backup(self, config: Dict[str, Any], backup_path: Path) -> Dict[str, Any]:
        """Override in subclasses"""
        return {"provider": self.name, "success": False}

    def restore(self, backup_path: Path, config: Dict[str, Any]) -> bool:
        """Override in subclasses"""
        return False


class FilesProvider(BackupProvider):
    """Files and directories backup provider"""

    def __init__(self, logger: Logger, file_manager: FileManager):
        super().__init__("files", logger, file_manager)
        self.home = Path.home()

    def backup(self, config: Dict[str, Any], backup_path: Path) -> Dict[str, Any]:
        if not config.get("enabled", True):
            return {"provider": self.name, "success": True, "skipped": True}

        files = config.get("files", [])
        directories = config.get("directories", [])
        exclude_patterns = config.get("exclude_patterns", [])

        stats = {"files": 0, "dirs": 0, "errors": 0, "total_size": 0}

        # Backup files
        for file_pattern in files:
            src_path = self.home / file_pattern
            if src_path.exists():
                dest_path = backup_path / file_pattern
                if self.file_manager.copy_item(src_path, dest_path):
                    stats["files"] += 1
                    stats["total_size"] += self.file_manager.get_file_size(src_path)
                    self.logger.info(f"Backed up file: {file_pattern}")
                else:
                    stats["errors"] += 1
            else:
                self.logger.warn(f"File not found: {file_pattern}")

        # Backup directories
        for dir_pattern in directories:
            src_path = self.home / dir_pattern
            if src_path.exists():
                dest_path = backup_path / dir_pattern
                if self.file_manager.copy_item(src_path, dest_path):
                    stats["dirs"] += 1
                    stats["total_size"] += self.file_manager.get_file_size(src_path)
                    self.logger.info(f"Backed up directory: {dir_pattern}")
                else:
                    stats["errors"] += 1
            else:
                self.logger.warn(f"Directory not found: {dir_pattern}")

        # Backup succeeds if 80%+ of items copied successfully
        success_rate = (stats["files"] + stats["dirs"]) / max(1, stats["files"] + stats["dirs"] + stats["errors"])
        is_successful = success_rate >= 0.8

        return {
            "provider": self.name,
            "success": is_successful,
            "stats": stats,
            "total_size_formatted": self.file_manager.format_size(stats["total_size"]),
            "success_rate": f"{success_rate:.1%}"
        }

    def restore(self, backup_path: Path, config: Dict[str, Any]) -> bool:
        if not config.get("enabled", True):
            return True

        files = config.get("files", [])
        directories = config.get("directories", [])
        restored = 0

        # Restore files
        for file_pattern in files:
            src_path = backup_path / file_pattern
            dest_path = self.home / file_pattern
            if src_path.exists():
                if self.file_manager.copy_item(src_path, dest_path):
                    self.logger.info(f"Restored file: {file_pattern}")
                    restored += 1

        # Restore directories
        for dir_pattern in directories:
            src_path = backup_path / dir_pattern
            dest_path = self.home / dir_pattern
            if src_path.exists():
                if self.file_manager.copy_item(src_path, dest_path):
                    self.logger.info(f"Restored directory: {dir_pattern}")
                    restored += 1

        self.logger.info(f"Restored {restored} items")
        return True


class HomebrewProvider(BackupProvider):
    """Homebrew backup provider"""

    def __init__(self, logger: Logger, file_manager: FileManager):
        super().__init__("homebrew", logger, file_manager)

    def backup(self, config: Dict[str, Any], backup_path: Path) -> Dict[str, Any]:
        if not config.get("enabled", True) or not SystemUtils.which("brew"):
            return {"provider": self.name, "success": True, "skipped": True}

        stats = {"brewfile": False, "formulas": 0, "casks": 0, "services": 0}
        success = True

        try:
            # Generate Brewfile
            SystemUtils.run_command([
                "brew", "bundle", "dump", "--force", "--file", str(backup_path / "Brewfile")
            ])
            stats["brewfile"] = True
            self.logger.info("Generated Brewfile")

            # Export lists
            result = SystemUtils.run_command(["brew", "list", "--formula"])
            (backup_path / "brew-formulas.txt").write_text(result.stdout)
            stats["formulas"] = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0

            result = SystemUtils.run_command(["brew", "list", "--cask"])
            (backup_path / "brew-casks.txt").write_text(result.stdout)
            stats["casks"] = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0

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
    """Fonts backup provider"""

    def __init__(self, logger: Logger, file_manager: FileManager):
        super().__init__("fonts", logger, file_manager)
        self.home = Path.home()

        # Platform-specific font paths
        if SystemUtils.get_platform() == "macos":
            self.fonts_dir = self.home / "Library" / "Fonts"
        else:
            self.fonts_dir = self.home / ".fonts"

    def backup(self, config: Dict[str, Any], backup_path: Path) -> Dict[str, Any]:
        if not config.get("enabled", True):
            return {"provider": self.name, "success": True, "skipped": True}

        if not self.fonts_dir.exists():
            return {"provider": self.name, "success": True, "stats": {"fonts": 0}}

        stats = {"fonts": 0}
        font_list = []

        font_extensions = {'.ttf', '.otf', '.woff', '.woff2', '.eot'}

        for font_file in self.fonts_dir.rglob("*"):
            if font_file.is_file() and font_file.suffix.lower() in font_extensions:
                font_list.append(font_file.name)
                stats["fonts"] += 1

        if font_list:
            (backup_path / "custom-fonts.txt").write_text('\n'.join(sorted(font_list)))
            self.logger.info(f"Listed {stats['fonts']} custom fonts")

        return {"provider": self.name, "success": True, "stats": stats}

    def restore(self, backup_path: Path, config: Dict[str, Any]) -> bool:
        # Fonts restore is typically just informational
        fonts_list = backup_path / "custom-fonts.txt"
        if fonts_list.exists():
            font_count = len(fonts_list.read_text().strip().split('\n'))
            self.logger.info(f"Font list available: {font_count} fonts (manual restore required)")
        return True


class Shelf:
    """Main backup system"""

    def __init__(self):
        self.home = Path.home()
        self.config_dir = self.home / ".config" / "shelf"
        self.backup_dir = self.home / ".local" / "share" / "shelf"

        # Auto-detect OS for profile name and check for cached profile
        self.os_name = SystemUtils.get_platform()
        self.profile_name = self._get_cached_profile_name()

        # Create directories
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # Cache the profile name for future use
        self._cache_profile_name(self.profile_name)

        # Initialize with basic logger (will be updated per operation)
        self.logger = Logger()
        self.file_manager = FileManager(self.logger)

        # Initialize providers
        self.providers = {
            "files": FilesProvider(self.logger, self.file_manager),
            "homebrew": HomebrewProvider(self.logger, self.file_manager),
            "fonts": FontsProvider(self.logger, self.file_manager)
        }

    def _get_cached_profile_name(self) -> str:
        """Get cached profile name or use OS name"""
        cache_file = self.backup_dir / ".profile_cache"

        if cache_file.exists():
            try:
                cached_name = cache_file.read_text().strip()
                if cached_name:
                    return cached_name
            except Exception:
                pass

        # Default to OS name
        return self.os_name

    def _cache_profile_name(self, profile_name: str):
        """Cache the profile name"""
        cache_file = self.backup_dir / ".profile_cache"
        try:
            cache_file.write_text(profile_name)
        except Exception:
            pass

    def _create_profile_from_template(self) -> Dict[str, Any]:
        """Create profile from OS-specific template"""
        # Load OS-specific template from current directory
        script_dir = Path(__file__).parent
        template_file = script_dir / f"{self.profile_name}.json"

        if not template_file.exists():
            self.logger.error(f"Template file not found: {template_file}")
            self.logger.error(f"Required template files: macos.json or linux.json")
            raise FileNotFoundError(f"Template file required: {template_file}")

        try:
            template_content = template_file.read_text()
            profile = json.loads(template_content)
            profile["name"] = self.profile_name
            self.logger.info(f"Using template: {template_file}")
        except Exception as e:
            self.logger.error(f"Failed to load template {template_file}: {e}")
            raise

        # Save the profile
        self.save_profile(profile)
        self.logger.info(f"Created profile: {self.profile_name}")
        return profile


    def load_profile(self, name: str) -> Dict[str, Any]:
        """Load profile from JSON config file"""
        profile_path = self.config_dir / f"{name}.json"

        if not profile_path.exists():
            # Create profile from template
            profile = self._create_profile_from_template()
            return profile

        try:
            profile = json.loads(profile_path.read_text())
        except Exception as e:
            self.logger.error(f"Failed to load profile {name}: {e}")
            raise

        return profile

    def save_profile(self, profile: Dict[str, Any]):
        """Save profile to JSON config file"""
        profile_path = self.config_dir / f"{profile['name']}.json"
        profile_path.write_text(json.dumps(profile, indent=2))

    def backup(self, target_path: Optional[str] = None) -> Dict[str, Any]:
        """Run backup"""
        # Load profile to get backup path
        profile = self.load_profile(self.profile_name)

        # Determine backup path - require explicit path
        if target_path:
            backup_path = Path(target_path).resolve()
        elif "backup_path" in profile:
            backup_path = Path(profile["backup_path"]).expanduser().resolve()
        else:
            self.logger.error("No backup path specified. Use shelf backup <path> or set 'backup_path' in profile config.")
            raise ValueError("Backup path required")

        self.logger.info(f"Backup target: {backup_path}")
        backup_path.mkdir(parents=True, exist_ok=True)

        # Setup structured logger for this backup session
        log_file = backup_path / f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ndjson"
        self.logger = Logger(log_file)

        # Log metadata as first line
        self.logger.log_metadata("backup", self.profile_name, backup_path=str(backup_path))

        self.logger.info(f"Starting backup with profile: {self.profile_name}", "backup_start")

        # Initialize git
        git_manager = GitManager(backup_path, self.logger)
        git_manager.init()

        # Run backups
        results = {
            "timestamp": datetime.now().isoformat(),
            "profile": self.profile_name,
            "success": True,
            "providers": {},
            "log_file": str(log_file)
        }

        # Execute each provider
        for provider_name, provider in self.providers.items():
            if provider_name in profile:
                self.logger.info(f"Running {provider_name} backup...")
                result = provider.backup(profile[provider_name], backup_path)
                results["providers"][provider_name] = result

                if not result.get("success", False) and not result.get("skipped", False):
                    results["success"] = False

        # Save metadata
        metadata_file = backup_path / ".backup_metadata.json"
        metadata_file.write_text(json.dumps(results, indent=2))

        # Git commit
        message = f"Backup: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        git_manager.add_all()
        if git_manager.commit(message):
            commit_hash = git_manager.get_current_commit()
            results["git_commit"] = commit_hash[:8]
            self.logger.info(f"Git commit: {commit_hash[:8]}")
        else:
            self.logger.info("No changes to commit")

        if results["success"]:
            self.logger.info("Backup completed successfully")
        else:
            self.logger.error("Backup completed with errors")

        return results

    def restore(self, commit_hash: Optional[str] = None, source_path: Optional[str] = None) -> bool:
        """Restore from backup"""
        # Load profile to get backup path
        profile = self.load_profile(self.profile_name)

        # Determine backup path
        if source_path:
            backup_path = Path(source_path).resolve()
        elif "backup_path" in profile:
            backup_path = Path(profile["backup_path"]).expanduser().resolve()
        else:
            self.logger.error("No backup path specified. Use shelf restore <commit> <path> or set 'backup_path' in profile config.")
            raise ValueError("Backup path required")

        if not backup_path.exists():
            self.logger.error(f"No backup found at: {backup_path}")
            return False

        # Git operations
        git_manager = GitManager(backup_path, self.logger)

        if commit_hash:
            try:
                git_manager.checkout(commit_hash)
                self.logger.info(f"Checked out commit: {commit_hash[:8]}")
            except subprocess.CalledProcessError:
                self.logger.error(f"Failed to checkout commit: {commit_hash}")
                return False

        self.logger.info(f"Starting restore from profile: {self.profile_name}")

        success = True

        # Execute each provider restore
        for provider_name, provider in self.providers.items():
            if provider_name in profile and profile[provider_name].get("enabled", True):
                self.logger.info(f"Restoring {provider_name}...")
                if not provider.restore(backup_path, profile[provider_name]):
                    success = False

        if success:
            self.logger.info("Restore completed successfully")
        else:
            self.logger.error("Restore completed with errors")

        return success

    def list_backups(self, source_path: Optional[str] = None, limit: int = 20):
        """List available backups from NDJSON logs"""
        # Load profile to get backup path
        profile = self.load_profile(self.profile_name)

        # Determine backup path
        if source_path:
            backup_path = Path(source_path).resolve()
        elif "backup_path" in profile:
            backup_path = Path(profile["backup_path"]).expanduser().resolve()
        else:
            self.logger.error("No backup path specified. Use shelf list <path> or set 'backup_path' in profile config.")
            return

        if not backup_path.exists():
            self.logger.info(f"No backups found at: {backup_path}")
            return

        # Find all backup log files
        log_files = sorted(backup_path.glob("backup_*.ndjson"), reverse=True)

        if not log_files:
            self.logger.info("No backup history found")
            return

        self.logger.info(f"Recent backups for profile '{self.profile_name}':")
        print("-" * 80)

        count = 0
        for log_file in log_files[:limit]:
            if count >= limit:
                break

            try:
                with open(log_file, 'r') as f:
                    first_line = f.readline().strip()
                    if first_line:
                        metadata = json.loads(first_line)
                        if metadata.get("type") == "metadata":
                            timestamp = metadata.get("timestamp", "unknown")
                            operation = metadata.get("operation", "backup")
                            session_id = metadata.get("session_id", "unknown")

                            # Parse timestamp for display
                            try:
                                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                                formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                            except:
                                formatted_time = timestamp

                            print(f"{session_id} - {operation} - {formatted_time}")
                            count += 1
            except Exception as e:
                self.logger.debug(f"Failed to read log file {log_file}: {e}")

    def status(self):
        """Show status information"""
        self.logger.info("Shelf Backup Status")
        print("=" * 50)

        print(f"Config directory: {self.config_dir}")
        print(f"Backup directory: {self.backup_dir}")
        print(f"Platform: {SystemUtils.get_platform()}")
        print(f"Profile: {self.profile_name} (auto-detected)")

        # Profile-specific info
        profile_path = self.config_dir / f"{self.profile_name}.json"
        backup_path = self.backup_dir / self.profile_name

        print(f"\nCurrent Profile: {self.profile_name}")
        print(f"Config: {profile_path}")
        print(f"Exists: {'Yes' if profile_path.exists() else 'No'}")

        if backup_path.exists():
            git_manager = GitManager(backup_path, self.logger)
            recent_commits = git_manager.log(5)
            if recent_commits:
                print(f"Recent backups:")
                for line in recent_commits.strip().split('\n'):
                    print(f"  {line}")
            else:
                print("No backup history")
        else:
            print("No backups yet")

    def init_profile(self):
        """Initialize profile for current OS"""
        profile_path = self.config_dir / f"{self.profile_name}.json"

        if profile_path.exists():
            self.logger.info(f"Profile '{self.profile_name}' already exists")
            self.logger.info(f"Edit: {profile_path}")
            return

        # Create profile from template
        profile = self._create_profile_from_template()

        self.logger.info(f"Configuration: {profile_path}")

        # Show what will be backed up
        print(f"\n{profile['description']}")
        print(f"Files: {', '.join(profile['files']['files'][:5])}{'...' if len(profile['files']['files']) > 5 else ''}")
        print(f"Directories: {', '.join(profile['files']['directories'])}")
        if profile['homebrew']['enabled']:
            print("Homebrew: enabled")
        if profile['fonts']['enabled']:
            print("Fonts: enabled")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  shelf init                     # Initialize profile")
        print("  shelf backup <path>            # Backup to path")
        print("  shelf restore [commit] [path]  # Restore from path")
        print("  shelf list [path]              # List backups at path")
        print("  shelf status                   # Show system status")
        print()
        print("Backup path must be specified explicitly or set in profile config.")
        return

    shelf = Shelf()
    command = sys.argv[1].lower()

    try:
        if command == "backup":
            path = sys.argv[2] if len(sys.argv) > 2 else None
            shelf.backup(path)

        elif command == "restore":
            commit = None
            path = None

            if len(sys.argv) > 2:
                # Check if arg looks like commit hash
                if len(sys.argv[2]) >= 8 and sys.argv[2].replace('_', '').replace('-', '').isalnum():
                    commit = sys.argv[2]
                    path = sys.argv[3] if len(sys.argv) > 3 else None
                else:
                    # First arg is path
                    path = sys.argv[2]

            shelf.restore(commit, path)

        elif command == "list":
            path = sys.argv[2] if len(sys.argv) > 2 else None
            shelf.list_backups(path)

        elif command == "init":
            shelf.init_profile()

        elif command == "status":
            shelf.status()

        else:
            print(f"Unknown command: {command}")
            print("Use 'shelf' with no arguments to see usage.")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
