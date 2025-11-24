<div align="center">

<br>

<img src="logo.png" alt="Shelf Logo" width="120" height="120"/>

# Shelf

### A stupidly simple backup tool

**Single file • Zero dependencies • Auditable • Reliable**

[![PyPI version](https://img.shields.io/pypi/v/shelf-backup.svg)](https://pypi.org/project/shelf-backup/)
[![Python versions](https://img.shields.io/pypi/pyversions/shelf-backup.svg)](https://pypi.org/project/shelf-backup/)
[![Downloads](https://img.shields.io/pypi/dm/shelf-backup.svg)](https://pypi.org/project/shelf-backup/)
[![License](https://img.shields.io/pypi/l/shelf-backup.svg)](https://github.com/rdyv/shelf/blob/main/LICENSE)

[Install](#installation) • [Quick Start](#quick-start) • [Features](#features) • [Documentation](#documentation)

</div>

---

Shelf is a backup tool that is configurable and extensible. It backs up your dotfiles, config files, scripts, random directories etc to a git repository that you can upload to Github private remote.

**One auditable Python file** ([shelf.py](shelf.py)) contains all the logic for backup and restore. It auto-detects OS (macOS/Linux) and uses correct template ([macos.toml](macos.toml) or [linux.toml](linux.toml)) for configuration. Each backup session creates detailed structured NDJSON logging for auditability. The following is an example of sources that are enabled for backup:

- **Dotfiles**: `.zshrc`, `.gitconfig`, `.ssh/config`, etc.
- **App Configs**: VSCode, Vim, tmux, git settings
- **System Prefs**: macOS dock, finder, terminal settings (via plist files)
- **Package Managers**: Homebrew formulas, casks, taps, and services
- **Custom Fonts**: Your installed font collection
- **Recursive Directories**: Automatically backup specific subdirectories from multiple projects

## Quick Start

```bash
# Install
pip install shelf-backup

# Initialize profile
shelf init

# Backup to specific directory
shelf backup ~/my-backups

# Optional: customize what gets backed up
vim ~/.config/shelf/macos.toml

# Restore from backup
shelf restore
```

## Documentation

<details>
<strong>Advanced Commands</strong>

```bash
# Backup with git push
shelf backup ~/my-backups --push

# Dry-run restore (preview without making changes)
shelf restore --dry-run

# Restore from specific commit
shelf restore abc1234

# Restore from different location
shelf restore ~/different-backup

# Show backup history
shelf list

# Check system status
shelf status
```

</details>

<details>
<strong>File Locations</strong>

```
~/.config/shelf/           # Configuration files (TOML)
~/.local/share/shelf/      # Backup data (git repositories)
  └── logs/                # Backup logs (NDJSON)
```

</details>

<details>
<strong>Requirements</strong>

- Python 3.11+
- `git` command (for versioning)
- `brew` command (for Homebrew backups on macOS)

No pip packages, no external libraries.

</details>

## Configuration

Shelf uses a single TOML config file per machine at `~/.config/shelf/{os}.toml`. The config is automatically created from templates (`macos.toml` or `linux.toml`) shipped with the package, which provide sensible defaults. You can customize it to your needs.

### Config Structure

```toml
[backup]
path = "~/my-backups"
ignore_patterns = ["*.log", "*.tmp", "node_modules/", "*.so", "*.dylib"]

[git]
enabled = true
auto_commit = true
auto_push = false
commit_message = "Backup: {timestamp}"
branch = "main"

[providers.files]
enabled = true
paths = [
    "~/.zshrc",
    "~/.gitconfig",
    "~/.ssh/config",
    "~/.config/nvim",
    "~/.config/tmux"
]

# Recursive backups from multiple parent directories
# [providers.files.recursive]
# "~/Developer/github" = ["_scripts", ".github", "config"]
# "~/Developer/projects" = ["scripts", "docs"]

[providers.homebrew]
enabled = true
brewfile = true
formulas = true
casks = true
services = true
taps = true

[providers.fonts]
enabled = true
custom_fonts_only = true
system_fonts = false
```

### Configuration Options

**Backup Settings:**
- **backup.path**: Where backups are stored (supports `~` and relative paths)
- **backup.ignore_patterns**: Global patterns to exclude from backups

**Git Settings:**
- **git.enabled**: Enable git versioning
- **git.auto_commit**: Automatically commit after backup
- **git.auto_push**: Automatically push to remote after commit
- **git.commit_message**: Commit message template (supports `{timestamp}`, `{date}`, `{time}`)
- **git.branch**: Git branch to use

**Providers:**
- **providers.files.paths**: Files and directories to backup (auto-detected)
- **providers.files.recursive**: Map parent directories to subdirectories to recursively backup
- **providers.homebrew.enabled**: Backup Homebrew packages (macOS only)
- **providers.fonts.enabled**: List installed custom fonts

### Backup Logs and History

Each backup session creates detailed NDJSON structured logs with metadata, timing, and results:

```bash
# View backup history
shelf list

# Example output:
# 20250122_143052 - backup - 2025-01-22 14:30:52
# 20250121_091234 - backup - 2025-01-21 09:12:34
# 20250120_160845 - backup - 2025-01-20 16:08:45
```

**Log files contain:**

- Session metadata (timestamp, platform, operation type)
- File and directory backup results
- Error details and warnings
- Git commit information
- Provider statistics (files copied, sizes, errors)

**Log location:** `{backup_path}/logs/backup_YYYYMMDD_HHMMSS.ndjson`

Each log entry is a complete JSON object on its own line, making them easy to parse with tools like `jq` or analyze programmatically.

---

<div align="center">

**[Install Now](https://pypi.org/project/shelf-backup/)** • **[Report Issues](https://github.com/rdyv/shelf/issues)**

_Made for developers who value simplicity_

</div>
