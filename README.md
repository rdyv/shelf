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

**One auditable Python file** ([shelf.py](shelf.py)) contains all the logic for backup and restore. It auto-detects OS (macOS/Linux) and uses correct template ([macos.json](macos.json) or [linux.json](linux.json)) for configuration. Each backup session creates detailed structured NDJSON logging for auditability. The following is an example of sources that are enabled for backup:

- **Dotfiles**: `.zshrc`, `.gitconfig`, `.ssh/config`, etc.
- **App Configs**: VSCode, Vim, tmux, git settings
- **System Prefs**: macOS dock, finder, terminal settings
- **Package Managers**: Homebrew formulas and casks
- **Custom Fonts**: Your installed font collection

## Quick Start

```bash
# Install
pip install shelf-backup

# Initialize profile
shelf init

# Backup to specific directory
shelf backup ~/my-backups

# Optional: customize what gets backed up
vim ~/.config/shelf/macos.json

# Restore from backup
shelf restore
```

## Documentation

<details>
<strong>Advanced Commands</strong>

```bash
# Restore from specific commit
shelf restore abc1234

# Restore from different location
shelf restore ~/different-backup

# Show backup history at specific path
shelf list ~/my-backups

# Check system status
shelf status
```

</details>

<details>
<strong>File Locations</strong>

```
~/.config/shelf/           # Configuration files (JSON)
~/.local/share/shelf/      # Backup data (git repositories)
```

</details>

<details>
<strong>Requirements</strong>

- Python 3.8+
- `git` command (for versioning)
- `brew` command (for Homebrew backups on macOS)

No pip packages, no external libraries.

</details>

## Configuration

Shelf uses a single JSON config file per machine at `~/.config/shelf/{os}.json`. The config is automatically created from templates (`macos.json` or `linux.json`) but can be customized to your needs.

### Config Structure

```json
{
	"name": "macos",
	"description": "macOS system backup profile",
	"backup_path": "~/my-backups",
	"files": {
		"enabled": true,
		"files": [".zshrc", ".gitconfig", ".ssh/config"],
		"directories": [
			".config/nvim",
			".config/tmux",
			"Library/Preferences/com.apple.dock.plist"
		],
		"exclude_patterns": ["**/.git/**", "**/node_modules/**", "**/*.log"]
	},
	"homebrew": {
		"enabled": true
	},
	"fonts": {
		"enabled": true
	}
}
```

### Configuration Options

1. **backup_path**: Where backups are stored (supports `~` expansion)
1. **files.files**: Individual files to backup (relative to home directory)
1. **files.directories**: Entire directories to backup (relative to home directory)
1. **files.exclude_patterns**: Glob patterns to skip during backup
1. **homebrew.enabled**: Backup Homebrew packages and Brewfile (macOS only)
1. **fonts.enabled**: List installed custom fonts

### Backup Logs and History

Each backup session creates detailed NDJSON structured logs with metadata, timing, and results:

```bash
# View backup history
shelf list ~/my-backups

# Example output:
# 20250122_143052 - backup - 2025-01-22 14:30:52
# 20250121_091234 - backup - 2025-01-21 09:12:34
# 20250120_160845 - backup - 2025-01-20 16:08:45
```

**Log files contain:**

- Session metadata (timestamp, platform, hostname)
- File and directory backup results
- Error details and warnings
- Git commit information
- Provider statistics (files copied, sizes, etc.)

**Log location:** `{backup_path}/backup_YYYYMMDD_HHMMSS.ndjson`

Each log entry is a complete JSON object on its own line, making them easy to parse with tools like `jq` or analyze programmatically.

---

<div align="center">

**[Install Now](https://pypi.org/project/shelf-backup/)** • **[Report Issues](https://github.com/rdyv/shelf/issues)**

_Made for developers who value simplicity_

</div>
