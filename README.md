# File Integrity Monitor (FIM)

A security tool that detects unauthorized file modifications by maintaining SHA-256 hash baselines and comparing against current state.

## Features

- **SHA-256 hash-based** file integrity verification
- **Real-time watch mode** with configurable intervals
- **Change detection**: additions, deletions, modifications, permission changes
- **Smart filtering**: monitors code and config files by default
- **Baseline management**: create, check, update, and query baselines
- **Color-coded alerts** for different severity levels
- **Exit codes** for scripting integration (0 = clean, 1 = changes detected)

## Installation

```bash
git clone https://github.com/SebMRX/file-integrity-monitor.git
cd file-integrity-monitor
```

No external dependencies — uses only Python standard library.

## Usage

### Create a baseline
```bash
python fim.py init /var/www/html
python fim.py init /etc --all    # Include all file types
```

### Check for changes
```bash
python fim.py check /var/www/html
python fim.py check /var/www/html --verbose    # Show hash details
python fim.py check /var/www/html --update     # Update baseline after check
```

### Real-time monitoring
```bash
python fim.py watch /var/www/html
python fim.py watch /var/www/html --interval 30    # Check every 30 seconds
```

### View baseline info
```bash
python fim.py status /var/www/html
```

## Example Output

```
============================================================
  FILE INTEGRITY CHECK RESULTS
============================================================

  Summary:
    Unchanged : 142
    Added     : 2
    Removed   : 1
    Modified  : 3

  [NEW FILES]
    + uploads/shell.php  (1,337 bytes)
    + tmp/backdoor.py  (4,521 bytes)

  [REMOVED FILES]
    - config/firewall.conf

  [MODIFIED FILES]
    ~ index.html  (+45 bytes)
    ~ .htaccess  (+120 bytes)
    ~ config/database.yml  (-8 bytes)

============================================================
  ⚠  ALERT: File integrity compromised!
```

## Use Cases

- **Web server monitoring**: Detect defacement or webshell uploads
- **Configuration auditing**: Track changes to system config files
- **Malware detection**: Identify unauthorized binary modifications
- **Compliance**: Meet file integrity monitoring requirements (PCI-DSS, HIPAA)
- **Incident response**: Determine scope of compromise

## How It Works

1. **`init`** — Walks the target directory, computes SHA-256 hashes for all matching files, and stores the baseline in `~/.fim/`
2. **`check`** — Rescans and compares against baseline, reporting any differences
3. **`watch`** — Runs `check` in a loop at the specified interval
4. **Exit code 1** when changes are detected — useful in CI/CD or cron jobs

## License

MIT License
