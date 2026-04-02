#!/usr/bin/env python3
"""
File Integrity Monitor (FIM) - Detect unauthorized file changes.

Monitors directories for file modifications, additions, and deletions
by maintaining a baseline of SHA-256 hashes. Essential for detecting
tampering, malware, and unauthorized configuration changes.

Usage:
    python fim.py init /path/to/monitor          # Create baseline
    python fim.py check /path/to/monitor          # Check for changes
    python fim.py watch /path/to/monitor          # Real-time monitoring
    python fim.py diff /path/to/monitor           # Show detailed diffs

Author: SebMRX
"""

import os
import sys
import json
import time
import hashlib
import argparse
import stat
from datetime import datetime
from pathlib import Path


BASELINE_DIR = os.path.join(os.path.expanduser("~"), ".fim")
DEFAULT_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".go", ".rs",
    ".rb", ".php", ".sh", ".bash", ".ps1", ".bat",
    ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".json", ".xml",
    ".html", ".css", ".sql",
    ".env", ".htaccess", ".gitignore",
    ".crt", ".pem", ".key",
    ".service", ".timer", ".socket",
}


def get_file_hash(filepath):
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError):
        return None


def get_file_metadata(filepath):
    """Get file metadata (size, permissions, timestamps)."""
    try:
        st = os.stat(filepath)
        return {
            "size": st.st_size,
            "mode": oct(st.st_mode),
            "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
            "created": datetime.fromtimestamp(st.st_ctime).isoformat(),
        }
    except (PermissionError, OSError):
        return None


def scan_directory(directory, extensions=None, include_all=False):
    """
    Scan directory and build file inventory with hashes.

    Returns:
        dict mapping relative file paths to their hash and metadata.
    """
    inventory = {}
    directory = os.path.abspath(directory)

    for root, dirs, files in os.walk(directory):
        # Skip hidden directories and common non-essential dirs
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".")
            and d not in ("node_modules", "__pycache__", "venv", ".venv", ".git")
        ]

        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, directory)

            # Filter by extension unless include_all
            if not include_all and extensions:
                _, ext = os.path.splitext(filename)
                if ext.lower() not in extensions:
                    continue

            file_hash = get_file_hash(filepath)
            metadata = get_file_metadata(filepath)

            if file_hash and metadata:
                inventory[rel_path] = {
                    "hash": file_hash,
                    "metadata": metadata,
                }

    return inventory


def get_baseline_path(directory):
    """Get the baseline file path for a given directory."""
    dir_hash = hashlib.md5(os.path.abspath(directory).encode()).hexdigest()[:12]
    os.makedirs(BASELINE_DIR, exist_ok=True)
    return os.path.join(BASELINE_DIR, f"baseline_{dir_hash}.json")


def save_baseline(directory, inventory):
    """Save file inventory as baseline."""
    baseline = {
        "directory": os.path.abspath(directory),
        "created": datetime.now().isoformat(),
        "file_count": len(inventory),
        "files": inventory,
    }

    path = get_baseline_path(directory)
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)

    return path


def load_baseline(directory):
    """Load existing baseline for a directory."""
    path = get_baseline_path(directory)
    if not os.path.exists(path):
        return None

    with open(path, "r") as f:
        return json.load(f)


def compare_inventories(baseline_files, current_files):
    """
    Compare baseline with current state.

    Returns:
        dict with 'added', 'removed', 'modified', 'unchanged' lists.
    """
    changes = {
        "added": [],
        "removed": [],
        "modified": [],
        "permission_changed": [],
        "unchanged": 0,
    }

    baseline_set = set(baseline_files.keys())
    current_set = set(current_files.keys())

    # New files
    for path in sorted(current_set - baseline_set):
        changes["added"].append({
            "path": path,
            "hash": current_files[path]["hash"],
            "size": current_files[path]["metadata"]["size"],
        })

    # Removed files
    for path in sorted(baseline_set - current_set):
        changes["removed"].append({
            "path": path,
            "hash": baseline_files[path]["hash"],
        })

    # Check existing files for modifications
    for path in sorted(baseline_set & current_set):
        old = baseline_files[path]
        new = current_files[path]

        if old["hash"] != new["hash"]:
            changes["modified"].append({
                "path": path,
                "old_hash": old["hash"][:16] + "...",
                "new_hash": new["hash"][:16] + "...",
                "old_size": old["metadata"]["size"],
                "new_size": new["metadata"]["size"],
            })
        elif old["metadata"]["mode"] != new["metadata"]["mode"]:
            changes["permission_changed"].append({
                "path": path,
                "old_mode": old["metadata"]["mode"],
                "new_mode": new["metadata"]["mode"],
            })
        else:
            changes["unchanged"] += 1

    return changes


def display_changes(changes, verbose=False):
    """Display detected changes with color coding."""
    red = "\033[91m"
    green = "\033[92m"
    yellow = "\033[93m"
    cyan = "\033[96m"
    bold = "\033[1m"
    reset = "\033[0m"

    total_changes = (
        len(changes["added"])
        + len(changes["removed"])
        + len(changes["modified"])
        + len(changes["permission_changed"])
    )

    print()
    print("=" * 60)
    print(f"  {bold}FILE INTEGRITY CHECK RESULTS{reset}")
    print("=" * 60)

    if total_changes == 0:
        print(f"\n  {green}[+] No changes detected. All {changes['unchanged']} files intact.{reset}")
        print()
        print("=" * 60)
        return False

    # Summary
    print(f"\n  {bold}Summary:{reset}")
    print(f"    Unchanged : {changes['unchanged']}")
    if changes["added"]:
        print(f"    {green}Added     : {len(changes['added'])}{reset}")
    if changes["removed"]:
        print(f"    {red}Removed   : {len(changes['removed'])}{reset}")
    if changes["modified"]:
        print(f"    {yellow}Modified  : {len(changes['modified'])}{reset}")
    if changes["permission_changed"]:
        print(f"    {cyan}Perms     : {len(changes['permission_changed'])}{reset}")

    # Details
    if changes["added"]:
        print(f"\n  {green}{bold}[NEW FILES]{reset}")
        for item in changes["added"]:
            print(f"    + {item['path']}  ({item['size']:,} bytes)")

    if changes["removed"]:
        print(f"\n  {red}{bold}[REMOVED FILES]{reset}")
        for item in changes["removed"]:
            print(f"    - {item['path']}")

    if changes["modified"]:
        print(f"\n  {yellow}{bold}[MODIFIED FILES]{reset}")
        for item in changes["modified"]:
            size_diff = item["new_size"] - item["old_size"]
            sign = "+" if size_diff >= 0 else ""
            print(f"    ~ {item['path']}  ({sign}{size_diff} bytes)")
            if verbose:
                print(f"      Old hash: {item['old_hash']}")
                print(f"      New hash: {item['new_hash']}")

    if changes["permission_changed"]:
        print(f"\n  {cyan}{bold}[PERMISSION CHANGES]{reset}")
        for item in changes["permission_changed"]:
            print(f"    ! {item['path']}  {item['old_mode']} → {item['new_mode']}")

    print()
    print("=" * 60)

    # Alert level
    if changes["removed"] or changes["modified"]:
        print(f"  {red}{bold}⚠  ALERT: File integrity compromised!{reset}")
    elif changes["added"]:
        print(f"  {yellow}⚠  WARNING: New files detected.{reset}")

    print()
    return True


def watch_directory(directory, interval, extensions, include_all):
    """Continuously monitor directory for changes."""
    bold = "\033[1m"
    reset = "\033[0m"

    baseline = load_baseline(directory)
    if not baseline:
        print("[!] No baseline found. Run 'init' first.")
        sys.exit(1)

    print(f"\n{bold}[*] Watching: {os.path.abspath(directory)}{reset}")
    print(f"[*] Check interval: {interval} seconds")
    print("[*] Press Ctrl+C to stop\n")

    check_count = 0
    try:
        while True:
            check_count += 1
            timestamp = datetime.now().strftime("%H:%M:%S")

            current = scan_directory(directory, extensions, include_all)
            changes = compare_inventories(baseline["files"], current)

            total_changes = (
                len(changes["added"])
                + len(changes["removed"])
                + len(changes["modified"])
                + len(changes["permission_changed"])
            )

            if total_changes > 0:
                print(f"\n[{timestamp}] Check #{check_count} — CHANGES DETECTED!")
                display_changes(changes)
            else:
                sys.stdout.write(
                    f"\r[{timestamp}] Check #{check_count} — No changes "
                    f"({changes['unchanged']} files monitored)"
                )
                sys.stdout.flush()

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n\n[*] Monitoring stopped after {check_count} checks.")


def cmd_init(args):
    """Initialize baseline for a directory."""
    directory = args.directory
    extensions = None if args.all else DEFAULT_EXTENSIONS

    print(f"\n[*] Scanning: {os.path.abspath(directory)}")
    inventory = scan_directory(directory, extensions, args.all)
    path = save_baseline(directory, inventory)

    print(f"[+] Baseline created: {len(inventory)} files indexed")
    print(f"[+] Saved to: {path}")


def cmd_check(args):
    """Check directory against baseline."""
    directory = args.directory
    extensions = None if args.all else DEFAULT_EXTENSIONS

    baseline = load_baseline(directory)
    if not baseline:
        print("[!] No baseline found. Run 'init' first.")
        sys.exit(1)

    print(f"\n[*] Checking: {os.path.abspath(directory)}")
    print(f"[*] Baseline from: {baseline['created']}")

    current = scan_directory(directory, extensions, args.all)
    changes = compare_inventories(baseline["files"], current)
    has_changes = display_changes(changes, verbose=args.verbose)

    if args.update and has_changes:
        save_baseline(directory, current)
        print("[+] Baseline updated with current state.")

    sys.exit(1 if has_changes else 0)


def cmd_watch(args):
    """Start real-time monitoring."""
    extensions = None if args.all else DEFAULT_EXTENSIONS
    watch_directory(args.directory, args.interval, extensions, args.all)


def cmd_status(args):
    """Show baseline info."""
    baseline = load_baseline(args.directory)
    if not baseline:
        print("[!] No baseline found for this directory.")
        return

    print(f"\n  Directory  : {baseline['directory']}")
    print(f"  Created    : {baseline['created']}")
    print(f"  Files      : {baseline['file_count']}")

    total_size = sum(
        f["metadata"]["size"] for f in baseline["files"].values()
    )
    print(f"  Total size : {total_size:,} bytes")
    print(f"  Baseline   : {get_baseline_path(args.directory)}")


def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor - Detect unauthorized file changes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fim.py init /var/www/html
  python fim.py check /var/www/html
  python fim.py check /var/www/html --verbose --update
  python fim.py watch /var/www/html --interval 30
  python fim.py status /var/www/html
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    subparsers.required = True

    # init
    p_init = subparsers.add_parser("init", help="Create file baseline")
    p_init.add_argument("directory", help="Directory to monitor")
    p_init.add_argument("--all", action="store_true", help="Include all file types")
    p_init.set_defaults(func=cmd_init)

    # check
    p_check = subparsers.add_parser("check", help="Check for changes")
    p_check.add_argument("directory", help="Directory to check")
    p_check.add_argument("--all", action="store_true", help="Include all file types")
    p_check.add_argument("-v", "--verbose", action="store_true", help="Show hash details")
    p_check.add_argument("--update", action="store_true", help="Update baseline after check")
    p_check.set_defaults(func=cmd_check)

    # watch
    p_watch = subparsers.add_parser("watch", help="Real-time monitoring")
    p_watch.add_argument("directory", help="Directory to watch")
    p_watch.add_argument("--all", action="store_true", help="Include all file types")
    p_watch.add_argument(
        "--interval", type=int, default=10, help="Check interval in seconds [default: 10]"
    )
    p_watch.set_defaults(func=cmd_watch)

    # status
    p_status = subparsers.add_parser("status", help="Show baseline info")
    p_status.add_argument("directory", help="Directory to query")
    p_status.set_defaults(func=cmd_status)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
