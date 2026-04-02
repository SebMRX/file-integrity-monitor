# File Integrity Monitor

monitors directories for file changes by keeping sha256 hash baselines. if someone modifes, adds or deletes a file you'll know about it

## usage

```
# create baseline first
python fim.py init /path/to/monitor

# check for changes
python fim.py check /path/to/monitor

# realtime monitoring (checks every 10sec)
python fim.py watch /path/to/monitor
python fim.py watch /path/to/monitor --interval 30

# see baseline info
python fim.py status /path/to/monitor
```

## what it detects

- new files added
- files deleted
- file content modified (hash comparison)
- permission changes

usefull for monitoring web servers, config files, detecting malware etc

returns exit code 1 when changes found so you can use it in cron jobs

no dependencies, just python3
