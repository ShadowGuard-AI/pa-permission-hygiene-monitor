# pa-permission-hygiene-monitor
A utility that checks permission configurations for common hygiene issues: files and directories whose modes meet or exceed a threshold, matched by glob patterns, and, on request, files named like common offensive tools. It reports what it finds; it does not check passwords or account settings. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowGuard-AI/pa-permission-hygiene-monitor`

## Usage
`python3 main.py PATH [options]`

## Parameters
- `-h`: Show help message and exit
- `PATH`: (required) The path to monitor (e.g., /var/www).
- `--wildcard-patterns`: Glob patterns matched against each entry name and full path, in one-or-more form. A custom pattern such as `*.txt` matches entries whose name or path ends in `.txt`. Defaults to ['*'].
- `--min-permissions`: Minimum permission value considered overly permissive, given as an octal value such as `755`, `0755`, or `0o755`. Defaults to 0777.
- `--exclude-paths`: Paths to exclude from the check (e.g., /tmp, /var/log), in one-or-more form. Defaults to an empty list.
- `--include-offensive-tools`: Include checks for common locations of offensive tools.
- `--report-file`: Path to write the report to a file. If not specified, prints to console. The report file must be outside the scanned path; a report path inside the scanned tree is refused with exit 1.

## Behaviour notes
- Both files and subdirectories under the scanned path are checked against the threshold. The scanned root itself is not counted as an entry.
- This tool has no default password check and no privileged account check. An earlier `--privileged-users` option was parsed and never used, and it has been removed.
- If no entry is actually checked, for example an empty directory or patterns that match nothing, the tool reports that nothing was checked and exits non-zero instead of printing a clean result.

## License
See LICENSE.
