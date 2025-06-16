# pa-permission-hygiene-monitor
A utility that continuously monitors permission configurations for common hygiene issues like overly permissive wildcard grants, default passwords on privileged accounts, or misconfigured access controls. Alerts on deviations from best practices. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowGuardAI/pa-permission-hygiene-monitor`

## Usage
`./pa-permission-hygiene-monitor [params]`

## Parameters
- `-h`: Show help message and exit
- `--wildcard-patterns`: No description provided
- `--privileged-users`: No description provided
- `--min-permissions`: No description provided
- `--exclude-paths`: No description provided
- `--include-offensive-tools`: Include checks for common locations of offensive tools.
- `--report-file`: Path to write the report to a file. If not specified, prints to console.

## License
Copyright (c) ShadowGuardAI
