### Fixed
- The agent hooks on Windows: a PowerShell command that already runs through `zn-gate run -- ...` with a secret placeholder is left as it is. Before, `zn-gate` was taken for a PowerShell cmdlet because of its name and the command was refused (`zn run -- ...` worked).
