### Added
- GitHub Action: `mode` input (`scan`, `audit`, `both`; default `scan`). `audit` runs `zn audit` from the npm package on agent configs, hooks, MCP servers, plugins and skills; `both` runs the scan and the audit, and runs the scan only, with a warning, when `version` is older than 1.6.0 or is a PyPI-only `.post` version. `mode: scan` keeps the previous behaviour.
- GitHub Action: `format: sarif` writes a SARIF file with one run per check and exposes it as the `sarif-file` output, for `github/codeql-action/upload-sarif`. New inputs `severity-threshold` (`critical`, `high`, `medium` or `low`; default `high`: the lowest audit severity that fails the step when `fail-on-threat` is `true`), `fail-on` (passed to `zn audit --fail-on`; overrides `fail-on-threat` and `severity-threshold` for the audit), `agents`, `sarif-file` (inside the workspace or the runner temp directory, never through a symbolic link) and `npm-integrity`; new outputs `audit-exit-code` and `sarif-file`.

### Changed
- GitHub Action: the default `version` is now 1.9.0.
- GitHub Action: `fail-on-threat` must be `true` or `false`; any other value now fails the step instead of being read as `true`.
