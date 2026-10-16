### Added
- `zn-gate scan`, the agent hooks and the Python package also find Square access tokens and OAuth secrets (`EAAA...`, `sq0atp-...`, `sq0csp-...`) and Discord bot tokens. A Discord token counts only when its first part encodes a numeric bot id, so dotted random strings are not reported. `RULES_VERSION` is `2026-10-16.7`.
