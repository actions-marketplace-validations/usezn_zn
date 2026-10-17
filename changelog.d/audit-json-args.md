### Fixed
- `zn audit` hides a secret value given as the next item of a JSON array after a credential flag, as in the arguments of an MCP server: `"args": ["--api-key", "..."]`. Earlier versions could quote it in the evidence of a finding.
