### Changed
- `zn-gate init` no longer installs the Claude Code plugin when Node.js is older than 20.12, which the plugin needs: it sets up zn's hooks for Claude Code instead and says so in one line, and `zn-gate check` reports an installed plugin on such a Node.js with the way out.
