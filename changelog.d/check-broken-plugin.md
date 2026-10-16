### Fixed
- `zn-gate check` and `zn-gate init` with the zn-gate plugin and the hooks of `zn hooks install claude-code` both set up: when the plugin does not work (for example on a Node.js the plugin does not support), the fix is to turn the plugin off with `claude plugin disable zn-gate@usezn`, which keeps zn's own hooks, instead of removing the hooks that still work.
