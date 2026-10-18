### Fixed
- The guard that refuses commands loading zn-gate's own key modules now matches the module names as whole names, so a command that only loads an unrelated package such as `@acme/cloud-key-manager` or `acme-zn-gate/lib/client` is no longer refused.

### Security
- The key-protection rule now also recognises the module names when characters of the name or of the path separator before it are written as escape sequences such as `\x2f`.
