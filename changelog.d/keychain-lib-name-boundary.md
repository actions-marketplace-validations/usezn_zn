### Fixed
- The guard that refuses commands loading zn-gate's own key modules now matches the module names as whole names, so a command that only loads an unrelated package such as `@acme/cloud-key-manager` or `acme-zn-gate/lib/client` is no longer refused.
