### Fixed
- The guard that stops a command from loading zn-gate's own key code now also catches upper-case paths, Windows-style `vault\keychain` paths and paths with `./` segments, such as `zn-gate/./lib/client`.
