### Fixed
- Internal safety default in the vault: the function that deletes the vault key no longer touches the shared keychain entry when it has no record of which keychain this vault uses, unless the caller names one. Nothing in `zn-gate` calls it today, so there is no change for users.
