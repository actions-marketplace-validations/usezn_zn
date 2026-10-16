### Fixed
- A database URL whose password is only a reference to a name (`postgres://${PGUSER}:${PGPASSWORD}@db/app`, `$PASS`, `%PASS%`, `<password>`, `{{ password }}`, with the name in upper or lower case) is no longer reported or redacted as a secret, in Node.js and Python alike; a value that looks random is still treated as a password. `RULES_VERSION` is `2026-10-16.5`.
