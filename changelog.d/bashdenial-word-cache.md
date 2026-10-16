### Fixed
- The agent hooks check a long shell command faster: each word is looked up once per command, so a command of 80 KB that repeats its words takes well under a second instead of up to three. `POLICY_RULES_VERSION` is `2026-10-16.6`.
