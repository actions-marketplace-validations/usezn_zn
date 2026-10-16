### Fixed
- The agent hooks check a long shell command faster: each word is looked up once per command, so a command of 80 KB that repeats its words takes well under a second instead of several seconds. A hook that runs out of time lets the command go ahead unchecked, so this also keeps long commands checked. `POLICY_RULES_VERSION` is `2026-10-16.6`.
