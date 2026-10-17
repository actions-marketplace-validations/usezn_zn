### Security
- The agent hooks: reading a `.env` or credential file from the git repository (`git show HEAD:.env`, `git cat-file -p :app/.env`) is refused, like reading it from disk. `POLICY_RULES_VERSION` is `2026-10-17.7`.
