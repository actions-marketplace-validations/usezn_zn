### Security
- The agent hooks: a shell command that names a `.env` file in a subfolder through a wildcard (`cat app*/.env`, `cat src/*/.env`, `cat {a,b}/.env`) is refused, like the plain path. Earlier versions let it run, because the file was looked for under the pattern itself and not found. `POLICY_RULES_VERSION` is `2026-10-17.3`.
