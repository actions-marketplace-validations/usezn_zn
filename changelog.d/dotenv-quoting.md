### Security
- The agent hooks: a `.env` file with values is refused when a shell command names it with bash `$'...'` quoting (`cat $'\x2eenv'`), through an input redirection with a descriptor number (`cat 0<.env`) or as the value of a `name=value` argument (`dd if=.env`). `POLICY_RULES_VERSION` is `2026-10-17.6`.
