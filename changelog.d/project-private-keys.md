### Security
- The agent hooks: a private key kept outside `~/.ssh`, for example in a project, is refused like one in `~/.ssh`: `id_rsa`, `id_ed25519` and the other SSH key names, key stores (`.p12`, `.pfx`, `.jks`, `.ppk`), and `.pem`, `.key` or `.p8` files that hold a private key. Certificates and public keys stay readable. `POLICY_RULES_VERSION` is `2026-10-17.8`.
- The agent hooks look inside a `.env` or key file without blocking: a FIFO or other special file with such a name is refused without being read, and a name repeated in a long command is checked once.
- The agent hooks check a shell command within a time and disk budget, well below the agent's hook timeout: a command with too many paths to check in time is refused, instead of running unchecked once the agent stops waiting.
- The agent hooks refuse a shell command that chains more than 1000 commands. Earlier versions checked only the first 1000 and let the rest run unchecked.
