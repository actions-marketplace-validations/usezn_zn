### Security
- The agent hooks: a private key kept outside `~/.ssh`, for example in a project, is refused like one in `~/.ssh`: `id_rsa`, `id_ed25519` and the other SSH key names, key stores (`.p12`, `.pfx`, `.jks`, `.ppk`), and `.pem`, `.key` or `.p8` files that hold a private key. Certificates and public keys stay readable. `POLICY_RULES_VERSION` is `2026-10-17.8`.
