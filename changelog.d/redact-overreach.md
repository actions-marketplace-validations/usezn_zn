### Fixed
- `zn audit`: when it hides a secret value in escaped JSON (`{\"password\":\"...\",\"user\":\"...\"}`), it hides only that value and keeps the next fields, and a URL after a flag such as `-url:` is no longer taken for `-u user:password`.
