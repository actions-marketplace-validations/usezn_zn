### Security
- `zn audit` hides, in its text, JSON and SARIF reports, the value that follows a credential flag in an array of arguments (for example `"args": ["--api-key", "VALUE"]` or `args = ['--token', 'VALUE']`), whatever its format. This now also covers single-quoted TOML items and arrays written one item per line, where the flag and its value sit on different lines.
