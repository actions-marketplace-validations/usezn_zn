### Security
- `zn audit` also hides the value after a credential flag in an array when a multi-line block comment, a comment longer than 1024 characters, a wide run of spaces, a literal `\n` or deeper nested escaping sits between the flag and its value.
