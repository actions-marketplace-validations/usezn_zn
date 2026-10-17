### Fixed
- The hook no longer refuses a command that writes a file from a here-document (`cat > file <<'EOF'`) when the body holds a `*` or another glob character, and it checks a 100 KB body in a few milliseconds instead of tens of milliseconds.
- A here-document body is only read as data for a plain data command. Bodies a shell, an interpreter or `xargs` runs, bodies piped to a shell or inside a group, a script the same command writes and then runs, and every read of `.env` or a credential file on the command line, are still refused.
