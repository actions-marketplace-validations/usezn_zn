### Fixed
- The hook no longer refuses a command that writes a file from a here-document (`cat > file <<'EOF'`) when the body holds a `*` or another glob character, and it checks a 100 KB body in a few milliseconds instead of tens of milliseconds. Reads of `.env` and credential files on the command line, and here-documents that a shell or an interpreter runs, are still refused.
