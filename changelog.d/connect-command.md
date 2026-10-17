### Added
- `zn-gate connect` turns on the optional cloud check for `analyze_prompt` from your own terminal. It opens usezn.com, you paste an API key at a hidden prompt, and the key is kept in your system keychain or the zn vault, never in a file. `zn-gate disconnect` removes it and offers to revoke it. `zn-gate status` shows whether a key is connected and where it comes from, without showing it. Nothing changes until you run it: zn-gate still needs no account and sends nothing by default. See [docs/connect.md](docs/connect.md).
- A zn API key (`zn_` followed by 48 characters) is now recognised by the scrubber and hidden like other provider keys.

### Security
- The hooks refuse commands that ask the system keychain for zn's own entries (`security find-generic-password`, `secret-tool lookup`, `cmdkey /list`, `Get-StoredCredential` with zn's service or target name), so an agent cannot read the API key saved by `zn-gate connect` or the vault key. The same tools stay free for other entries.
