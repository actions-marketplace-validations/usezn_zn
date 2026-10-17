# Turn on the optional cloud check

```bash
npx -y zn-gate connect
```

(or `zn-gate connect` if you installed it with `npm i -g zn-gate`).

zn-gate works fully on your computer, needs no account and sends nothing. This command is optional. It adds one thing: when you or your agent use the `analyze_prompt` tool (or `zn-gate analyze`), the text, with detected secrets hidden first, is also checked by the Galvanize 2 classifier at usezn.com. Hooks, file and secret protection, the shield and every other command stay local and never use it.

## What `zn-gate connect` does

1. It only runs in a terminal you are typing in. If an AI agent started it, it refuses.
2. It tells you what will change and asks you to confirm.
3. It opens https://usezn.com/connect in your browser. Create a free account (or log in) and create an API key there.
4. Back in the terminal, paste the key at the hidden prompt. Nothing you type is shown, and the key is never taken from the command line or an environment variable.
5. It checks the key once with https://api.usezn.com (only the key is sent, as a request header, to that one address, over a verified TLS connection). A key the server rejects is not saved.
6. It saves the key, and prints the last four characters so you can recognise it.

## Where the key is kept

Only in one of these, never in a file:

- **Your system keychain**: the macOS Keychain, the Windows Credential Manager, or the Linux Secret Service (GNOME Keyring, KWallet).
- **The zn vault**, when your system has no keychain and the vault is unlocked (`zn unlock`). The vault encrypts it.

If neither is available (for example Linux without a desktop session), nothing is saved and `zn-gate connect` says so. You can still set `ZN_CLOUD=1` and `ZN_API_KEY` in your shell yourself, as before.

`~/.zn/config.json` records only that you connected, where the key is kept and its last four characters. It never holds the key.

Your agent cannot read the key. zn's hooks refuse commands that ask the system keychain for zn's own entries (`security find-generic-password`, `secret-tool lookup`, `cmdkey /list`, `Get-StoredCredential` with zn's name), they already keep `~/.zn` out of reach, and zn hides the key's format (`zn_` followed by 48 characters) in anything the agent would see. Other uses of those tools are not affected.

## See and change the state

- `zn-gate status` shows whether a key is connected and where it comes from (`ZN_API_KEY`, `--key`, the keychain or the vault), never the key.
- `zn-gate connect --reconnect` replaces the saved key.
- `zn-gate disconnect` removes the key from this computer and turns the cloud check off. It then offers to revoke the key on usezn.com so it stops working everywhere (you confirm). If the server cannot revoke it from here, it tells you to do it at usezn.com/api-keys.
- A key in `--key` or `ZN_API_KEY` is used instead of the saved one. `ZN_LOCAL_ONLY=true` or `--local-only` turns the cloud check off even when connected.

## What is sent

Only the text of `analyze_prompt` and `zn-gate analyze` calls, after zn-gate removed the secrets it detects (personal data is not removed on this path), and the key as a request header. Tool output, tool-call arguments and tool descriptions are never sent. `zn-gate status` shows the state at any time. See also [What leaves your machine](../README.md#what-leaves-your-machine).
