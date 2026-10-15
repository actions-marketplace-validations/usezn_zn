# Check that it works

After you install zn-gate for your coding agent, run:

```bash
npx -y zn-gate check
```

(or `zn-gate check` if you installed it with `npm i -g zn-gate`).

## What it does

zn-gate makes a temporary folder with a `.env` file that holds a fake key (`ZN_CHECK_EXAMPLE_KEY=zn-check-fake-value-not-a-real-key`). For each agent, it sends zn's hook the same request your agent sends when it is about to read that file, and shows you what happened.

- It works with Claude Code, Codex CLI, Cursor and OpenCode.
- For Claude Code, Codex CLI and Cursor it also runs the hook that is actually installed. This catches a hook that can no longer start, for example after the Node.js version it was installed with was removed.
- Nothing is sent over the network, no agent is started and no setting changes. The folder is deleted at the end.

## What you will see

```text
zn-gate check: does zn stop your coding agent from reading a secret?

  OK Claude Code  blocked. Your agent would be told:
     "zn: blocked reading .env: ..."
  -  Codex CLI    zn is not set up for this agent. To protect it: zn hooks install codex
  ...

Your agent cannot read secret files such as .env through these tools. Nothing was sent anywhere.
```

- **OK ... blocked**: zn is protecting that agent. The quoted text is what your agent is told when it tries.
- **- ... not set up**: zn is not installed for that agent. The line gives the command that installs it.
- **X ... NOT protected**: zn is installed but did not block, or its hook cannot start. The line says what to run to fix it.

`zn-gate check` exits with 0 only when every agent that has zn set up blocked the read.

## If your agent needs a value from `.env`

zn blocks the file because it holds secret values. To let your agent use them without seeing them, move the values into zn's vault:

```bash
zn env shadow .env
```

The file keeps markers such as `__ZN_API_KEY__` instead of the values, and zn puts the real values back only in the commands you allow. See [Secrets](secrets.md).

## Related

- `zn-gate test` runs zn's built-in rule self-test (51 examples). It checks the rules, not your agent setup.
- `zn-gate status` shows what your configuration sends over the network (nothing, unless you turned on the optional cloud check).
