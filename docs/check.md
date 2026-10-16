# Check that it works

After you install zn-gate for your coding agent, run:

```bash
npx -y zn-gate check
```

(or `zn-gate check` if you installed it with `npm i -g zn-gate`).

## What it does

zn-gate makes a temporary folder with two files: a `.env` file that holds a fake key (`ZN_CHECK_EXAMPLE_KEY=zn-check-fake-value-not-a-real-key`) and an ordinary `README.txt`. For each agent set up for your user, it asks zn's hook to let the agent read each file, the same way your agent asks. An agent counts as protected only when the `.env` file is blocked and the ordinary file is allowed.

- **Claude Code**: zn-gate checks the zn-gate plugin, or the hooks of `zn hooks install claude-code`. It also notices when the plugin is turned off and when a Claude Code setting turns hooks off.
- **Codex CLI and Cursor**: zn-gate checks the hooks of `zn hooks install`.
- **What it runs**: for Claude Code, Codex CLI and Cursor it runs the hook that is installed, exactly as your agent would. On Windows, a hook installed as `zn hook <agent>` is not started; zn-gate checks zn's rules for it instead and says so in the output. A hook that cannot start, or that blocks every file because part of zn is missing, is reported as **NOT protected**.
- **OpenCode**: zn-gate checks zn's rules. The zn plugin runs inside OpenCode, so it is not started here.
- **What it leaves alone**: it checks the setup for your user. A setup made for one project only (`--project`) is listed but not run.
- **Nothing changes**: nothing is sent over the network, no agent is started and no setting changes. The folder is deleted at the end.

## What you will see

```text
zn-gate check: does zn stop your coding agent from reading a secret?

  OK Claude Code  blocked the .env file and allowed the ordinary file. Your agent would be told:
     "zn: ..."
  -  Codex CLI    zn is not set up for this agent. To protect it, run `zn hooks install codex` in your own terminal.
  ...

Your agent cannot read secret files such as .env through these tools. Nothing was sent anywhere.
```

- **OK**: zn is protecting that agent. The quoted text is what your agent is told when it tries to read the file.
- **-**: zn is not set up for that agent, or only for one project. The line gives the command that sets it up for your user.
- **X ... NOT protected**: zn is set up but would not protect the agent. The line says why and what to run to fix it. When a hook cannot start because the Node.js it was installed with is gone (for example after `nvm uninstall`), the fix is a fresh `npm install -g zn-gate` and then `zn hooks install <agent>`, since the old Node.js took its `zn` with it.

`zn-gate check` exits with 0 only when every agent that is set up for your user is protected.

## If your agent needs a value from `.env`

zn blocks the file because it holds secret values. To let your agent use them without seeing them, move the values into zn's vault:

```bash
zn env shadow .env
```

The file keeps markers such as `__ZN_API_KEY__` instead of the values, and zn puts the real values back only in the commands you allow. See [Secrets](secrets.md).

## Related

- `zn-gate test` runs zn's built-in rule self-test (51 examples). It checks the rules, not your agent setup.
- `zn-gate status` shows what your configuration sends over the network (nothing, unless you turned on the optional cloud check).
