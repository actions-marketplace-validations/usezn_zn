# Performance of the agent hooks

Each time a coding agent calls a tool, it starts zn's hook and waits for it: once before the call (for
example a shell command) and once after it, with the tool's output. This page says how long that takes and
how it is measured.

## How it is measured

`bench/hook_latency_matrix.js` starts `node lib/hooks/runner.js <agent>` with the agent's event on stdin,
exactly as the agent does, and times it until the process exits:

- Claude Code and Codex CLI: `PreToolUse` for a shell command, and `PostToolUse` with shell output.
- Cursor: `beforeShellExecution`, and `postToolUse` with MCP output (Cursor only lets zn rewrite MCP
  output; see [compat.md](compat.md)).
- Outputs of 1 KB, 100 KB (also with two secrets in it) and 1000 KB of source-like text.
- The vault is locked, so detected values are redacted for good and no background process is involved.
- Each case runs 20 times after one warm-up run. Fake values are generated for the run; a case fails if one
  of them comes back from the hook.

```bash
cd packages/zn-gate && npm ci --ignore-scripts && cd ../..
node bench/hook_latency_matrix.js --runs 20
```

Most of the time is Node.js starting: a bare `node -e ""` is measured between the samples of every case,
and each result is also given as its p95 divided by that start-up time.

## Results

GitHub Actions `ubuntu-latest` runner (4 vCPU AMD EPYC 7763), Node.js 22.23, 2026-10-17. Times in
milliseconds; a bare `node -e ""` takes 23.8 ms (p50).

| Agent | Event | p50 | p95 |
|---|---|---|---|
| Claude Code | PreToolUse, shell command | 50.9 | 62.8 |
| Codex CLI | PreToolUse, shell command | 50.6 | 52.9 |
| Cursor | beforeShellExecution | 49.9 | 53.7 |
| Claude Code | PostToolUse, 1 KB of output | 60.3 | 64.5 |
| Codex CLI | PostToolUse, 1 KB | 59.6 | 61.7 |
| Cursor | postToolUse (MCP), 1 KB | 59.9 | 62.4 |
| Claude Code | PostToolUse, 100 KB | 64.9 | 66.8 |
| Codex CLI | PostToolUse, 100 KB | 65.7 | 67.7 |
| Cursor | postToolUse (MCP), 100 KB | 65.5 | 71.2 |
| Claude Code | PostToolUse, 100 KB with 2 secrets | 70.4 | 73.7 |
| Codex CLI | PostToolUse, 100 KB with 2 secrets | 70.6 | 74.1 |
| Cursor | postToolUse (MCP), 100 KB with 2 secrets | 71.1 | 75.2 |
| Claude Code | PostToolUse, 1000 KB | 81.8 | 100.7 |
| Codex CLI | PostToolUse, 1000 KB | 82.3 | 85.3 |
| Cursor | postToolUse (MCP), 1000 KB | 85.1 | 89.2 |

On a slower machine every number grows by about the same factor as Node's own start-up.
[`bench/HOOK_LATENCY.md`](../bench/HOOK_LATENCY.md) has earlier measurements with the vault unlocked and a
breakdown of where the time goes.

OpenCode is not in the table: its zn plugin runs inside the OpenCode process, so no hook process is started.

## The budget in CI

The `Hook latency` workflow runs this benchmark on every pull request that changes the hook code. It fails
when a case's p95, divided by Node's start-up in the same run, is more than 20 % above
`bench/hook_latency_baseline.json`. A case over the limit is measured again with twice the samples first,
so one slow sample does not fail it. A deliberate change of the baseline is a commit of its own:
`node bench/hook_latency_gate.js report.json --update-baseline`.
