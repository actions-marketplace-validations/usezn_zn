'use strict';

/**
 * zn-gate init: the guided setup. It finds the coding agents on this machine,
 * checks which ones zn already protects (lib/check.js), and for each one that
 * is not protected shows the one route that protects it:
 *   - Claude Code: the zn-gate plugin (two `claude plugin` commands);
 *   - Codex CLI, Cursor, OpenCode: `zn hooks install <agent>`, from a global
 *     install of zn-gate (hooks never point into the npx cache, which npm can
 *     delete).
 * In your own terminal it offers to run each step, one confirmation each.
 * Without a terminal, or when an AI agent runs it, it only prints the steps:
 * installing hooks stays a person's decision. It ends with `zn-gate check`.
 *
 * The previous behaviour of `init` (wrapping the MCP servers you already use
 * with the zn-gate proxy) is `zn-gate init --wrap-mcp`.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const PKG_ROOT = path.join(__dirname, '..');
const VERSION = require('../package.json').version;

/* zn-gate is running from the npx cache (or another temporary copy) rather than a global install. */
function fromNpx(dir = __dirname) {
  return /[\\/]_npx[\\/]/.test(dir);
}

/* The plan: [{id, name, found, state, steps: [{label, file, args}]}]. */
async function plan(opts = {}) {
  const { getAdapter } = require('./agents');
  const { check } = require('./check');
  const env = opts.env || process.env;
  const home = opts.home;
  const res = await check({ home, env, cwd: opts.cwd });
  const npx = opts.npx !== undefined ? opts.npx : fromNpx();
  const out = [];
  for (const r of res.results) {
    const found = r.state !== 'not-set-up' || getAdapter(r.id).detect({ home, env });
    const item = { id: r.id, name: r.name, found, state: r.state, problem: r.problem || '', steps: [] };
    if (found && r.state !== 'protected') {
      if (r.id === 'claude-code') {
        item.steps.push({ label: 'add the usezn plugin marketplace', file: 'claude', args: ['plugin', 'marketplace', 'add', 'usezn/zn'] });
        item.steps.push({ label: 'install the zn-gate plugin', file: 'claude', args: ['plugin', 'install', 'zn-gate@usezn'] });
      } else {
        if (npx) item.steps.push({ label: 'install zn-gate ' + VERSION + ' for your user', file: 'npm', args: ['install', '-g', 'zn-gate@' + VERSION] });
        item.steps.push({ label: 'install zn\'s hooks for ' + r.name, file: 'zn', args: ['hooks', 'install', r.id] });
      }
    }
    out.push(item);
  }
  return out;
}

function commandLine(step) {
  return [step.file, ...step.args].join(' ');
}

/* Run one step in the user's terminal (inherits stdio). Fixed program names and arguments only. */
function runStep(step, env) {
  let file = step.file;
  let args = step.args;
  if (step.file === 'zn' && !fromNpx()) {
    // This install's own CLI: no PATH lookup.
    file = process.execPath;
    args = [path.join(PKG_ROOT, 'bin', 'cli.js'), ...step.args];
  }
  // npm and claude are .cmd files on Windows, which only start through a shell; the arguments are fixed strings.
  const r = spawnSync(file, args, { stdio: 'inherit', env, shell: process.platform === 'win32' && file !== process.execPath });
  return !r.error && r.status === 0;
}

/**
 * guide({home, env, cwd, stdin, stdout, confirm}) -> exit code.
 * `confirm(question)` resolves true/false; it is asked only when a person runs init in a terminal.
 */
async function guide(opts = {}) {
  const env = opts.env || process.env;
  const w = opts.write || ((s) => process.stdout.write(s));
  const tty = require('./broker/tty');
  const stdin = opts.stdin || process.stdin;
  const agent = tty.agentEnvDetected(env);
  const interactive = Boolean(stdin.isTTY) && !agent;
  const items = await plan(opts);

  w('\nzn-gate init: set up zn for the coding agents on this machine\n\n');
  const todo = items.filter((i) => i.steps.length);
  for (const i of items) {
    if (!i.found) w(`  -  ${i.name.padEnd(12)} not found on this machine\n`);
    else if (i.state === 'protected') w(`  OK ${i.name.padEnd(12)} already protected by zn\n`);
    else w(`  >  ${i.name.padEnd(12)} ${i.state === 'not-protected' ? 'not protected: ' + i.problem : 'not set up yet'}\n`);
  }
  w('\n');
  if (!items.some((i) => i.found)) {
    w('No supported coding agent was found (Claude Code, Codex CLI, Cursor, OpenCode).\n');
    w('Install one, then run `npx -y zn-gate init` again. Other editors: https://usezn.com/docs/install\n');
    return 1;
  }
  if (!todo.length) {
    w('Every agent found is already protected. To see it block a test secret: `zn-gate check`\n');
    return 0;
  }
  if (!interactive) {
    w(agent
      ? 'An AI agent is running this, so zn only prints the steps: installing hooks is your decision.\n'
      : 'This is not an interactive terminal, so zn only prints the steps.\n');
    w('Run them in your own terminal:\n\n');
    for (const i of todo) for (const s of i.steps) w(`  ${commandLine(s)}\n`);
    w('\nThen check that it works: `npx -y zn-gate check`\n');
    return 1;
  }
  const ask = opts.confirm || ((q) => tty.confirm(q, { stdin, stderr: process.stderr }));
  let skipped = 0;
  for (const i of todo) {
    w(`${i.name}:\n`);
    for (const s of i.steps) {
      if (!(await ask(`  ${s.label}: run \`${commandLine(s)}\`?`))) {
        w(`  skipped. You can run it later: ${commandLine(s)}\n`);
        skipped++;
        break;
      }
      const ok = (opts.run || runStep)(s, env);
      if (!ok) {
        w(`  that did not finish. Run it yourself: ${commandLine(s)}\n`);
        skipped++;
        break;
      }
    }
  }
  w('\n');
  const { check, report } = require('./check');
  const code = report(await check({ home: opts.home, env, cwd: opts.cwd }), w);
  return skipped ? 1 : code;
}

module.exports = { guide, plan, fromNpx, _internal: { commandLine, runStep } };
