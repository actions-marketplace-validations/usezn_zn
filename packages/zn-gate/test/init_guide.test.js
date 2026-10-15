'use strict';

// zn-gate init (guided setup): one route per agent, runs steps only for a person in a terminal with a
// confirmation each, prints them otherwise, never installs hooks from the npx cache, ends with zn-gate check.

process.env.ZN_STATS = 'off';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { getAdapter } = require('../lib/agents');
const { guide, plan } = require('../lib/init-guide');
const { AGENT_ENV_VARS } = require('../lib/broker/tty');
const { tempDir } = require('./helpers/tmp');

const RUNNER = path.join(__dirname, '..', 'lib', 'hooks', 'runner.js');

function machine(t, agents) {
  const home = tempDir(t, 'zn-init-home-');
  const env = { HOME: home, PATH: '' };
  for (const a of agents) {
    if (a === 'claude-code') fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    if (a === 'codex') fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
    if (a === 'cursor') fs.mkdirSync(path.join(home, '.cursor'), { recursive: true });
  }
  return { home, env, cwd: tempDir(t, 'zn-init-cwd-') };
}

function capture() {
  let s = '';
  return { write: (x) => { s += x; }, text: () => s };
}

const tty = { isTTY: true };

test('plan: one route per agent found; agents not found get no steps', async (t) => {
  const m = machine(t, ['claude-code', 'codex']);
  const items = await plan({ ...m, npx: false });
  const by = Object.fromEntries(items.map((i) => [i.id, i]));
  assert.deepEqual(by['claude-code'].steps.map((s) => s.args.join(' ')), ['plugin marketplace add usezn/zn', 'plugin install zn-gate@usezn']);
  assert.deepEqual(by.codex.steps.map((s) => [s.file, ...s.args].join(' ')), ['zn hooks install codex']);
  assert.equal(by.cursor.found, false);
  assert.equal(by.cursor.steps.length, 0);
});

test('plan: from the npx cache, zn-gate is installed for the user before any hook', async (t) => {
  const m = machine(t, ['codex']);
  const cx = (await plan({ ...m, npx: true })).find((i) => i.id === 'codex');
  assert.equal(cx.steps[0].file, 'npm');
  assert.match(cx.steps[0].args.join(' '), /^install -g zn-gate@\d/);
  assert.equal(cx.steps[1].args.join(' '), 'hooks install codex');
});

test('guide: without a terminal it only prints the steps and runs nothing', async (t) => {
  const m = machine(t, ['codex']);
  const out = capture();
  let ran = 0;
  const code = await guide({ ...m, stdin: { isTTY: false }, write: out.write, run: () => { ran++; return true; }, confirm: async () => true });
  assert.equal(ran, 0);
  assert.equal(code, 1);
  assert.match(out.text(), /only prints the steps/);
  assert.match(out.text(), /zn hooks install codex/);
  assert.match(out.text(), /npx -y zn-gate check/);
});

test('guide: when an AI agent runs it, it only prints the steps, also in a terminal', async (t) => {
  const m = machine(t, ['codex']);
  m.env[AGENT_ENV_VARS[0]] = '1';
  const out = capture();
  let ran = 0;
  await guide({ ...m, stdin: tty, write: out.write, run: () => { ran++; return true; }, confirm: async () => true });
  assert.equal(ran, 0);
  assert.match(out.text(), /An AI agent is running this/);
});

test('guide: in a terminal each step is confirmed, run, and the result is checked', async (t) => {
  const m = machine(t, ['codex']);
  const out = capture();
  const asked = [];
  const run = (step) => {
    assert.deepEqual(step.args, ['hooks', 'install', 'codex']);
    getAdapter('codex').install({ scope: 'user', home: m.home, env: m.env, nodePath: process.execPath, runnerPath: RUNNER, mcp: false });
    return true;
  };
  const code = await guide({ ...m, npx: false, stdin: tty, write: out.write, run, confirm: async (q) => { asked.push(q); return true; } });
  assert.equal(asked.length, 1);
  assert.match(asked[0], /zn hooks install codex/);
  assert.match(out.text(), /OK Codex CLI\s+blocked the \.env file/);
  assert.equal(code, 0);
});

test('guide: a step the person declines is skipped and shown for later', async (t) => {
  const m = machine(t, ['codex']);
  const out = capture();
  let ran = 0;
  const code = await guide({ ...m, npx: false, stdin: tty, write: out.write, run: () => { ran++; return true; }, confirm: async () => false });
  assert.equal(ran, 0);
  assert.equal(code, 1);
  assert.match(out.text(), /skipped\. You can run it later: zn hooks install codex/);
});

test('guide: nothing found, and everything already protected', async (t) => {
  const empty = machine(t, []);
  const out = capture();
  assert.equal(await guide({ ...empty, stdin: tty, write: out.write }), 1);
  assert.match(out.text(), /No supported coding agent was found/);
  const m = machine(t, ['codex']);
  getAdapter('codex').install({ scope: 'user', home: m.home, env: m.env, nodePath: process.execPath, runnerPath: RUNNER, mcp: false });
  const out2 = capture();
  assert.equal(await guide({ ...m, stdin: tty, write: out2.write }), 0);
  assert.match(out2.text(), /already protected by zn/);
});
