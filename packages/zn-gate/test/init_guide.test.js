'use strict';

// zn-gate init (guided setup): one route per agent, runs steps only for a person in a terminal with a
// confirmation each, prints them otherwise, never installs hooks from a temporary copy (npx cache) and
// never downgrades a global install, runs programs by absolute path only, ends with zn-gate check.

process.env.ZN_STATS = 'off';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { getAdapter } = require('../lib/agents');
const { guide, plan, fromTemporaryCopy, _internal } = require('../lib/init-guide');
const { AGENT_ENV_VARS } = require('../lib/broker/tty');
const policy = require('../lib/hooks/policy');
const { tempDir } = require('./helpers/tmp');

const RUNNER = path.join(__dirname, '..', 'lib', 'hooks', 'runner.js');
const VERSION = require('../package.json').version;
const ZN = path.resolve('/opt/npm/bin/zn');
const NPM = path.resolve('/opt/npm/bin/npm');

function machine(t, agents) {
  const home = tempDir(t, 'zn-init-home-');
  const env = { HOME: home, PATH: '' };
  for (const a of agents) {
    if (a === 'claude-code') fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    if (a === 'codex') fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
    if (a === 'cursor') fs.mkdirSync(path.join(home, '.cursor'), { recursive: true });
  }
  return { home, env, cwd: tempDir(t, 'zn-init-cwd-'), claude: null };
}

function capture() {
  let s = '';
  return { write: (x) => { s += x; }, text: () => s };
}

const tty = { isTTY: true };
const line = (s) => s.manual;

test('plan: one route per agent found; agents not found get no steps', async (t) => {
  const m = machine(t, ['claude-code', 'codex']);
  const { items, setup } = await plan({ ...m, claude: path.resolve('/opt/bin/claude'), temporary: false });
  const by = Object.fromEntries(items.map((i) => [i.id, i]));
  assert.deepEqual(by['claude-code'].steps.map(line), ['claude plugin marketplace add usezn/zn', 'claude plugin install zn-gate@usezn']);
  assert.equal(by['claude-code'].steps[0].run[0], path.resolve('/opt/bin/claude'));
  assert.deepEqual(by.codex.steps.map(line), ['zn hooks install codex']);
  // An install that stays runs its own CLI with node, by absolute path.
  assert.equal(by.codex.steps[0].run[0], process.execPath);
  assert.deepEqual(by.codex.steps[0].run[1].slice(-3), ['hooks', 'install', 'codex']);
  assert.equal(setup.length, 0);
  assert.equal(by.cursor.found, false);
  assert.equal(by.cursor.steps.length, 0);
});

test('plan: without a claude command, Claude Code gets the two /plugin commands to type', async (t) => {
  const m = machine(t, ['claude-code']);
  const { items } = await plan({ ...m, temporary: false });
  const cc = items.find((i) => i.id === 'claude-code');
  assert.equal(cc.steps.length, 1);
  assert.equal(cc.steps[0].run, null);
  assert.match(cc.steps[0].manual, /\/plugin marketplace add usezn\/zn.*\/plugin install zn-gate@usezn/);
});

test('plan: from a temporary copy, one global install comes before the hooks, by absolute path', async (t) => {
  const m = machine(t, ['codex', 'cursor']);
  const { items, setup } = await plan({ ...m, temporary: true, global: { npm: NPM } });
  assert.equal(setup.length, 1, 'a single npm step for every agent');
  assert.deepEqual(setup[0].run, [NPM, ['install', '-g', 'zn-gate@' + VERSION]]);
  const cx = items.find((i) => i.id === 'codex');
  assert.equal(cx.steps[0].needsGlobal, true);
});

test('plan: a global install that is the same or newer is kept, never downgraded', async (t) => {
  const m = machine(t, ['codex']);
  const newer = (await plan({ ...m, temporary: true, global: { npm: NPM, version: '99.0.0', zn: ZN } }));
  assert.equal(newer.setup.length, 0);
  assert.deepEqual(newer.items.find((i) => i.id === 'codex').steps[0].run, [ZN, ['hooks', 'install', 'codex']]);
  const older = (await plan({ ...m, temporary: true, global: { npm: NPM, version: '1.0.0', zn: ZN } }));
  assert.equal(older.setup.length, 1);
  assert.match(older.setup[0].label, /you have 1\.0\.0/);
});

test('fromTemporaryCopy: npx, pnpm dlx, yarn dlx and bunx caches; not a global install', () => {
  assert.equal(fromTemporaryCopy('/home/u/.npm/_npx/abc/node_modules/zn-gate/lib'), true);
  assert.equal(fromTemporaryCopy('C:\\Users\\u\\AppData\\Local\\npm-cache\\_npx\\abc\\node_modules\\zn-gate\\lib'), true);
  assert.equal(fromTemporaryCopy('/home/u/.cache/pnpm/dlx-1a2b/node_modules/zn-gate/lib'), true);
  assert.equal(fromTemporaryCopy('/home/u/.cache/pnpm/dlx/5f3c/node_modules/.pnpm/zn-gate@1.9.0/node_modules/zn-gate/lib'), true);
  assert.equal(fromTemporaryCopy('/home/u/.bun/install/cache/zn-gate@1.9.0/lib'), true);
  assert.equal(fromTemporaryCopy('/usr/lib/node_modules/zn-gate/lib'), false);
});

test('findProgram: only absolute PATH entries are searched (a program in the current folder never runs)', (t) => {
  const dir = tempDir(t, 'zn-init-bin-');
  const name = process.platform === 'win32' ? 'zntestprog.cmd' : 'zntestprog';
  fs.writeFileSync(path.join(dir, name), '');
  // Relative entries are resolved against the current folder; on Windows the temp folder can be on another drive.
  const before = process.cwd();
  process.chdir(dir);
  try {
    assert.equal(_internal.findProgram('zntestprog', { PATH: '.' }), null);
    process.chdir(path.dirname(dir));
    assert.equal(_internal.findProgram('zntestprog', { PATH: path.basename(dir) }), null);
    assert.equal(_internal.findProgram('zntestprog', { PATH: '.' + path.delimiter + path.basename(dir) }), null);
  } finally {
    process.chdir(before);
  }
  assert.equal(_internal.findProgram('zntestprog', { PATH: dir }), path.join(dir, name));
});

test('guide: without a terminal it only prints the steps and runs nothing', async (t) => {
  const m = machine(t, ['codex']);
  const out = capture();
  let ran = 0;
  const code = await guide({ ...m, temporary: false, stdin: { isTTY: false }, write: out.write, run: () => { ran++; return true; }, confirm: async () => true });
  assert.equal(ran, 0);
  assert.equal(code, 1);
  assert.match(out.text(), /only prints the steps\. Nothing was changed\./);
  assert.match(out.text(), /zn hooks install codex/);
  assert.match(out.text(), /npx -y zn-gate check/);
  assert.match(out.text(), /zn-gate init --wrap-mcp/);
});

test('guide: when an AI agent runs it, it only prints the steps, also in a terminal', async (t) => {
  const m = machine(t, ['codex']);
  m.env[AGENT_ENV_VARS[0]] = '1';
  const out = capture();
  let ran = 0;
  await guide({ ...m, temporary: false, stdin: tty, write: out.write, run: () => { ran++; return true; }, confirm: async () => true });
  assert.equal(ran, 0);
  assert.match(out.text(), /An AI agent is running this/);
});

test('guide: in a terminal each step is confirmed, run, and the result is checked', async (t) => {
  const m = machine(t, ['codex']);
  const out = capture();
  const asked = [];
  const run = (step) => {
    assert.deepEqual(step.run[1].slice(-3), ['hooks', 'install', 'codex']);
    getAdapter('codex').install({ scope: 'user', home: m.home, env: m.env, nodePath: process.execPath, runnerPath: RUNNER, mcp: false });
    return true;
  };
  const code = await guide({ ...m, temporary: false, stdin: tty, write: out.write, run, confirm: async (q) => { asked.push(q); return true; } });
  assert.equal(asked.length, 1);
  assert.match(asked[0], /zn hooks install codex/);
  assert.match(out.text(), /OK Codex CLI\s+blocked the \.env file/);
  assert.equal(code, 0);
});

test('guide: from a temporary copy the global install runs first, then the hooks with the global zn', async (t) => {
  const m = machine(t, ['codex']);
  const out = capture();
  const ran = [];
  const run = (step) => { ran.push(step.run); return true; };
  await guide({ ...m, temporary: true, global: { npm: NPM, version: null, zn: ZN }, stdin: tty, write: out.write, run, confirm: async () => true });
  assert.deepEqual(ran[0], [NPM, ['install', '-g', 'zn-gate@' + VERSION]]);
  assert.deepEqual(ran[1], [ZN, ['hooks', 'install', 'codex']]);
});

test('guide: declining the global install skips the hooks that need it', async (t) => {
  const m = machine(t, ['codex']);
  const out = capture();
  let ran = 0;
  const code = await guide({ ...m, temporary: true, global: { npm: NPM }, stdin: tty, write: out.write, run: () => { ran++; return true; }, confirm: async () => false });
  assert.equal(ran, 0);
  assert.equal(code, 1);
  assert.match(out.text(), /needs zn-gate installed for your user first/);
});

test('guide: a step the person declines is skipped and shown for later', async (t) => {
  const m = machine(t, ['codex']);
  const out = capture();
  let ran = 0;
  const code = await guide({ ...m, temporary: false, stdin: tty, write: out.write, run: () => { ran++; return true; }, confirm: async () => false });
  assert.equal(ran, 0);
  assert.equal(code, 1);
  assert.match(out.text(), /skipped\. You can run it later: zn hooks install codex/);
});

test('guide: nothing found, and everything already protected', async (t) => {
  const empty = machine(t, []);
  const out = capture();
  assert.equal(await guide({ ...empty, stdin: tty, write: out.write }), 1);
  assert.match(out.text(), /No supported coding agent was found/);
  assert.match(out.text(), /Nothing was changed/);
  const m = machine(t, ['codex']);
  getAdapter('codex').install({ scope: 'user', home: m.home, env: m.env, nodePath: process.execPath, runnerPath: RUNNER, mcp: false });
  const out2 = capture();
  assert.equal(await guide({ ...m, stdin: tty, write: out2.write }), 0);
  assert.match(out2.text(), /already protected by zn/);
});

test('agent guard: the guided init is refused to agents; init --wrap-mcp and its options are not', () => {
  for (const cmd of ['zn-gate init', 'npx -y zn-gate init', 'npx -y zn-gate@1.9.0 init', 'script -qfec "npx -y zn-gate init" /dev/null',
    'node /x/bin/cli.js init', 'C:\\npm\\zn-gate.cmd init', 'npx -y zn-gate init; echo --wrap-mcp']) {
    const d = policy.bashDenial(cmd);
    assert.ok(d, 'expected a denial for: ' + cmd);
    assert.match(d, /ask the user to run it in their own terminal/);
  }
  for (const cmd of ['npx -y zn-gate init --wrap-mcp', 'npx -y zn-gate init --dry-run', 'zn-gate init --revert', 'zn-gate init --shadow',
    'npx -y zn-gate check', 'git init', 'npm init -y']) {
    assert.equal(policy.bashDenial(cmd), null, 'expected no denial for: ' + cmd);
  }
});

test('cmp: a prerelease is older than the release', () => {
  assert.ok(_internal.cmp('1.9.0-rc.1', '1.9.0') < 0);
  assert.ok(_internal.cmp('1.9.0', '1.9.0-rc.1') > 0);
  assert.equal(_internal.cmp('1.9.0', '1.9.0'), 0);
  assert.ok(_internal.cmp('1.10.0', '1.9.0') > 0);
});

test('plan: an install that is not the global one (a project dependency, a checkout) uses the global install', async (t) => {
  const m = machine(t, ['codex']);
  const elsewhere = tempDir(t, 'zn-init-global-');
  const { items, setup } = await plan({ ...m, global: { npm: NPM, pkgDir: elsewhere, version: '99.0.0', zn: ZN } });
  assert.equal(setup.length, 0);
  assert.deepEqual(items.find((i) => i.id === 'codex').steps[0].run, [ZN, ['hooks', 'install', 'codex']]);
});

test('agent guard: the options that allow init must be whole words of the same command', () => {
  for (const cmd of ['zn-gate init --wrap-mcp-x', 'zn-gate init --dry-run=1', 'zn-gate init --shadow.', 'zn-gate init # --dry-run',
    "zn-gate init 'x --revert'", 'zn-gate init > --dry-run', 'zn-gate init 2> --shadow', 'zn-gate init < --revert', 'zn-gate init $(: --dry-run)', 'zn-gate init `: --dry-run`', 'zn-gate init --wrap-mcp && zn-gate init']) {
    assert.ok(policy.bashDenial(cmd), 'expected a denial for: ' + cmd);
  }
  assert.equal(policy.bashDenial('zn-gate init --dry-run --shadow'), null);
  assert.equal(policy.bashDenial('zn-gate init --dry-run > out.txt'), null);
});

test('agent guard: many init words with an option at the end stay fast', () => {
  const cmd = 'zn init '.repeat(Math.floor(99 * 1024 / 8)) + ' --dry-run';
  const t0 = Date.now();
  policy.bashDenial(cmd);
  assert.ok(Date.now() - t0 < 500, 'took ' + (Date.now() - t0) + ' ms');
});

test('plan: Claude Code set up with zn hooks is repaired with zn hooks, not with the plugin', async (t) => {
  const m = machine(t, ['claude-code']);
  getAdapter('claude-code').install({ scope: 'user', home: m.home, env: m.env, nodePath: path.join(m.home, 'gone', 'node'), runnerPath: RUNNER, mcp: false });
  const { items } = await plan({ ...m, claude: path.resolve('/opt/bin/claude'), temporary: false });
  const cc = items.find((i) => i.id === 'claude-code');
  assert.equal(cc.state, 'not-protected');
  assert.deepEqual(cc.steps.map(line), ['zn hooks install claude-code']);
});

test('plan: the plugin together with zn hooks gets one step that removes the hooks', async (t) => {
  const m = machine(t, ['claude-code']);
  getAdapter('claude-code').install({ scope: 'user', home: m.home, env: m.env, nodePath: process.execPath, runnerPath: RUNNER, mcp: false });
  const root = path.join(m.home, '.claude', 'plugins', 'cache', 'usezn', 'zn-gate', '1.9.0');
  fs.mkdirSync(path.join(root, 'scripts'), { recursive: true });
  fs.writeFileSync(path.join(root, 'scripts', 'zn-launch.js'), 'process.exit(0);\n');
  fs.writeFileSync(path.join(m.home, '.claude', 'plugins', 'installed_plugins.json'),
    JSON.stringify({ version: 2, plugins: { 'zn-gate@usezn': [{ scope: 'user', installPath: root }] } }));
  const { items } = await plan({ ...m, claude: path.resolve('/opt/bin/claude'), temporary: false });
  const cc = items.find((i) => i.id === 'claude-code');
  assert.deepEqual(cc.steps.map(line), ['zn hooks uninstall claude-code']);
  assert.match(cc.steps[0].label, /the zn-gate plugin stays/);
});

function pluginIn(home, enabled) {
  const root = path.join(home, '.claude', 'plugins', 'cache', 'usezn', 'zn-gate', '1.9.0');
  fs.mkdirSync(path.join(root, 'scripts'), { recursive: true });
  fs.writeFileSync(path.join(root, 'scripts', 'zn-launch.js'), 'process.exit(0);\n');
  fs.writeFileSync(path.join(home, '.claude', 'plugins', 'installed_plugins.json'),
    JSON.stringify({ version: 2, plugins: { 'zn-gate@usezn': [{ scope: 'user', installPath: root }] } }));
  if (enabled === false) {
    const file = path.join(home, '.claude', 'settings.json');
    let tree = {};
    try { tree = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) { /* none yet */ }
    tree.enabledPlugins = { 'zn-gate@usezn': false };
    fs.writeFileSync(file, JSON.stringify(tree));
  }
}

test('plan: a plugin turned off next to zn hooks never removes the hooks', async (t) => {
  const m = machine(t, ['claude-code']);
  getAdapter('claude-code').install({ scope: 'user', home: m.home, env: m.env, nodePath: process.execPath, runnerPath: RUNNER, mcp: false });
  pluginIn(m.home, false);
  const { items } = await plan({ ...m, claude: path.resolve('/opt/bin/claude'), temporary: false });
  const cc = items.find((i) => i.id === 'claude-code');
  assert.equal(cc.state, 'protected');
  assert.deepEqual(cc.steps, []);
});

test('plan: a plugin alone that is turned off gets one step that turns it on', async (t) => {
  const m = machine(t, ['claude-code']);
  pluginIn(m.home, false);
  const { items } = await plan({ ...m, claude: path.resolve('/opt/bin/claude'), temporary: false });
  const cc = items.find((i) => i.id === 'claude-code');
  assert.deepEqual(cc.steps.map(line), ['claude plugin enable zn-gate@usezn']);
});

test('agent guard: a backslash before the option and npm exec options do not unlock the guided init', () => {
  for (const cmd of ['zn-gate init x\\ --wrap-mcp', 'npx -y zn-gate init a\\ --dry-run', 'npm exec zn-gate init --dry-run',
    'npm x zn-gate init --wrap-mcp', 'npm exec -y zn-gate@1.9.0 init --revert', 'npm.cmd exec zn-gate init --shadow']) {
    const d = policy.bashDenial(cmd);
    assert.ok(d, 'expected a denial for: ' + cmd);
    assert.match(d, /ask the user to run it in their own terminal/);
  }
  for (const cmd of ['npm exec -- zn-gate init --dry-run', 'npm exec zn-gate -- init --wrap-mcp', 'npx -y zn-gate init --wrap-mcp', 'npm exec zn-gate check', 'npm init -y']) {
    assert.equal(policy.bashDenial(cmd), null, 'expected no denial for: ' + cmd);
  }
});

test('agent guard: the npm exec check stays fast', () => {
  const t0 = process.hrtime.bigint();
  assert.equal(policy.adminCommand('npm exec ' + 'a '.repeat(40000) + 'zn-gate init --dry-run'), 'init');
  assert.equal(policy.adminCommand(('npm x ' + 'b'.repeat(50) + ' ').repeat(1500)), null);
  assert.equal(policy.adminCommand(('npm exec ' + '-- '.repeat(20)).repeat(1500)), null);
  assert.equal(policy.adminCommand('npm exec ' + '--yes '.repeat(200) + 'zn-gate init --dry-run'), 'init', 'padding does not hide it');
  assert.ok(Number(process.hrtime.bigint() - t0) / 1e6 < 500);
});
