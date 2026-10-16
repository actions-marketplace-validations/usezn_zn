'use strict';

// zn-gate check: an agent counts as protected only when its zn hook for reading
// files is installed, zn blocks the fake .env and allows an ordinary file, and
// the installed hook does the same when it is run as the agent runs it.

process.env.ZN_STATS = 'off';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { getAdapter } = require('../lib/agents');
const { check, report } = require('../lib/check');
const { tempDir } = require('./helpers/tmp');

const RUNNER = path.join(__dirname, '..', 'lib', 'hooks', 'runner.js');

function homeWithHooks(t, agents) {
  const home = tempDir(t, 'zn-check-home-');
  const env = { HOME: home, PATH: process.env.PATH };
  for (const id of agents) {
    getAdapter(id).install({ scope: 'user', home, env, nodePath: process.execPath, runnerPath: RUNNER, mcp: false });
  }
  return { home, env, cwd: tempDir(t, 'zn-check-cwd-') };
}

function textOf(res) {
  let s = '';
  const code = report(res, (x) => { s += x; });
  return { s, code };
}

const byId = (res, id) => res.results.find((r) => r.id === id);

function fakePlugin(home, launcherSource, settings) {
  const root = path.join(home, '.claude', 'plugins', 'cache', 'usezn', 'zn-gate', '1.8.1');
  fs.mkdirSync(path.join(root, 'scripts'), { recursive: true });
  fs.writeFileSync(path.join(root, 'scripts', 'zn-launch.js'), launcherSource);
  fs.writeFileSync(path.join(home, '.claude', 'plugins', 'installed_plugins.json'),
    JSON.stringify({ version: 2, plugins: { 'zn-gate@usezn': [{ scope: 'user', installPath: root }] } }));
  if (settings) fs.writeFileSync(path.join(home, '.claude', 'settings.json'), JSON.stringify(settings));
  return root;
}

// A stand-in for the plugin launcher that hands the event to the real runner (as the real launcher does after
// verifying the pinned package), or fails closed on every event when `broken`.
function launcher({ broken = false, systemMessage = '' } = {}) {
  return "const [mode] = process.argv.slice(2);\n" +
    "if (mode === 'check') { " + (systemMessage ? "process.stdout.write(JSON.stringify({ systemMessage: " + JSON.stringify(systemMessage) + " }));" : '') + " process.exit(0); }\n" +
    (broken ? "process.stderr.write('zn plugin: zn-gate is not installed'); process.exit(2);\n"
      : "const r = require('child_process').spawnSync(process.execPath, [" + JSON.stringify(RUNNER) + ", 'claude-code'], { input: require('fs').readFileSync(0), encoding: 'utf8' });\n" +
        "process.stdout.write(r.stdout || ''); process.exit(r.status || 0);\n");
}

test('check: every agent installed for the user blocks .env and allows an ordinary file, also through the installed hook', async (t) => {
  const ctx = homeWithHooks(t, ['claude-code', 'codex', 'cursor', 'opencode']);
  const res = await check(ctx);
  for (const r of res.results) {
    assert.equal(r.state, 'protected', `${r.id}: ${r.problem}`);
    assert.ok(r.message.length > 0, r.id);
    if (r.id !== 'opencode') assert.equal(r.verified, true, `${r.id}: installed hook not run`);
  }
  assert.equal(res.removed, true);
  const { s, code } = textOf(res);
  assert.equal(code, 0);
  assert.match(s, /OK Claude Code\s+blocked the \.env file and allowed the ordinary file/);
  assert.match(s, /its plugin runs inside OpenCode, so it was not started here/);
  assert.match(s, /zn env shadow \.env/);
});

test('check: no setup at all is a failure, with the command for each agent', async (t) => {
  const home = tempDir(t, 'zn-check-empty-');
  const res = await check({ home, env: { HOME: home, PATH: process.env.PATH }, cwd: home });
  const { s, code } = textOf(res);
  assert.equal(code, 1);
  assert.match(s, /Codex CLI\s+zn is not set up for this agent\. To protect it, run `zn hooks install codex` in your own terminal/);
  assert.match(s, /claude plugin install zn-gate@usezn/);
});

test('check: a hook whose Node.js is gone is not protected', async (t) => {
  const ctx = homeWithHooks(t, ['codex']);
  const file = getAdapter('codex').hooksFile(ctx);
  fs.writeFileSync(file, fs.readFileSync(file, 'utf8').split(process.execPath.replace(/\\/g, '/')).join(path.join(ctx.home, 'gone', 'node').replace(/\\/g, '/')));
  const r = byId(await check(ctx), 'codex');
  assert.equal(r.state, 'not-protected');
  assert.match(r.problem, /Node\.js .* is no longer there/);
  // The repair names a fresh global install first: the old Node.js took its `zn` with it.
  assert.equal(r.fix, 'install zn-gate again for the Node.js you use now: run `npm install -g zn-gate`, then `zn hooks install codex`, in your own terminal');
});

test('check: Claude Code set up with zn hooks is repaired with zn hooks, not with the plugin', async (t) => {
  const ctx = homeWithHooks(t, ['claude-code']);
  const file = getAdapter('claude-code').settingsFile(ctx);
  fs.writeFileSync(file, fs.readFileSync(file, 'utf8').split(process.execPath.replace(/\\/g, '/')).join(path.join(ctx.home, 'gone', 'node').replace(/\\/g, '/')));
  const r = byId(await check(ctx), 'claude-code');
  assert.equal(r.state, 'not-protected');
  assert.match(r.fix, /`zn hooks install claude-code`/);
  assert.doesNotMatch(r.fix, /plugin/);
  const { s } = textOf(await check(ctx));
  assert.match(s, /To fix it, install zn-gate again for the Node\.js you use now: run `npm install -g zn-gate`, then `zn hooks install claude-code`/);
});

test('check: a Claude Code prompt hook without onFailure "block" gets a note', async (t) => {
  const ctx = homeWithHooks(t, ['claude-code']);
  const file = getAdapter('claude-code').settingsFile(ctx);
  const ok = byId(await check(ctx), 'claude-code');
  assert.equal(ok.state, 'protected');
  assert.ok(!ok.notes.some((n) => /prompt hook/.test(n)));
  const tree = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const g of tree.hooks.UserPromptSubmit) for (const h of g.hooks || []) delete h.onFailure;
  fs.writeFileSync(file, JSON.stringify(tree));
  const r = byId(await check(ctx), 'claude-code');
  assert.equal(r.state, 'protected');
  assert.ok(r.notes.some((n) => /prompt hook lets prompts through when it cannot run/.test(n)));
});

test('check: zn hooks without the read hook are not protected', async (t) => {
  const ctx = homeWithHooks(t, ['codex']);
  const file = getAdapter('codex').hooksFile(ctx);
  const tree = JSON.parse(fs.readFileSync(file, 'utf8'));
  delete tree.hooks.PreToolUse;
  fs.writeFileSync(file, JSON.stringify(tree));
  const r = byId(await check(ctx), 'codex');
  assert.equal(r.state, 'not-protected');
  assert.match(r.problem, /not the one that checks reading files \(PreToolUse\)/);
});

test('check: a `zn hook` command with no zn on PATH is not protected', async (t) => {
  const ctx = homeWithHooks(t, ['cursor']);
  const file = getAdapter('cursor').hooksFile(ctx);
  const tree = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const list of Object.values(tree.hooks)) for (const h of list) h.command = 'zn hook cursor';
  fs.writeFileSync(file, JSON.stringify(tree));
  ctx.env = { HOME: ctx.home, PATH: path.join(ctx.home, 'empty-bin') };
  const r = byId(await check(ctx), 'cursor');
  assert.equal(r.state, 'not-protected');
  assert.match(r.problem, /no `zn` on your PATH/);
});

test('check: a command that is not zn\'s exact hook is never run', async (t) => {
  const ctx = homeWithHooks(t, ['cursor']);
  const file = getAdapter('cursor').hooksFile(ctx);
  const marker = path.join(ctx.home, 'ran');
  const tree = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const list of Object.values(tree.hooks)) for (const h of list) h.command = h.command.replace("'" + RUNNER.replace(/\\/g, '/'), "'$(touch " + marker + ")" + RUNNER.replace(/\\/g, '/'));
  fs.writeFileSync(file, JSON.stringify(tree));
  const r = byId(await check(ctx), 'cursor');
  assert.equal(fs.existsSync(marker), false);
  assert.equal(r.state, 'not-set-up');
});

test('check: the Claude Code plugin is checked through its launcher; a launcher that blocks everything is not protected', async (t) => {
  const home = tempDir(t, 'zn-check-plugin-');
  const env = { HOME: home, PATH: process.env.PATH };
  fakePlugin(home, launcher());
  let r = byId(await check({ home, env, cwd: home }), 'claude-code');
  assert.equal(r.state, 'protected', r.problem);
  assert.equal(r.verified, true);
  fakePlugin(home, launcher({ broken: true }));
  r = byId(await check({ home, env, cwd: home }), 'claude-code');
  assert.equal(r.state, 'not-protected');
  assert.match(r.problem, /blocks everything, ordinary files too/);
});

test('check: the plugin\'s own check message, a plugin turned off, and a disableAllHooks setting are not protected', async (t) => {
  const home = tempDir(t, 'zn-check-plugin2-');
  const env = { HOME: home, PATH: process.env.PATH };
  fakePlugin(home, launcher({ systemMessage: 'zn plugin: zn-gate 1.8.1 is not installed. Run: npm i -g zn-gate@1.8.1' }));
  let r = byId(await check({ home, env, cwd: home }), 'claude-code');
  assert.equal(r.state, 'not-protected');
  assert.match(r.problem, /npm i -g zn-gate@1\.8\.1/);
  fakePlugin(home, launcher(), { enabledPlugins: { 'zn-gate@usezn': false } });
  r = byId(await check({ home, env, cwd: home }), 'claude-code');
  assert.match(r.problem, /turned off/);
  fakePlugin(home, launcher(), { disableAllHooks: true });
  r = byId(await check({ home, env, cwd: home }), 'claude-code');
  assert.equal(r.state, 'not-protected');
  assert.match(r.problem, /disableAllHooks/);
});

test('check: a setup for one project only is reported, not run, and not counted as protected', async (t) => {
  const home = tempDir(t, 'zn-check-proj-');
  const proj = tempDir(t, 'zn-check-repo-');
  getAdapter('codex').install({ scope: 'project', projectDir: proj, home, env: { HOME: home }, nodePath: process.execPath, runnerPath: RUNNER, mcp: false });
  const res = await check({ home, env: { HOME: home, PATH: process.env.PATH }, cwd: proj });
  const r = byId(res, 'codex');
  assert.equal(r.state, 'project-only');
  const { s, code } = textOf(res);
  assert.equal(code, 1);
  assert.match(s, /set up only for one project/);
});

test('check: a project file that is a FIFO or a symlink is not read, and relative PATH entries are ignored', { skip: process.platform === 'win32' }, async (t) => {
  const home = tempDir(t, 'zn-check-fifo-');
  const proj = tempDir(t, 'zn-check-fiforepo-');
  fs.mkdirSync(path.join(proj, '.codex'), { recursive: true });
  require('child_process').spawnSync('mkfifo', [path.join(proj, '.codex', 'hooks.json')]);
  fs.mkdirSync(path.join(proj, '.cursor'), { recursive: true });
  fs.symlinkSync('/etc/hostname', path.join(proj, '.cursor', 'hooks.json'));
  const started = Date.now();
  const res = await check({ home, env: { HOME: home, PATH: 'relbin:' + process.env.PATH }, cwd: proj });
  assert.ok(Date.now() - started < 10000, 'a FIFO in the project never blocks the check');
  assert.equal(byId(res, 'codex').state, 'not-set-up');
  assert.equal(byId(res, 'cursor').state, 'not-set-up');
});

test('check: a `zn hook` command does not find zn through a relative PATH entry', async (t) => {
  const ctx = homeWithHooks(t, ['cursor']);
  const file = getAdapter('cursor').hooksFile(ctx);
  const tree = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const list of Object.values(tree.hooks)) for (const h of list) h.command = 'zn hook cursor';
  fs.writeFileSync(file, JSON.stringify(tree));
  const rel = path.join(ctx.cwd, 'relbin');
  fs.mkdirSync(rel);
  fs.writeFileSync(path.join(rel, process.platform === 'win32' ? 'zn.cmd' : 'zn'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  const saved = process.cwd();
  process.chdir(ctx.cwd);
  try {
    ctx.env = { HOME: ctx.home, PATH: 'relbin' };
    const r = byId(await check(ctx), 'cursor');
    assert.equal(r.state, 'not-protected');
    assert.match(r.problem, /no `zn` on your PATH/);
  } finally {
    process.chdir(saved);
  }
});

test('check: a hook whose zn-gate files are gone gets the same repair', async (t) => {
  const ctx = homeWithHooks(t, ['codex']);
  const file = getAdapter('codex').hooksFile(ctx);
  fs.writeFileSync(file, fs.readFileSync(file, 'utf8').split(RUNNER.replace(/\\/g, '/')).join(path.join(ctx.home, 'gone', 'zn-gate', 'lib', 'hooks', 'runner.js').replace(/\\/g, '/')));
  const r = byId(await check(ctx), 'codex');
  assert.equal(r.state, 'not-protected');
  assert.match(r.problem, /its zn-gate files .* is no longer there/);
  assert.match(r.fix, /^install zn-gate again for the Node\.js you use now: run `npm install -g zn-gate`/);
});

test('check: the plugin together with zn hooks is not protected, and the fix removes the hooks', async (t) => {
  const ctx = homeWithHooks(t, ['claude-code']);
  const settings = JSON.parse(fs.readFileSync(getAdapter('claude-code').settingsFile(ctx), 'utf8'));
  fakePlugin(ctx.home, launcher(), settings);
  const r = byId(await check(ctx), 'claude-code');
  assert.equal(r.via, 'both');
  assert.equal(r.state, 'not-protected');
  assert.match(r.problem, /plugin and the hooks of `zn hooks install claude-code` are both set up/);
  assert.equal(r.fix, 'remove the second set: run `zn hooks uninstall claude-code` in your own terminal');
  assert.ok(!r.notes.some((n) => /prompt hook/.test(n)));
});

test('check: the plugin alone keeps the plugin fix', async (t) => {
  const ctx = homeWithHooks(t, []);
  fs.mkdirSync(path.join(ctx.home, '.claude'), { recursive: true });
  fakePlugin(ctx.home, launcher());
  const r = byId(await check(ctx), 'claude-code');
  assert.equal(r.via, 'plugin');
  assert.equal(r.state, 'protected');
  assert.match(r.fix, /claude plugin install zn-gate@usezn/);
});

test('check: a plugin that is turned off next to zn hooks: the hooks are checked, nothing is offered for removal', async (t) => {
  const ctx = homeWithHooks(t, ['claude-code']);
  const settings = JSON.parse(fs.readFileSync(getAdapter('claude-code').settingsFile(ctx), 'utf8'));
  fakePlugin(ctx.home, launcher(), { ...settings, enabledPlugins: { 'zn-gate@usezn': false } });
  const r = byId(await check(ctx), 'claude-code');
  assert.equal(r.via, 'hooks');
  assert.equal(r.state, 'protected');
  assert.ok(r.notes.includes('the zn-gate plugin is also installed, but turned off'));
  assert.doesNotMatch(r.fix, /uninstall/);
});

test('check: a plugin alone that is turned off is fixed by turning it on', async (t) => {
  const ctx = homeWithHooks(t, []);
  fs.mkdirSync(path.join(ctx.home, '.claude'), { recursive: true });
  fakePlugin(ctx.home, launcher(), { enabledPlugins: { 'zn-gate@usezn': false } });
  const r = byId(await check(ctx), 'claude-code');
  assert.equal(r.state, 'not-protected');
  assert.equal(r.pluginOff, true);
  assert.equal(r.fix, 'turn it on: run `claude plugin enable zn-gate@usezn` in your own terminal');
});

test('check: a broken plugin next to zn hooks is turned off, not the hooks removed', async (t) => {
  const ctx = homeWithHooks(t, ['claude-code']);
  const settings = JSON.parse(fs.readFileSync(getAdapter('claude-code').settingsFile(ctx), 'utf8'));
  fakePlugin(ctx.home, launcher({ broken: true }), settings);
  const r = byId(await check(ctx), 'claude-code');
  assert.equal(r.via, 'both');
  assert.equal(r.pluginBroken, true);
  assert.equal(r.state, 'not-protected');
  assert.match(r.problem, /the zn-gate plugin does not work here/);
  assert.match(r.fix, /claude plugin disable zn-gate@usezn/);
  assert.doesNotMatch(r.fix, /hooks uninstall/);
});
