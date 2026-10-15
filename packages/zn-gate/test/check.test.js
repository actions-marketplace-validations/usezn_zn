'use strict';

// zn-gate check: every installed agent hook blocks the fake .env read, the
// installed command itself is run when it has zn's exact shape, a hook whose
// Node.js is gone is reported, and the report says what to do in plain words.

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
  const env = { HOME: home };
  for (const id of agents) {
    getAdapter(id).install({ scope: 'user', home, env, nodePath: process.execPath, runnerPath: RUNNER, mcp: false });
  }
  return { home, env };
}

function textOf(res) {
  let s = '';
  const code = report(res, (x) => { s += x; });
  return { s, code };
}

test('check: every installed agent blocks the fake .env read, through zn and through the installed hook', async (t) => {
  const { home, env } = homeWithHooks(t, ['claude-code', 'codex', 'cursor', 'opencode']);
  const res = await check({ home, env });
  for (const r of res.results) {
    assert.equal(r.installed, true, r.id);
    assert.equal(r.blocked, true, `${r.id}: ${r.message || r.error}`);
    assert.ok(r.message.length > 0, r.id);
    if (r.id !== 'opencode') {
      assert.equal(r.live && r.live.ok, true, `${r.id}: ${r.live && r.live.why}`);
      assert.equal(r.live.blocked, true, `${r.id}: the installed hook did not block`);
    }
  }
  assert.equal(res.removed, true, 'the test folder is deleted');
  const { s, code } = textOf(res);
  assert.equal(code, 0);
  assert.match(s, /OK Claude Code\s+blocked/);
  assert.match(s, /Nothing was sent anywhere/);
  assert.match(s, /zn env shadow \.env/);
});

test('check: agents without zn are listed with the command that protects them; none installed is a failure', async (t) => {
  const home = tempDir(t, 'zn-check-empty-');
  const res = await check({ home, env: { HOME: home } });
  assert.ok(res.results.every((r) => !r.installed));
  const { s, code } = textOf(res);
  assert.equal(code, 1);
  assert.match(s, /Codex CLI\s+zn is not set up for this agent\. To protect it: zn hooks install codex/);
  assert.match(s, /zn is not set up for any agent yet/);
});

test('check: a hook whose Node.js is gone is reported as not protected, with the fix', async (t) => {
  const { home, env } = homeWithHooks(t, ['codex']);
  const file = getAdapter('codex').hooksFile({ home, env });
  const missingNode = path.join(home, 'gone', 'node');
  fs.writeFileSync(file, fs.readFileSync(file, 'utf8').split(process.execPath.replace(/\\/g, '/')).join(missingNode.replace(/\\/g, '/')));
  const res = await check({ home, env });
  const cx = res.results.find((r) => r.id === 'codex');
  assert.equal(cx.installed, true);
  assert.equal(cx.live.ok, false);
  assert.match(cx.live.why, /no longer there/);
  const { s, code } = textOf(res);
  assert.equal(code, 1);
  assert.match(s, /X  Codex CLI\s+NOT protected: the hook installed in .* cannot start/);
  assert.match(s, /run `zn hooks install codex` again in your own terminal/);
});

test('check: a command that is not zn\'s exact hook is never run', async (t) => {
  const { home, env } = homeWithHooks(t, ['cursor']);
  const file = getAdapter('cursor').hooksFile({ home, env });
  const marker = path.join(home, 'ran');
  const tree = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const list of Object.values(tree.hooks || {})) {
    for (const h of list) h.command = 'touch ' + marker + ' && ' + h.command;
  }
  fs.writeFileSync(file, JSON.stringify(tree));
  const res = await check({ home, env });
  assert.equal(fs.existsSync(marker), false);
  assert.equal(res.results.find((r) => r.id === 'cursor').installed, false);
});

test('check: the Claude Code plugin is found and its own launcher is run, as Claude Code runs it', async (t) => {
  const home = tempDir(t, 'zn-check-plugin-');
  const env = { HOME: home };
  const pluginRoot = path.join(home, '.claude', 'plugins', 'cache', 'usezn', 'zn-gate', '1.8.1');
  fs.mkdirSync(path.join(pluginRoot, 'scripts'), { recursive: true });
  const seen = path.join(home, 'launcher-ran');
  // A stand-in launcher: records that it ran with CLAUDE_PLUGIN_ROOT and answers like zn's hook (deny).
  fs.writeFileSync(path.join(pluginRoot, 'scripts', 'zn-launch.js'),
    "require('fs').writeFileSync(" + JSON.stringify(seen) + ", process.env.CLAUDE_PLUGIN_ROOT + ' ' + process.argv.slice(2).join(' '));\n" +
    "process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny' } }));\n");
  fs.writeFileSync(path.join(home, '.claude', 'plugins', 'installed_plugins.json'),
    JSON.stringify({ version: 2, plugins: { 'zn-gate@usezn': [{ scope: 'user', installPath: pluginRoot }] } }));
  const res = await check({ home, env });
  const cc = res.results.find((r) => r.id === 'claude-code');
  assert.equal(cc.installed, true);
  assert.equal(cc.live.via, 'plugin');
  assert.equal(cc.live.blocked, true);
  assert.equal(fs.readFileSync(seen, 'utf8'), pluginRoot + ' hook claude-code');
});
