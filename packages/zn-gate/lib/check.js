'use strict';

/**
 * zn-gate check: shows, safely, that the zn hooks installed for each agent
 * stop a secret from being read.
 *
 * It makes a temporary folder with a .env file that holds an obviously fake
 * key, and sends each agent's zn hook the event that agent sends when it is
 * about to read that file. For every agent it reports:
 *   - whether zn's hooks are installed for it;
 *   - what zn decides, and the message the agent would be shown;
 *   - for Claude Code, Codex and Cursor, whether the installed hook command
 *     itself still runs (a Node.js version that was removed, for example,
 *     leaves a hook that cannot start).
 * Claude Code is checked through the zn-gate plugin when it is installed
 * (its own launcher, scripts/zn-launch.js, run as Claude Code runs it), or
 * through the hooks of `zn hooks install claude-code` otherwise.
 * The installed command is run only when it has the exact shape zn writes
 * (the same check `zn audit` uses), as node + runner without a shell. Nothing
 * leaves the machine, no agent is started, no setting changes, and the folder
 * is deleted at the end.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const FAKE_LINE = 'ZN_CHECK_EXAMPLE_KEY=zn-check-fake-value-not-a-real-key\n';
const HOOK_TIMEOUT_MS = 15000;
// Claude Code runs hooks with sh, so its adapter writes each path as one single-quoted word
// (lib/agents/claude-code.js quoteArg); the double-quoted forms are in lib/audit OUR_HOOKS.
const ABS = '(?:/|[A-Za-z]:/)';
const SH_QUOTED = new RegExp("^'(" + ABS + "[^'\\r\\n]{1,4096})' '(" + ABS +
  "[^'\\r\\n]{1,4096}/zn-gate/lib/hooks/runner\\.js)' (?:claude-code|codex|cursor|opencode)$");

const AGENTS = [
  {
    id: 'claude-code', name: 'Claude Code', install: 'the zn-gate plugin (see https://usezn.com/docs/install)',
    file: (a, o) => a.settingsFile(o),
    event: (dir, env) => ({ hook_event_name: 'PreToolUse', session_id: 'zn-check', cwd: dir, tool_name: 'Read', tool_input: { file_path: env } }),
  },
  {
    id: 'codex', name: 'Codex CLI', install: 'zn hooks install codex',
    file: (a, o) => a.hooksFile(o),
    event: (dir) => ({ hook_event_name: 'PreToolUse', session_id: 'zn-check', cwd: dir, tool_name: 'Bash', tool_input: { command: 'cat .env' } }),
  },
  {
    id: 'cursor', name: 'Cursor', install: 'zn hooks install cursor',
    file: (a, o) => a.hooksFile(o),
    event: (dir, env) => ({ hook_event_name: 'beforeReadFile', cwd: dir, file_path: env, content: FAKE_LINE, workspace_roots: [dir] }),
  },
  {
    id: 'opencode', name: 'OpenCode', install: 'zn hooks install opencode',
    file: (a, o) => a.pluginPath(o),
    event: (dir, env) => ({ hook: 'tool.execute.before', tool: 'read', cwd: dir, args: { filePath: env } }),
  },
];

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    return null;
  }
}

/* The zn hook commands in an agent's settings file, parsed: [{node, runner} | {onPath: true}]. */
function ourCommands(spec, file, agentId) {
  const { _internal: audit } = require('./audit');
  if (spec.id === 'opencode') {
    let src = '';
    try { src = fs.readFileSync(file, 'utf8'); } catch (err) { return []; }
    return /lib\/hooks\/runner\.js|"hook", "opencode"/.test(src) ? [{ plugin: true }] : [];
  }
  const tree = readJson(file);
  if (!tree) return [];
  const out = [];
  for (const { command } of audit.hookCommands(tree)) {
    const c = String(command).trim();
    for (const re of [...audit.OUR_HOOKS, SH_QUOTED]) {
      const m = re.exec(c);
      if (!m || !c.endsWith(agentId) && !c.endsWith(agentId + '"')) continue;
      out.push(m[2] ? { node: m[1], runner: m[2] } : { onPath: true });
      break;
    }
  }
  return out;
}

function blockedOutput(agentId, r) {
  if (r.status === 2) return true;  // Claude Code and Codex: exit code 2 blocks the call
  const o = String(r.stdout || '');
  return /"permissionDecision"\s*:\s*"deny"|"decision"\s*:\s*"(?:deny|block)"|"permission"\s*:\s*"deny"|"continue"\s*:\s*false/.test(o);
}

/* Folders of the zn-gate Claude Code plugin installed for this user (newest first). */
function claudePluginRoots(home, env) {
  const base = path.join(require('./agents').getAdapter('claude-code').configDir({ home, env }), 'plugins');
  const roots = [];
  const listed = readJson(path.join(base, 'installed_plugins.json'));
  (function walk(node, key, depth) {
    if (!node || typeof node !== 'object' || depth > 6) return;
    if (/^zn-gate@/.test(key || '') || node.name === 'zn-gate') {
      if (typeof node.installPath === 'string') roots.push(node.installPath);
    }
    for (const [k, v] of Object.entries(node)) walk(v, /^zn-gate@/.test(k) ? k : key, depth + 1);
  })(listed, '', 0);
  try {
    for (const mk of fs.readdirSync(path.join(base, 'cache'))) {
      const dir = path.join(base, 'cache', mk, 'zn-gate');
      if (!fs.existsSync(dir)) continue;
      for (const v of fs.readdirSync(dir).sort().reverse()) roots.push(path.join(dir, v));
    }
  } catch (err) { /* no plugin cache */ }
  return [...new Set(roots)].filter((r) => fs.existsSync(path.join(r, 'scripts', 'zn-launch.js')));
}

/* Run the plugin's launcher as Claude Code does (node, CLAUDE_PLUGIN_ROOT), with the event on stdin. */
function runPlugin(root, event) {
  const r = spawnSync(process.execPath, [path.join(root, 'scripts', 'zn-launch.js'), 'hook', 'claude-code'], {
    input: JSON.stringify(event), encoding: 'utf8', timeout: HOOK_TIMEOUT_MS,
    env: { ...process.env, CLAUDE_PLUGIN_ROOT: root, ZN_STATS: 'off' }, windowsHide: true,
  });
  if (r.error) return { ok: false, why: 'the plugin did not run (' + (r.error.code || r.error.message) + ')' };
  return { ok: true, blocked: blockedOutput('claude-code', r), via: 'plugin' };
}

/* Run the installed hook command (node + runner, no shell) with the event on stdin. */
function runInstalled(cmd, agentId, event) {
  if (!fs.existsSync(cmd.node)) return { ok: false, why: 'its Node.js (' + cmd.node + ') is no longer there' };
  if (!fs.existsSync(cmd.runner)) return { ok: false, why: 'its zn-gate files (' + cmd.runner + ') are no longer there' };
  const r = spawnSync(cmd.node, [cmd.runner, agentId], {
    input: JSON.stringify(event), encoding: 'utf8', timeout: HOOK_TIMEOUT_MS,
    env: { ...process.env, ZN_STATS: 'off' }, windowsHide: true,
  });
  if (r.error) return { ok: false, why: 'it did not run (' + (r.error.code || r.error.message) + ')' };
  return { ok: true, blocked: blockedOutput(agentId, r) };
}

/**
 * check({home, env, cwd}) -> {results: [...], tmp} ; never throws for one agent.
 * Each result: {id, name, installed, blocked, message, live: null|{ok, blocked, why}, install}
 */
async function check(opts = {}) {
  const { getAdapter } = require('./agents');
  const runner = require('./hooks/runner');
  const home = opts.home || os.homedir();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-check-'));
  const envFile = path.join(dir, '.env');
  const results = [];
  try {
    fs.writeFileSync(path.join(dir, '.gitignore'), '.env\n');
    fs.writeFileSync(envFile, FAKE_LINE, { mode: 0o600 });
    for (const spec of AGENTS) {
      const res = { id: spec.id, name: spec.name, install: spec.install, installed: false, blocked: false, message: '', live: null };
      try {
        const adapter = getAdapter(spec.id);
        const file = spec.file(adapter, { home, env: opts.env || process.env });
        const cmds = ourCommands(spec, file, spec.id);
        const plugins = spec.id === 'claude-code' ? claudePluginRoots(home, opts.env || process.env) : [];
        res.installed = cmds.length > 0 || plugins.length > 0;
        res.settings = plugins.length ? plugins[0] : file;
        const event = spec.event(dir, envFile);
        const { decision } = await runner.handle(adapter, event, { home });
        res.blocked = Boolean(decision) && decision.decision === 'deny';
        res.message = (decision && decision.message) || '';
        const exe = cmds.find((c) => c.node);
        if (plugins.length) res.live = runPlugin(plugins[0], event);
        else if (res.installed && exe) res.live = runInstalled(exe, spec.id, event);
      } catch (err) {
        res.error = err && err.message ? err.message : String(err);
      }
      results.push(res);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  return { results, removed: !fs.existsSync(dir) };
}

/** Plain-language report; returns the exit code (0 when every installed agent blocks). */
function report({ results, removed }, write) {
  const w = write || ((s) => process.stdout.write(s));
  w('\nzn-gate check: does zn stop your coding agent from reading a secret?\n\n');
  w('zn made a test folder with a .env file that holds a fake key, and asked each agent\'s zn hook\n');
  w('to let the agent read it. This is what happened:\n\n');
  let installed = 0;
  let failed = 0;
  for (const r of results) {
    if (!r.installed) {
      w(`  -  ${r.name.padEnd(12)} zn is not set up for this agent. To protect it: ${r.install}\n`);
      continue;
    }
    installed++;
    const liveBad = r.live && (!r.live.ok || !r.live.blocked);
    if (r.error || !r.blocked || liveBad) {
      failed++;
      const why = r.error ? 'zn could not check it: ' + r.error
        : !r.blocked ? 'zn did not block the read'
          : !r.live.ok ? 'the hook installed in ' + r.settings + ' cannot start: ' + r.live.why
            : 'the hook installed in ' + r.settings + ' did not block the read';
      w(`  X  ${r.name.padEnd(12)} NOT protected: ${why}.\n`);
      w(`     Fix: ${r.install.startsWith('zn ') ? 'run `' + r.install + '` again in your own terminal' : 'reinstall ' + r.install}.\n`);
      continue;
    }
    w(`  OK ${r.name.padEnd(12)} blocked. Your agent would be told:\n`);
    w(`     "${r.message.replace(/\s+/g, ' ').slice(0, 300)}"\n`);
    if (r.live === null && r.id !== 'opencode') w('     (the installed hook uses `zn` from your PATH; the check ran zn\'s rules directly)\n');
  }
  w('\n');
  if (!installed) {
    w('zn is not set up for any agent yet, so nothing protects your secrets. Install it for your agent:\n');
    w('https://usezn.com/docs/install\n\n');
  } else if (!failed) {
    w('Your agent cannot read secret files such as .env through these tools. Nothing was sent anywhere.\n');
    w('If your agent needs a value from .env, keep it in zn\'s vault instead: `zn env shadow .env`.\n');
    w('More: https://usezn.com/docs/check\n\n');
  } else {
    w('Some agents are not protected (see above). More: https://usezn.com/docs/check\n\n');
  }
  w(removed ? 'The test folder was deleted.\n' : 'The test folder could not be deleted; it holds only the fake key.\n');
  return installed && !failed ? 0 : 1;
}

module.exports = { check, report, FAKE_LINE, AGENTS, _internal: { ourCommands, blockedOutput, runInstalled, claudePluginRoots } };
