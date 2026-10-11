'use strict';

/**
 * Small helpers shared by the agent adapters to edit their JSON config
 * files: read (missing file = {}), timestamped backup, atomic write, and
 * removal of only the hook entries zn wrote.
 */

const fs = require('fs');
const path = require('path');
const { writeFileAtomic } = require('../broker/files');

function readJson(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }
  if (!text.trim()) return {};
  let data;
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new Error('cannot parse ' + file + ': ' + err.message + ' (left unchanged)');
  }
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error(file + ' must hold a JSON object, not ' + (data === null ? 'null' : Array.isArray(data) ? 'an array' : typeof data) + ' (left unchanged)');
  }
  return data;
}

/** The "hooks" object of a config file: missing or null is empty; anything else must be an object. */
function hooksOf(data, file) {
  if (data.hooks === undefined || data.hooks === null) return {};
  if (typeof data.hooks !== 'object' || Array.isArray(data.hooks)) {
    throw new Error('"hooks" in ' + file + ' must be an object, not ' + (Array.isArray(data.hooks) ? 'an array' : typeof data.hooks) + ' (left unchanged)');
  }
  return data.hooks;
}

function backup(file) {
  if (!fs.existsSync(file)) return null;
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '');
  const dest = file + '.bak-zn-' + stamp;
  fs.copyFileSync(file, dest);
  return dest;
}

/** Where the config really lives: an existing symlink is followed, so the link itself stays as it is. */
function realFile(file) {
  try { return fs.realpathSync(file); } catch (_) { return file; }
}

function writeJson(file, data) {
  const target = realFile(file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const mode = fs.existsSync(target) ? fs.statSync(target).mode & 0o777 : 0o644;
  writeFileAtomic(target, JSON.stringify(data, null, 2) + '\n', mode);
}

/** Double quotes for sh: $, backticks and quotes are escaped, so the path is taken literally. */
function quoteArg(s) {
  return '"' + String(s).replace(/\\/g, '/').replace(/(["$`])/g, '\\$1') + '"';
}

function runnerPath() {
  return path.resolve(__dirname, '..', 'hooks', 'runner.js');
}

/**
 * The command an agent runs for each hook event. A user install names this
 * user's node and runner. A project install is shared through the repository,
 * so it names `zn` on PATH instead of any path of this user.
 */
function hookCommand(agentId, opts = {}) {
  if (opts.command) return opts.command;
  if ((opts.scope || 'user') === 'project') return 'zn hook ' + agentId;
  return quoteArg(opts.nodePath || process.execPath) + ' ' + quoteArg(opts.runnerPath || runnerPath()) + ' ' + agentId;
}

/**
 * The same command for agents that run `commandWindows` through PowerShell
 * (Codex documents the field but not the shell). A bare quoted path is only a
 * string in PowerShell, so the call is wrapped in powershell.exe, which runs
 * the same way from cmd.exe and from PowerShell.
 */
function hookCommandWindows(agentId, opts = {}) {
  if ((opts.scope || 'user') === 'project') return 'zn hook ' + agentId;
  const ps = (s) => "'" + String(s).replace(/\\/g, '/').replace(/'/g, "''") + "'";
  const inner = '& ' + ps(opts.nodePath || process.execPath) + ' ' + ps(opts.runnerPath || runnerPath()) + ' ' + agentId;
  return 'powershell.exe -NoProfile -NonInteractive -Command "' + inner + '"';
}

function isOurs(command, agentId) {
  return typeof command === 'string' && new RegExp('(\\bhook ' + agentId + '|hooks[\\\\/]runner\\.js"? ' + agentId + ')\\s*$').test(command);
}

module.exports = { readJson, hooksOf, backup, writeJson, quoteArg, runnerPath, hookCommand, hookCommandWindows, isOurs };
