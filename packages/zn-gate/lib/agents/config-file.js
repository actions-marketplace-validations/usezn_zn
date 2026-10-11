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
  try {
    const text = fs.readFileSync(file, 'utf8');
    return text.trim() ? JSON.parse(text) : {};
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw new Error('cannot parse ' + file + ': ' + err.message + ' (left unchanged)');
  }
}

function backup(file) {
  if (!fs.existsSync(file)) return null;
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '');
  const dest = file + '.bak-zn-' + stamp;
  fs.copyFileSync(file, dest);
  return dest;
}

function writeJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  writeFileAtomic(file, JSON.stringify(data, null, 2) + '\n', 0o644);
}

function quoteArg(s) {
  return '"' + String(s).replace(/\\/g, '/').replace(/"/g, '\\"') + '"';
}

function runnerPath() {
  return path.resolve(__dirname, '..', 'hooks', 'runner.js');
}

/** The command an agent runs for each hook event. */
function hookCommand(agentId, opts = {}) {
  if (opts.command) return opts.command;
  return quoteArg(opts.nodePath || process.execPath) + ' ' + quoteArg(opts.runnerPath || runnerPath()) + ' ' + agentId;
}

function isOurs(command, agentId) {
  return typeof command === 'string' && new RegExp('(\\bhook ' + agentId + '|hooks[\\\\/]runner\\.js"? ' + agentId + ')\\s*$').test(command);
}

module.exports = { readJson, backup, writeJson, quoteArg, runnerPath, hookCommand, isOurs };
