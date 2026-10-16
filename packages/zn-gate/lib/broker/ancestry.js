'use strict';

/**
 * Is this process running under a coding agent's command-line program?
 *
 * The environment variables that agents set (tty.js AGENT_ENV_VARS) can be
 * removed by the agent itself (`env -u CLAUDECODE zn ...`). The chain of
 * parent processes cannot: a command that an agent runs is a descendant of
 * the agent's own process. This walks that chain and looks for the agents'
 * command-line programs only (claude, codex, opencode, cursor-agent), never
 * for an editor app, so the integrated terminal of VS Code or Cursor, where
 * a person types, is not affected.
 *
 * A heuristic second line of defence, like the variables: when the process
 * table cannot be read, it reports nothing and the other checks still apply.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const MAX_DEPTH = 32;
const TIMEOUT_MS = 3000;

// Programs, by the base name of the executable (lower case, without .exe/.cmd).
const AGENT_PROGRAMS = new Set(['claude', 'codex', 'opencode', 'cursor-agent']);
// The same agents started by a JavaScript runtime: a path segment of the script.
const RUNTIMES = new Set(['node', 'nodejs', 'bun', 'deno']);
const AGENT_SCRIPT_RE = /[\\/](?:@anthropic-ai[\\/]claude-code|@openai[\\/]codex|opencode-ai|cursor-agent)(?:[\\/]|$)/i;

function baseName(file) {
  return path.basename(String(file || '').replace(/\\/g, '/')).toLowerCase().replace(/\.(exe|cmd|bat|com)$/, '');
}

/** The agent program a process entry {name, argv|cmd} belongs to, or null. */
function agentOf(proc) {
  const argv = proc.argv && proc.argv.length ? proc.argv : null;
  const exe = baseName((argv && argv[0]) || proc.name);
  const name = baseName(proc.name);
  if (AGENT_PROGRAMS.has(exe)) return exe;
  if (AGENT_PROGRAMS.has(name)) return name;
  if (RUNTIMES.has(exe) || RUNTIMES.has(name)) {
    const rest = argv ? argv.slice(1) : String(proc.cmd || '').split(/\s+/).slice(1);
    for (const a of rest) {
      const m = AGENT_SCRIPT_RE.exec(a);
      if (m) return /claude-code/i.test(m[0]) ? 'claude' : /codex/i.test(m[0]) ? 'codex' : /opencode/i.test(m[0]) ? 'opencode' : 'cursor-agent';
    }
  }
  return null;
}

/* Linux: /proc/<pid>/stat for the parent (the name in parentheses may hold spaces and parentheses), /proc/<pid>/cmdline for argv. */
function parseStat(text) {
  const close = text.lastIndexOf(')');
  if (close < 0) return null;
  const fields = text.slice(close + 2).split(' ');
  const ppid = Number(fields[1]);
  return { name: text.slice(text.indexOf('(') + 1, close), ppid: Number.isInteger(ppid) ? ppid : 0 };
}

function linuxEntry(pid) {
  try {
    const st = parseStat(fs.readFileSync('/proc/' + pid + '/stat', 'utf8'));
    if (!st) return null;
    let argv = [];
    try { argv = fs.readFileSync('/proc/' + pid + '/cmdline', 'utf8').split('\0').filter(Boolean); } catch (_) { argv = []; }
    return { pid, ppid: st.ppid, name: st.name, argv };
  } catch (_) {
    return null;
  }
}

/* macOS (and Linux without /proc): one `ps` call for the whole table. `args` is split on spaces, which is enough for names and paths. */
function parsePs(text) {
  const table = new Map();
  for (const line of String(text).split('\n')) {
    const m = /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(line);
    if (!m) continue;
    const args = m[3].trim();
    table.set(Number(m[1]), { pid: Number(m[1]), ppid: Number(m[2]), name: args.split(/\s+/)[0] || '', argv: args.split(/\s+/) });
  }
  return table;
}

/* Windows: one CIM query; JSON array of {ProcessId, ParentProcessId, Name, CommandLine}. */
function parseCim(text) {
  const table = new Map();
  let rows;
  try { rows = JSON.parse(String(text).trim() || '[]'); } catch (_) { return table; }
  if (!Array.isArray(rows)) rows = [rows];
  for (const r of rows) {
    if (!r || !Number.isInteger(r.ProcessId)) continue;
    const cmd = String(r.CommandLine || '');
    // The command line is one string; the executable is its first token, quoted or not.
    const exe = /^\s*"([^"]*)"/.exec(cmd) ? /^\s*"([^"]*)"/.exec(cmd)[1] : cmd.trim().split(/\s+/)[0] || r.Name;
    const rest = cmd.replace(/^\s*("[^"]*"|\S+)\s*/, '');
    table.set(r.ProcessId, { pid: r.ProcessId, ppid: Number(r.ParentProcessId) || 0, name: String(r.Name || ''), argv: [exe, ...rest.split(/\s+/).filter(Boolean)] });
  }
  return table;
}

function psTable() {
  for (const ps of ['/bin/ps', '/usr/bin/ps']) {
    if (!fs.existsSync(ps)) continue;
    const r = spawnSync(ps, ['-axo', 'pid=,ppid=,args='], { encoding: 'utf8', timeout: TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024 });
    if (!r.error && r.status === 0) return parsePs(r.stdout);
  }
  return null;
}

function cimTable() {
  // Absolute path only, like the clipboard reader: a powershell planted on PATH would decide.
  const ps = path.join(process.env.SystemRoot || process.env.SYSTEMROOT || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const script = 'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json -Compress';
  const r = spawnSync(ps, ['-NoProfile', '-NonInteractive', '-Command', script], { encoding: 'utf8', timeout: TIMEOUT_MS * 3, maxBuffer: 64 * 1024 * 1024, windowsHide: true });
  return !r.error && r.status === 0 ? parseCim(r.stdout) : null;
}

/** Walks from `pid`'s parent upwards with `lookup(pid) -> entry|null`; the first agent found, or null. */
function walk(pid, lookup) {
  const seen = new Set();
  let cur = lookup(pid);
  let next = cur ? cur.ppid : 0;
  for (let i = 0; i < MAX_DEPTH && next > 0 && !seen.has(next); i++) {
    seen.add(next);
    cur = lookup(next);
    if (!cur) return null;
    const a = agentOf(cur);
    if (a) return a;
    next = cur.ppid;
  }
  return null;
}

/**
 * agentAncestor({pid, platform}) -> 'claude' | 'codex' | 'opencode' | 'cursor-agent' | null.
 * Never throws; null when no agent program is an ancestor or the process table cannot be read.
 */
function agentAncestor(opts = {}) {
  const pid = opts.pid || process.pid;
  const platform = opts.platform || process.platform;
  try {
    if (platform === 'linux' && fs.existsSync('/proc/self/stat')) return walk(pid, linuxEntry);
    const table = platform === 'win32' ? cimTable() : psTable();
    return table ? walk(pid, (p) => table.get(p) || null) : null;
  } catch (_) {
    return null;
  }
}

module.exports = { agentAncestor, _internal: { agentOf, parseStat, parsePs, parseCim, walk, AGENT_PROGRAMS } };
