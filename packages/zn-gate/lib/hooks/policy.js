'use strict';

/**
 * Agent-independent policy used by the hook runner.
 *
 *  - Credential files: reads are denied (except .env files that only hold
 *    __ZN_ markers, see `zn env shadow`).
 *  - zn's own state (~/.zn) is off limits to agents, for reads and writes.
 *  - Commands that manage secrets (`zn secret set`, `zn env shadow`, ...)
 *    must be run by the user, never by an agent.
 *  - Bash commands with named markers are wrapped in `zn run --`, which
 *    applies allowCommands, first-use approval and output masking.
 *
 * Hooks are a guardrail, not a sandbox: a determined process can always
 * find another way to read a file. The goal is that secret values never
 * reach the model through the normal tool paths.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const dotenv = require('../broker/dotenv');
const markers = require('../broker/markers');

/* ------------------------------ paths ------------------------------ */

// Home and zn-home references written as shell variables (bash, PowerShell,
// cmd), so `cat $HOME/.zn/...` or `gc $env:USERPROFILE\.aws\credentials`
// are classified like their literal paths.
const HOME_VAR_RE = /^(?:\$\{?HOME\}?|\$env:(?:HOME|USERPROFILE)|%USERPROFILE%|%HOMEDRIVE%%HOMEPATH%)(?=$|[\\/])/i;
const ZN_HOME_VAR_RE = /^(?:\$\{?ZN_HOME\}?|\$env:ZN_HOME|%ZN_HOME%)(?=$|[\\/])/i;

function expandHome(p, home) {
  if (p === '~') return home;
  if (p.startsWith('~/') || p.startsWith('~\\')) return path.join(home, p.slice(2));
  if (ZN_HOME_VAR_RE.test(p)) return path.join(home, '.zn', p.replace(ZN_HOME_VAR_RE, ''));
  if (HOME_VAR_RE.test(p)) return path.join(home, p.replace(HOME_VAR_RE, ''));
  return p;
}

function slash(p) {
  return String(p).replace(/\\/g, '/');
}

const DOTENV_BASENAME_RE = /^\.env(\.[A-Za-z0-9_.-]+)?$/;
const DOTENV_SAFE_RE = /\.(example|sample|template|dist|defaults|schema)$/i;

const CREDENTIAL_RES = [
  [/(^|\/)\.aws\/credentials$/, 'AWS credentials file'],
  [/(^|\/)\.ssh\/(id_[^/]+|[^/]+_key)$/, 'SSH private key'],
  [/(^|\/)[._]netrc$/, '.netrc credentials'],
  [/(^|\/)\.docker\/config\.json$/, 'Docker registry credentials'],
  [/(^|\/)\.config\/gh\/hosts\.ya?ml$/, 'GitHub CLI token'],
  [/(^|\/)\.git-credentials$/, 'git credentials'],
  [/(^|\/)\.pgpass$/, 'PostgreSQL password file'],
  [/(^|\/)\.kube\/config$/, 'Kubernetes credentials'],
  [/(^|\/)\.config\/gcloud\/(credentials\.db|access_tokens\.db|application_default_credentials\.json)$/, 'Google Cloud credentials'],
  [/(^|\/)\.azure\/(accessTokens\.json|msal_token_cache\.json)$/, 'Azure credentials'],
];

/**
 * Classify a path. Returns null or {kind, reason}:
 *   kind 'credential' | 'dotenv' | 'zn_state'
 */
function classifyPath(p, opts = {}) {
  if (typeof p !== 'string' || !p) return null;
  const home = opts.home || os.homedir();
  const cwd = opts.cwd || process.cwd();
  const abs = path.resolve(cwd, expandHome(p, home));
  const s = slash(abs);
  const h = slash(path.resolve(home));
  if (s === h + '/.zn' || s.startsWith(h + '/.zn/')) return { kind: 'zn_state', reason: 'zn keeps its vault and audit log in ~/.zn' };
  if (s.endsWith('.pub')) return null;
  for (const [re, reason] of CREDENTIAL_RES) if (re.test(s)) return { kind: 'credential', reason };
  if (s === h + '/.npmrc' || s === h + '/.pypirc') return { kind: 'credential', reason: 'package registry token' };
  const base = path.basename(abs);
  if (DOTENV_BASENAME_RE.test(base) && !DOTENV_SAFE_RE.test(base)) return { kind: 'dotenv', reason: '.env file' };
  return null;
}

/**
 * Decide on a read of `p`. Returns null (allowed) or a deny message.
 * .env files are allowed once shadowed (only markers inside).
 */
function readDenial(p, opts = {}) {
  const c = classifyPath(p, opts);
  if (!c) return null;
  if (c.kind === 'dotenv') {
    const abs = path.resolve(opts.cwd || process.cwd(), expandHome(p, opts.home || os.homedir()));
    let text;
    try {
      text = fs.readFileSync(abs, 'utf8');
    } catch (_) {
      return null; // missing file: nothing to protect
    }
    if (dotenv.isShadowed(text)) return null;
    return 'zn: ' + path.basename(abs) + ' holds plain-text secrets. Ask the user to run `zn env shadow ' +
      path.basename(abs) + '` in their terminal: it moves the values to the local vault and leaves __ZN_<NAME>__ markers you can read and use.';
  }
  if (c.kind === 'zn_state') return 'zn: ~/.zn is the local secret vault; agents may not read or change it.';
  return 'zn: reading ' + c.reason + ' (' + p + ') is blocked so secret values never reach the model. ' +
    'If a command needs it, ask the user to add the value with `zn secret set <NAME>` and use the __ZN_<NAME>__ marker.';
}

/** Writes are only blocked for zn's own state. */
function writeDenial(p, opts = {}) {
  const c = classifyPath(p, opts);
  if (c && c.kind === 'zn_state') return 'zn: ~/.zn is the local secret vault; agents may not read or change it.';
  return null;
}

/* ------------------------------ shell ------------------------------ */

/**
 * Split a shell command into top-level words of its first simple command.
 * Returns {end, words: [{text, start, end}], substitution, operator}
 *   end: index where the first simple command stops (first top-level
 *        ; & | newline ( ) or end of string)
 *   substitution: true if $( or ` appears inside the first command
 *   words[].text is the word with quotes removed (approximation of bash)
 */
function scanFirstCommand(cmd) {
  const s = String(cmd);
  const words = [];
  let i = 0;
  let cur = null;
  let substitution = false;
  let quote = null;
  const pushChar = (ch, at) => {
    if (!cur) cur = { text: '', start: at, end: at };
    cur.text += ch;
    cur.end = at + 1;
  };
  const endWord = () => {
    if (cur) words.push(cur);
    cur = null;
  };
  for (; i < s.length; i++) {
    const ch = s[i];
    if (quote === "'") {
      if (ch === "'") { quote = null; cur.end = i + 1; } else pushChar(ch, i);
      continue;
    }
    if (quote === '"') {
      if (ch === '\\' && i + 1 < s.length) { pushChar(s[i + 1], i); i++; continue; }
      if (ch === '"') { quote = null; cur.end = i + 1; continue; }
      if (ch === '`' || (ch === '$' && s[i + 1] === '(')) substitution = true;
      pushChar(ch, i);
      continue;
    }
    if (ch === '\\' && i + 1 < s.length) {
      if (s[i + 1] === '\n') { i++; continue; }
      pushChar(s[i + 1], i);
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      if (!cur) cur = { text: '', start: i, end: i + 1 };
      continue;
    }
    if (ch === '`' || (ch === '$' && s[i + 1] === '(')) { substitution = true; pushChar(ch, i); continue; }
    if (ch === ';' || ch === '&' || ch === '|' || ch === '\n' || ch === '(' || ch === ')') {
      endWord();
      return { end: i, words, substitution, operator: ch, unterminated: false };
    }
    if (ch === ' ' || ch === '\t') { endWord(); continue; }
    pushChar(ch, i);
  }
  endWord();
  return { end: s.length, words, substitution, operator: null, unterminated: quote !== null };
}

/** Every word of the whole command (rough), with a flag for > / >> targets. */
function allWords(cmd) {
  const out = [];
  let rest = String(cmd);
  let guard = 0;
  while (rest.length && guard++ < 1000) {
    const scan = scanFirstCommand(rest);
    for (let k = 0; k < scan.words.length; k++) {
      const w = scan.words[k];
      const prev = k > 0 ? scan.words[k - 1].text : '';
      const isRedirTarget = /^[0-9]*>>?$/.test(prev) || /^[0-9]*>>?./.test(w.text);
      out.push({ text: w.text.replace(/^[0-9]*>>?/, '').replace(/^</, ''), redirectTarget: isRedirTarget });
    }
    rest = rest.slice(scan.end + 1);
  }
  return out;
}

const RESERVED_WORDS = new Set(['if', 'then', 'else', 'elif', 'fi', 'for', 'while', 'until', 'do', 'done', 'case', 'esac', 'function', '{', '}', '!', '[[', 'time', 'coproc', 'select', 'eval', 'exec', 'source', '.', 'sudo', 'doas', 'env', 'xargs', 'nohup', 'command', 'builtin', 'export', 'declare', 'local', 'readonly', 'typeset', 'alias', 'set', 'unset', 'let']);
const ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * Prefix the first simple command with `zn run --` so the broker applies
 * policy, approval and masking. Only when every named marker is inside the
 * first simple command; anything else is refused with guidance.
 * Returns {ok: true, command} or {ok: false, reason}.
 */
function wrapWithZnRun(cmd, znRunPrefix) {
  const s = String(cmd);
  const named = markers.findNamedMarkers(s);
  if (named.length === 0) return { ok: true, command: s, wrapped: false };
  const scan = scanFirstCommand(s);
  const tail = s.slice(scan.end);
  const guidance = ' Put the command that uses the secret first, as a single simple command ' +
    '(for example: psql "postgres://app:__ZN_DB_PASSWORD__@db/app" -c "select 1"), in its own Bash call.';
  if (scan.unterminated) return { ok: false, reason: 'zn: could not parse the command (unterminated quote).' };
  if (markers.findNamedMarkers(tail).length > 0) {
    return { ok: false, reason: 'zn: secret markers are only supported in the first command of a Bash call.' + guidance };
  }
  if (scan.substitution) {
    return { ok: false, reason: 'zn: secret markers cannot be combined with $( ) or backtick substitution in the same command.' + guidance };
  }
  let k = 0;
  while (k < scan.words.length && ASSIGNMENT_RE.test(scan.words[k].text)) k++;
  if (k >= scan.words.length) {
    return { ok: false, reason: 'zn: a secret marker in a plain variable assignment would only store the marker.' + guidance };
  }
  for (let j = 0; j < k; j++) {
    if (markers.findNamedMarkers(scan.words[j].text).length) {
      return { ok: false, reason: 'zn: pass secrets to a command with `zn run --secrets NAME -- <command>` instead of a leading VAR=__ZN_NAME__ assignment.' };
    }
  }
  const first = scan.words[k];
  if (RESERVED_WORDS.has(first.text)) {
    return { ok: false, reason: 'zn: `' + first.text + '` cannot be wrapped for secret injection.' + guidance };
  }
  // Already wrapped by the agent or a previous hook: leave it alone, zn run applies policy.
  if (/(^|[\\/])(zn|zn-gate)(\.js|\.cmd)?$/.test(first.text) && scan.words[k + 1] && scan.words[k + 1].text === 'run') {
    return { ok: true, command: s, wrapped: false };
  }
  return { ok: true, command: s.slice(0, first.start) + znRunPrefix + ' ' + s.slice(first.start), wrapped: true };
}

/* ---------------------------- PowerShell ---------------------------- */

// Aliases that Windows PowerShell maps to cmdlets (curl and wget are
// Invoke-WebRequest there): never treated as native commands.
const PS_ALIASES = new Set(['curl', 'wget', 'iwr', 'irm', 'iex', 'icm', 'cat', 'gc', 'type', 'echo', 'write', 'ls', 'dir', 'gci',
  'cp', 'copy', 'mv', 'move', 'rm', 'del', 'erase', 'ri', 'sc', 'ac', 'set', 'sv', 'sl', 'cd', 'chdir', 'pushd', 'popd',
  'start', 'saps', 'sajb', 'foreach', 'where', '%', '?', 'select', 'sort', 'measure', 'tee', 'ni', 'md', 'mkdir', 'sleep',
  'kill', 'spps', 'ps', 'gps', 'history', 'h', 'r', 'clear', 'cls', 'man', 'help', 'ipmo', 'ise', 'nal', 'sal']);
const PS_META = new Set([';', '|', '&', '(', ')', '{', '}', '@', '$', '`', '<', '>', ',', '\n', '\r']);

/**
 * Tokenize a PowerShell command line conservatively. Returns
 * {words: [{text, start, end}], simple} where simple is false when the line
 * has anything beyond one native command with plain arguments: pipelines,
 * statements, script blocks, variables, subexpressions, splatting,
 * redirection, or double-quoted strings that would expand.
 */
function scanPowerShell(cmd) {
  const s = String(cmd);
  const words = [];
  let cur = null;
  let simple = true;
  let quote = null;
  const push = (ch, at) => {
    if (!cur) cur = { text: '', start: at, end: at };
    cur.text += ch;
    cur.end = at + 1;
  };
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote === "'") {
      if (ch === "'" && s[i + 1] === "'") { push("'", i); i++; continue; }
      if (ch === "'") { quote = null; cur.end = i + 1; continue; }
      push(ch, i);
      continue;
    }
    if (quote === '"') {
      if (ch === '"') { quote = null; cur.end = i + 1; continue; }
      if (ch === '$' || ch === '`') simple = false;
      push(ch, i);
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      if (!cur) cur = { text: '', start: i, end: i + 1 };
      continue;
    }
    if (ch === ' ' || ch === '\t') {
      if (cur) words.push(cur);
      cur = null;
      continue;
    }
    if (PS_META.has(ch)) simple = false;
    push(ch, i);
  }
  if (cur) words.push(cur);
  if (quote) simple = false;
  return { words, simple };
}

function psQuote(s) {
  return "'" + String(s).replace(/\\/g, '/').replace(/'/g, "''") + "'";
}

/**
 * PowerShell counterpart of wrapWithZnRun. Commands with named markers are
 * only wrapped when the whole line is one native command with plain
 * arguments; anything else (cmdlets, aliases, pipelines, variables) is
 * refused, because zn cannot rewrite it safely.
 * opts: {nodePath, runJs, agent}
 */
function wrapPowerShell(cmd, opts) {
  const s = String(cmd);
  const named = markers.findNamedMarkers(s);
  if (named.length === 0) return { ok: true, command: s, wrapped: false };
  const guidance = ' In PowerShell, put the secret in a single native command with plain arguments ' +
    "(for example: psql 'postgres://app:__ZN_DB_PASSWORD__@db/app' -c 'select 1'). " +
    'For HTTP APIs use the secrets_http_request tool of the zn "secrets" MCP server instead of Invoke-WebRequest or curl.';
  const scan = scanPowerShell(s);
  if (!scan.simple || scan.words.length === 0) {
    return { ok: false, reason: 'zn: this PowerShell command cannot be rewritten safely for secret injection (pipelines, variables, script blocks and expanding strings are not supported).' + guidance };
  }
  const first = scan.words[0].text;
  const base = path.basename(first.replace(/\\/g, '/')).toLowerCase().replace(/\.(exe|cmd|bat|ps1)$/, '');
  if (/^[a-z]+-[a-z]+$/i.test(first) || PS_ALIASES.has(first.toLowerCase())) {
    return { ok: false, reason: 'zn: `' + first + '` is a PowerShell cmdlet or alias; zn can only pass secrets to native programs.' + guidance };
  }
  if (/\.ps1$/i.test(first)) {
    return { ok: false, reason: 'zn: PowerShell scripts (.ps1) cannot receive secrets through zn run.' + guidance };
  }
  if (!/^[A-Za-z0-9_.\-\\/:]+$/.test(first)) {
    return { ok: false, reason: 'zn: could not identify the program in this command.' + guidance };
  }
  if ((base === 'zn' || base === 'zn-gate') && scan.words[1] && scan.words[1].text === 'run') {
    return { ok: true, command: s, wrapped: false };
  }
  const prefix = '& ' + psQuote(opts.nodePath) + ' ' + psQuote(opts.runJs) + ' --agent ' + String(opts.agent).replace(/[^a-z0-9-]/g, '') + ' --';
  return { ok: true, command: prefix + ' ' + s.slice(scan.words[0].start), wrapped: true };
}

const NETWORK_RE = /(^|[\s;&|(`$'"])(curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync|ftp|tftp|http|https|httpie|xh|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)(?=$|[\s;&|)'"])|\bgit\s+(push|fetch|pull|clone|remote|ls-remote)\b|\b(npm|pnpm|yarn)\s+publish\b|\b(docker|podman)\s+(push|login)\b|\bhttps?:\/\/|\/dev\/(tcp|udp)\//i;

function hasNetworkSignals(cmd) {
  const s = String(cmd || '');
  if (NETWORK_RE.test(s)) return true;
  // Same heuristic as the engine's restore policy (network commands, URLs,
  // sockets and HTTP libraries in inline code).
  try { return require('../scrub/engine').isNetworkCommand(s); } catch (_) { return false; }
}

const ZN_ADMIN_RE = /(^|[\s;&|(`$'"\\/])(zn|zn-gate|cli\.js)(\.cmd|\.js)?["']?\s+(secret\s+(set|get|rm|remove|import|adopt|approve|allow|reveal|link)|env\s+(shadow|unshadow)|unlock|lock|hooks\s+(install|uninstall))\b/i;

function adminCommand(cmd) {
  const m = ZN_ADMIN_RE.exec(String(cmd || ''));
  return m ? m[4].replace(/\s+/g, ' ') : null;
}

/**
 * Bash commands that read credential files or touch ~/.zn.
 * Returns null or a deny message.
 */
function bashDenial(cmd, opts = {}) {
  const admin = adminCommand(cmd);
  if (admin) {
    return 'zn: `zn ' + admin + '` manages secret values and must be run by the user in their own terminal, not by an agent. ' +
      'Ask the user to run it.';
  }
  for (const w of allWords(cmd)) {
    if (!w.text || w.text.startsWith('-')) continue;
    const c = classifyPath(w.text, opts);
    if (!c) continue;
    if (c.kind === 'zn_state') return writeDenial(w.text, opts) || readDenial(w.text, opts);
    if (w.redirectTarget) continue; // appending to .env is a write, not a read
    const deny = readDenial(w.text, opts);
    if (deny) return deny;
  }
  return null;
}

module.exports = {
  classifyPath,
  readDenial,
  writeDenial,
  scanFirstCommand,
  wrapWithZnRun,
  scanPowerShell,
  wrapPowerShell,
  hasNetworkSignals,
  adminCommand,
  bashDenial,
};
