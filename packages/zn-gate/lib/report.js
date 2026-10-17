'use strict';

/**
 * zn-gate report            what zn-gate did on this machine in the last 7 days
 * zn-gate report --since Nd another window (1-90 days)
 * zn-gate report --json     the same as JSON
 * zn-gate report --no-team-line   leave out the closing line about zn Team
 *
 * Reads only local files (~/.zn/stats.json and the MCP pins). It writes nothing,
 * opens no network connection and never prints payloads, paths or secret names.
 * This module does not load the network client.
 */

const path = require('path');
const stats = require('./stats');
const pins = require('./mcp-pins');

const USAGE = 'Usage: zn-gate report [--since 1d-90d] [--json] [--no-team-line]\n';
const DEFAULT_DAYS = 7;
const TEAM_LINE = 'Teams: share these protections across your team with zn Team \u2014 https://usezn.com/team (hide this line with --no-team-line)';

function fmt(n) {
  return Number(n || 0).toLocaleString('en-US');
}

function parse(args) {
  const o = { days: DEFAULT_DAYS, json: false, teamLine: true, bad: false };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    let v = null;
    if (a === '--json') o.json = true;
    else if (a === '--no-team-line') o.teamLine = false;
    else if (a === '--since') v = args[++i];
    else if (a.startsWith('--since=')) v = a.slice(8);
    else o.bad = true;
    if (v !== null) {
      const m = /^(\d{1,3})d$/.exec(String(v));
      const n = m ? Number(m[1]) : NaN;
      if (!m || n < 1 || n > stats.KEEP_DAYS) o.bad = true;
      else o.days = n;
    }
  }
  return o;
}

function dayMinus(now, n) {
  return stats.today(new Date(now.getTime() - n * 86400000));
}

/** A server command for display: secrets hidden, folders reduced to the file name, at most 80 characters. */
function safeCommand(cmd) {
  let s = String(cmd || '');
  try { s = require('./rules').redactSecrets(s).sanitized; } catch (_) { /* below */ }
  const fileName = (t) => path.posix.basename(t.split('\\').join('/')) || '...';
  s = s.split(/\s+/).filter(Boolean).map((t) => (/[\\/]/.test(t) || t.startsWith('~') ? fileName(t) : t)).join(' ');
  return s.length > 80 ? s.slice(0, 77) + '...' : s;
}

function inTeam() {
  try { return Boolean(require('./team/policy').readTeam()); } catch (_) { return false; }
}

function collect(days, now) {
  const from = dayMinus(now, days - 1);
  const until = stats.today(now);
  const data = stats.load();
  const r = { since: from, until, days, checked: 0, blocked: 0, warned: 0, redacted: 0, byAgent: {}, secretTypes: {}, busiest: null };
  for (const [day, entries] of Object.entries(data.days || {})) {
    if (day < from || day > until) continue;
    let dayBlocked = 0;
    for (const [key, c] of Object.entries(entries || {})) {
      const agent = String(key).split(':')[1] || 'other';
      for (const f of ['checked', 'blocked', 'warned', 'redacted']) r[f] += Number(c[f]) || 0;
      dayBlocked += Number(c.blocked) || 0;
      if (Number(c.blocked) > 0) r.byAgent[agent] = (r.byAgent[agent] || 0) + Number(c.blocked);
      for (const [t, n] of Object.entries(c.detections || {})) r.secretTypes[t] = (r.secretTypes[t] || 0) + (Number(n) || 0);
    }
    if (dayBlocked > 0 && (!r.busiest || dayBlocked > r.busiest.blocked)) r.busiest = { day, blocked: dayBlocked };
  }
  let servers = [];
  try { servers = pins.list(); } catch (_) { servers = []; }
  r.newServers = servers
    .filter((s) => typeof s.pinnedAt === 'string' && s.pinnedAt.slice(0, 10) >= from && s.pinnedAt.slice(0, 10) <= until)
    .map((s) => ({ command: safeCommand(s.command), pinned_at: s.pinnedAt }));
  r.pending = servers.reduce((n, s) => n + (Array.isArray(s.pending) ? s.pending.length : 0), 0);
  return r;
}

function top(obj, n) {
  return Object.entries(obj).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, n);
}

function toJson(r) {
  return {
    since: r.since,
    until: r.until,
    days: r.days,
    blocked: r.blocked,
    redacted: r.redacted,
    by_agent: r.byAgent,
    secret_types: r.secretTypes,
    new_mcp_servers: r.newServers,
    pending_tool_changes: r.pending,
    busiest_day: r.busiest ? { day: r.busiest.day, blocked: r.busiest.blocked } : null,
    sources: ['stats.json', 'mcp-pins'],
    sent: false,
  };
}

function run(args, out = (s) => process.stdout.write(s), { now = new Date() } = {}) {
  const o = parse(args);
  if (o.bad) { out(USAGE); return 2; }
  const r = collect(o.days, now);
  if (o.json) { out(JSON.stringify(toJson(r), null, 2) + '\n'); return 0; }

  const team = o.teamLine && !inTeam() ? TEAM_LINE + '\n' : '';
  const title = `zn-gate report: ${r.since} to ${r.until} (this computer only; nothing was sent)\n\n`;
  const empty = !r.checked && !r.blocked && !r.redacted && !r.warned && !r.newServers.length && !r.pending;
  if (!stats.enabled() && empty) {
    out(title + '  Counting is off on this computer (ZN_STATS=off), so there are no numbers to show.\n\n' + team);
    return 0;
  }
  if (empty) {
    out(title + '  Nothing to report yet. zn-gate counts once it checks something (agent hooks, MCP tools or wrapped MCP servers).\n\n' + team);
    return 0;
  }
  out(title);
  const agents = top(r.byAgent, 5).map(([a, n]) => `${a} ${fmt(n)}`).join(', ');
  const types = top(r.secretTypes, 5).map(([t, n]) => `${t} ${fmt(n)}`).join(', ');
  out(`  Blocked actions   : ${fmt(r.blocked)}${agents ? `  (${agents})` : ''}\n`);
  out(`  Secrets hidden    : ${fmt(r.redacted)}${types ? `  (${types})` : ''}\n`);
  if (r.newServers.length) {
    out(`  New MCP servers   : ${r.newServers.length}  (${r.newServers.slice(0, 5).map((s) => s.command).join('; ')}${r.newServers.length > 5 ? '; ...' : ''})\n`);
  } else {
    out('  New MCP servers   : 0  (only servers wrapped by zn-gate are listed)\n');
  }
  if (r.pending) out(`  Tools changed, waiting for your approval: ${fmt(r.pending)}  (run: zn-gate pins)\n`);
  if (r.busiest) out(`\n  Busiest day: ${r.busiest.day} (${fmt(r.busiest.blocked)} blocked)\n`);
  out('\nThis report was built from files on your computer. Nothing left it.\n' + team);
  return 0;
}

module.exports = { run, parse, TEAM_LINE, safeCommand };
