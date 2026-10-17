'use strict';
// zn-gate report: reads local stats and pins only; writes nothing and opens no network connection.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const home = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'zn-report-test-'));
process.env.ZN_HOME = home;
delete process.env.ZN_STATS;

// Guard: any network use during a report is a failure.
let netCalls = 0;
for (const m of ['net', 'tls', 'http', 'https', 'dns']) {
  const mod = require(m);
  for (const fn of ['connect', 'createConnection', 'request', 'get', 'lookup', 'resolve']) {
    if (typeof mod[fn] === 'function') mod[fn] = () => { netCalls++; throw new Error('network used by report'); };
  }
}
if (typeof globalThis.fetch === 'function') globalThis.fetch = () => { netCalls++; throw new Error('network used by report'); };

const stats = require('../lib/stats');
const report = require('../lib/report');

test.after(() => fs.rmSync(home, { recursive: true, force: true }));
const reset = () => { for (const f of fs.readdirSync(home)) fs.rmSync(path.join(home, f), { recursive: true, force: true }); };
const NOW = new Date('2026-10-17T12:00:00Z');
const run = (args) => { let out = ''; const code = report.run(args, (s) => { out += s; }, { now: NOW }); return { code, out }; };
const snapshot = () => JSON.stringify(fs.readdirSync(home, { recursive: true }).sort().map((f) => [f, fs.statSync(path.join(home, f)).isFile() ? fs.readFileSync(path.join(home, f), 'utf8') : '']));

function seed() {
  const at = (d) => new Date(`${d}T10:00:00Z`);
  stats.record({ layer: 'hook', agent: 'claude-code', checked: 20, blocked: 9, redacted: 20, detections: { AWS_KEY: 14, GITHUB_TOKEN: 6 } }, { now: at('2026-10-14') });
  stats.record({ layer: 'hook', agent: 'cursor', checked: 5, blocked: 3, redacted: 11, detections: { DB_PASSWORD: 8 } }, { now: at('2026-10-15') });
  stats.record({ layer: 'hook', agent: 'claude-code', checked: 4, blocked: 40, redacted: 1 }, { now: at('2026-09-01') });
  const dir = path.join(home, 'mcp-pins');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, '0123456789abcdef.json'), JSON.stringify({
    command: 'node /home/maria/projects/secret-client/my-mcp.js --token ghp_abcdefghijklmnopqrstuvwxyz0123456789',
    pinnedAt: '2026-10-16T08:00:00.000Z', tools: { a: 'h1' }, pending: { b: { hash: 'h2', seenAt: '2026-10-16T09:00:00Z' } },
  }));
  fs.writeFileSync(path.join(dir, 'fedcba9876543210.json'), JSON.stringify({ command: 'npx old-server', pinnedAt: '2026-08-01T00:00:00.000Z', tools: {}, pending: {} }));
  fs.writeFileSync(path.join(dir, 'aaaaaaaaaaaaaaaa.json'), '{not json');
}

test('empty data gives a friendly message and the Team line', () => {
  reset();
  const { code, out } = run([]);
  assert.equal(code, 0);
  assert.match(out, /Nothing to report yet/);
  assert.match(out, /zn Team/);
});

test('a normal week: counts, agents, secret types, new servers, pending, busiest day', () => {
  reset(); seed();
  const { code, out } = run([]);
  assert.equal(code, 0);
  assert.match(out, /2026-10-11 to 2026-10-17/);
  assert.match(out, /Blocked actions\s+: 12\s+\(claude-code 9, cursor 3\)/);
  assert.match(out, /Secrets hidden\s+: 31\s+\(AWS_KEY 14, DB_PASSWORD 8, GITHUB_TOKEN 6\)/);
  assert.match(out, /New MCP servers\s+: 1\s+\(node my-mcp\.js --token/);
  assert.match(out, /waiting for your approval: 1/);
  assert.match(out, /Busiest day: 2026-10-14 \(9 blocked\)/);
  assert.match(out, /Nothing left it/);
  assert.match(out, /Teams: share these protections across your team with zn Team/);
});

test('never prints paths, folders or token values', () => {
  reset(); seed();
  const { out } = run([]);
  assert.doesNotMatch(out, /maria|projects|secret-client|ghp_|\/home/);
  assert.equal(report.safeCommand('node C:\\Users\\Ana\\app\\srv.js').includes('Ana'), false);
});

test('--since changes the window; bad values exit 2', () => {
  reset(); seed();
  assert.match(run(['--since', '1d']).out, /2026-10-17 to 2026-10-17/);
  assert.match(run(['--since=90d']).out, /Blocked actions\s+: 52/);
  assert.match(run(['--since', '4d']).out, /Blocked actions\s+: 12/);
  assert.match(run(['--since', '3d']).out, /Blocked actions\s+: 3/);
  assert.match(run(['--since', '2d']).out, /Blocked actions\s+: 0/);
  for (const bad of [['--since', '91d'], ['--since', '0d'], ['--since', '7'], ['--since', '7w'], ['--since'], ['--bogus']]) {
    const r = run(bad);
    assert.equal(r.code, 2, bad.join(' '));
    assert.match(r.out, /Usage: zn-gate report/);
  }
});

test('--json has the documented schema and no Team line', () => {
  reset(); seed();
  const { code, out } = run(['--json']);
  assert.equal(code, 0);
  const j = JSON.parse(out);
  assert.deepEqual(Object.keys(j).sort(), ['blocked', 'busiest_day', 'by_agent', 'days', 'new_mcp_servers', 'pending_tool_changes', 'redacted', 'secret_types', 'sent', 'since', 'sources', 'until']);
  assert.equal(j.blocked, 12); assert.equal(j.redacted, 31); assert.equal(j.days, 7); assert.equal(j.sent, false);
  assert.deepEqual(j.by_agent, { 'claude-code': 9, cursor: 3 });
  assert.equal(j.pending_tool_changes, 1);
  assert.equal(j.new_mcp_servers.length, 1);
  assert.deepEqual(j.busiest_day, { day: '2026-10-14', blocked: 9 });
  assert.doesNotMatch(out, /Teams|zn Team/);
});

test('--no-team-line and being in a Team hide the Team line', () => {
  reset(); seed();
  assert.doesNotMatch(run(['--no-team-line']).out, /zn Team/);
  const policy = require('../lib/team/policy');
  const orig = policy.readTeam;
  policy.readTeam = () => ({ v: 1, org: 'acme' });
  try { assert.doesNotMatch(run([]).out, /zn Team/); } finally { policy.readTeam = orig; }
});

test('ZN_STATS=off with no data says counting is off', () => {
  reset();
  process.env.ZN_STATS = 'off';
  try { assert.match(run([]).out, /Counting is off on this computer \(ZN_STATS=off\)/); } finally { delete process.env.ZN_STATS; }
});

test('corrupt stats and pins files do not break it', () => {
  reset();
  fs.writeFileSync(path.join(home, 'stats.json'), 'not json');
  fs.mkdirSync(path.join(home, 'mcp-pins'));
  fs.writeFileSync(path.join(home, 'mcp-pins', '0123456789abcdef.json'), '[]');
  assert.equal(run([]).code, 0);
});

test('writes no files and opens no network connection', () => {
  reset(); seed();
  const before = snapshot();
  run([]); run(['--json']); run(['--since', '30d']);
  assert.equal(snapshot(), before);
  assert.equal(netCalls, 0);
});

test('the report module does not load a network client', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'report.js'), 'utf8');
  assert.doesNotMatch(src, /require\(['"](https?|net|tls|\.\/client|\.\/team\/(api|cli|upload))/);
});

test('zn-gate report runs from the command line', () => {
  reset(); seed();
  const r = require('child_process').spawnSync(process.execPath, [path.join(__dirname, '..', 'bin', 'cli.js'), 'report', '--no-team-line'], { env: { ...process.env, ZN_HOME: home }, encoding: 'utf8' });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /zn-gate report: /);
});
