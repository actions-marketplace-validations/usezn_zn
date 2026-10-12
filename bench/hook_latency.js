#!/usr/bin/env node
'use strict';
/**
 * End-to-end latency of the agent hook process with the real engine and a
 * real vault daemon: each sample spawns `node lib/hooks/runner.js
 * claude-code` with a Claude Code event on stdin, exactly like Claude Code
 * does, and times it until the process exits.
 *
 *   node bench/hook_latency.js [--runs 40] [--json out.json]
 *
 * The daemon runs in this process with a temporary ZN_HOME (passphrase
 * backend). Values are fake and generated at run time. Target: PostToolUse
 * with 64 KB of output, p50 <= 60 ms.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const PKG = path.resolve(__dirname, '..', 'packages', 'zn-gate');
const RUNNER = path.join(PKG, 'lib', 'hooks', 'runner.js');

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : def;
}

const RUNS = Number(arg('--runs', 40));
const JSON_OUT = arg('--json', null);

const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-hookbench-'));
process.env.ZN_HOME = HOME;
process.env.ZN_KEYCHAIN_BACKEND = 'passphrase';

const keychain = require(path.join(PKG, 'lib', 'vault', 'keychain'));
const daemon = require(path.join(PKG, 'lib', 'vault', 'daemon'));
const client = require(path.join(PKG, 'lib', 'vault', 'client'));
const { generateAll } = require(path.join(PKG, 'test', 'fixtures', 'fake_secrets'));

const FAKE = generateAll(31337, { perType: 1, piiPerType: 1 });
const AWS = FAKE.secrets.find((s) => s.type === 'aws_access_key_id').value;
const GHP = FAKE.secrets.find((s) => s.type === 'github_pat_classic').value;

/* Realistic tool output: source-like lines, optionally with secrets inside. */
function output(bytes, withSecrets) {
  const lines = [];
  let n = 0;
  let size = 0;
  while (size < bytes) {
    const l = '  ' + (n % 7 === 0 ? 'const handler_' + n + ' = require("./mod_' + n + '");' : 'logger.info("request " + id + " took " + ms + "ms", { route: "/api/v1/items/' + n + '" });');
    lines.push(l);
    size += l.length + 1;
    n++;
  }
  if (withSecrets) {
    lines[Math.floor(lines.length / 3)] = 'AWS_ACCESS_KEY_ID=' + AWS;
    lines[Math.floor((2 * lines.length) / 3)] = 'token: ' + GHP;
  }
  return lines.join('\n').slice(0, bytes);
}

function postEvent(bytes, withSecrets) {
  return {
    session_id: 'bench', cwd: HOME, hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_use_id: 't',
    tool_input: { command: 'cat src/app.js' },
    tool_response: { stdout: output(bytes, withSecrets), stderr: '', interrupted: false, isImage: false },
  };
}

const CASES = [
  ['PreToolUse Bash (no markers)', { session_id: 'bench', cwd: HOME, hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'npm test' }, tool_use_id: 't' }],
  ['UserPromptSubmit 1 KB', { session_id: 'bench', cwd: HOME, hook_event_name: 'UserPromptSubmit', prompt: output(1024, false) }],
  ['PostToolUse Bash 4 KB clean', postEvent(4096, false)],
  ['PostToolUse Bash 64 KB clean', postEvent(65536, false)],
  ['PostToolUse Bash 64 KB with 2 secrets', postEvent(65536, true)],
];

function once(event) {
  return new Promise((resolve, reject) => {
    const t0 = process.hrtime.bigint();
    const child = spawn(process.execPath, [RUNNER, 'claude-code'], { env: process.env, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.on('error', reject);
    child.on('close', (code) => {
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      if (code !== 0) reject(new Error('hook exited ' + code));
      else resolve({ ms, out });
    });
    child.stdin.end(JSON.stringify(event));
  });
}

function pct(sorted, p) {
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

async function measure(label, event) {
  await once(event); // warm the file cache
  const times = [];
  let last = '';
  for (let i = 0; i < RUNS; i++) {
    const r = await once(event);
    times.push(r.ms);
    last = r.out;
  }
  times.sort((a, b) => a - b);
  if (last.includes(AWS) || last.includes(GHP)) throw new Error('a fake secret passed through: ' + label);
  return { label, runs: RUNS, p50: +pct(times, 50).toFixed(1), p95: +pct(times, 95).toFixed(1), min: +times[0].toFixed(1) };
}

async function main() {
  const passphrase = crypto.randomBytes(16).toString('hex');
  const { identity } = await keychain.initIdentity({ backend: 'passphrase', passphrase, workFactor: 10 });
  const srv = await daemon.serve({ identity, ttlMs: 3600000, idleMs: 3600000 });
  const c = client.createClient({});
  await c.setSecret('GITHUB_TOKEN', GHP, { mode: 'proxy', allowHosts: ['api.github.com'] });
  c.close();

  const results = { unlocked: [], locked: [] };
  for (const [label, ev] of CASES) results.unlocked.push(await measure(label, ev));
  await srv.close();
  for (const [label, ev] of CASES.slice(2)) results.locked.push(await measure(label, ev));

  const nodeStart = [];
  for (let i = 0; i < RUNS; i++) {
    const t0 = process.hrtime.bigint();
    await new Promise((r) => spawn(process.execPath, ['-e', ''], { stdio: 'ignore' }).on('close', r));
    nodeStart.push(Number(process.hrtime.bigint() - t0) / 1e6);
  }
  nodeStart.sort((a, b) => a - b);

  const meta = {
    date: new Date().toISOString().slice(0, 10),
    node: process.version,
    platform: process.platform + ' ' + os.release(),
    cpu: (os.cpus()[0] || {}).model + ' x' + os.cpus().length,
    runs: RUNS,
    bareNodeStartP50: +pct(nodeStart, 50).toFixed(1),
  };
  const report = { meta, ...results };
  const row = (r) => '| ' + r.label + ' | ' + r.p50 + ' | ' + r.p95 + ' | ' + r.min + ' |';
  console.log('Hook process latency (ms), ' + meta.platform + ', ' + meta.cpu + ', Node ' + meta.node + ', ' + RUNS + ' runs; bare `node -e ""` p50 ' + meta.bareNodeStartP50 + ' ms');
  console.log('\nVault unlocked (real daemon):\n| case | p50 | p95 | min |\n|---|---|---|---|');
  results.unlocked.forEach((r) => console.log(row(r)));
  console.log('\nVault locked (irreversible redaction):\n| case | p50 | p95 | min |\n|---|---|---|---|');
  results.locked.forEach((r) => console.log(row(r)));
  const target = results.unlocked.find((r) => r.label === 'PostToolUse Bash 64 KB with 2 secrets');
  console.log('\nTarget PostToolUse 64 KB p50 <= 60 ms: ' + (target.p50 <= 60 ? 'PASS' : 'FAIL') + ' (' + target.p50 + ' ms)');
  if (JSON_OUT) fs.writeFileSync(JSON_OUT, JSON.stringify(report, null, 2) + '\n');
  fs.rmSync(HOME, { recursive: true, force: true });
  process.exitCode = target.p50 <= 60 ? 0 : 1;
}

main().catch((err) => {
  console.error(err);
  try { fs.rmSync(HOME, { recursive: true, force: true }); } catch (_) { /* ignore */ }
  process.exit(1);
});
