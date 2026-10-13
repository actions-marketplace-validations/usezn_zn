#!/usr/bin/env node
'use strict';
/**
 * Test vault for end-to-end runs: creates a vault in $ZN_HOME (passphrase
 * backend), stores the fake secrets of the scenario and serves the daemon
 * in this process until SIGTERM.
 *
 * The out-of-band confirmation channel is answered by this script, standing
 * in for the person at the keyboard: it approves only first use by `node`
 * and logs every request to <out>/confirmations.jsonl. Everything else is
 * declined, so the "not approved" path is exercised too.
 *
 *   ZN_HOME=... node vault_daemon.js --pkg <packages/zn-gate> --secrets secrets.json --out dir
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : def;
}

const PKG = path.resolve(arg('--pkg'));
const OUT = path.resolve(arg('--out', '.'));
const SECRETS = JSON.parse(fs.readFileSync(arg('--secrets'), 'utf8'));
process.env.ZN_KEYCHAIN_BACKEND = 'passphrase';
fs.mkdirSync(OUT, { recursive: true });

const keychain = require(path.join(PKG, 'lib', 'vault', 'keychain'));
const daemon = require(path.join(PKG, 'lib', 'vault', 'daemon'));
const client = require(path.join(PKG, 'lib', 'vault', 'client'));

async function confirm(req) {
  const allow = req.kind === 'approval' && /^Command: node$/m.test(req.message);
  fs.appendFileSync(path.join(OUT, 'confirmations.jsonl'), JSON.stringify({ ts: new Date().toISOString(), kind: req.kind, title: req.title, answer: allow }) + '\n');
  return allow;
}

(async () => {
  const passphrase = crypto.randomBytes(16).toString('hex');
  const { identity } = await keychain.initIdentity({ backend: 'passphrase', passphrase, workFactor: 10 });
  const srv = await daemon.serve({ identity, ttlMs: 4 * 3600000, idleMs: 4 * 3600000, confirm });
  const c = client.createClient({});
  for (const s of SECRETS) await c.setSecret(s.name, s.value, s.meta);
  c.close();
  fs.writeFileSync(path.join(OUT, 'vault.ready'), String(process.pid));
  process.on('SIGTERM', async () => { await srv.close(); process.exit(0); });
})().catch((err) => {
  fs.writeFileSync(path.join(OUT, 'vault.error'), String(err && err.stack));
  process.exit(1);
});
