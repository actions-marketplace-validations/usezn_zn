'use strict';

// Fixes from the review of the connect feature: the keychain checks of the hooks run in linear time and still
// refuse what they refused, NODE_OPTIONS that expose the TLS session or the process memory hold the saved key
// back, `connect` and `disconnect` are admin commands, and the vault's request tool never fills in the saved key.

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const os = require('os');
const path = require('path');

const policy = require('../lib/hooks/policy');
const cloudKey = require('../lib/cloud-key');
const { createSecretsServer } = require('../lib/broker/mcp');
const { createFakeVault } = require('./helpers/fake_vault');
const fakeEngine = require('./helpers/fake_engine');

const HOME = path.join(os.tmpdir(), 'zn-review-home');
const OPTS = { cwd: path.join(HOME, 'project'), home: HOME, env: {} };

/* ---- M1: the keychain checks are linear ---- */

test('keychain checks take well under a second on 100 KB of padding, and the verdict does not change', () => {
  const n = 100 * 1000;
  const pads = [
    'from '.repeat(n / 5) + '; cat .env',
    'from\t'.repeat(n / 5) + '; cat .env',
    'security '.repeat(n / 9) + 'x',
    'import('.repeat(n / 7) + 'x',
    'require('.repeat(n / 8) + 'x',
    'import '.repeat(n / 7) + 'cloud-key',
    'security dump '.repeat(n / 14),
  ];
  for (const p of pads) {
    const t0 = process.hrtime.bigint();
    policy.bashDenial(p.slice(0, n), OPTS);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    assert.ok(ms < 2500, JSON.stringify(p.slice(0, 14)) + ' took ' + ms.toFixed(0) + ' ms');
  }
});

test('the keychain checks still refuse the direct ways, however far apart the words are', () => {
  const far = ' '.repeat(5000);
  for (const cmd of [
    'security find-generic-password -s zn-cloud -w',
    'security dump-keychain',
    'security' + far + 'dump-keychain',
    'security   -v   dump-keychain -d',
    'secret-tool lookup service zn-cloud',
    "node -e \"require('./lib/cloud-key').loadStoredKey()\"",
    "node -e \"require(" + far + "'zn-gate/lib/cloud-key').loadStoredKey()\"",
    "python3 -c \"import keyring; keyring.get_password('zn-cloud','cloud-api-key')\"",
  ]) {
    assert.ok(policy.bashDenial(cmd, OPTS), cmd.slice(0, 60));
  }
  for (const cmd of ['security find-generic-password -s my-own-service -w', 'echo import and from', 'git log --oneline']) {
    assert.equal(policy.bashDenial(cmd, OPTS), null, cmd);
  }
});

/* ---- L1: TLS and debugger options ---- */

test('--tls-keylog, --inspect and its variants hold back a saved key', () => {
  const why = (o) => cloudKey.tlsRefusal({ NODE_OPTIONS: o });
  for (const o of [
    '--tls-keylog=/tmp/k.log', '--tls-keylog /tmp/k.log', '"--tls-keylog=/tmp/k.log"', '--inspect', '--inspect=9229', '--inspect-brk',
    '--inspect-brk=0.0.0.0:9229', '--inspect-port=9230', '--inspect-wait', '--no-warnings --inspect', '--openssl-shared-config=/tmp/o.cnf',
  ]) {
    assert.match(why(o), /NODE_OPTIONS/, o);
  }
  for (const o of ['', '--max-old-space-size=512', '--title="--inspect"', '--enable-source-maps']) assert.equal(why(o), null, o);
});

/* ---- L3: connect and disconnect are admin commands ---- */

test('an agent running zn-gate connect or disconnect is refused as an admin command', () => {
  for (const cmd of [
    'zn-gate connect', 'npx -y zn-gate connect --reconnect', 'zn-gate disconnect --revoke', 'zn disconnect --no-revoke',
    'node bin/cli.js connect', 'cd /tmp && zn-gate@1.13.0 disconnect', 'zn-gate -- connect',
  ]) {
    assert.ok(policy.adminCommand(cmd), cmd);
    const deny = policy.bashDenial(cmd, OPTS);
    assert.match(deny, /connect/, cmd);
    assert.match(deny, /own terminal/, cmd);
  }
  for (const cmd of ['zn-gate status', 'zn-gate analyze hello', 'echo connect', 'zn-gate help connect', 'ssh connect-host']) {
    assert.equal(policy.adminCommand(cmd), null, cmd);
  }
});

/* ---- L2: the vault request tool never fills in the saved key ---- */

function startServer() {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({ method: req.method, url: req.url, auth: req.headers.authorization });
    res.end('{}');
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, seen, port: server.address().port })));
}

test('secrets_http_request refuses the key stored by connect, even for an allowed host, and still serves other secrets', async () => {
  const { server, seen, port } = await startServer();
  try {
    const vault = createFakeVault();
    const key = 'zn_' + 'ab12'.repeat(12);
    await vault.setSecret(cloudKey.VAULT_SECRET, key, { mode: 'proxy', allowHosts: ['127.0.0.1', 'api.usezn.com'] });
    await vault.setSecret('OTHER_TOKEN', 'ghp_' + 'x1'.repeat(18), { mode: 'proxy', allowHosts: ['127.0.0.1'] });
    const srv = createSecretsServer({ vault, engine: fakeEngine });
    const call = (name, args) => srv.handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } })
      .then((r) => ({ isError: r.result.isError, text: r.result.content[0].text }));
    const base = 'http://127.0.0.1:' + port;
    for (const method of ['DELETE', 'GET', 'POST']) {
      const r = await call('secrets_http_request', { method, url: base + '/prod/keys/self', headers: { Authorization: 'Bearer __ZN_' + cloudKey.VAULT_SECRET + '__' } });
      assert.equal(r.isError, true, method);
      assert.match(r.text, /connect/);
      assert.ok(!r.text.includes(key));
    }
    assert.equal(seen.length, 0, 'no request was made with the key');
    const ok = await call('secrets_http_request', { method: 'GET', url: base + '/x', headers: { Authorization: 'Bearer __ZN_OTHER_TOKEN__' } });
    assert.equal(ok.isError, false, ok.text);
    assert.equal(seen.length, 1);
  } finally { server.close(); }
});
