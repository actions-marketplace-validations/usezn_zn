'use strict';
// deleteIdentity safe default. The native helpers are stubbed and spawnSync is
// blocked, so the real OS keychain is never touched.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');

const spawned = [];
const realSpawnSync = cp.spawnSync;
cp.spawnSync = function (cmd) { spawned.push(String(cmd)); return { status: 1, stdout: '', stderr: '' }; };
const keychain = require('../lib/vault/keychain');
const store = require('../lib/vault/store');
cp.spawnSync = realSpawnSync;

const RECIPIENT = 'age1' + 'q'.repeat(58);
const ENV = ['ZN_HOME', 'ZN_KEYCHAIN_BACKEND', 'ZN_KEYCHAIN_SERVICE'];

function setup() {
  const saved = {};
  for (const k of ENV) { saved[k] = process.env[k]; delete process.env[k]; }
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'znd-'));
  process.env.ZN_HOME = home;
  const removed = [];
  const orig = {};
  for (const b of ['macos', 'windows', 'libsecret']) {
    orig[b] = keychain._native[b].remove;
    keychain._native[b].remove = () => { removed.push(b); };
  }
  spawned.length = 0;
  return {
    home, removed,
    done() {
      for (const b of Object.keys(orig)) keychain._native[b].remove = orig[b];
      for (const k of ENV) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
      fs.rmSync(home, { recursive: true, force: true });
    },
  };
}

function writeMeta(home, backend) {
  store.ensureLayout({ home });
  fs.writeFileSync(store.paths({ home }).metaFile, JSON.stringify({ v: 1, backend, recipient: RECIPIENT }));
}

test('deleteIdentity: no keychain.json and no backend deletes nothing and says why', async () => {
  const t = setup();
  try {
    const r = await keychain.deleteIdentity({ home: t.home });
    assert.strictEqual(r.deleted, false);
    assert.match(r.reason, /nothing was deleted/);
    assert.match(r.reason, /backend/);
    assert.deepStrictEqual(t.removed, []);
    assert.deepStrictEqual(spawned, []);
  } finally { t.done(); }
});

test('deleteIdentity: with keychain.json it removes its own slot and the file', async () => {
  const t = setup();
  try {
    writeMeta(t.home, 'windows');
    const r = await keychain.deleteIdentity({ home: t.home });
    assert.deepStrictEqual(r, { deleted: true, backend: 'windows' });
    assert.deepStrictEqual(t.removed, ['windows']);
    assert.ok(!fs.existsSync(store.paths({ home: t.home }).metaFile));
  } finally { t.done(); }
});

test('deleteIdentity: an explicit backend works without keychain.json', async () => {
  const t = setup();
  try {
    const r = await keychain.deleteIdentity({ home: t.home, backend: 'macos' });
    assert.deepStrictEqual(r, { deleted: true, backend: 'macos' });
    assert.deepStrictEqual(t.removed, ['macos']);
  } finally { t.done(); }
});

test('deleteIdentity: explicit passphrase backend removes identity.age only', async () => {
  const t = setup();
  try {
    store.ensureLayout({ home: t.home });
    const idFile = store.paths({ home: t.home }).identityFile;
    fs.writeFileSync(idFile, 'fake');
    const r = await keychain.deleteIdentity({ home: t.home, backend: 'passphrase' });
    assert.strictEqual(r.deleted, true);
    assert.ok(!fs.existsSync(idFile));
    assert.deepStrictEqual(t.removed, []);
  } finally { t.done(); }
});
