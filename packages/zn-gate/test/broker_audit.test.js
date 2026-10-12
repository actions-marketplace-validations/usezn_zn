'use strict';
/* `zn audit` (the vault audit log) works with no vault and with a locked vault. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { tempDir } = require('./helpers/tmp');

const CLI = path.join(__dirname, '..', 'bin', 'cli.js');

function zn(home, args) {
  const env = { ...process.env, HOME: home, USERPROFILE: home, ZN_HOME: path.join(home, '.zn') };
  return spawnSync(process.execPath, [CLI, ...args], { env, encoding: 'utf8', timeout: 20000 });
}

test('zn audit with no vault lists nothing and does not crash', (t) => {
  const home = tempDir(t, 'zn-audit-');
  for (const args of [['audit'], ['audit', '--since', '1h']]) {
    const r = zn(home, args);
    assert.strictEqual(r.status, 0, r.stderr);
    assert.doesNotMatch(r.stderr + r.stdout, /argument must be|TypeError/);
    assert.match(r.stdout, /chain: not checked/);
  }
});

test('zn audit lists records of a locked vault and says the chain was not checked', (t) => {
  const home = tempDir(t, 'zn-audit-');
  fs.mkdirSync(path.join(home, '.zn'), { recursive: true });
  const rec = { seq: 1, ts: new Date().toISOString(), decision: 'allow', secret: 'DB_PASSWORD', mode: 'run', agent: 'claude-code', tool: 'Bash', prev: '0', mac: '00' };
  fs.writeFileSync(path.join(home, '.zn', 'audit.jsonl'), JSON.stringify(rec) + '\n');
  const r = zn(home, ['audit']);
  assert.strictEqual(r.status, 0, r.stderr);
  assert.match(r.stdout, /DB_PASSWORD/);
  assert.match(r.stdout, /chain: not checked/);
});
