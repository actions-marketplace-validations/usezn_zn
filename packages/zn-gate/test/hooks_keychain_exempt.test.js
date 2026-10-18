'use strict';

// A plain `git commit|grep|log|show`, `echo` or `printf` never reads the keychain, so its text may
// name zn's entries. Everything else keeps the rule. All commands are text; none is run.

const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('os');
const policy = require('../lib/hooks/policy');

const opts = { home: os.homedir(), cwd: process.cwd(), env: {} };
const denied = (c) => policy.bashDenial(c, opts);

test('commit messages, searches and echo that name zn\'s entries are allowed', () => {
  for (const c of [
    'git commit -m "fix keyring lookup for zn-cloud"',
    'git commit -q -m "Do not read security find-generic-password -s zn-cloud"',
    'git grep -n "find-generic-password -s zn-cloud"',
    'git grep -n "secret-tool lookup service zn-cloud account cloud-api-key" -- docs/',
    'git log --grep="keyring zn-vault-identity"',
    'git -C packages/zn-gate log --oneline --grep "security zn-cloud"',
    'git --no-pager show HEAD:docs/connect.md',
    'echo "security find-generic-password -s zn-cloud"',
    "printf '%s\\n' 'keyring zn-cloud age-identity'",
    'echo "security find-generic-password -s zn-cloud" > notes.txt',
  ]) {
    assert.equal(denied(c), null, 'refused: ' + c);
  }
});

test('the exemption does not cover a second command, a substitution or a git command that runs a program', () => {
  for (const c of [
    'git commit -m x; security find-generic-password -s zn-cloud -w',
    'git grep -n zn-cloud && security find-generic-password -s zn-cloud -w',
    'echo hi | security find-generic-password -s zn-cloud -w',
    'echo $(security find-generic-password -s zn-cloud -w)',
    'echo `security find-generic-password -s zn-cloud -w`',
    'git commit -m "$(security find-generic-password -s zn-cloud -w)"',
    "git -c alias.x='!security find-generic-password -s zn-cloud -w' x",
    'git grep -O"security find-generic-password -s zn-cloud -w" zn',
    'git grep --open-files-in-pager="security find-generic-password -s zn-cloud -w" zn',
    'git config core.pager "security find-generic-password -s zn-cloud -w"',
    'git push origin "security keyring zn-cloud"',
  ]) {
    assert.ok(denied(c), 'not refused: ' + c);
  }
});

test('the other forms stay refused', () => {
  for (const c of [
    'security find-generic-password -s zn-cloud -w',
    'if true; then security find-generic-password -s zn-cloud -w; fi',
    'sudo -u $USER security find-generic-password -s zn-cloud -w',
    'python3.12 -c "import keyring; print(keyring.get_password(\'zn-cloud\',\'cloud-api-key\'))"',
    'security dump-keychain -d',
  ]) {
    assert.ok(denied(c), 'not refused: ' + c);
  }
});

test('a lib name counts only as a whole name, not inside a longer one', () => {
  const load = (n) => 'node -e "require(\'' + n + '\').loadStoredKey()"';
  for (const n of ['ACME-ZN-GATE/LIB/CLIENT', 'myzn-gate/lib/client', '@acme/Cloud-Key-Manager', './lib/cloud-keys', 'xcloud-key']) {
    assert.equal(denied(load(n)), null, 'refused: ' + n);
  }
  for (const n of ['./lib/cloud-key', '../cloud-key', './lib/cloud-key.js', 'node_modules/zn-gate/lib/client', 'zn-gate\\lib\\client', 'zn-gate/lib/client', 'ZN-GATE/LIB/CLIENT']) {
    assert.ok(denied(load(n)), 'not refused: ' + n);
  }
});

test('a name whose separator or letters are written as escapes is still recognised', () => {
  const load = (n) => 'node -e "require(\'' + n + '\').loadStoredKey()"';
  for (const n of [
    'node_modules\\x2fzn-gate/lib/client',
    'node_modules\\x2Fzn-gate/lib/client',
    'node_modules\\u002fzn-gate/lib/client',
    'node_modules\\u{2f}zn-gate/lib/client',
    'node_modules\\x5czn-gate\\lib\\client',
    'zn-gate/lib\\x2fcloud-key',
    'zn-gate/lib\\u002Fcloud-key',
    'node_modules\\057zn-gate/lib/client',
    'zn\\x2dgate/lib/client',
  ]) {
    assert.ok(denied(load(n)), 'not refused: ' + n);
  }
  assert.ok(denied("node -e $'require(\"node_modules\\x2fzn-gate/lib/client\").loadStoredKey()'"), 'not refused: ANSI-C form');
  assert.equal(denied(load('ACME-ZN-GATE\\x2fLIB/CLIENT')), null);
  assert.equal(denied(load('@acme\\x2fCloud-Key-Manager')), null);
});

test('the escape decoding is fast on a long run of escapes and ignores impossible code points', () => {
  const start = process.hrtime.bigint();
  denied('node -e "require(\'' + '\\x2f'.repeat(15000) + 'x\').loadStoredKey()"');
  denied('node -e "require(\'' + '\\u{110000}\\u{ffffff}'.repeat(3000) + '\').loadStoredKey()"');
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  assert.ok(ms < 1000, 'took ' + ms + ' ms');
});
