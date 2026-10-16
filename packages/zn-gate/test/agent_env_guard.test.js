'use strict';
// Removing an agent variable is refused: it would let user-only commands run as if a person ran them.
const test = require('node:test');
const assert = require('node:assert/strict');
const policy = require('../lib/hooks/policy');

test('unset, export -n, env -u and PowerShell removals of an agent variable are refused', () => {
  for (const cmd of ['unset CLAUDECODE', 'unset -v CODEX_SANDBOX; zn-gate init', 'export -n CLAUDECODE', 'env -u CLAUDECODE zn-gate init',
    'env --unset=CLAUDECODE npx -y zn-gate init', 'env -uZN_AGENT zn secret set X', '/usr/bin/env -u CURSOR_AGENT bash',
    'env -i PATH=/usr/bin zn-gate init', 'yes | env -i script -qec "zn-gate init" /dev/null; env -i npx zn-gate init',
    'Remove-Item Env:CLAUDECODE', 'Remove-Item -Path "Env:CLAUDECODE"', '$env:CLAUDECODE = $null', "[Environment]::SetEnvironmentVariable('CLAUDECODE', $null)",
    '(unset CLAUDECODE; zn-gate init)']) {
    assert.ok(policy.agentVarRemoval(cmd), 'expected the removal to be found in: ' + cmd);
    const d = policy.bashDenial(cmd);
    assert.ok(d, 'expected a denial for: ' + cmd);
    assert.match(d, /^zn blocked this: /);
  }
  // On its own (no zn command after it), the message names the variable.
  assert.match(policy.bashDenial('unset CLAUDECODE'), /`CLAUDECODE` tells zn that an AI agent runs the command[\s\S]*ask the user to run the command in their own terminal/);
  assert.match(policy.bashDenial('env -i PATH=/usr/bin npx something'), /clearing the environment/);
});

test('other variables and other uses of env are left alone', () => {
  for (const cmd of ['unset FOO', 'export -n PATH', 'env -u HOME ls', 'env FOO=1 npm test', 'env -i PATH=/usr/bin ls', 'printenv CLAUDECODE',
    'echo $CLAUDECODE', 'Remove-Item Env:FOO', 'git log --grep unset']) {
    assert.equal(policy.agentVarRemoval(cmd), null, cmd);
  }
});

test('the check stays fast on long commands', () => {
  const t0 = process.hrtime.bigint();
  policy.agentVarRemoval('env ' + '-a '.repeat(30000) + 'ls');
  policy.agentVarRemoval(('unset ' + 'X '.repeat(20) + '; ').repeat(2000));
  assert.ok(Number(process.hrtime.bigint() - t0) / 1e6 < 1000);
});
