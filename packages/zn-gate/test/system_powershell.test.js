'use strict';

// The system PowerShell receives secret values (the vault identity, the clipboard) and decides the parent-process
// check, so zn finds it through the kernel's \SystemRoot link, never through SystemRoot or PATH.

const test = require('node:test');
const assert = require('node:assert/strict');
const { systemPowerShell } = require('../lib/exe');
const { guiCommand } = require('../lib/vault/confirm');

test('systemPowerShell: found on Windows, whatever SystemRoot and PATH say; null elsewhere', () => {
  if (process.platform !== 'win32') {
    assert.equal(systemPowerShell(), null);
    return;
  }
  const real = systemPowerShell();
  // Without it, the parent check, the approval dialog and the Windows keychain would all be off: fail loudly here.
  assert.ok(real, 'the system PowerShell was not found');
  assert.match(real, /^[A-Za-z]:\\[^%!"]+\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe$/i);
  const saved = { SystemRoot: process.env.SystemRoot, SYSTEMROOT: process.env.SYSTEMROOT, PATH: process.env.PATH };
  try {
    process.env.SystemRoot = 'Z:\\Windows';
    process.env.SYSTEMROOT = 'Z:\\Windows';
    process.env.PATH = '';
    assert.equal(systemPowerShell(), real);
  } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
});

test('the approval dialog on Windows uses only the system PowerShell, and there is none without it', () => {
  const req = { title: 'x', secret: 'S', command: 'c' };
  const env = { SystemRoot: 'Z:\\Windows' };
  assert.equal(guiCommand(req, { platform: 'win32', env, powershell: null, exists: () => true }), null);
  const cmd = guiCommand(req, { platform: 'win32', env, powershell: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', exists: () => true });
  assert.equal(cmd.file, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
});
