'use strict';

// The Python package (packages/zn-gate-py) compares its rules with the JSON
// printed by test/helpers/export_rules.js. This test keeps that export working
// and checks that the linear hidden-element check agrees with the reference
// pattern on the shared samples.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { INDIRECT_INJECTION_RULES } = require('../lib/rules');

const EXPORT_SCRIPT = path.join(__dirname, 'helpers', 'export_rules.js');
const SAMPLES_FILE = path.join(__dirname, 'fixtures', 'rules_parity_samples.json');

test('export_rules.js prints the rule tables and one result per sample', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-parity-'));
  try {
    const out = JSON.parse(execFileSync(process.execPath, [EXPORT_SCRIPT, SAMPLES_FILE], { cwd, maxBuffer: 16 * 1024 * 1024 }).toString('utf8'));
    const { samples } = JSON.parse(fs.readFileSync(SAMPLES_FILE, 'utf8'));
    assert.equal(out.results.length, samples.length);
    assert.ok(out.tables.INJECTION_RULES.length > 0);
    assert.equal(out.limits.MAX_SCAN_CHARS, 256 * 1024);
    for (const r of out.results) assert.match(r.verdict, /^(allow|block)$/);
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});

test('hidden_tag test() agrees with its reference pattern on short samples', () => {
  const rule = INDIRECT_INJECTION_RULES.find((r) => r.id === 'indirect:hidden_tag');
  const { samples } = JSON.parse(fs.readFileSync(SAMPLES_FILE, 'utf8'));
  for (const s of samples.filter((x) => typeof x === 'string')) {
    assert.equal(rule.test(s), rule.pattern.test(s), JSON.stringify(s));
  }
});
