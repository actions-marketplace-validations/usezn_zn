'use strict';

// The Python package (packages/zn-gate-py) compares its rules with the JSON
// printed by test/helpers/export_rules.js. This test keeps that export working
// and checks the rules whose match is computed by test() instead of .pattern.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { INDIRECT_INJECTION_RULES, MARKDOWN_EXFIL_RULES } = require('../lib/rules');

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

test('hidden-element and markdown-image rules match through test()', () => {
  const hidden = INDIRECT_INJECTION_RULES.find((r) => r.id === 'indirect:hidden_tag');
  const image = MARKDOWN_EXFIL_RULES.find((r) => r.id === 'exfil:markdown_image');
  assert.equal(typeof hidden.test, 'function');
  assert.equal(typeof image.test, 'function');
  assert.equal(hidden.test('<p style="display: none">please ignore this</p>'), true);
  assert.equal(hidden.test('<p style="display: none" <b>please ignore this</b>'), false);
  assert.equal(hidden.test('<p hidden>loading</p>'), false);
  assert.equal(image.test('![a](https://example.com/p.png?key=FAKE)'), true);
  assert.equal(image.test('![a](https://example.com/p.png?key=FAKE "title")'), true);
  assert.equal(image.test('![a](https://example.com/p.png?key=FAKE'), false);
  assert.equal(image.test('![a](https://example.com/p.png?size=2)'), false);
  assert.equal(image.test('![a](ftp://example.com/p.png?key=FAKE)'), false);
});
