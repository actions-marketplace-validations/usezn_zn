'use strict';

// A ledger with invalid bytes or a broken line is reported as corrupted and never lets
// the next write silently restart the hash chain.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const {
  logEvidence, verifyEvidenceLedger, getEvidenceStats, exportEvidenceLedger, EvidenceLedgerError, GENESIS_HASH,
} = require('../lib/evidence');

function tmpLedger(n = 2) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-ev-corrupt-'));
  const file = path.join(dir, 'evidence.jsonl');
  for (let i = 0; i < n; i++) logEvidence({ payload: `example-${i}`, tool_name: 'bash' }, file);
  return { dir, file };
}

const makers = {
  'invalid bytes at the end': (file) => { fs.appendFileSync(file, Buffer.from([0xff, 0xfe, 0x80, 0x67, 0x0a])); return 3; },
  'invalid bytes in the middle': (file) => {
    const lines = fs.readFileSync(file).toString('latin1').split('\n');
    lines[1] = lines[1].slice(0, 20) + '\xff\xfe' + lines[1].slice(20);
    fs.writeFileSync(file, Buffer.from(lines.join('\n'), 'latin1'));
    return 2;
  },
  'truncated last line': (file) => {
    const data = fs.readFileSync(file);
    fs.writeFileSync(file, data.subarray(0, data.length - 40));
    return 2;
  },
};

function freshEvidence() {
  delete require.cache[require.resolve('../lib/evidence')];
  return require('../lib/evidence');
}

function captureStderr(fn) {
  const orig = process.stderr.write;
  let out = '';
  process.stderr.write = (chunk) => { out += chunk; return true; };
  try { fn(); } finally { process.stderr.write = orig; }
  return out;
}

test('valid, empty and missing ledgers are unchanged', () => {
  const { dir, file } = tmpLedger(3);
  try {
    assert.equal(verifyEvidenceLedger(file).valid, true);
    assert.equal(getEvidenceStats(file).valid, true);
    assert.equal(exportEvidenceLedger(file).valid, true);
    const empty = path.join(dir, 'empty.jsonl');
    fs.writeFileSync(empty, '');
    assert.equal(verifyEvidenceLedger(empty).valid, true);
    assert.equal(logEvidence({ payload: 'x' }, empty).prev_hash, GENESIS_HASH);
    assert.equal(logEvidence({ payload: 'x' }, path.join(dir, 'missing.jsonl')).prev_hash, GENESIS_HASH);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

for (const [name, make] of Object.entries(makers)) {
  test(`corrupt ledger (${name}): verify, stats and export report it`, () => {
    const { dir, file } = tmpLedger();
    try {
      const line = make(file);
      const v = verifyEvidenceLedger(file);
      assert.equal(v.valid, false);
      assert.match(v.error, new RegExp(`line ${line}`));
      assert.equal(v.broken_index, line - 1);
      const s = getEvidenceStats(file);
      assert.equal(s.valid, false);
      assert.ok(s.error);
      for (const fmt of ['jsonl', 'csv']) {
        const e = exportEvidenceLedger(file, fmt);
        assert.equal(e.valid, false);
        assert.ok(e.error);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test(`corrupt ledger (${name}): logEvidence refuses to append and warns once`, () => {
    const { dir, file } = tmpLedger();
    try {
      make(file);
      const before = fs.readFileSync(file);
      const fresh = freshEvidence();
      let r1; let r2;
      const err = captureStderr(() => {
        r1 = fresh.logEvidence({ payload: 'after' }, file);
        r2 = fresh.logEvidence({ payload: 'again' }, file);
      });
      assert.equal(r1, null);
      assert.equal(r2, null);
      assert.ok(fs.readFileSync(file).equals(before), 'nothing is appended');
      assert.equal(err.split('damaged').length - 1, 1, 'warns once');
      assert.match(err, /--verify/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
}

test('invalid bytes are named in the verify message', () => {
  const { dir, file } = tmpLedger();
  try {
    makers['invalid bytes at the end'](file);
    assert.match(verifyEvidenceLedger(file).error, /Invalid UTF-8/);
    assert.ok(EvidenceLedgerError);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
