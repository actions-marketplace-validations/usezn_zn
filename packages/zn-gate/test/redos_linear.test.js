'use strict';

// The linear replacements of lib/linear-text.js and their callers: same result
// as the regex each one replaced (random inputs built from the characters that
// matter), and fast on the inputs that made those regexes backtrack.

const test = require('node:test');
const assert = require('node:assert/strict');
const { trimTrailing, stripInlineComment } = require('../lib/linear-text');
const codex = require('../lib/agents/codex');
const opencode = require('../lib/agents/opencode');
const { parseDotenv } = require('../lib/scrub/exact');
const exact = require('../lib/linear-text');
const { normalizeProject } = require('../lib/vault/store');
const { claudePermission } = require('../lib/audit/patterns');
const { _internal: audit } = require('../lib/audit');

const BIG = 200 * 1024;

function ms(fn) {
  const t0 = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

// Deterministic pseudo-random strings from a list of pieces.
function* randomStrings(pieces, count, maxPieces, seed = 7) {
  let x = seed;
  const next = () => {
    x = (x * 1103515245 + 12345) % 2147483648;
    return x;
  };
  for (let n = 0; n < count; n++) {
    let s = '';
    const len = next() % (maxPieces + 1);
    for (let i = 0; i < len; i++) s += pieces[next() % pieces.length];
    yield s;
  }
}

function oldPatchFiles(patch) {
  const files = [];
  const re = /^\s*\*\*\* (?:Add|Update|Delete) File: (.+)$|^\s*\*\*\* Move to: (.+)$/gm;
  let m;
  while ((m = re.exec(String(patch || ''))) !== null) files.push((m[1] || m[2]).trim());
  return files;
}

test('patchFiles gives the same files as the old regex', () => {
  const pieces = ['*** Add File: ', '*** Update File: ', '*** Delete File: ', '*** Move to: ', '*** Add File:', '** Add File: ',
    ' ', '\t', '\n', '\r', '\r\n', '\u2028', '\v', '\f', '\u00a0', '\ufeff', '\u0085', 'a', 'b.js', ' x ', '*', '#'];
  for (const s of randomStrings(pieces, 20000, 12)) assert.deepEqual(codex.patchFiles(s), oldPatchFiles(s), JSON.stringify(s));
});

test('stripInlineComment gives the same value as the old regex, and .env values use it', () => {
  const pieces = [' ', '\t', '#', 'a', 'b', '\n', '\r', '\u2028', '##', ' #', '"', "'"];
  for (const s of randomStrings(pieces, 20000, 12)) {
    assert.equal(stripInlineComment(s), s.replace(/\s+#.*$/, ''), JSON.stringify(s));
  }
  assert.deepEqual(parseDotenv('A=abc  # comment\nB="a # b"\nC=a#b'), [['A', 'abc'], ['B', 'a # b'], ['C', 'a#b']]);
});

test('the .npmrc and .znrules readers give the same result as the old regexes', () => {
  const oldNpm = /(?:^|:)(_authToken|_auth|_password)\s*=\s*(\S+)\s*$/;
  const npmPieces = ['_authToken', '_auth', '_password', '_authT', ':', '=', ' ', '\t', '\v', '\u00a0', '\ufeff', '\u0085', '\r', 'a', 'b', '${X}', '//r/'];
  for (const s of randomStrings(npmPieces, 30000, 10)) {
    const line = s.trim();
    const m = oldNpm.exec(line);
    assert.deepEqual(exact.npmAuth(line), m ? [m[1], m[2]] : null, JSON.stringify(line));
  }
  const oldZn = /^\s*secret:\s*(.+?)\s*$/;
  const znPieces = ['secret:', 'secret', ':', ' ', '\t', '\r', '\u2028', '\u00a0', '\ufeff', '\u0085', 'A=', 'x', 'B_C=v', '#'];
  for (const s of randomStrings(znPieces, 30000, 10)) {
    const m = oldZn.exec(s);
    assert.equal(exact.znrulesValue(s), m ? m[1] : null, JSON.stringify(s));
  }
});

test('trimTrailing, the audit helpers and normalizeProject match the old regexes', () => {
  for (const s of randomStrings(['=', 'a', ' ', '*', '/', '\\', 'x='], 5000, 10)) {
    assert.equal(trimTrailing(s, '='), s.replace(/=+$/, ''));
    assert.equal(trimTrailing(s, '*'), s.replace(/\*+$/, ''));
    assert.equal(trimTrailing(s, '\\/'), s.replace(/[\\/]+$/, ''));
    const t = s.trim();
    assert.equal(audit.withoutTrailingEquals(t), t.replace(/\s*=$/, ''), JSON.stringify(t));
  }
  const old = /^\s*(?:contents|pull-requests|issues|actions|packages|id-token|deployments|statuses|checks)\s*:\s*write\b/m;
  const pieces = ['contents', 'issues', 'checks', 'checksum', 'id-token', 'pull-requests', ':', ' ', '\t', '\n', '\r', 'write', 'writer',
    'read', 'x', '#', '\u2029'];
  for (const s of randomStrings(pieces, 20000, 10)) assert.equal(audit.grantsWrite(s), old.test(s), JSON.stringify(s));
});

test('the inputs that made those regexes backtrack now take milliseconds', () => {
  const nl = '\n'.repeat(BIG);
  const cases = {
    'patchFiles on newlines': () => codex.patchFiles(nl + '*** Add File: x'),
    '.env value on spaces': () => parseDotenv('A=a' + ' '.repeat(BIG) + 'b'),
    '.env value on spaces then #': () => parseDotenv('A=a' + ' '.repeat(BIG) + '#'),
    'grantsWrite on newlines': () => audit.grantsWrite('contents' + nl + 'x'),
    'grantsWrite on spaces': () => audit.grantsWrite(('checks' + ' '.repeat(50)).repeat(BIG / 60)),
    'withoutTrailingEquals on spaces': () => audit.withoutTrailingEquals('[' + ' '.repeat(BIG) + 'x'),
    'claudePermission on stars': () => claudePermission('Bash(' + '*'.repeat(BIG) + 'x)'),
    'normalizeProject on slashes': () => normalizeProject('/' + '\\'.repeat(BIG) + 'x'),
    'trimTrailing on equals': () => trimTrailing('='.repeat(BIG) + 'x', '='),
    '.npmrc line of auth keys': () => exact.npmAuth(':_auth='.repeat(BIG / 7) + ' x'),
    '.npmrc line of spaces': () => exact.npmAuth('_auth=' + ' '.repeat(BIG) + 'x y'),
    '.znrules line of spaces': () => exact.znrulesValue('secret: a' + ' '.repeat(BIG) + 'b'),
    '.znrules line of spaces only': () => exact.znrulesValue('secret:' + ' '.repeat(BIG)),
  };
  for (const [name, fn] of Object.entries(cases)) {
    const t = Math.min(ms(fn), ms(fn));
    assert.ok(t < 200, `${name} took ${t.toFixed(1)} ms`);
  }
});

test('Codex and OpenCode refuse a patch over 100 KB before parsing it', () => {
  const big = '*** Begin Patch\n*** Add File: a.txt\n+' + 'x'.repeat(codex.PATCH_SCAN_CAP) + '\n*** End Patch';
  const ev = codex.normalize({ hook_event_name: 'PreToolUse', tool_name: 'apply_patch', tool_input: { command: big }, cwd: '/w' });
  assert.equal(ev.input.tooLong, true);
  assert.equal(ev.input.unparsed, false);
  const oc = opencode.normalize({ hook: 'tool.execute.before', tool: 'apply_patch', args: { patchText: big }, cwd: '/w' });
  assert.equal(oc.input.tooLong, true);
  const small = codex.normalize({ hook_event_name: 'PreToolUse', tool_name: 'apply_patch', tool_input: { command: '*** Add File: a.txt\n+x' }, cwd: '/w' });
  assert.equal(small.input.tooLong, false);
  assert.deepEqual(small.input.paths, ['a.txt']);
});

test('the OpenCode hook denies a patch over 100 KB too', async () => {
  const runner = require('../lib/hooks/runner');
  const big = '*** Begin Patch\n' + '\n'.repeat(codex.PATCH_SCAN_CAP) + '*** Add File: a.txt\n+x\n*** End Patch';
  const raw = { hook: 'tool.execute.before', tool: 'apply_patch', args: { patchText: big }, cwd: process.cwd() };
  const { decision } = await runner.handle(opencode, raw, {});
  assert.equal(decision.decision, 'deny');
  assert.match(decision.message, /too long for zn to check/);
});

test('the Codex hook denies a patch over 100 KB with a clear message', async () => {
  const runner = require('../lib/hooks/runner');
  const big = '*** Begin Patch\n' + '\n'.repeat(codex.PATCH_SCAN_CAP) + '*** Add File: a.txt\n+x\n*** End Patch';
  const raw = { hook_event_name: 'PreToolUse', tool_name: 'apply_patch', tool_input: { command: big }, cwd: process.cwd() };
  const t0 = Date.now();
  const { decision } = await runner.handle(codex, raw, {});
  assert.equal(decision.decision, 'deny');
  assert.match(decision.message, /too long for zn to check/);
  assert.ok(Date.now() - t0 < 2000);
});
