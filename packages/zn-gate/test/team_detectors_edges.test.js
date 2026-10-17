'use strict';
/*
 * Custom detectors from an organization policy (lib/team/detectors.js):
 * every reason a pattern is refused, what compile() drops, and the time
 * limits, with a controlled clock so the tests do not depend on speed.
 */
const test = require('node:test');
const assert = require('node:assert');
const detectors = require('../lib/team/detectors');

const TOKEN = 'ACME-' + 'K7Q2ZP4M9XW3LB8RT5VN6YC1';

test('a pattern that is not a string, or has the wrong length, is refused', () => {
  for (const p of [undefined, null, 42, {}, [], '', 'abc', 'a'.repeat(257)]) {
    assert.strictEqual(detectors.checkPattern(p), 'invalid length', String(p));
  }
  assert.strictEqual(detectors.checkPattern('a'.repeat(4)), null);
});

test('each kind of unsupported syntax is refused with its own reason', () => {
  const cases = [
    ['abc\\', 'unsupported escape \\'], // a lone backslash at the end
    ['ab\\q{3}', 'unsupported escape \\q'],
    ['ab[\\q]{3}', 'unsupported escape in a class'],
    ['ab[a\\', 'unsupported escape in a class'],
    ['ab[a[b]]', 'nested character class'],
    ['ab[]cd', 'empty character class'],
    ['ab[^]cd', 'empty character class'],
    ['ab[abc', 'unterminated character class'],
    ['ab[abc\\d', 'unterminated character class'],
    ['ab(cd', 'only characters, character classes and {n} or {m,n} repetitions are allowed (no ()'],
    ['ab|cd', 'only characters, character classes and {n} or {m,n} repetitions are allowed (no |)'],
    ['a^bcd', 'only characters, character classes and {n} or {m,n} repetitions are allowed (no ^)'],
    ['ab$cd', 'only characters, character classes and {n} or {m,n} repetitions are allowed (no $)'],
    ['abcd{x}', 'repetitions are written {n} or {m,n}'],
    ['abcd{1,2,3}', 'repetitions are written {n} or {m,n}'],
    ['abcd{1000}', 'repetitions are written {n} or {m,n}'],
    ['abcd{5,2}', 'repetition bounds must be 1 to 256'],
    ['abcd{0}', 'repetition bounds must be 1 to 256'],
    ['abcd{300}', 'repetition bounds must be 1 to 256'],
    ['abcd{1,100}', 'a variable repetition can span at most 64'],
    ['abcd{2}?', 'repetition modifiers are not allowed'],
    ['abcd{2}+', 'repetition modifiers are not allowed'],
    ['abcd{2}{3}', 'repetition modifiers are not allowed'],
    ['a{1,2}b{1,2}cd', 'at most 1 variable-length repetition is allowed'],
    ['abcd$e', 'only characters, character classes and {n} or {m,n} repetitions are allowed (no $)'],
  ];
  for (const [pattern, why] of cases) assert.strictEqual(detectors.checkPattern(pattern), why, pattern);
});

test('cost, empty matches and invalid expressions are refused', () => {
  assert.match(detectors.checkPattern('.{0,64}.{256}.{256}.{256}x'), /pattern too costly/);
  assert.strictEqual(detectors.checkPattern('[a-z]{0,3}[0-9]{0,0}'), 'repetition bounds must be 1 to 256');
  assert.strictEqual(detectors.checkPattern('[a-z]{0,5}'), 'pattern must not match the empty string');
  assert.strictEqual(detectors.checkPattern('[z-a]{3}'), 'invalid regular expression');
});

test('anchors, escapes and classes that the grammar allows are accepted', () => {
  for (const p of ['^abcd', 'abcd$', '^abcd$', '\\d{4}-\\w{4}', '[^abc]{4}', '[\\]\\[a]{4}', 'a.b.c.', 'ab\\.cd', 'tok-[a-f0-9]{8,16}', '\\/\\/ab']) {
    assert.strictEqual(detectors.checkPattern(p), null, p);
  }
});

test('compile drops bad entries, caps the list at 50 and tolerates junk input', () => {
  for (const junk of [undefined, null, 'x', 7, {}]) assert.deepStrictEqual(detectors.compile(junk), []);
  const good = { id: 'acme', pattern: 'ACME-[A-Z0-9]{24}', type: 'ACME_TOKEN' };
  const compiled = detectors.compile([
    null, undefined, 'text', {},
    { id: 'no_type', pattern: 'ACME-[A-Z0-9]{24}' },
    { id: 'lower_type', pattern: 'ACME-[A-Z0-9]{24}', type: 'acme' },
    { id: 'type_ends_underscore', pattern: 'ACME-[A-Z0-9]{24}', type: 'ACME_' },
    { id: 'x'.repeat(65), pattern: 'ACME-[A-Z0-9]{24}', type: 'OK' },
    { id: 'has-dash', pattern: 'ACME-[A-Z0-9]{24}', type: 'OK' },
    { id: 'bad_pattern', pattern: '(a+)+$', type: 'OK' },
    good,
    { id: 'single', pattern: 'ACME-[A-Z0-9]{24}', type: 'X' },
  ]);
  assert.deepStrictEqual(compiled.map((d) => d.id), ['acme', 'single']);
  assert.ok(compiled.every((d) => d.re.global && d.off === false));
  const many = Array.from({ length: 80 }, (_, i) => ({ id: 'd' + i, pattern: 'ACME-[A-Z0-9]{24}', type: 'T' }));
  assert.strictEqual(detectors.compile(many).length, 50);
});

test('find returns nothing for no detectors, no text or text that is not a string', () => {
  const c = detectors.compile([{ id: 'acme', pattern: 'ACME-[A-Z0-9]{24}', type: 'ACME_TOKEN' }]);
  assert.deepStrictEqual(detectors.find('x ' + TOKEN, null), []);
  assert.deepStrictEqual(detectors.find('x ' + TOKEN, undefined), []);
  assert.deepStrictEqual(detectors.find('x ' + TOKEN, []), []);
  assert.deepStrictEqual(detectors.find('', c), []);
  assert.deepStrictEqual(detectors.find(null, c), []);
  assert.deepStrictEqual(detectors.find(12345, c), []);
  assert.deepStrictEqual(detectors.find({ text: TOKEN }, c), []);
});

test('find reports every match with its detector, across lines and blank lines', () => {
  detectors.resetBudget();
  const c = detectors.compile([
    { id: 'acme', pattern: 'ACME-[A-Z0-9]{24}', type: 'ACME_TOKEN' },
    { id: 'ids', pattern: 'id-\\d{4}', type: 'ID' },
  ]);
  const text = '\n\n' + TOKEN + '\r\n\nid-1234 and id-5678\n' + TOKEN + '\n';
  const spans = detectors.find(text, c);
  assert.strictEqual(spans.length, 4);
  for (const s of spans) {
    assert.strictEqual(s.source, 'pattern');
    assert.ok(text.slice(s.start, s.end).length > 0);
  }
  assert.deepStrictEqual(spans.filter((s) => s.detector === 'ids').map((s) => text.slice(s.start, s.end)), ['id-1234', 'id-5678']);
  assert.deepStrictEqual([...new Set(spans.map((s) => s.type))].sort(), ['ACME_TOKEN', 'ID']);
});

test('a value that sits exactly at a window boundary is found when it fits in one window', () => {
  detectors.resetBudget();
  const c = detectors.compile([{ id: 'acme', pattern: 'ACME-[A-Z0-9]{24}', type: 'ACME_TOKEN' }]);
  const text = 'a'.repeat(detectors.WINDOW - TOKEN.length) + TOKEN;
  const spans = detectors.find(text, c);
  assert.strictEqual(spans.length, 1);
  assert.strictEqual(spans[0].end, detectors.WINDOW);
  // Split across two windows: documented limitation, nothing is found and nothing breaks.
  const split = 'a'.repeat(detectors.WINDOW - 10) + TOKEN;
  assert.deepStrictEqual(detectors.find(split, c), []);
});

/** A clock that advances `step` ms every time it is read. */
function fakeClock(t, step) {
  let now = 1000000;
  t.mock.method(Date, 'now', () => { const v = now; now += step; return v; });
}

test('one call stops scanning when it used up its time budget', (t) => {
  detectors.resetBudget();
  const c = detectors.compile([{ id: 'acme', pattern: 'ACME-[A-Z0-9]{24}', type: 'ACME_TOKEN' }]);
  // Each clock read costs more than the call budget: the first window check already fails.
  fakeClock(t, detectors.CALL_BUDGET_MS + 1);
  assert.deepStrictEqual(detectors.find(TOKEN + '\n' + TOKEN, c), []);
  t.mock.restoreAll();
  detectors.resetBudget();
  assert.strictEqual(detectors.find(TOKEN, c).length, 1, 'the next call starts fresh');
});

test('a detector that is too slow on one window is switched off for the rest of the process', (t) => {
  detectors.resetBudget();
  const c = detectors.compile([
    { id: 'slow', pattern: 'ACME-[A-Z0-9]{24}', type: 'SLOW' },
    { id: 'other', pattern: 'id-\\d{4}', type: 'ID' },
  ]);
  // Two reads per window (call-budget check, window start) and one at the end:
  // 60 ms per read: the window takes 60 ms (over the 50 ms limit) and the second detector then hits the call budget.
  fakeClock(t, 60);
  const text = TOKEN + ' id-1234';
  const first = detectors.find(text, c);
  t.mock.restoreAll();
  assert.strictEqual(first.filter((s) => s.detector === 'slow').length, 1, 'the match of that window is kept');
  assert.strictEqual(c[0].off, true);
  assert.strictEqual(c[1].off, false);
  detectors.resetBudget();
  const second = detectors.find(text, c);
  assert.deepStrictEqual(second.map((s) => s.detector), ['other'], 'the slow detector no longer runs');
});

test('after the process budget is spent every detector is switched off and find returns nothing', (t) => {
  detectors.resetBudget();
  const c = detectors.compile([{ id: 'acme', pattern: 'ACME-[A-Z0-9]{24}', type: 'ACME_TOKEN' }]);
  // One call that "takes" more than the process budget: reads are start (0) and end (+1001).
  let calls = 0;
  const base = 2000000;
  t.mock.method(Date, 'now', () => base + (calls++ >= 2 ? detectors.PROCESS_BUDGET_MS + 1 : 0));
  detectors.find(TOKEN, c);
  t.mock.restoreAll();
  assert.ok(c.every((d) => d.off), 'the compiled detectors are off');
  const fresh = detectors.compile([{ id: 'acme', pattern: 'ACME-[A-Z0-9]{24}', type: 'ACME_TOKEN' }]);
  assert.deepStrictEqual(detectors.find(TOKEN, fresh), [], 'new detectors do not run either in this process');
  detectors.resetBudget();
  assert.strictEqual(detectors.find(TOKEN, fresh).length, 1, 'resetBudget starts a new process budget');
});

test('a pattern that matches nothing in a long hostile line returns quickly and finds nothing', () => {
  detectors.resetBudget();
  const c = detectors.compile([{ id: 'acme', pattern: 'ACME-[A-Z0-9]{24}', type: 'ACME_TOKEN' }]);
  const hostile = 'ACME-'.repeat(3000);
  assert.deepStrictEqual(detectors.find(hostile, c), []);
  detectors.resetBudget();
});
