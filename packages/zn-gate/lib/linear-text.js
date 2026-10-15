'use strict';

// Linear-time replacements for a few regexes that backtrack quadratically on
// long runs of one character (spaces, newlines, '*', '=', '/'). Each returns
// exactly what the regex it replaces returned; test/redos_linear.test.js checks
// that against the old regex on random inputs.

const LINE_BREAKS = new Set(['\n', '\r', '\u2028', '\u2029']);

/** s without the run of characters from `chars` at its end (was s.replace(/[<chars>]+$/, '')). */
function trimTrailing(s, chars) {
  let end = s.length;
  while (end > 0 && chars.includes(s[end - 1])) end--;
  return s.slice(0, end);
}

/**
 * Unquoted value without its trailing inline comment (was t.replace(/\s+#.*$/, '')):
 * cut at the whitespace before the first " #" whose comment runs to the end of
 * the value without a line break.
 */
function stripInlineComment(t) {
  let from = 0;
  for (let i = t.length - 1; i >= 0; i--) {
    if (LINE_BREAKS.has(t[i])) {
      from = i;
      break;
    }
  }
  const re = /\s#/g;
  re.lastIndex = from;
  const m = re.exec(t);
  return m ? t.slice(0, m.index).trimEnd() : t;
}

/** Lines of s, split at every character a regex treats as a line break. */
function lines(s) {
  return s.split(/[\n\r\u2028\u2029]/);
}

module.exports = { LINE_BREAKS, trimTrailing, stripInlineComment, lines };
