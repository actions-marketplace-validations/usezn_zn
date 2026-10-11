'use strict';
/**
 * Streaming scrubber: stdin -> tokenize per line -> stdout.
 *
 *   <command> 2>&1 | node lib/scrub/stream.js
 *
 * Used by agent hooks for tools that stream a command's output to the model
 * line by line (Claude Code's Monitor), where no PostToolUse hook sees the
 * lines. Each complete line is tokenized like any tool output (destination
 * "assistant"); with the vault locked the engine redacts irreversibly. A
 * partial line is held until its newline, or flushed after FLUSH_MS of
 * silence or MAX_LINE bytes, so a prompt without a newline still shows up.
 *
 * Fail-closed: if a line cannot be scrubbed it is replaced with a notice,
 * never passed through.
 */

const engine = require('./engine');
const deps = require('../deps');

const FLUSH_MS = 250;
const MAX_LINE = 64 * 1024;

async function main() {
  let vault = null;
  try { vault = await deps.loadVault(); } catch (err) { vault = null; }
  const ctx = {
    project: deps.findProjectRoot(process.cwd()),
    agent: process.env.ZN_AGENT || 'stream',
    tool: 'stream',
    destination: 'assistant',
    vault,
  };
  let pending = '';
  let queue = Promise.resolve();
  let timer = null;

  const emit = (text) => {
    queue = queue.then(async () => {
      let out;
      try {
        const res = await engine.tokenize(text, ctx);
        out = res && typeof res.text === 'string' ? res.text : '[zn: line withheld: scrubber error]\n';
      } catch (err) {
        out = '[zn: line withheld: scrubber error]' + (text.endsWith('\n') ? '\n' : '');
      }
      process.stdout.write(out);
    });
    return queue;
  };

  const flushPartial = () => {
    timer = null;
    if (pending) { const t = pending; pending = ''; emit(t); }
  };

  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    pending += chunk;
    let nl;
    while ((nl = pending.indexOf('\n')) >= 0) {
      emit(pending.slice(0, nl + 1));
      pending = pending.slice(nl + 1);
    }
    while (pending.length > MAX_LINE) {
      emit(pending.slice(0, MAX_LINE));
      pending = pending.slice(MAX_LINE);
    }
    if (timer) clearTimeout(timer);
    if (pending) timer = setTimeout(flushPartial, FLUSH_MS);
  });
  process.stdin.on('end', async () => {
    if (timer) clearTimeout(timer);
    if (pending) emit(pending);
    await queue;
    try { require('../vault/client').close(); } catch (_) { /* not loaded */ }
  });
}

module.exports = { main, FLUSH_MS, MAX_LINE };

if (require.main === module) main();
