#!/usr/bin/env node
'use strict';
/**
 * Step-by-step summary of a Claude Code end-to-end run, built from what the
 * provider received (requests.jsonl): for each tool call the model made, the
 * tool input as sent back in the conversation and the tool result the model
 * got. Fake values are replaced by their names before printing, so the
 * summary itself can be committed as evidence.
 *
 *   node summarize_claude.js <run dir>
 */

const fs = require('fs');
const path = require('path');

const RUN = path.resolve(process.argv[2]);
const values = JSON.parse(fs.readFileSync(path.join(RUN, 'values.json'), 'utf8'));
const redact = (s) => {
  let out = String(s);
  for (const v of values) out = out.split(v.value).join('<<LEAK:' + v.name + '>>');
  return out.split(RUN).join('<run>');
};

const reqs = fs.readFileSync(path.join(RUN, 'out', 'requests.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const main = reqs.filter((r) => r.body && Array.isArray(r.body.tools) && r.body.tools.length);
const last = main[main.length - 1];
const lines = [];
lines.push('requests to the provider: ' + reqs.length + ' (' + main.length + ' agent turns)');
const msgs = last ? last.body.messages : [];
const results = new Map();
for (const m of msgs) {
  if (m.role === 'user' && Array.isArray(m.content)) {
    for (const c of m.content) if (c.type === 'tool_result') results.set(c.tool_use_id, c);
  }
}
let n = 0;
for (const m of msgs) {
  if (m.role !== 'assistant' || !Array.isArray(m.content)) continue;
  for (const c of m.content) {
    if (c.type !== 'tool_use') continue;
    n++;
    const r = results.get(c.id);
    const text = r ? (Array.isArray(r.content) ? r.content.map((x) => x.text || '').join('') : String(r.content || '')) : '(no result)';
    lines.push('');
    lines.push('step ' + n + ': ' + c.name + ' ' + redact(JSON.stringify(c.input)));
    lines.push('  result' + (r && r.is_error ? ' (error)' : '') + ': ' + redact(text).replace(/\s+/g, ' ').slice(0, 600));
  }
}
const sys = last && Array.isArray(last.body.messages) ? JSON.stringify(last.body.messages) : '';
const notes = (sys.match(/zn: [^"\\]{0,200}/g) || []).map(redact);
if (notes.length) {
  lines.push('');
  lines.push('zn notes the model saw:');
  for (const x of [...new Set(notes)]) lines.push('  - ' + x);
}
process.stdout.write(lines.join('\n') + '\n');
