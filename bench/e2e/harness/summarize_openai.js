#!/usr/bin/env node
'use strict';
/**
 * Step-by-step summary of a Codex (Responses API) or OpenCode (Chat
 * Completions) end-to-end run, from what the provider received
 * (requests.jsonl). Fake values are replaced by their names before printing.
 *
 *   node summarize_openai.js <run dir>
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
const flat = (s) => redact(s).replace(/\s+/g, ' ').slice(0, 600);

const reqs = fs.readFileSync(path.join(RUN, 'out', 'requests.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const main = reqs.filter((r) => r.body && Array.isArray(r.body.tools) && r.body.tools.length);
const last = main[main.length - 1];
const lines = ['requests to the provider: ' + reqs.length + ' (' + main.length + ' agent turns)'];
let n = 0;
if (last && Array.isArray(last.body.input)) {
  const outs = new Map(last.body.input.filter((i) => /_output$/.test(i.type || '')).map((i) => [i.call_id, i]));
  for (const i of last.body.input) {
    if (i.type !== 'function_call' && i.type !== 'custom_tool_call') continue;
    const o = outs.get(i.call_id);
    const text = o ? (typeof o.output === 'string' ? o.output : JSON.stringify(o.output)) : '(no result)';
    lines.push('', 'step ' + (++n) + ': ' + i.name + ' ' + redact(i.arguments || i.input), '  result: ' + flat(text));
  }
} else if (last && Array.isArray(last.body.messages)) {
  const outs = new Map(last.body.messages.filter((m) => m.role === 'tool').map((m) => [m.tool_call_id, m]));
  for (const m of last.body.messages) {
    for (const c of (m.role === 'assistant' && m.tool_calls) || []) {
      const o = outs.get(c.id);
      const text = o ? (typeof o.content === 'string' ? o.content : JSON.stringify(o.content)) : '(no result)';
      lines.push('', 'step ' + (++n) + ': ' + c.function.name + ' ' + redact(c.function.arguments), '  result: ' + flat(text));
    }
  }
}
process.stdout.write(lines.join('\n') + '\n');
