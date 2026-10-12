#!/usr/bin/env node
'use strict';
/**
 * Stand-in for the person answering Claude Code's permission prompts in a
 * non-interactive run (`claude -p --permission-prompt-tool mcp__approver__approve`).
 * It approves every prompt with the input exactly as Claude Code shows it,
 * and logs what it was shown to $APPROVER_LOG, so a run can check what a
 * user would have seen in the dialog (for example a command rewritten by
 * the zn hook).
 */

const fs = require('fs');
const readline = require('readline');

const LOG = process.env.APPROVER_LOG;
const rl = readline.createInterface({ input: process.stdin, terminal: false });
const send = (msg) => process.stdout.write(JSON.stringify(msg) + '\n');

rl.on('line', (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch (_) { return; }
  const { id, method, params } = msg;
  if (method === 'initialize') {
    send({ jsonrpc: '2.0', id, result: { protocolVersion: (params && params.protocolVersion) || '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'approver', version: '1.0.0' } } });
  } else if (method === 'tools/list') {
    send({ jsonrpc: '2.0', id, result: { tools: [{ name: 'approve', description: 'Answer a permission prompt.', inputSchema: { type: 'object', properties: { tool_name: { type: 'string' }, input: { type: 'object' }, tool_use_id: { type: 'string' } }, required: ['tool_name', 'input'] } }] } });
  } else if (method === 'tools/call') {
    const a = (params && params.arguments) || {};
    if (LOG) fs.appendFileSync(LOG, JSON.stringify({ ts: new Date().toISOString(), tool_name: a.tool_name, input: a.input }) + '\n');
    send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify({ behavior: 'allow', updatedInput: a.input }) }] } });
  } else if (id !== undefined) {
    send({ jsonrpc: '2.0', id, result: {} });
  }
});
