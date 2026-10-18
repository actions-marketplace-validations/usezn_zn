#!/usr/bin/env node
'use strict';
// Runs every test of the package, in order, and stops at the first failure.
//
//   1. the files named in test/runner-plain.json, each with plain `node <file>`
//   2. every other test/*.test.js, together under `node --test`
//   3. test/integration/test_agent_workflows.js
//   4. `node bin/cli.js test`
//
// A new test/*.test.js is picked up by step 2 without touching package.json.
// Files that must run with plain `node` are listed in runner-plain.json.
//
//   node test/run-all.js          run everything
//   node test/run-all.js --list   print the steps without running them

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.resolve(__dirname, '..');
const testDir = __dirname;

// test/*.test.js files that are not tests of their own (none today).
// Add a name here with a comment saying why.
const EXCLUDE = [];

function load() {
  const plain = JSON.parse(fs.readFileSync(path.join(testDir, 'runner-plain.json'), 'utf8'));
  if (!Array.isArray(plain) || plain.some((f) => typeof f !== 'string')) {
    throw new Error('runner-plain.json must be an array of file names');
  }
  const missing = plain.filter((f) => !fs.existsSync(path.join(testDir, f)));
  if (missing.length) throw new Error('runner-plain.json names missing files: ' + missing.join(', '));
  const dup = plain.filter((f, i) => plain.indexOf(f) !== i);
  if (dup.length) throw new Error('runner-plain.json lists a file twice: ' + dup.join(', '));
  const bad = EXCLUDE.filter((f) => !fs.existsSync(path.join(testDir, f)));
  if (bad.length) throw new Error('EXCLUDE names missing files: ' + bad.join(', '));

  const discovered = fs.readdirSync(testDir).filter((f) => f.endsWith('.test.js')).sort();
  const harness = discovered.filter((f) => !plain.includes(f) && !EXCLUDE.includes(f));

  const rel = (f) => 'test/' + f;
  const steps = [];
  for (const f of plain) steps.push({ label: rel(f), args: [rel(f)] });
  if (harness.length) {
    steps.push({ label: 'node --test (' + harness.length + ' files)', args: ['--test', ...harness.map(rel)], files: harness.map(rel) });
  }
  steps.push({ label: 'test/integration/test_agent_workflows.js', args: ['test/integration/test_agent_workflows.js'] });
  steps.push({ label: 'bin/cli.js test', args: ['bin/cli.js', 'test'] });

  // Every .test.js is either run plain, run under --test, or excluded.
  const covered = new Set([...plain, ...harness, ...EXCLUDE]);
  const lost = discovered.filter((f) => !covered.has(f));
  if (lost.length) throw new Error('test files not run by any step: ' + lost.join(', '));
  return steps;
}

function main() {
  const steps = load();
  if (process.argv.includes('--list')) {
    for (const s of steps) {
      if (s.files) for (const f of s.files) console.log(f);
      else console.log(s.args.join(' '));
    }
    return 0;
  }
  for (const s of steps) {
    console.log('\n=== ' + s.label + ' ===');
    const r = spawnSync(process.execPath, s.args, { cwd: root, stdio: 'inherit', shell: false });
    if (r.error || r.status !== 0) {
      console.error('\nFAILED: ' + s.label + (r.error ? ' (' + r.error.message + ')' : ' (exit ' + (r.status === null ? 'signal ' + r.signal : r.status) + ')'));
      return r.status || 1;
    }
  }
  return 0;
}

try {
  process.exitCode = main();
} catch (e) {
  console.error('run-all: ' + e.message);
  process.exitCode = 1;
}
