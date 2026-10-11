#!/usr/bin/env node
'use strict';
/**
 * Leak check for an end-to-end run: looks for every fake secret value, and
 * its base64, base64url, hex and url-encoded forms, in the files given.
 *
 *   node check_leaks.js --values values.json --label sent <file|dir> ... [--label local <file|dir> ...]
 *
 * Prints one line per label with the count of files and findings, and the
 * value names found (never the values). Exit 1 if any "sent" file leaks.
 */

const fs = require('fs');
const path = require('path');

const argv = process.argv.slice(2);
let values = [];
const groups = [];
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--values') values = JSON.parse(fs.readFileSync(argv[++i], 'utf8'));
  else if (argv[i] === '--label') groups.push({ label: argv[++i], paths: [] });
  else if (groups.length) groups[groups.length - 1].paths.push(argv[i]);
}

function forms(v) {
  const b = Buffer.from(v, 'utf8');
  return [v, b.toString('base64').replace(/=+$/, ''), b.toString('base64url'), b.toString('hex'), b.toString('hex').toUpperCase(), encodeURIComponent(v)]
    .filter((x, i, a) => x.length >= 8 && a.indexOf(x) === i);
}

function files(p) {
  if (!fs.existsSync(p)) return [];
  const st = fs.statSync(p);
  if (st.isFile()) return [p];
  return fs.readdirSync(p).flatMap((n) => files(path.join(p, n)));
}

let sentLeaks = 0;
const report = [];
for (const g of groups) {
  const list = g.paths.flatMap(files);
  const found = [];
  for (const f of list) {
    const text = fs.readFileSync(f, 'latin1');
    for (const v of values) {
      for (const form of forms(v.value)) {
        if (text.includes(form)) found.push({ file: path.basename(f), name: v.name, form: form === v.value ? 'raw' : 'encoded' });
      }
    }
  }
  if (g.label === 'sent') sentLeaks += found.length;
  report.push({ label: g.label, files: list.length, findings: found.length, details: found });
  console.log(g.label + ': ' + list.length + ' file(s), ' + found.length + ' finding(s)' + (found.length ? ' -> ' + found.map((x) => x.name + '(' + x.form + ') in ' + x.file).join(', ') : ''));
}
if (process.env.LEAK_JSON) fs.writeFileSync(process.env.LEAK_JSON, JSON.stringify(report, null, 2) + '\n');
process.exitCode = sentLeaks ? 1 : 0;
