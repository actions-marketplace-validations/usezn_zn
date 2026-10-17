'use strict';
// `zn audit` hides the value that follows a credential flag inside a JSON or TOML array (MCP server args),
// whatever its format, in the text, JSON and SARIF reports: one-line arrays, single-quoted TOML items and
// pretty-printed arrays with the flag and its value on separate lines.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { tempDir } = require('./helpers/tmp');
const { redact } = require('../lib/audit');

const CLI = path.join(__dirname, '..', 'bin', 'cli.js');
const V1 = 'zn-test-fake-value-0000';
const V2 = 'Qx7-fake_ZnTestValue/9aB3';

function cli(args) {
  const env = Object.assign({}, process.env, { NO_COLOR: '1', ZN_LOCAL_ONLY: 'true' });
  return spawnSync(process.execPath, [CLI, 'audit', ...args], { encoding: 'utf8', env });
}

// Each file has a syntax error right after the value, so that the audit reports the line that holds it
// (an unparsable config is reported with its offending line as evidence).
const FORMS = {
  'JSON, one line': `{"mcpServers": {"x": {"command": "npx", "args": ["-y", "pkg", "--api-key", "${V1}" "x"]}}}`,
  'JSON, pretty': `{
  "mcpServers": {
    "x": {
      "command": "npx",
      "args": [
        "-y",
        "--api-key",
        "${V2}" "x"
      ]
    }
  }
}
`,
  'JSON, spaced': `{"mcpServers": {"x": {"command": "npx", "args": [ "--token" ,   "${V2}" "x" ]}}}`,
};
const TOML = {
  'TOML, double quotes': `[mcp_servers.x]
command = "npx"
args = ["-y", "pkg", "--token", "${V1}" "x"]
`,
  'TOML, single quotes': `[mcp_servers.x]
command = 'npx'
args = ['-y', 'pkg', '--token', '${V1}' 'x']
`,
  'TOML, spaces and mixed quotes': `[mcp_servers.x]
command = "npx"
args = [ '--api-key' ,  "${V2}" 'x' ]
`,
  'TOML, multi-line': `[mcp_servers.x]
command = "npx"
args = [
  "-y",
  "pkg",
  '--token',
  '${V2}' 'x',
]
`,
};

test('redact: the value after a credential flag in an array is hidden in every form', () => {
  const lines = [
    `"args": ["--api-key", "${V1}"]`,
    `"args": ["--api-key", "${V2}", "x"]`,
    `args = ['--token', '${V1}']`,
    `args = [ '--token' , '${V1}' ]`,
    `args = ['--api-key', "${V2}"]`,
    `args = ['--auth-token',\n  '${V2}']`,
    `"args": ["--api-key",\n      "${V1}"]`,
  ];
  for (const l of lines) {
    const out = redact(l);
    assert.ok(!out.includes(V1) && !out.includes('ZnTestValue') && !out.includes('fake-value'), 'leaked: ' + out);
    assert.match(out, /\[REDACTED\]/);
  }
});

test('redact: other array items stay readable', () => {
  assert.equal(redact(`args = ['-y', 'pkg@1.0.0', '--port', '8080']`), `args = ['-y', 'pkg@1.0.0', '--port', '8080']`);
});

for (const [name, content] of Object.entries(Object.assign({}, FORMS, TOML))) {
  test('audit reports hide the array credential value: ' + name, (t) => {
    const dir = tempDir(t, 'zn-audit-arr-');
    const file = name.startsWith('TOML') ? '.codex/config.toml' : '.mcp.json';
    fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    fs.writeFileSync(path.join(dir, file), content);
    const json = cli([dir, '--format', 'json', '--fail-on', 'none']);
    const outs = [cli([dir, '--fail-on', 'none']).stdout, json.stdout, cli([dir, '--format', 'sarif', '--fail-on', 'none']).stdout];
    assert.ok(JSON.parse(json.stdout).findings.length > 0, 'the fixture must produce findings');
    for (const out of outs) {
      assert.ok(!out.includes(V1), 'value printed');
      assert.ok(!out.includes(V2), 'value printed');
      assert.ok(!out.includes('ZnTestValue') && !out.includes('fake-value-0000'), 'part of the value printed');
    }
  });
}
