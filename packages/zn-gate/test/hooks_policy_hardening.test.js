'use strict';

// Hardening after the beta review: a backslash is read both ways, letter case
// follows the platform (simulated here on any system), agent configuration
// directories cannot be changed by a command, glob matches are checked on the
// disk, and a render never writes agent settings and asks before credentials.
// Values are fake. The platform is restored after each simulated block.

const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const policy = require('../lib/hooks/policy');
const { createSecretsServer } = require('../lib/broker/mcp');
const { createFakeVault } = require('./helpers/fake_vault');
const fakeEngine = require('./helpers/fake_engine');
const { generateAll } = require('./fixtures/fake_secrets');

const FAKE = generateAll(7171, { perType: 1, piiPerType: 1 });
const NPM = FAKE.secrets.find((s) => s.type === 'npm_access_token').value;
const AWS = FAKE.secrets.find((s) => s.type === 'aws_access_key_id').value;

// Runs fn as if process.platform were `name`, then restores it.
function asPlatform(name, fn) {
  const desc = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: name, configurable: true });
  try {
    return fn();
  } finally {
    Object.defineProperty(process, 'platform', desc);
  }
}

// Every directory a test makes is removed when the tests of this file are done.
const created = [];
after(() => {
  for (const d of created) fs.rmSync(d, { recursive: true, force: true });
});

function tmpHome() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-harden-'));
  created.push(home);
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj);
  return { home, proj };
}

function call(srv, name, args) {
  return srv.handleMessage({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } })
    .then((r) => ({ isError: r.result.isError, data: JSON.parse(r.result.content[0].text) }));
}

/* ------------------------------ both readings ------------------------------ */

test('a backslash before a letter is read both ways: a protected word is refused in either reading', () => {
  const { home, proj } = tmpHome();
  const opts = { home, cwd: proj, env: {} };
  // Bash reading: \e is e, so the word is .aws/credentials.
  assert.match(policy.bashDenial('cat ~/.aws/cr\\edentials', opts), /credential/);
  assert.match(policy.bashDenial('cat ~/.aws/credential\\s', opts), /credential/);
  // Windows reading (already covered): the backslashes are separators.
  assert.match(policy.bashDenial('type ' + path.join(home, '.aws', 'credentials'), opts), /credential/);
  // A .env file only counts when it holds a plain secret (a fake key here).
  fs.writeFileSync(path.join(proj, '.env'), 'KEY=' + AWS + '\n');
  assert.match(policy.bashDenial('cat .e\\nv', opts), /holds plain-text/);
  assert.equal(policy.bashDenial('cat src\\app.js', opts), null);
});

/* ------------------------------- platform case ------------------------------- */

test('case follows the platform: Azure token files and .env names match on Windows and macOS', () => {
  const { home, proj } = tmpHome();
  const opts = { home, cwd: proj, env: {} };
  fs.writeFileSync(path.join(proj, '.ENV'), 'PLAIN=1\n');
  asPlatform('darwin', () => {
    assert.equal(policy.classifyPath('~/.azure/accessTokens.json', opts).kind, 'credential');
    assert.equal(policy.classifyPath('~/.AZURE/ACCESSTOKENS.JSON', opts).kind, 'credential');
    assert.equal(policy.classifyPath('~/.azure/msal_token_cache.json', opts).kind, 'credential');
    assert.match(policy.bashDenial('cat ~/.azure/access*', opts), /credential/);
    assert.equal(policy.classifyPath('.ENV', opts).kind, 'dotenv');
    assert.equal(policy.classifyPath('.Env.Production', opts).kind, 'dotenv');
  });
  asPlatform('win32', () => {
    assert.equal(policy.classifyPath('~/.AZURE/accessTokens.JSON', opts).kind, 'credential');
  });
  asPlatform('linux', () => {
    assert.equal(policy.classifyPath('~/.AZURE/ACCESSTOKENS.JSON', opts), null, 'case kept on Linux');
    assert.equal(policy.classifyPath('.ENV', opts), null);
  });
});

/* ---------------------------- agent directories ---------------------------- */

test('a command cannot change an agent configuration directory, nor write into it', () => {
  const { home, proj } = tmpHome();
  const opts = { home, cwd: proj, env: {} };
  for (const cmd of [
    'cd ~/.claude && echo {} > settings.json',
    'rm -rf ~/.cursor',
    'mv ~/.codex /tmp/x',
    'find ~/.cursor -name hooks.json -delete',
    'tree -o ~/.claude/settings.json',
    'echo {} > $CODEX_HOME/hooks.json',
    'cp x.txt ' + path.join(proj, '.claude'),
  ]) {
    assert.match(policy.bashDenial(cmd, opts), /protected|configuration/, cmd);
  }
  for (const cmd of ['ls ~/.claude', 'cat ~/.claude/settings.json']) {
    assert.equal(policy.bashDenial(cmd, opts), null, cmd);
  }
});

test('the directories the environment names are agent configuration too', () => {
  const { home, proj } = tmpHome();
  const codexHome = path.join(home, 'codex-elsewhere');
  const opts = { home, cwd: proj, env: { CODEX_HOME: codexHome } };
  assert.match(policy.bashDenial('echo {} > ' + path.join(codexHome, 'hooks.json'), opts), /protected|configuration/);
  assert.match(policy.bashDenial('rm -rf ' + codexHome, opts), /protected|configuration/);
  assert.equal(policy.bashDenial('cat ' + path.join(home, 'notes.txt'), opts), null);
});

test('the directory named by CLAUDE_CONFIG_DIR is protected too, set or not', () => {
  const { home, proj } = tmpHome();
  const claudeDir = path.join(home, 'claude-elsewhere');
  const opts = { home, cwd: proj, env: { CLAUDE_CONFIG_DIR: claudeDir } };
  assert.match(policy.bashDenial('echo {} > ' + path.join(claudeDir, 'settings.json'), opts), /protected|configuration/);
  assert.match(policy.bashDenial('rm -rf ' + claudeDir, opts), /protected|configuration/);
  assert.match(policy.bashDenial('echo {} > $CLAUDE_CONFIG_DIR/settings.json', { home, cwd: proj, env: {} }), /protected|configuration/);
  assert.equal(policy.bashDenial('cat ' + path.join(claudeDir, 'settings.json'), opts), null, 'reading is allowed');
});

test('a PowerShell backtick is an escape: a word is refused with the backticks taken out', () => {
  const { home, proj } = tmpHome();
  const opts = { home, cwd: proj, env: {} };
  assert.match(policy.bashDenial('cat ~/.aws/cr`edentials', opts), /credential/);
  assert.match(policy.bashDenial('Get-Content ~/.aws/cred`entials', opts), /credential/);
  assert.equal(policy.bashDenial('Get-Content ' + path.join(proj, 'src', 'app.js'), opts), null);
});

test('the configuration roots (~/.config and XDG_CONFIG_HOME) cannot be removed or moved, but can be listed', () => {
  const { home, proj } = tmpHome();
  const xdg = path.join(home, 'xdg-elsewhere');
  const opts = { home, cwd: proj, env: { XDG_CONFIG_HOME: xdg } };
  assert.match(policy.bashDenial('rm -rf ~/.config', opts), /protected|configuration/);
  assert.match(policy.bashDenial('mv ~/.config /tmp/x', opts), /protected|configuration/);
  assert.match(policy.bashDenial('rm -r ' + xdg, opts), /protected|configuration/);
  assert.equal(policy.bashDenial('ls ~/.config', opts), null, 'listing is allowed');
  assert.equal(policy.bashDenial('rm -rf ~/.config/somebody-else', opts), null, 'only the root is protected');
});

/* ------------------------------ globs on disk ------------------------------ */

test('a glob is checked against the files that exist now, and a name starting with .env is a .env file', () => {
  const { home, proj } = tmpHome();
  const opts = { home, cwd: proj, env: {} };
  fs.writeFileSync(path.join(proj, '.env.production'), 'PLAIN=1\n');
  // Not a .env prefix and not in the example list: only the disk match names it.
  assert.match(policy.bashDenial('cat .en?.production', opts), /holds plain-text|credential|\.env/);
  // Starts with .env: refused whatever it matches.
  assert.match(policy.bashDenial('cat .env.nothing*', opts), /credential|holds plain-text|\.env/);
  // Named credential files, by pattern.
  assert.match(policy.bashDenial('cat ~/.config/gcloud/app*', opts), /credential/);
  assert.equal(policy.bashDenial('cat ~/Documents/*.pdf', opts), null);
});

/* --------------------------- render destinations --------------------------- */

test('secrets_render_file never writes agent settings, and asks before a credential file', async () => {
  const { home, proj } = tmpHome();
  fs.writeFileSync(path.join(proj, '.gitignore'), '.claude/\n.aws/\n*.rc\n');
  fs.writeFileSync(path.join(proj, 'npmrc.tpl'), 'token=__ZN_NPM_TOKEN__\n');
  spawnSync('git', ['init', '-q'], { cwd: proj });
  let answer = false;
  const vault = createFakeVault({ confirmFile: async () => answer });
  await vault.setSecret('NPM_TOKEN', NPM, { mode: 'file' });
  const srv = createSecretsServer({ vault, engine: fakeEngine, cwd: proj, home });

  const settings = await call(srv, 'secrets_render_file', { template: 'npmrc.tpl', out: '.claude/settings.local.json' });
  assert.equal(settings.isError, true);
  assert.match(settings.data.message, /agent hook or plugin configuration/);
  assert.ok(!fs.existsSync(path.join(proj, '.claude', 'settings.local.json')));

  const cred = await call(srv, 'secrets_render_file', { template: 'npmrc.tpl', out: '.aws/credentials' });
  assert.equal(cred.isError, true, 'declined: nothing written');
  assert.match(cred.data.message, /credential file/);
  assert.ok(!fs.existsSync(path.join(proj, '.aws', 'credentials')));
  assert.equal(vault.fileConfirmations[0].reason, 'the file is a credential file');

  answer = true;
  const yes = await call(srv, 'secrets_render_file', { template: 'npmrc.tpl', out: '.aws/credentials' });
  assert.equal(yes.isError, false, JSON.stringify(yes.data));
  assert.equal(fs.readFileSync(path.join(proj, '.aws', 'credentials'), 'utf8'), 'token=' + NPM + '\n');
});

test('an approved overwrite of a file with other hard links is refused, and the other name is untouched', { skip: process.platform === 'win32' }, async () => {
  const { home, proj } = tmpHome();
  fs.writeFileSync(path.join(proj, '.gitignore'), '*.rc\n');
  fs.writeFileSync(path.join(proj, 'npmrc.tpl'), 'token=__ZN_NPM_TOKEN__\n');
  spawnSync('git', ['init', '-q'], { cwd: proj });
  const a = path.join(proj, 'a.rc');
  const b = path.join(proj, 'b.rc');
  fs.writeFileSync(a, 'mine\n');
  fs.linkSync(a, b);
  const vault = createFakeVault({ confirmFile: async () => true });
  await vault.setSecret('NPM_TOKEN', NPM, { mode: 'file' });
  const srv = createSecretsServer({ vault, engine: fakeEngine, cwd: proj, home });
  const r = await call(srv, 'secrets_render_file', { template: 'npmrc.tpl', out: 'a.rc' });
  assert.equal(r.isError, true);
  assert.match(r.data.message, /hard links/);
  assert.equal(fs.readFileSync(b, 'utf8'), 'mine\n');
});

test('agent guard: versioned npm, npx and pnpm/bun launches of zn-gate are still admin commands', () => {
  const adminCommands = [
    'npx -y zn-gate@1.6.0 unlock',
    'npx zn-gate@latest hooks uninstall',
    'pnpm dlx zn-gate@1.6.0 env shadow .env',
    'bunx zn-gate@1.6.0 secret approve X',
    'npm exec zn-gate@1 -- hooks uninstall',
    'npm exec zn-gate@1 -- unlock',
    'npm x zn-gate@1 -- unlock',
    'npx -y zn-gate@1.6.0-beta.1 secret set DB_PASSWORD',
    'zn-gate@1.6.0 unlock',
  ];
  for (const cmd of adminCommands) {
    assert.ok(policy.bashDenial(cmd), 'expected a denial for: ' + cmd);
  }
  // An ordinary zn-gate command is not an admin command.
  assert.equal(policy.bashDenial('npx -y zn-gate@1.6.0 status'), null);
});

/* 1.8.0 review: zn admin commands written with a Windows path or .cmd. */
test('agent guard: zn admin commands with a Windows path or .cmd are refused', () => {
  const adminCommands = [
    'C:\\Users\\u\\AppData\\Roaming\\npm\\zn.cmd secret reveal X',
    '.\\zn.cmd secret get X',
    'zn.cmd hooks uninstall',
    'zn env unshadow',
    'zn-gate.cmd pins approve --all',
    'C:\\npm\\zn.cmd hooks uninstall',
    'C:\\Users\\u\\AppData\\Roaming\\npm\\zn.cmd env unshadow .env',
    'C:\\Users\\u\\AppData\\Roaming\\npm\\zn-gate.cmd pins approve --all',
    '& "C:\\Program Files\\nodejs\\zn.ps1" unlock',
    'node C:\\npm\\node_modules\\zn-gate\\bin\\cli.js secret set A',
  ];
  for (const cmd of adminCommands) {
    assert.ok(policy.bashDenial(cmd), 'expected a denial for: ' + cmd);
  }
  assert.match(policy.bashDenial('zn-gate.cmd pins approve --all'), /pins approve/);
  assert.equal(policy.adminCommand('C:\\npm\\zn.cmd secret reveal X'), 'secret reveal');
  // Ordinary commands and other programs whose name ends in zn are not admin commands.
  assert.equal(policy.bashDenial('C:\\npm\\zn.cmd status'), null);
  assert.equal(policy.adminCommand('C:\\tools\\myzn.cmd unlock'), null);
});

/* 1.8.0 review: commands over 100 KB are refused before any parsing. */
test('a shell command over 100 KB is refused at once; one just under the limit gets the normal check', () => {
  const cap = policy.SHELL_SCAN_CAP;
  assert.equal(cap, 100 * 1024);
  const tooLong = 'echo ' + 'a'.repeat(cap + 1 - 5);
  assert.equal(tooLong.length, cap + 1);
  const start = process.hrtime.bigint();
  const deny = policy.bashDenial(tooLong);
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  assert.equal(deny, 'zn: this command is too long for zn to check (over 100 KB), so it was blocked. Next step: tell the user; do not resend it in parts.');
  assert.ok(ms < 50, 'took ' + ms + ' ms');
  // Exactly at the limit and just under it: the normal check runs.
  assert.equal(policy.bashDenial('echo ' + 'a'.repeat(cap - 5)), null);
  const head = 'cat ~/.aws/credentials ';
  const under = head + 'a'.repeat(cap - 1 - head.length);
  assert.equal(under.length, cap - 1);
  assert.match(policy.bashDenial(under), /credential/);
  // Normal commands are unchanged.
  assert.equal(policy.bashDenial('npm test'), null);
  assert.match(policy.bashDenial('cat ~/.aws/credentials'), /credential/);
});

test('a long command that repeats its words is checked quickly, and still blocks', () => {
  const t0 = process.hrtime.bigint();
  assert.equal(policy.bashDenial('echo ' + 'a '.repeat(40000)), null);
  assert.ok(Number(process.hrtime.bigint() - t0) / 1e6 < 1500, 'too slow');
  assert.ok(policy.bashDenial('cat ' + 'README.md '.repeat(5000) + '~/.aws/credentials'));
});

test('a patch sent as a shell command (Codex apply_patch) is refused with the file it writes, not a glob word', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-ap-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, '.env'), 'EXAMPLE_API_KEY=zn-test-fake-value-0000\n');
  const cmd = "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: .env\n@@\n+EXAMPLE_DEBUG=1\n*** End Patch\nPATCH";
  const msg = policy.bashDenial(cmd, { cwd: dir, home: dir });
  assert.ok(msg, 'still refused');
  assert.match(msg, /this patch was blocked because it writes to \.env, which zn treats as holding secrets/);
  assert.doesNotMatch(msg, /\*\*\*/);
  // An ordinary command that names a glob and a literal secret file names the literal one.
  const m2 = policy.bashDenial('cat *.txt .env', { cwd: dir, home: dir });
  assert.match(m2, /\.env/);
  // A glob alone is still refused as before.
  assert.ok(policy.bashDenial('cat .e*', { cwd: dir, home: dir }));
  // A patch to an ordinary file sent as a shell command is still refused (its *** lines read as file patterns),
  // with a message that says why and what to do instead.
  const m3 = policy.bashDenial("apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: notes.txt\n+hello\n*** End Patch\nPATCH", { cwd: dir, home: dir });
  assert.match(m3, /sent as a shell command, which zn cannot check file by file/);
  assert.match(m3, /use the apply_patch tool/);
  // The file name is shown without control characters and cut short; a too-long command keeps its own message.
  const long = 'd'.repeat(300) + '/\u001b[2J/.env';
  const m4 = policy.bashDenial("apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: " + long + "\n@@\n+X=1\n*** End Patch\nPATCH", { cwd: dir, home: dir });
  assert.ok(m4 && m4.length < 400, String(m4 && m4.length));
  assert.doesNotMatch(m4, /\u001b/);
  const huge = "apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: a.txt\n+" + 'x'.repeat(policy.SHELL_SCAN_CAP + 10) + "\n*** End Patch\nPATCH";
  assert.doesNotMatch(policy.bashDenial(huge, { cwd: dir, home: dir }), /sent as a shell command/);
});

test('a long patch sent as a shell command is refused quickly, naming a secret file among its first files', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-ap-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, '.env'), 'EXAMPLE_API_KEY=zn-test-fake-value-0000\n');
  let body = '';
  for (let i = 0; body.length < 90 * 1024; i++) body += '*** Add File: src/part' + i + '/file' + i + '.txt\n+x\n';
  const big = "apply_patch <<'PATCH'\n*** Begin Patch\n" + body + "*** End Patch\nPATCH";
  assert.ok(big.length < policy.SHELL_SCAN_CAP);
  const t0 = process.hrtime.bigint();
  const m = policy.bashDenial(big, { cwd: dir, home: dir });
  assert.ok(Number(process.hrtime.bigint() - t0) / 1e6 < 1500, 'too slow');
  assert.match(m, /sent as a shell command, which zn cannot check file by file/);
  // A secret file among the first files is still named.
  const named = policy.bashDenial("apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: .env\n@@\n+X=1\n" + body + "*** End Patch\nPATCH", { cwd: dir, home: dir });
  assert.match(named, /writes to \.env/);
});

test('after a glob word, a command with many more words is still refused', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-gl-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, '.env'), 'EXAMPLE_API_KEY=zn-test-fake-value-0000\n');
  const filler = Array.from({ length: 40 }, (_, i) => 'notes' + i + '.txt').join(' ');
  // The literal file comes after more words than zn resolves once a glob has refused the command.
  assert.ok(policy.bashDenial('cat .e* ' + filler + ' .env', { cwd: dir, home: dir }));
  assert.ok(policy.bashDenial('cat .e* ' + filler + ' ~/.zn/vault', { cwd: dir, home: dir }));
  // Within the first words the literal file is still the one named.
  assert.match(policy.bashDenial('cat .e* notes.txt .env', { cwd: dir, home: dir }), /\.env/);
});

test('a glob that names a .env file in a subfolder is refused, as the plain path is', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-globenv-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(dir, 'app1', 'inner'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'app1', 'inner', '.env'), 'EXAMPLE_API_KEY=zn-test-fake-value-0000\n');
  fs.writeFileSync(path.join(dir, 'app1', 'inner', 'notes.txt'), 'hello\n');
  const o = { cwd: dir, home: dir };
  assert.ok(policy.bashDenial('cat app1/inner/.env', o), 'plain path');
  for (const cmd of ['cat app*/inner/.env', 'cat app1/*/.env', 'cat */inner/.env', 'cat a?p1/inner/.env', 'cat {app1,app2}/inner/.env', 'head -n 1 ./app1/*/.env']) {
    assert.ok(policy.bashDenial(cmd, o), cmd);
  }
  // An ordinary file reached the same way is still allowed.
  assert.equal(policy.bashDenial('cat app*/inner/notes.txt', o), null);
  assert.equal(policy.classifyWord('app*/inner/.env', o).kind, 'credential');
});

test('a .env file reached after a cd, through a path built at run time or from interpreter code is refused', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-cdenv-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(dir, 'app1', 'inner'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'app1', 'inner', '.env'), 'EXAMPLE_API_KEY=zn-test-fake-value-0000\n');
  fs.mkdirSync(path.join(dir, 'svc'));
  fs.writeFileSync(path.join(dir, 'svc', '.env'), 'EXAMPLE_API_KEY=__ZN_EXAMPLE_API_KEY__\n');
  const o = { cwd: dir, home: dir, env: {} };
  for (const cmd of [
    'cd app1/inner && cat .env',
    'cd app1 && cd inner && cat .env',
    'cd app1; cat inner/.env',
    'pushd app1/inner && cat .env',
    '(cd app1/inner && cat .env)',
    'cd "app1/inner" && head -n 1 .env',
    'cd $PROJ && cat .env',
    'cd - && cat .env',
    'cat $(echo app1)/inner/.env',
    'cat "$(echo app1)/inner/.env"',
    'D=app1/inner; cat $D/.env',
    'python3 -c "print(open(\'app1/inner/.env\').read())"',
    'node -e "console.log(require(\'fs\').readFileSync(\'app1/inner/.env\', \'utf8\'))"',
    'bash -c "cat app1/inner/.env"',
  ]) {
    assert.ok(policy.bashDenial(cmd, o), cmd);
  }
  for (const cmd of [
    'cd svc && cat .env',
    'cd app1 && npm test',
    'cd app1/inner && echo EXAMPLE_FLAG=1 >> .env',
    'cd app1/inner && cat .env.example',
    'cd /nonexistent && ls',
    'python3 -c "print(1)"',
    'cat .env',
  ]) {
    assert.equal(policy.bashDenial(cmd, o), null, cmd);
  }
});

test('a .env file named with bash $-quoting, a numbered input redirection or as name=value is refused', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-quoting-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, '.env'), 'EXAMPLE_API_KEY=zn-test-fake-value-0000\n');
  const o = { cwd: dir, home: dir, env: {} };
  for (const cmd of ["cat $'.env'", "cat $'\\x2eenv'", "cat $'\\56env'", "cat $'\\u002eenv'", "cat $'.e'nv", 'cat 0<.env', 'cat 3< .env', 'dd if=.env', 'ENV_FILE=.env docker compose up',
    "cat $'.env\\x00junk'", "cat $'.env\\0'", "cat $'.env\\c@x'", "cat $'.env\\u0000'", "cat $'.e\\0zz'nv",
    'cat $".env"', 'cat <>.env', 'cat 0<>.env', 'exec {fd}<.env; cat <&$fd']) {
    assert.ok(policy.bashDenial(cmd, o), cmd);
  }
  for (const cmd of ["echo $'hello\\n'", "printf $'%s\\t%s\\n' a b", 'dd if=/dev/zero of=out.bin count=1', 'make DEBUG=1']) {
    assert.equal(policy.bashDenial(cmd, o), null, cmd);
  }
  assert.equal(policy._decodeAnsiC("a $'\\x41\\102\\'c' z"), "a 'AB'\\''c' z");
});

test('after a cd, only the folders the command can reach are checked, also when the current .env is shadowed', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-cdenv2-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(dir, 'app1', 'inner'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'app', 'app'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'a', 'b'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.env'), 'EXAMPLE_API_KEY=__ZN_EXAMPLE_API_KEY__\n');
  fs.writeFileSync(path.join(dir, 'app1', 'inner', '.env'), 'EXAMPLE_API_KEY=zn-test-fake-value-0000\n');
  // A folder the command never reaches (app/app) holds values.
  fs.writeFileSync(path.join(dir, 'app', 'app', '.env'), 'EXAMPLE_API_KEY=zn-test-fake-value-0000\n');
  const o = { cwd: dir, home: dir, env: { PWD: dir } };
  for (const cmd of [
    'cd app1/inner && cat .env',
    'cd app1/inner && cat $PWD/.env',
    '{ cd app1/inner; cat .env; }',
    'if cd app1/inner; then cat .env; fi',
    'bash -c "cd app1/inner && cat .env"',
    'cd $PROJ && cat .env',
  ]) {
    assert.ok(policy.bashDenial(cmd, o), cmd);
  }
  assert.match(policy.bashDenial('cd app1/inner && cat .env', o), /changes to app1\/inner first/);
  for (const cmd of [
    'cat .env',
    'cd app && cat .env',
    'cd a && cd b && cat d1/.env',
    'echo $(date) && cat .env',
    'cd app1 && npm test',
  ]) {
    assert.equal(policy.bashDenial(cmd, o), null, cmd);
  }
});

test('a .env or credential file read from the git repository is refused', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-gitobj-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const o = { cwd: dir, home: dir, env: {} };
  for (const cmd of ['git show HEAD:.env', 'git show :.env', 'git show :0:.env', 'git cat-file -p HEAD:.env', 'git -C app1 show HEAD:.env',
    'git show HEAD~1:app1/inner/.env', 'git show main:./.env.local', 'git show HEAD:.aws/credentials', 'git cat-file blob v1.0:config/.env']) {
    assert.ok(policy.bashDenial(cmd, o), cmd);
  }
  for (const cmd of ['git show HEAD:README.md', 'git show HEAD:.env.example', 'git log --oneline', 'git show HEAD',
    'git push origin main:main', 'git fetch https://example.com/repo.git', 'git diff HEAD:src/a.js HEAD~1:src/a.js']) {
    assert.equal(policy.bashDenial(cmd, o), null, cmd);
  }
});
