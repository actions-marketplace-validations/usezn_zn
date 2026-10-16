import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseFragment, buildSection, assemble, checkPullRequest, needsFragment } from './changelog.mjs';

const CHANGELOG = `# Changelog

## [Unreleased]

### Fixed
- An old fix still under Unreleased.

## [1.0.0] - 2026-01-01

### Added
- First release.
`;

function repo(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-changelog-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const g = (...a) => execFileSync('git', a, { cwd: dir, encoding: 'utf8' });
  g('init', '-q', '-b', 'next'); g('config', 'user.email', 't@example.com'); g('config', 'user.name', 't');
  fs.writeFileSync(path.join(dir, 'CHANGELOG.md'), CHANGELOG);
  fs.mkdirSync(path.join(dir, 'packages', 'zn-gate', 'lib'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'packages', 'zn-gate', 'lib', 'a.js'), '1\n');
  g('add', '-A'); g('commit', '-q', '-m', 'base');
  g('checkout', '-q', '-b', 'feature');
  return { dir, g };
}

test('a fragment holds only section headings and bullets', () => {
  const ok = parseFragment('### Fixed\n- One.\n  continued.\n\n### Added\n- Two.\n');
  assert.deepEqual(ok.errors, []);
  assert.deepEqual(ok.sections.Fixed, ['- One.\n  continued.']);
  assert.match(parseFragment('### Fixes\n- x\n').errors[0], /unknown section "Fixes"/);
  assert.match(parseFragment('- x\n').errors[0], /before any/);
  assert.match(parseFragment('### Added\nplain text\n').errors[0], /only/);
  assert.match(parseFragment('### Added\n').errors[0], /no bullets/);
});

test('the release section merges [Unreleased] and the fragments in a fixed section order', () => {
  const s = buildSection('### Fixed\n- Old fix.', [parseFragment('### Fixed\n- New fix.\n### Added\n- New thing.\n')]);
  assert.equal(s, '### Added\n- New thing.\n\n### Fixed\n- Old fix.\n- New fix.\n');
});

test('assemble writes the version, empties [Unreleased] and deletes the fragments', (t) => {
  const { dir } = repo(t);
  fs.mkdirSync(path.join(dir, 'changelog.d'));
  fs.writeFileSync(path.join(dir, 'changelog.d', 'README.md'), 'how to\n');
  fs.writeFileSync(path.join(dir, 'changelog.d', 'feat-x.md'), '### Added\n- Feature X.\n');
  assemble(dir, '1.1.0', '2026-02-01');
  const out = fs.readFileSync(path.join(dir, 'CHANGELOG.md'), 'utf8');
  assert.match(out, /## \[Unreleased\]\n\n## \[1\.1\.0\] - 2026-02-01\n\n### Added\n- Feature X\.\n\n### Fixed\n- An old fix still under Unreleased\.\n\n## \[1\.0\.0\]/);
  assert.equal(fs.existsSync(path.join(dir, 'changelog.d', 'feat-x.md')), false);
  assert.equal(fs.existsSync(path.join(dir, 'changelog.d', 'README.md')), true);
  assert.throws(() => assemble(dir, '1.1.0', '2026-02-01'), /already has a section/);
});

test('a pull request that changes shipped code needs a fragment; docs and tests do not', (t) => {
  const { dir, g } = repo(t);
  fs.writeFileSync(path.join(dir, 'packages', 'zn-gate', 'lib', 'a.js'), '2\n');
  g('commit', '-qam', 'code');
  assert.match(checkPullRequest(dir, 'next').errors.join(), /adds no changelog\.d\/ fragment/);
  assert.deepEqual(checkPullRequest(dir, 'next', { skip: true }).errors, []);
  fs.mkdirSync(path.join(dir, 'changelog.d'));
  fs.writeFileSync(path.join(dir, 'changelog.d', 'feature.md'), '### Fixed\n- A fix.\n');
  g('add', '-A'); g('commit', '-qm', 'fragment');
  assert.deepEqual(checkPullRequest(dir, 'next').errors, []);
  assert.equal(needsFragment('docs/check.md'), false);
  assert.equal(needsFragment('packages/zn-gate/test/a.test.js'), false);
  assert.equal(needsFragment('packages/zn-gate/README.md'), false);
  assert.equal(needsFragment('packages/zn-gate-py/src/zn_gate/cli.py'), true);
});

test('editing [Unreleased] directly is refused, except on a release branch; a bad fragment fails', (t) => {
  const { dir, g } = repo(t);
  fs.writeFileSync(path.join(dir, 'CHANGELOG.md'), CHANGELOG.replace('- An old fix still under Unreleased.', '- An old fix still under Unreleased.\n- Added by hand.'));
  g('commit', '-qam', 'edit');
  assert.match(checkPullRequest(dir, 'next').errors.join(), /\[Unreleased\] was edited/);
  assert.deepEqual(checkPullRequest(dir, 'next', { release: true }).errors, []);
  g('checkout', '-q', 'next'); g('checkout', '-q', '-b', 'bad');
  fs.mkdirSync(path.join(dir, 'changelog.d'));
  fs.writeFileSync(path.join(dir, 'changelog.d', 'bad.md'), 'just text\n');
  g('add', '-A'); g('commit', '-qm', 'bad');
  assert.match(checkPullRequest(dir, 'next').errors.join(), /only "### <Section>" headings/);
});
