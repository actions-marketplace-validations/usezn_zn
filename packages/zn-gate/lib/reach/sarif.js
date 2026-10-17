'use strict';
/**
 * SARIF 2.1.0 for `zn-gate reach --sarif`. zn audit findings keep their ZNA
 * rules; the findings reach adds have ZNR rules. Info findings are left out:
 * they say that something is already protected.
 */

const crypto = require('crypto');

const DOCS_URL = 'https://github.com/usezn/zn/blob/main/docs/audit.md';
const LEVEL = { high: 'error', medium: 'warning', low: 'note' };
const SECURITY_SEVERITY = { high: '8.0', medium: '5.0', low: '3.0' };

const REACH_RULES = {
  'agent': { id: 'ZNR001', name: 'AgentNotProtected', title: 'Coding agent not protected by zn', help: 'A coding agent on this machine runs without zn, so it can read any file and run any command you allow.' },
  'dotenv': { id: 'ZNR002', name: 'DotenvSecretsReachable', title: '.env file with secrets an agent can read', help: 'A .env file in the folder holds secret values that a coding agent without zn can read.' },
  'credential-files': { id: 'ZNR003', name: 'CredentialFilesReachable', title: 'Credential files an agent can read', help: 'Credential files in the home folder (cloud, SSH, registry) can be read by a coding agent without zn.' },
  'environment': { id: 'ZNR004', name: 'SecretEnvironmentVariables', title: 'Environment variables with secrets', help: 'Environment variables that hold secrets are passed to an agent started from this terminal.' },
};

function encodePath(p) {
  return String(p).split('/').map((seg) => encodeURIComponent(seg)).join('/');
}

function ruleKey(f) {
  if (f.kind === 'audit') return f.id;
  return f.section === 'agents' ? 'agent' : f.kind;
}

function toSarif(r, meta = {}) {
  const { RULES, BY_ID } = require('../audit/rules');
  const used = [];
  const index = new Map();
  const ruleOf = (key) => {
    if (index.has(key)) return index.get(key);
    let rule;
    const own = REACH_RULES[key];
    if (own) {
      rule = { id: own.id, name: own.name, shortDescription: { text: own.title }, fullDescription: { text: own.help }, help: { text: own.help } };
    } else {
      const a = BY_ID[key] || RULES.find((x) => x.id === key);
      if (!a) return null;
      rule = {
        id: a.id,
        name: a.name.replace(/(^|-)([a-z])/g, (m, d, c) => c.toUpperCase()),
        shortDescription: { text: a.title },
        fullDescription: { text: a.help },
        help: { text: a.help + '\n\nFix: ' + a.fix },
        helpUri: DOCS_URL + '#rules',
      };
    }
    used.push(rule);
    index.set(key, used.length - 1);
    return used.length - 1;
  };
  const ordinals = new Map();
  const results = [];
  for (const f of r.findings) {
    if (!LEVEL[f.severity]) continue;
    const ri = ruleOf(ruleKey(f));
    if (ri === null) continue;
    const base = [used[ri].id, f.file || '', f.kind === 'audit' ? f.title : ''].join('\u0000');
    const n = (ordinals.get(base) || 0) + 1;
    ordinals.set(base, n);
    const res = {
      ruleId: used[ri].id,
      ruleIndex: ri,
      level: LEVEL[f.severity],
      message: { text: f.title + (f.detail ? ': ' + f.detail : '') + (f.fix ? ' Fix: ' + f.fix : '') },
      partialFingerprints: { 'znReach/v1': crypto.createHash('sha256').update(base + '\u0000' + n).digest('hex') },
      properties: { severity: f.severity, 'security-severity': SECURITY_SEVERITY[f.severity], section: f.section },
    };
    // Only findings about a file have a location; agents and environment variables belong to the machine.
    if (f.file) {
      const home = String(f.file).startsWith('~/');
      res.locations = [{ physicalLocation: {
        artifactLocation: { uri: encodePath(home ? f.file.slice(2) : f.file), uriBaseId: home ? 'HOME' : '%SRCROOT%' },
        region: { startLine: f.line || 1 },
      } }];
    }
    results.push(res);
  }
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'zn-gate reach', informationUri: DOCS_URL, version: meta.toolVersion, semanticVersion: meta.toolVersion, rules: used } },
      originalUriBaseIds: {
        '%SRCROOT%': { description: { text: 'The folder that was checked.' } },
        HOME: { description: { text: 'The user home folder.' } },
      },
      columnKind: 'utf16CodeUnits',
      results,
    }],
  }, null, 2) + '\n';
}

module.exports = { toSarif, REACH_RULES };
