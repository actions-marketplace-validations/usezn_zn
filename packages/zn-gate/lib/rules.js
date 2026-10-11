'use strict';

const fs = require('fs');
const path = require('path');

/**
 * zn deterministic rules engine - SINGLE SOURCE OF TRUTH.
 * RULES_VERSION: 2026-10-11.1
 */

const RULES_VERSION = '2026-10-11.1';

const INJECTION_RULES = [
  // The verb alone is not enough: "ignore the noise in the logs" is ordinary
  // prose. An attack names what to ignore (previous/prior/above instructions).
  { id: 'pi:ignore_previous', pattern: /ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|existing|system)\s+(?:instructions?|prompts?|rules|guidelines|context)|ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above)\b/i, description: 'Override prior instructions' },
  { id: 'pi:disregard', pattern: /disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|existing|system)\s+(?:instructions?|prompts?|rules|guidelines|context)|disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above)\b/i, description: 'Disregard instructions' },
  { id: 'pi:forget', pattern: /forget\s+(about\s+)?(everything|all|your)/i, description: 'Forget-context attack' },
  { id: 'pi:identity_override', pattern: /you\s+are\s+now/i, description: 'Identity override' },
  { id: 'pi:new_instructions', pattern: /new\s+instructions?:/i, description: 'Instruction replacement' },
  { id: 'pi:system_tag', pattern: /(?:^|[\r\n"'`\[<])\s*system\s*:\s*|<[\s/]*system\b[^>]*>/i, description: 'Fake system tag' },
  { id: 'pi:system_bracket', pattern: /\[system\]/i, description: 'Bracketed system tag' },
  { id: 'pi:act_as', pattern: /act\s+as\s+(if|a)/i, description: 'Role hijack (act as)' },
  { id: 'pi:pretend', pattern: /pretend\s+(you|to\s+be)/i, description: 'Role hijack (pretend)' },
  { id: 'pi:roleplay', pattern: /roleplay\s+as/i, description: 'Role hijack (roleplay)' },
  { id: 'pi:jailbreak', pattern: /\bjailbreak\b/i, description: 'Explicit jailbreak term' },
  { id: 'pi:bypass', pattern: /bypass\s+(your|the|all)/i, description: 'Guardrail bypass attempt' },
  { id: 'pi:override', pattern: /\boverride\s+(?:all\s+|your\s+|the\s+)?(?:system|policy|safety|rules|instructions|guidelines|restrictions)\b|\bsystem\s+override\s*:/i, description: 'Policy override attempt' },
  { id: 'pi:template_boundary', pattern: /\[INST\]|\[\/INST\]|<<<SYS>>>|<\/<<SYS>>>|<\|im_start\|>|<\|im_end\|>/i, description: 'Chat template boundary injection' },
  { id: 'pi:multi_es', pattern: /ignora\s+(todas\s+las\s+)?(instrucciones|anteriores|previas)|olvida\s+(todo|las\s+instrucciones)|act[uú]a\s+como|ahora\s+eres/iu, description: 'Multilingual prompt injection (Spanish)' },
  { id: 'pi:multi_fr', pattern: /ignore[rz]?\s+(toutes\s+les\s+)?instructions|oublie[rz]?\s+tout|agis\s+comme|tu\s+es\s+maintenant/iu, description: 'Multilingual prompt injection (French)' },
  { id: 'pi:multi_de', pattern: /ignoriere\s+(alle\s+)?(anweisungen|instruktionen)|vergiss\s+(alles|jede)|du\s+bist\s+jetzt|handle\s+als/iu, description: 'Multilingual prompt injection (German)' },
  { id: 'pi:multi_ru', pattern: /забудь\s+[^\n]{0,80}?(все|инструкции)|игнорируй\s+[^\n]{0,80}?(все|предыдущие)|действуй\s+как|ты\s+теперь|найди\s+пароли/iu, description: 'Multilingual prompt injection (Russian)' },
  { id: 'pi:multi_zh', pattern: /忽略[^\n]{0,80}?(指示|指令|提示)|忘记[^\n]{0,80}?(指示|指令|一切)|你现在是|初始提示词/u, description: 'Multilingual prompt injection (Chinese)' },
];

// Hidden-element detection in two linear passes: find the first opening tag
// whose attributes hide it, then search once for a payload keyword after it.
// A single regex with a lazy `[\s\S]*?` tail re-scans the rest of the input
// from every candidate tag, which is quadratic on adversarial markup.
const OPEN_TAG_RE = /<[a-z0-9]+\b([^>]{0,2000})>/gi;
const HIDDEN_ATTR_RE = /\b(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px)?|color\s*:\s*transparent|text-indent\s*:\s*-[0-9]{3,}px|hidden\b)/i;
const HIDDEN_PAYLOAD_RE = /ignore|system|instruction|prompt|bypass|override|exfil|leak/gi;

function testHiddenTag(text) {
  const tagRe = new RegExp(OPEN_TAG_RE.source, OPEN_TAG_RE.flags);
  let m;
  while ((m = tagRe.exec(text)) !== null) {
    if (HIDDEN_ATTR_RE.test(m[1])) {
      const payloadRe = new RegExp(HIDDEN_PAYLOAD_RE.source, HIDDEN_PAYLOAD_RE.flags);
      payloadRe.lastIndex = tagRe.lastIndex;
      return payloadRe.test(text);
    }
  }
  return false;
}

const INDIRECT_INJECTION_RULES = [
  {
    id: 'indirect:html_comment',
    pattern: /<!--\s*(?:system|instruction|prompt|override|command)\s*:/i,
    description: 'Hidden instruction in HTML comment',
  },
  {
    id: 'indirect:hidden_tag',
    // Kept for reference and for callers that read `.pattern`; matching goes
    // through test() below, which runs in linear time.
    pattern: /<[a-z0-9]+\b[^>]{0,2000}\b(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px)?|color\s*:\s*transparent|text-indent\s*:\s*-[0-9]{3,}px|hidden\b)[^>]{0,2000}>[\s\S]*?(?:ignore|system|instruction|prompt|bypass|override|exfil|leak)/i,
    test: testHiddenTag,
    description: 'Hidden DOM element with injection payload',
  },
];

const EVASION_RULES = [
  {
    id: 'evasion:bidi_override',
    pattern: /[\u202A-\u202E\u2066-\u2069]/,
    description: 'Unicode bidirectional override (Trojan Source evasion attempt)',
  },
];

const EXFIL_VERB_SOURCE = '\\b(give|reveal|send|show|print|expose|leak|paste|dump|read|open|cat|fetch|extract|steal)\\b';
const CRED_OBJECT_SOURCE =
  '\\b(passwords?|api[_ -]?keys?|secrets?|credentials?|tokens?|ssh[ _-]?keys?|private[ _-]?keys?|aws_secret[a-z0-9_]*|aws_access[a-z0-9_]*)\\b|(?:^|\\s|[\'"\`])\\.env(?:\\.[a-z0-9]+)?\\b';

const EXFIL_RULES = [
  {
    id: 'exfil:credentials',
    compound: [new RegExp(EXFIL_VERB_SOURCE, 'i'), new RegExp(CRED_OBJECT_SOURCE, 'i')],
    description: 'Imperative verb requesting credentials/secrets',
  },
];

const SENSITIVE_PATH_RULES = [
  {
    id: 'path:sensitive_file',
    pattern: /(?:^|[\s"'`(\[])(?:~|\/home\/[^\s/]+|\/root)?\/?\.(?:ssh\/(?:id_rsa|id_ed25519|authorized_keys)|aws\/credentials|env(?:\.[a-z0-9]+)?)\b|\/etc\/(?:shadow|passwd)\b/i,
    description: 'Targeting sensitive system credentials or environment file',
  },
];

const MARKDOWN_EXFIL_RULES = [
  {
    id: 'exfil:markdown_image',
    pattern: /!\[[^\]]{0,500}\]\(https?:\/\/[^\s\)]{1,2048}?[\?&](?:key|token|pass|secret|cred|data|val|leak|exfil)=[^)]*\)/i,
    description: 'Covert exfiltration via markdown image URL parameter',
  },
];

// Local custom rules cache (.znrules or zn.config.json)
let customConfig = null;
let lastConfigCheck = 0;

function loadCustomConfig(forceReload = false) {
  const now = Date.now();
  if (!forceReload && customConfig !== null && now - lastConfigCheck < 5000) {
    return customConfig;
  }
  lastConfigCheck = now;
  customConfig = { bannedPatterns: [], forbiddenPaths: [] };

  const candidates = [
    path.join(process.cwd(), '.znrules'),
    path.join(process.cwd(), 'zn.config.json'),
  ];

  for (const file of candidates) {
    if (fs.existsSync(file)) {
      try {
        if (file.endsWith('.json')) {
          const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
          if (Array.isArray(parsed.bannedPatterns)) {
            customConfig.bannedPatterns = parsed.bannedPatterns.map((p) => new RegExp(p, 'i'));
          }
          if (Array.isArray(parsed.forbiddenPaths)) {
            customConfig.forbiddenPaths = parsed.forbiddenPaths;
          }
        } else {
          const lines = fs.readFileSync(file, 'utf8').split('\n');
          for (let line of lines) {
            line = line.trim();
            if (!line || line.startsWith('#')) continue;
            // `secret:` lines feed the scrubber's exact-value layer; they are
            // values, not patterns, and must never be compiled as regexes.
            if (line.startsWith('secret:')) continue;
            if (line.startsWith('path:')) {
              customConfig.forbiddenPaths.push(line.slice(5).trim());
            } else {
              customConfig.bannedPatterns.push(new RegExp(line, 'i'));
            }
          }
        }
      } catch (err) {
        // Silently ignore malformed custom configs in production
      }
      break;
    }
  }
  return customConfig;
}

const HOMOGLYPH_MAP = {
  '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
  '\u0456': 'i', '\u0455': 's', '\u0443': 'y', '\u0445': 'x',
  '\u0410': 'A', '\u0415': 'E', '\u041e': 'O', '\u0420': 'P', '\u0421': 'C',
};
const ZERO_WIDTH_RE = /[\u200B-\u200D\uFEFF\u00AD]/g;
const ANSI_ESCAPE_RE = /\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07\x1b]*\x07/g;
const B64_EXEC_RE = /(?:echo|printf)\s+([A-Za-z0-9+/=]{16,})\s*\|\s*(?:base64\s+-(?:d|-decode)|openssl)/i;

// Maximal whitespace runs; only runs that contain a line break are joined.
// A pattern anchored on the line break (such as /[^\S\r\n]*[\r\n]/) would
// rescan a long run of spaces from every position.
const WHITESPACE_RUN_RE = /\s+/g;
const LINE_BREAK_RE = /[\r\n]/;
const JOIN_LEFT_RE = /[\p{L}\p{N}_<|/.-]/u;
const JOIN_RIGHT_RE = /[\p{L}\p{N}_>|/.-]/u;

// Removes /* ... */ comments in one pass. An unterminated "/*" ends the
// search: no later comment can be closed either.
function stripCComments(str) {
  let start = str.indexOf('/*');
  if (start === -1) return str;
  let out = '';
  let from = 0;
  while (start !== -1) {
    const end = str.indexOf('*/', start + 2);
    if (end === -1) break;
    out += str.slice(from, start);
    from = end + 2;
    start = str.indexOf('/*', from);
  }
  return out + str.slice(from);
}

function normalizeInput(str) {
  if (typeof str !== 'string') return { normalized: '', stripped: '' };
  // 1. Strip zero-width evasion characters
  let stripped = str.replace(ZERO_WIDTH_RE, '');
  // 2. Strip ANSI escape sequences
  stripped = stripped.replace(ANSI_ESCAPE_RE, '');
  // 3. Strip inline C-style comments (e.g. sys/*safe*/tem -> system)
  stripped = stripCComments(stripped);
  // 4. Rejoin words and tokens split across newlines (e.g. sys\ntem -> system, /l\neak -> /leak, Cyrillic & Chinese).
  //    Linear: only the character on each side of a newline run is inspected.
  if (LINE_BREAK_RE.test(stripped)) {
    stripped = stripped.replace(WHITESPACE_RUN_RE, (run, offset, whole) => {
      if (!LINE_BREAK_RE.test(run)) return run;
      const left = offset > 0 ? whole[offset - 1] : '';
      const right = whole[offset + run.length] || '';
      return left && right && JOIN_LEFT_RE.test(left) && JOIN_RIGHT_RE.test(right) ? '' : run;
    });
  }
  // 5. Normalize homoglyphs (Cyrillic to Latin for English hijack detection)
  let normalized = stripped.replace(/[\u0410-\u0456]/g, (m) => HOMOGLYPH_MAP[m] || m);
  return { normalized, stripped };
}

// Inputs longer than MAX_SCAN_CHARS are analysed as head + tail; the result
// then carries `truncated: true`.
const MAX_SCAN_CHARS = 256 * 1024;
const SCAN_HEAD_CHARS = 192 * 1024;
// One character is reserved for the separator, so the window fits the limit.
const SCAN_TAIL_CHARS = MAX_SCAN_CHARS - SCAN_HEAD_CHARS - 1;

function evaluateUncached(input, options = {}) {
  if (typeof input !== 'string') {
    return { verdict: 'allow', confidence: 1.0, rule: 'none', reason: null, engine: 'oss-local', rules_version: RULES_VERSION };
  }
  if (input.length > MAX_SCAN_CHARS) {
    // NUL is neither whitespace nor a word character, so normalization cannot
    // join the end of the head and the start of the tail into a new token.
    const window = input.slice(0, SCAN_HEAD_CHARS) + '\u0000' + input.slice(-SCAN_TAIL_CHARS);
    return { ...evaluateUncached(window, options), truncated: true };
  }

  // Pre-normalization passes: stripped (preserves non-Latin) and normalized (maps homoglyphs)
  const { normalized, stripped } = normalizeInput(input);

  // Check Base64 payload smuggling
  const b64Match = normalized.match(B64_EXEC_RE) || stripped.match(B64_EXEC_RE);
  if (b64Match && b64Match[1]) {
    try {
      const decoded = Buffer.from(b64Match[1], 'base64').toString('utf8');
      const innerRes = evaluate(decoded, options);
      if (innerRes.verdict === 'block') {
        return {
          ...innerRes,
          reason: `Smuggled Base64 execution: ${innerRes.reason || innerRes.rule}`,
          rule: 'evasion:base64_smuggling',
        };
      }
    } catch (e) {
      // ignore invalid base64
    }
  }

  // Check against normalized, stripped, and raw input
  const targets = Array.from(new Set([normalized, stripped, input]));

  for (const text of targets) {
    // 0. Evasion Rules (BiDi Trojan Source)
    for (const rule of EVASION_RULES) {
      if (rule.pattern.test(text)) {
        return { verdict: 'block', confidence: 0.99, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }

    // 1. Covert Markdown Image Exfiltration
    for (const rule of MARKDOWN_EXFIL_RULES) {
      if (rule.pattern.test(text)) {
        return { verdict: 'block', confidence: 0.98, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }

    // 2. Sensitive Path Traversal / Credential File Access
    for (const rule of SENSITIVE_PATH_RULES) {
      if (rule.pattern.test(text)) {
        return { verdict: 'block', confidence: 0.92, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }

    // 3. Indirect Injection Rules (HTML comments / hidden elements)
    for (const rule of INDIRECT_INJECTION_RULES) {
      if (rule.test ? rule.test(text) : rule.pattern.test(text)) {
        return { verdict: 'block', confidence: 0.95, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }

    // 4. Standard Prompt Injection Rules
    for (const rule of INJECTION_RULES) {
      if (rule.pattern.test(text)) {
        return { verdict: 'block', confidence: 0.95, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }

    // 5. Exfiltration Rules
    for (const rule of EXFIL_RULES) {
      if (rule.compound.every((re) => re.test(text))) {
        return { verdict: 'block', confidence: 0.9, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }
  }

  // 6. Project-specific Custom Rules (.znrules / zn.config.json)
  const cfg = loadCustomConfig();
  for (const pat of cfg.bannedPatterns) {
    if (pat.test(input)) {
      return { verdict: 'block', confidence: 1.0, reason: `Matches custom repository rule: ${pat.source}`, rule: 'custom:banned_pattern', engine: 'oss-local', rules_version: RULES_VERSION };
    }
  }
  for (const fpath of cfg.forbiddenPaths) {
    if (input.includes(fpath)) {
      return { verdict: 'block', confidence: 1.0, reason: `Matches custom repository forbidden path: ${fpath}`, rule: 'custom:forbidden_path', engine: 'oss-local', rules_version: RULES_VERSION };
    }
  }

  return { verdict: 'allow', confidence: 0.99, rule: 'none', reason: null, engine: 'oss-local', rules_version: RULES_VERSION };
}

// -------------------------------------------------------------------------
// DLP & Secret Masking Rules
// -------------------------------------------------------------------------
const SECRET_PATTERNS = [
  { id: 'secret:private_key', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: '[REDACTED_PRIVATE_KEY]' },
  { id: 'secret:anthropic_key', pattern: /\b(sk-ant-[A-Za-z0-9_-]{30,})\b/g, replacement: '[REDACTED_ANTHROPIC_KEY]' },
  { id: 'secret:openai_key', pattern: /\b(sk-(?!ant-)(?:proj-|svcacct-|none-)?[A-Za-z0-9_-]{28,})\b/g, replacement: '[REDACTED_OPENAI_KEY]' },
  { id: 'secret:aws_access_key', pattern: /\b(AKIA[0-9A-Z]{16})\b/g, replacement: '[REDACTED_AWS_KEY]' },
  { id: 'secret:aws_secret_key', pattern: /(aws_secret_access_key|aws_secret|aws_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, replacement: "$1='[REDACTED_AWS_SECRET]'" },
  { id: 'secret:github_token', pattern: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,40}|github_pat_[A-Za-z0-9_]{82})\b/g, replacement: '[REDACTED_GITHUB_TOKEN]' },
  { id: 'secret:db_url_password', pattern: /((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s\/]+:)([^@\s\/]+)(@)/gi, replacement: '$1[REDACTED_DB_PASSWORD]$3' },
  // The lookahead + backreference pairs act as atomic groups, so a long run of
  // "-eyJ" cannot make the engine retry every split point. Only used when the
  // text contains ".eyJ" (see redactSecrets).
  { id: 'secret:jwt_token', pattern: /\b(eyJ(?=([A-Za-z0-9_=-]{10,512}))\2\.eyJ(?=([A-Za-z0-9_=-]{10,8192}))\3\.[A-Za-z0-9_.+/=-]{10,4096})\b/g, replacement: '[REDACTED_JWT]', requires: '.eyJ' },
  { id: 'secret:env_credential', pattern: /\b((?:AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|AUTH_TOKEN|PRIVATE_KEY|DATABASE_PASSWORD)\s*[:=]\s*['"]?)([^\s'"]{12,})(['"]?)/gi, replacement: '$1[REDACTED_SECRET]$3' },
];

function redactSecrets(text) {
  if (typeof text !== 'string' || !text) {
    return { sanitized: text, detections: [] };
  }
  let sanitized = text;
  const detections = [];
  for (const item of SECRET_PATTERNS) {
    if (item.requires && !sanitized.includes(item.requires)) continue;
    let match;
    const regex = new RegExp(item.pattern.source, item.pattern.flags);
    while ((match = regex.exec(sanitized)) !== null) {
      detections.push({
        rule: item.id,
        index: match.index,
      });
    }
    sanitized = sanitized.replace(item.pattern, item.replacement);
  }
  return { sanitized, detections };
}

function sanitizeToolResult(toolOrResult, content, options = {}) {
  if (content !== undefined && content !== null) {
    const toolName = String(toolOrResult);
    const textContent = typeof content === 'string' ? content : JSON.stringify(content);
    const assessment = evaluate(textContent, options);
    const isBlock = assessment.verdict?.toLowerCase() === 'block';

    let sanitized = textContent;
    let secretsRedacted = 0;

    if (isBlock) {
      sanitized = `[REDACTED BY ZN-GATE: Malicious prompt injection payload detected in ${toolName} output (${assessment.reason || assessment.rule})]`;
    } else if (options.maskSecrets !== false) {
      const res = redactSecrets(textContent);
      sanitized = res.sanitized;
      secretsRedacted = res.detections.length;
    }

    return {
      tool_name: toolName,
      safe_to_ingest: !isBlock,
      assessment,
      secrets_redacted: secretsRedacted,
      sanitized_content: sanitized,
    };
  }

  // Deep sanitization of objects/arrays
  const detections = [];
  function _sanitize(val) {
    if (typeof val === 'string') {
      const res = redactSecrets(val);
      if (res.detections.length > 0) {
        detections.push(...res.detections);
      }
      return res.sanitized;
    } else if (Array.isArray(val)) {
      return val.map(_sanitize);
    } else if (val !== null && typeof val === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(val)) {
        out[k] = _sanitize(v);
      }
      return out;
    }
    return val;
  }

  const sanitized = _sanitize(toolOrResult);
  return { sanitized, detections };
}

// LRU cache for evaluate(): max 2048 entries keyed on raw input, only for
// inputs up to 8 KB so the cache itself stays small.
// Invalidated when RULES_VERSION changes or custom config reloads.
const EVAL_CACHE_MAX = 2048;
const EVAL_CACHE_MAX_INPUT = 8 * 1024;
const evalCache = new Map();
function evaluate(input, options = {}) {
  if (typeof input !== 'string' || input.length > EVAL_CACHE_MAX_INPUT) return evaluateUncached(input, options);
  const cfg = loadCustomConfig();
  const hit = evalCache.get(input);
  if (hit !== undefined && hit.ver === RULES_VERSION && hit.cfg === cfg) {
    evalCache.delete(input);
    evalCache.set(input, hit);
    return { ...hit.res };
  }
  const res = evaluateUncached(input, options);
  evalCache.set(input, { res, cfg, ver: RULES_VERSION });
  if (evalCache.size > EVAL_CACHE_MAX) {
    evalCache.delete(evalCache.keys().next().value);
  }
  return { ...res };
}

module.exports = {
  evaluate,
  analyzePrompt: evaluate,
  loadCustomConfig,
  redactSecrets,
  sanitizeToolResult,
  normalizeInput,
  MAX_SCAN_CHARS,
  SCAN_HEAD_CHARS,
  SCAN_TAIL_CHARS,
  EVAL_CACHE_MAX_INPUT,
  // Helper patterns used by normalization and the hidden-element check,
  // exported so the Python port can be checked against them.
  HELPER_PATTERNS: { ZERO_WIDTH_RE, ANSI_ESCAPE_RE, B64_EXEC_RE, WHITESPACE_RUN_RE, OPEN_TAG_RE, HIDDEN_ATTR_RE, HIDDEN_PAYLOAD_RE },
  SECRET_PATTERNS,
  RULES_VERSION,
  INJECTION_RULES,
  INDIRECT_INJECTION_RULES,
  EVASION_RULES,
  EXFIL_RULES,
  SENSITIVE_PATH_RULES,
  MARKDOWN_EXFIL_RULES,
};
