# zn-gate API Reference

## Node.js (`zn-gate`)

```javascript
const { evaluate, redactSecrets, sanitizeToolResult } = require('zn-gate/lib/rules');
const { analyze, checkToolResult } = require('zn-gate/lib/client');
const { logEvidence, verifyEvidenceLedger } = require('zn-gate/lib/evidence');
```

### `evaluate(text, options)`
- Synchronous in-memory deterministic rule evaluation.
- Returns: `{ verdict: 'allow' | 'block', confidence: number, rule: string, reason: string | null }`

### `analyze(text, options)`
- Prompt evaluation: runs local rules first. Queries the cloud classifier only when the user opted in with both an API key (`apiKey` or `ZN_API_KEY`) and `ZN_CLOUD=1`, and `ZN_LOCAL_ONLY` is not `true`. The text is secret-redacted locally before it is sent.
- Returns: `Promise<AssessmentResult>`

### `sanitizeToolResult(toolName, content, options)`
- Deep sanitization of external tool outputs. Blocks indirect prompt injections and redacts sensitive credentials (AWS keys, OpenAI tokens, DB passwords).

### `checkToolResult(toolName, content, options)`
- Local only; never touches the network. Inspects tool output before it enters the model context and always redacts secrets.
- Returns: `Promise<{ tool_name, safe_to_ingest, secrets_redacted, sanitized_content, assessment }>`

### `verifyEvidenceLedger(filePath)`
- Verifies the SHA-256 hash chain in `~/.zn/evidence.jsonl`. It detects accidental or partial edits; it is not tamper-proof against someone with write access to the file.

---

## Python (`zn-gate`)

```python
from zn_gate import evaluate, guard, check_tool_call, check_tool_result, redact_secrets
from zn_gate.client import analyze
from zn_gate.evidence import verify_evidence_ledger
```

### `evaluate(text: str) -> Assessment`
- Pure Python in-memory deterministic evaluation. Never touches the network.
- Returns: `Assessment(verdict='allow'|'block', confidence=1.0, rule='...', reason='...')`

### `@guard(on_block='raise'|'return', check_args=True, check_result=False, mask_secrets=False)`
- Python decorator protecting sync and async agent functions and tool handlers.

### `check_tool_call(tool_name: str, arguments: Any) -> Assessment`
- Recursively extracts and inspects all strings in arguments for malicious commands or credentials.

### `check_tool_result(result: Any) -> Assessment`
- Inspects external tool return values for indirect injection payloads.
