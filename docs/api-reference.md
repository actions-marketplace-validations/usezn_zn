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
- Hybrid evaluation: runs local rules first; escalates to cloud gate if `apiKey` is provided.
- Returns: `Promise<AssessmentResult>`

### `sanitizeToolResult(toolName, content, options)`
- Deep sanitization of external tool outputs. Blocks indirect prompt injections and redacts sensitive credentials (AWS keys, OpenAI tokens, DB passwords).

### `verifyEvidenceLedger(filePath)`
- Verifies the cryptographic integrity of the SHA-256 hash chain in `~/.zn/evidence.jsonl`.

---

## Python (`zn-gate`)

```python
from zn_gate import evaluate, guard, check_tool_call, check_tool_result, redact_secrets
from zn_gate.client import analyze
from zn_gate.evidence import verify_evidence_ledger
```

### `evaluate(text: str) -> Assessment`
- Pure Python in-memory deterministic evaluation (< 10 µs).
- Returns: `Assessment(verdict='allow'|'block', confidence=1.0, rule='...', reason='...')`

### `@guard(on_block='raise'|'return', check_args=True, check_result=False, mask_secrets=True)`
- Python decorator protecting sync and async agent functions and tool handlers.

### `check_tool_call(tool_name: str, arguments: Any) -> Assessment`
- Recursively extracts and inspects all strings in arguments for malicious commands or credentials.

### `check_tool_result(result: Any) -> Assessment`
- Inspects external tool return values for indirect injection payloads.
