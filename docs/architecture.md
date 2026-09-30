# zn Architecture

zn operates as a **sacrificial, lightweight checkpoint** situated directly between AI agents (or LLMs) and untrusted external inputs.

![zn Architecture](../assets/architecture.svg)

## Defense-in-Depth Lifecycle

zn enforces security across three distinct lifecycle phases:

```
[User / External Input]
         │
         ▼
 ┌───────────────┐
 │ analyze_prompt│ ──► Pre-execution check (Jailbreaks, roleplay, LFI, exfil)
 └───────┬───────┘
         │ (Clean)
         ▼
    [AI Agent]
         │
         ▼
 ┌─────────────────┐
 │ check_tool_call │ ──► Pre-flight tool argument check (bash, DB queries, file ops)
 └───────┬─────────┘
         │ (Safe)
         ▼
  [Tool Execution] (Web search, bash, filesystem, APIs)
         │
         ▼
 ┌──────────────────┐
 │check_tool_result │ ──► Post-execution result check (Indirect injection, DLP redaction)
 └───────┬──────────┘
         │ (Sanitized)
         ▼
    [LLM Context]
```

## Key Architectural Principles

1. **Zero External Dependencies:**
   Both `zn-gate` (npm) and `zn-gate-py` (PyPI) are written in pure standard library. No native compilation, no third-party package vulnerabilities, minimal attack surface.

2. **Sub-millisecond Deterministic Fastpath:**
   Local evaluation uses compiled regular expressions, homoglyph normalization, and LRU-2048 caching to make verdicts in < 10 µs.

3. **Hybrid Cloud Gate (Optional):**
   When `ZN_API_KEY` is provided, obvious attacks are still blocked locally in-process ($0 cost, 0 network latency). Clean payloads escalate to cloud neural models (v30 ONNX) for deep semantic analysis.

4. **Cryptographic Tamper-Evident Ledger:**
   Every security assessment is hashed using SHA-256 and chained into `~/.zn/evidence.jsonl`. Node and Python implementations use canonical JSON to guarantee byte-for-byte cross-language ledger verification.
