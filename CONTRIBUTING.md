# Contributing to zn

Thank you for your interest in contributing to **zn**! We welcome bug reports, rule improvements, security research, and pull requests.

## Architecture Overview

`zn` is designed as a local-first, zero-dependency security gate:
- `packages/zn-gate/`: Node.js SDK, CLI, MCP Server, and stdio Shield proxy (Zero external dependencies).
- `packages/zn-gate-py/`: Python SDK, CLI, and agent framework integrations (Zero external dependencies).
- `src/`: High-throughput Rust core engine for enterprise edge deployments.

## Development Setup

### Prerequisites
- Node.js >= 18.0.0
- Python >= 3.8
- (Optional for Rust core) Rust toolchain 1.75+, `protoc`

### Running Tests Locally

#### Node.js (`packages/zn-gate`)
```bash
cd packages/zn-gate
npm test
```
This runs the full unit test suite, shield proxy tests, auto-shielding init tests, cryptographic evidence tests, and the 51-vector self-test suite.

#### Python (`packages/zn-gate-py`)
```bash
cd packages/zn-gate-py
python -m pip install -e .
python -m pytest tests/ -v
```

## Adding New Rules

When adding new detection rules:
1. Ensure the rule ID follows naming conventions (`pi:name`, `evasion:name`, `exfil:name`, `indirect:name`).
2. Add the rule to **both** `packages/zn-gate/lib/rules.js` and `packages/zn-gate-py/src/zn_gate/rules.py`.
3. Bump `RULES_VERSION` in both packages.
4. Add positive test cases (attack vectors that must be blocked) and negative test cases (benign developer code that must be allowed).
5. Verify zero false positives against real technical text (SQL, React, Docker, shell scripts).

## Security Vulnerability Reporting

If you find a security vulnerability, please do NOT open a public issue. Follow our [Security Policy](SECURITY.md) and report it to `security@usezn.com`.
