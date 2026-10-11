# Rust gateway (legacy, not released)

The root `src/` directory contains the original Rust gateway (`zn`) from the 1.0.0 line: an HTTP management API and MCP proxy on `localhost:9090`, a rules engine, an optional local ONNX classifier (Candle), a SQLite audit log, WASM policies and a terminal UI.

It is kept for reference and for future work on a local classifier. It is not published on crates.io, has no published container image, is not part of the npm or PyPI packages, and is not built or tested in CI. `zn mcp` exposes two MCP tools: `analyze_prompt` and `version`.

The Rust gateway reads `ZN_API_KEY` as the key for its own management API. It never contacts `api.usezn.com`.

> For agent protection (Claude Code, Codex CLI, Cursor, OpenCode, LangChain, CrewAI), use `zn-gate` (Node.js) or `zn-gate` on PyPI (Python). They need no compilation.

## Building from Source

### Prerequisites
- Rust stable (`cargo`); the Dockerfile builds with `rust:1-bookworm`
- `protoc` 29 or later
- OpenSSL / libssl-dev

```bash
cargo build --release
./target/release/zn --help
```
