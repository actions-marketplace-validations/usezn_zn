# zn Native Rust Core Engine

The root `src/` directory contains an enterprise-grade, high-throughput Rust engine (`zn`).

## When to Use the Rust Engine

- **High-throughput API Gateway:** Processing > 50,000 requests/sec with minimal memory footprint.
- **Enterprise Edge Proxy:** Standalone sidecar service (`localhost:9090`) with gRPC, SSE, WebSockets, and OpenTelemetry tracing.
- **Hardware-accelerated Neural Inference:** Embedded Candle / ONNX runtime for on-premise classification without external cloud calls.

> **Note for Open-Source Users:**  
> For everyday AI agent protection (Claude Code, Cursor, Antigravity, OpenCode, LangChain, CrewAI), use `zn-gate` (Node.js) or `zn-gate-py` (Python). They require zero compilation and install in seconds.

## Building from Source

### Prerequisites
- Rust 1.75+ (`cargo`)
- `protobuf-compiler` (v29+ recommended)
- OpenSSL / libssl-dev

```bash
cargo build --release
./target/release/zn --help
```
