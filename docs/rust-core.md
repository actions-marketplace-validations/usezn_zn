# Rust gateway (legacy, not released)

The root `src/` directory contains the original Rust gateway (`zn`) from the 1.0.0 line: an HTTP management API and MCP proxy on `localhost:9090`, a rules engine, an optional local ONNX classifier (Candle), a SQLite audit log, WASM policies and a terminal UI.

It is kept for reference and for future work on a local classifier. It is not published on crates.io, has no published container image and is not part of the npm or PyPI packages. CI builds it, runs its tests, clippy and rustfmt, and checks its dependencies with `cargo audit` (`.github/workflows/rust.yml`). `zn mcp` exposes two MCP tools: `analyze_prompt` and `version`.

The Rust gateway reads `ZN_API_KEY` as the key for its own management API. It never contacts `api.usezn.com`.

> For agent protection (Claude Code, Codex CLI, Cursor, OpenCode, LangChain, CrewAI), use `zn-gate` (Node.js) or `zn-gate` on PyPI (Python). They need no compilation.

## Management API authentication

Send a key or token in `X-API-Key`, in `Authorization: Bearer <value>`, or (for SSE and WebSocket clients) in the `api_key` or `token` query parameter. Prefer the headers: query strings can end up in proxy logs. The value is checked in this order:

1. `ZN_API_KEY`: full access (super-admin).
2. A tenant API key: the tenant's role, scoped to its namespace. Blocked tenants get 403.
3. A JWT signed with `ZN_JWT_SECRET` (HS256 only; other algorithms and unsigned tokens are rejected).

JWT claims:

| Claim | Required | Meaning |
|---|---|---|
| `sub` | yes | Who the token is for; logged when a token is refused. |
| `exp` | yes | Expiry (Unix seconds). |
| `roles` | yes | List of roles, exact lowercase names: `superadmin`, `admin`, `user`, `viewer`, `blocked`. The highest role applies; `blocked` overrides everything. |
| `namespace` | for every role except `superadmin` | Tenant namespace the token is scoped to. No whitespace or control characters; `global` is reserved. |

A token with a bad signature, another algorithm, or past its expiry gets **401**. A correctly signed token with no usable role (missing, empty, unknown or wrongly cased roles, only `blocked`, or a tenant role without a valid namespace) gets **403**.

**Breaking change:** earlier versions of the gateway gave any valid HS256 token full super-admin access. Tokens must now carry `roles`, and `namespace` for tenant roles. Role names are case-sensitive.

## Upgrading the vector memory

The per-agent vector memory is now stored in SQLite (`data/vectors/<model>_d<dim>.sqlite3`). The older Lance directories (`data/vectors/<model>_d<dim>/`) are not migrated or read and can be deleted.

## Building from Source

### Prerequisites
- Rust 1.95 or later (`cargo`); CI uses 1.99.0 and the Dockerfile builds with `rust:1-bookworm`
- `protoc` 29 or later
- OpenSSL / libssl-dev

```bash
cargo build --release
./target/release/zn --help
```
