# Rust gateway (legacy, not released)

The root `src/` directory contains the original Rust gateway (`zn`) from the 1.0.0 line: an HTTP management API and MCP proxy on `localhost:9090`, a rules engine, an optional local ONNX classifier (Candle), a SQLite audit log, WASM policies and a terminal UI.

It is kept for reference and for future work on a local classifier. It is not published on crates.io, has no published container image and is not part of the npm or PyPI packages. CI builds it, runs its tests, clippy and rustfmt, and checks its dependencies with `cargo audit` (`.github/workflows/rust.yml`). `zn mcp` exposes two MCP tools: `analyze_prompt` and `version`.

The Rust gateway reads `ZN_API_KEY` as the key for its own management API. It never contacts `api.usezn.com`.

On first start, with an empty database, the gateway seeds a default organisation with a super-admin key: `ZN_API_KEY` if it is set, otherwise a random key. A random key is written to `zn-superadmin-key.txt` next to the audit database (`zn.db` by default), readable only by your user (mode 0600 on Unix; on Windows the file inherits the permissions of its directory). Copy it somewhere safe, then delete the file. The key is never printed, so it does not end up in terminal scrollback or container logs; earlier versions printed a generated key to stdout. If the file cannot be written, the gateway does not start and seeds nothing.

> For agent protection (Claude Code, Codex CLI, Cursor, OpenCode, LangChain, CrewAI), use `zn-gate` (Node.js) or `zn-gate` on PyPI (Python). They need no compilation.

## Management API authentication

Send a key or token in `X-API-Key`, in `Authorization: Bearer <value>` (`Bearer` in any letter case), or (for SSE and WebSocket clients) in the `api_key` or `token` query parameter, percent-encoded. Prefer the headers: query strings can end up in proxy logs. The value is checked in this order:

1. `ZN_API_KEY`: full access (super-admin). An empty or blank `ZN_API_KEY` counts as not set, and an empty key or token never authenticates.
2. A tenant API key: the tenant's role, scoped to its namespace. Blocked tenants get 403.
3. A JWT signed with `ZN_JWT_SECRET` (HS256 only; other algorithms and unsigned tokens are rejected). The secret must be at least 32 bytes, or the gateway refuses to start (for example `openssl rand -hex 32`).

JWT claims:

| Claim | Required | Meaning |
|---|---|---|
| `sub` | yes | Who the token is for; logged when a token is refused. |
| `exp` | yes | Expiry (Unix seconds). |
| `nbf` | no | Not valid before this time (Unix seconds). |
| `roles` | yes | List of roles, exact lowercase names: `superadmin`, `admin`, `user`, `viewer`, `blocked`. The highest role applies; `blocked` overrides everything. |
| `namespace` | for every role except `superadmin` | Tenant namespace the token is scoped to. No whitespace or control characters; `global` is reserved. |

A token with a bad signature, another algorithm, past its expiry or before its `nbf` gets **401**. A correctly signed token with no usable role (missing, empty, unknown or wrongly cased roles, only `blocked`, or a tenant role without a valid namespace) gets **403**.

**Breaking change:** earlier versions of the gateway gave any valid HS256 token full super-admin access. Tokens must now carry `roles`, and `namespace` for tenant roles. Role names are case-sensitive. `ZN_JWT_SECRET` must be at least 32 bytes or the gateway refuses to start, so tokens signed with a shorter secret stop working. Tokens with an `nbf` (not before) time in the future are rejected, with 60 seconds of leeway for clock differences. Tenants can no longer be created in the `global` namespace or with a namespace that has whitespace, and the gateway no longer prints a `ZN_API_KEY` taken from the environment when it seeds the default organisation.

## Policy endpoints

`POST /api/v1/policies/upload` and `POST /api/v1/policies/delete` (super-admin only) work on `engine.policy_dir` (default `./policies_bin`), the directory the gateway loads and watches. A policy name, and an uploaded file name without its `.wasm` extension, must be 1-64 ASCII letters, digits, `.`, `-` or `_`, starting with a letter or digit. Other names are refused, and so is a policy file that resolves outside the directory through a symlink. Earlier versions wrote uploads to `./policies` and joined the name from the request to that path as given, so a name such as `../x` could write or delete a `.wasm` file outside it.

Uploads are written to a temporary file and renamed into place, so the watcher never loads a half-written policy, and a symlink at the target name is refused.

**Upgrading:** policies uploaded with an earlier version are in `./policies` and are no longer loaded. Move the `.wasm` files, with their `.wasm.sig` / `.wasm.pqs` signatures if you use them, to `engine.policy_dir` before you start the new version, for example `mv policies/*.wasm* policies_bin/`.

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
