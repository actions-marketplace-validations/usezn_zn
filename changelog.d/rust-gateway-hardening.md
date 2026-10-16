### Security
- Rust gateway in `src/` (experimental, not distributed: not part of the npm or PyPI packages or the plugin): bans are kept per tenant namespace, an allowed call forwards the sanitized images, `/mcp/ws` limits messages to 1 MiB, and query-string credentials are accepted only for SSE and WebSocket. See `docs/rust-core.md`.
