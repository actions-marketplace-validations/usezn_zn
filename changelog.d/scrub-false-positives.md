### Fixed
- The scrubber no longer reports a masked example as a secret: an Anthropic key or an `Authorization: Bearer` value made mostly of one repeated character (for example `sk-ant-api03-xxxx...`) is treated as a placeholder. `SCRUB_RULES_VERSION` is `2026-10-17.3`.
