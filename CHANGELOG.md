# Changelog

## 0.1.0 — unreleased

- Workspace scaffold: `mecfeedmcp-core`, `mecfeedmcp`, `mecfeed-serve`.
- CI, cargo-deny, cargo-audit, gitleaks, CodeQL, packaging conformance.
- Distroless images and the mecmcp v0.28.1 release pipeline.
- Empty MCP tool surface and empty read-only feed server. Not usable in production.
- Indicator checks reject special-purpose ranges and overly broad prefixes.
- `mecfeedmcp-core` admits indicators, versions immutable snapshots, and renders vendor feed documents.
- A domain's final label must start with a letter. Publishing re-checks the live set, and republishing an earlier snapshot names that snapshot and the current latest.
- Validation errors bound the value they echo.
- Each feed document is one format and one indicator kind. Junos has no domain document.
- A name whose last two labels are a known multi-label public suffix needs one more label.
