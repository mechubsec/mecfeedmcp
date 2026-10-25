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
- The MCP server publishes a snapshot only after an approved change-set digest still matches. An unapproved digest is not written.
- Feed change-control writes an audit event, and the actor type comes from the caller token. `get_feed_change` shows the canonical rows and the diff against the current snapshot, and refuses the preview when that snapshot no longer matches the stored plan.
- `list_indicators` and `search_indicators` read mapped MISP attributes over HTTPS. The API key is a file or environment reference. Operator prefix and domain allowlists load from `feed.json`.
- `mecfeed-serve` serves the current verified snapshot at `/feeds/{format}/{kind}` with ETag/If-None-Match and fails closed when the log does not verify.
- The packaged MCP server and mecfeed-serve share /var/lib/mecfeed-snapshots; serve reads feed.json through systemd LoadCredential.
- The MCP server verifies stored history without the operator allowlists, so a new allowlist entry that matches an old version no longer stops it starting.
- **Breaking:** published snapshots are signed with Ed25519 and mecfeed-serve serves only a current snapshot whose signature verifies. New required flags: `--snapshot-signing-key-file` (mecfeedmcp, to publish) and `--trusted-snapshot-key` (mecfeed-serve). The installer creates the key; after upgrading, serve returns 503 until one new version is published. See docs/operations.md, "Snapshot signing".
