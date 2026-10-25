> [!WARNING]
> 🚧 **Under construction — not usable.** The MCP server can read MISP and publish an approved snapshot. `mecfeed-serve` serves verified snapshots; auth, abuse limits, and the security review are not done. Do not deploy it.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">mecfeedmcp</h1>

<p align="center"><strong>Governed threat-intel → firewall feeds: propose, validate, approve, publish — firewalls pull, nothing is committed per indicator</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This is an independent community project and does not claim affiliation with or endorsement by Palo Alto Networks, Juniper Networks, Fortinet, Deciso (OPNsense), MISP, Filigran (OpenCTI) or any other vendor. Product names and trademarks are used only to identify the systems with which the software interoperates.

---

## What it will do

"Block this indicator on every firewall" is the canonical SOC containment action. Today it is manual, or a SOAR playbook with no deterministic guardrails. `mecfeedmcp` makes it a governed change:

1. **Read** indicators (IPs, CIDRs, domains) from threat-intel sources — MISP first, OpenCTI later — read-only.
2. **Propose** a feed change as a [`mecmcp`](https://github.com/mechubsec/mecmcp) change set. The model proposes; deterministic validators decide.
3. **Validate** before any human sees it: reject private/reserved ranges, the operator's own prefixes and an allowlist (CDNs, resolvers, partners); require an expiry on every entry; cap entries per change; dedupe against the live feed.
4. **Approve** the exact digest — a human, and a second human for production.
5. **Publish** a new immutable, versioned feed. Firewalls already configured to pull it pick it up on their next refresh — no config commit per indicator. **Rollback** = re-publish the previous version; entries also expire on their own.

## Components (all in this repo)

| Component | Role |
|---|---|
| `mecfeedmcp-core` | Indicator model, validators, allowlist, TTL/expiry, versioning, rollback, per-vendor feed renderers. Pure logic, no I/O. |
| `mecfeedmcp` | The MCP server (stdio and HTTP via mecmcp): source readers, change-set lifecycle (plan → approve → apply = publish), audit, redaction. The only component that can change a feed. |
| `mecfeed-serve` | The feed web server firewalls pull from. Separate binary and container. Serves published snapshots **read-only**; has no write API and no knowledge of approvals. |

### Feed formats (rendered from one source of truth)

PAN-OS External Dynamic Lists · Junos SRX dynamic-address / SecIntel feeds · FortiGate external threat feeds · OPNsense URL-table aliases. Each format is one document per indicator kind (address, prefix, domain). Junos has no domain document. Each firewall subscribes once (a one-time config change made through its own mechub MCP server); after that only the feed content changes.

## Security design for `mecfeed-serve`

The feed server is on the enforcement path of every subscribed firewall, so it is built to be small, boring and hard to misuse:

- **Rust end to end**: `hyper`/`axum` with **rustls** (no OpenSSL), `#![forbid(unsafe_code)]`, minimal dependency tree, `cargo-deny` and `cargo-audit` gated.
- **Read-only by construction**: GET/HEAD only on a fixed route set; no directory listing, no uploads, no admin endpoints. It reads signed, versioned snapshots that `mecfeedmcp` writes atomically to a shared directory; it never writes.
- **TLS only**, modern ciphers; optional **mTLS** and/or per-feed credentials (HTTP Basic for firewalls that support it) and a **client IP/CIDR allowlist**.
- **Integrity**: every snapshot carries a digest-signed manifest; the server refuses to serve a snapshot whose manifest does not verify. `ETag`/`If-None-Match` so firewalls fetch only on change.
- **Abuse limits**: request size/time limits, per-client rate limits, structured access log feeding the mecmcp audit pipeline.
- **mecmcp image rules** ([DOCKER-STANDARD](https://github.com/mechubsec/mecmcp/blob/main/docs/DOCKER-STANDARD.md), [PACKAGING](https://github.com/mechubsec/mecmcp/blob/main/docs/PACKAGING.md)): distroless `cc-debian13:nonroot`, uid/gid **65532**, no shell, read-only root filesystem, `cap_drop: ALL`, linux/amd64, cosign-signed and SBOM-attested images published on signed tags to GHCR and Docker Hub, plus the signed Debian 13 LXC tarball.

## What stays out of this repo

Only what is strictly necessary lives elsewhere:

| Repo | Change |
|---|---|
| [`mecmcp`](https://github.com/mechubsec/mecmcp) | None planned — `mecmcp-changeset`, auth, audit and redaction are reused as-is. Upstream changes only if a concrete gap appears. |
| [`rustpanosmcp`](https://github.com/mechubsec/rustpanosmcp), [`rustjunosmcp`](https://github.com/mechubsec/rustjunosmcp), [`rustfortimcp`](https://github.com/mechubsec/rustfortimcp), [`rustopnsmcp`](https://github.com/mechubsec/rustopnsmcp) | A **read-only feed-status tool** (subscribed? which version did the firewall last pull? entry count?) and docs for the one-time subscription. No new write power. |
| mechub console (planned) | Operator UI: feed history, what was blocked and why, expiring entries, lagging firewalls — and proposing, approving and applying feed changes **through mecfeedmcp's own change-set flow** (lab-mode or two-person approval as the server enforces). It never bypasses the server's approval. |

## Status

**Under construction — not usable.** P0 (workspace, CI, and release pipeline, [#1](https://github.com/mechubsec/mecfeedmcp/issues/1)) is on `main`. `mecfeedmcp-core` admits indicators, versions snapshots, and renders feed documents ([#2](https://github.com/mechubsec/mecfeedmcp/issues/2)). The MCP server plans, approves, and publishes a snapshot, and can list and search MISP indicators ([#3](https://github.com/mechubsec/mecfeedmcp/issues/3)). The approver reads `get_feed_change` before approving, and each plan, approval, waiver, publish, and rollback writes an audit event. `mecfeed-serve` serves verified snapshots; auth, abuse limits, and the security review are not done, so do not deploy it. Scope history: [mecmcp#424](https://github.com/mechubsec/mecmcp/issues/424). Work is tracked in this repo's issues.

## License

Licensed under [MIT](LICENSE).
