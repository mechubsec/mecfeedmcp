# Security policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting for this repository
(Security tab → Report a vulnerability, or the link below):

https://github.com/mechubsec/mecfeedmcp/security/advisories/new

Include affected version or commit, reproduction steps, and impact. Do not
include live credentials, tenant identifiers, or real threat-intel payloads
anywhere, including in a private report — sanitize or describe them instead.

## Scope

`mecfeedmcp` will expose governed threat-intel → firewall feeds as a bounded
MCP tool surface. `mecfeed-serve` is on the enforcement path of every
subscribed firewall: it is read-only by construction (GET/HEAD only) and
serves signed snapshots.

Vulnerability classes we especially want to hear about: anything that lets a
caller bypass token scope checks, anything that lets a feed change skip
prepare → independent approval → apply, anything that lets `mecfeed-serve`
write or serve an unverified snapshot, and credential handling issues.

## Security boundaries

- Feed-source credentials are external environment values, never configuration
  fields, MCP arguments, or audit metadata.
- Deterministic validators decide which indicators may enter a feed. Model
  output cannot publish.
- `mecfeed-serve` has no write API and no knowledge of approvals.
- No telemetry, analytics, or phone-home.
