# Operations

> 🚧 **Under construction.** This package installs empty skeleton binaries.
> Do not point production firewalls at `mecfeed-serve`, and do not use
> `mecfeedmcp` as a change-control path until a later phase registers tools.

The shared `mecmcp` crates are pinned — to `v0.28.1`.

## Layout

| Path | Role |
|---|---|
| `/usr/local/bin/mecfeedmcp` | MCP server |
| `/usr/local/bin/mecfeed-serve` | read-only TLS feed server |
| `/etc/mecfeedmcp/feed.json` | operator-authored feed config (no secrets) |
| `/var/lib/mecfeedmcp/tokens.json` | bearer-token store |
| `/var/lib/mecfeedmcp/audit-hmac.key` | audit HMAC key (generated on first run) |
| `/etc/mecfeed-serve/tls.crt`, `tls.key` | feed-server TLS material |
| `/var/lib/mecfeed-serve/snapshots` | published feed snapshots (empty in this phase) |

The installer never enables either unit. Create config and credentials first,
then `systemctl enable --now mecfeedmcp.service` (and `mecfeed-serve.service`
once TLS files exist).

## Docker

Images: `ghcr.io/mechubsec/mecfeedmcp` and `ghcr.io/mechubsec/mecfeed-serve`
(and the matching `docker.io/mechub/...` names). Both run as uid **65532**.
The MCP image's `ENTRYPOINT` keeps `--device-mapping`, `--tokens-file`, and
`--audit-hmac-key-file` so an operator `--host` override cannot drop them.
`--audit-format json` is the correct audit sink in a container (there is no
journald socket).

## Tokens and audit

Match the rest of the mecmcp fleet: bearer tokens in
`/var/lib/mecfeedmcp/tokens.json` mode `0600`, owned by `mecfeedmcp`. The
binary generates `/var/lib/mecfeedmcp/audit-hmac.key` on first start if it
is absent.
