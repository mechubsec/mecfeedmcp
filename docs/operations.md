# Operations

> 🚧 **Under construction.** The MCP server publishes an approved snapshot.
> `mecfeed-serve` does not serve snapshots yet. Do not point production
> firewalls at it.

The shared `mecmcp` crates are pinned — to `v0.28.1`.

## Layout

| Path | Role |
|---|---|
| `/usr/local/bin/mecfeedmcp` | MCP server |
| `/usr/local/bin/mecfeed-serve` | read-only TLS feed server |
| `/etc/mecfeedmcp/feed.json` | operator-authored feed config (no secrets) |
| `/var/lib/mecfeedmcp/tokens.json` | bearer-token store |
| `/var/lib/mecfeedmcp/audit-hmac.key` | audit HMAC key (generated on first run) |
| `/var/lib/mecfeedmcp/changeset-state.json` | change-set state |
| `/var/lib/mecfeedmcp/snapshots` | snapshots written by the MCP server |
| `/etc/mecfeed-serve/tls.crt`, `tls.key` | feed-server TLS material |
| `/var/lib/mecfeed-serve/snapshots` | feed-server snapshot directory (not served yet) |

The installer never enables either unit. Create config and credentials first,
then `systemctl enable --now mecfeedmcp.service` (and `mecfeed-serve.service`
once TLS files exist).

## Docker

Images: `ghcr.io/mechubsec/mecfeedmcp` and `ghcr.io/mechubsec/mecfeedmcp/mecfeed-serve`
(and the matching `docker.io/mechub/...` names). Both run as uid **65532**.
The MCP image's `ENTRYPOINT` keeps `--device-mapping`, `--tokens-file`, and
`--audit-hmac-key-file` so an operator `--host` override cannot drop them.
`--audit-format json` is the correct audit sink in a container (there is no
journald socket).

`mecfeed-serve` matches its client allowlist against the TCP peer address.
Behind Docker NAT that address is the bridge gateway, so the default
loopback-only allowlist rejects every client. Use host networking, or pass
`--allow-cidr` with the firewall addresses that should pull snapshots.

## Tokens and audit

Match the rest of the mecmcp fleet: bearer tokens in
`/var/lib/mecfeedmcp/tokens.json` mode `0600`, owned by `mecfeedmcp`. The
binary generates `/var/lib/mecfeedmcp/audit-hmac.key` on first start if it
is absent.
