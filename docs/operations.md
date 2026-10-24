# Operations

> 🚧 **Under construction.** The MCP server publishes an approved snapshot
> and can read MISP. `mecfeed-serve` serves verified snapshots; auth, abuse
> limits, and the security review are not done. Do not deploy it.

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
| `/var/lib/mecfeed-serve/snapshots` | feed-server snapshot directory (served read-only at `/feeds/{format}/{kind}`) |

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

`mecfeed-serve` serves `GET`/`HEAD /feeds/{format}/{kind}` from the current
verified snapshot and answers 503 when the snapshot log does not verify.
Formats: `panos-edl`, `junos-dynamic-address`, `fortigate-threat-feed`,
`opnsense-url-table`. Kinds: `address`, `prefix`, `domain` (Junos has no
`domain`). Everything else is 404.

## Tokens and audit

Match the rest of the mecmcp fleet: bearer tokens in
`/var/lib/mecfeedmcp/tokens.json` mode `0600`, owned by `mecfeedmcp`. The
binary generates `/var/lib/mecfeedmcp/audit-hmac.key` on first start if it
is absent. Each plan, approval, waiver, publish, and rollback writes an
audit event. The approver reads `get_feed_change` before `approve_feed_change`.

`feed.json` holds operator prefix and domain allowlists. It never holds a
MISP API key. Name the key with `misp.api_key_env` or `misp.api_key_file`
(absolute path, mode `0600`). `misp.base_url` is an `https://` origin only.
`list_indicators` and `search_indicators` read mapped MISP attributes; they
do not plan or publish. OpenCTI is not wired.
