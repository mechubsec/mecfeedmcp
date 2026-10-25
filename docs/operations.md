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
| `/var/lib/mecfeed-snapshots` | snapshots: written by the MCP server, read by mecfeed-serve (mecfeedmcp:mecfeed-serve, setgid 2750) |
| `/etc/mecfeed-serve/tls.crt`, `tls.key` | feed-server TLS material |

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
Mount one host directory at `/var/lib/mecfeed-snapshots` in both containers: writable by uid 65532 for the MCP server, `:ro` for `mecfeed-serve`.

`mecfeed-serve` matches its client allowlist against the TCP peer address.
Behind Docker NAT that address is the bridge gateway, so the default
loopback-only allowlist rejects every client. Use host networking, or pass
`--allow-cidr` with the firewall addresses that should pull snapshots.

`mecfeed-serve` serves `GET`/`HEAD /feeds/{format}/{kind}` from the current
verified snapshot and answers 503 when the snapshot log does not verify.
Formats: `panos-edl`, `junos-dynamic-address`, `fortigate-threat-feed`,
`opnsense-url-table`. Kinds: `address`, `prefix`, `domain` (Junos has no
`domain`). Everything else is 404.

`mecfeed-serve` requires `--feed-config` (the MCP server's `feed.json`). It reads
the operator allowlists at startup and applies them to the current snapshot on
every render, so restart it after editing `feed.json`. Older versions are
verified without them. An allowlist entry that conflicts with the current
version makes it answer 503 until a new version is published without that
entry. The packaged serve unit reads `feed.json` through
`LoadCredential`, so the file stays `0640 root:mecfeedmcp`; the MCP unit runs with
`UMask=0027` so new snapshots are group-readable by `mecfeed-serve`. Installs from
before this change kept snapshots in `/var/lib/mecfeedmcp/snapshots`. To upgrade, stop
both services first so no publish lands in the old tree. Re-run the installer with
`MECFEEDMCP_FORCE_UNIT=1`: both unit files changed, and it otherwise keeps a changed
unit as customized. The installer creates `/var/lib/mecfeed-snapshots`, so move the
old tree's contents into it rather than the tree itself:

```sh
mv /var/lib/mecfeedmcp/snapshots/current /var/lib/mecfeedmcp/snapshots/versions /var/lib/mecfeed-snapshots/
chown -R mecfeedmcp:mecfeed-serve /var/lib/mecfeed-snapshots
find /var/lib/mecfeed-snapshots -type d -exec chmod 2750 {} +
find /var/lib/mecfeed-snapshots -type f -exec chmod 0640 {} +
```

Then set `snapshot_dir` to `/var/lib/mecfeed-snapshots` in `feed.json` and start both
services.

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
