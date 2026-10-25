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
| `/var/lib/mecfeedmcp/snapshot-signing.key` | snapshot signing key (`0600 mecfeedmcp`, never leaves the host) |
| `/var/lib/mecfeed-snapshots` | snapshots: written by the MCP server, read by mecfeed-serve (mecfeedmcp:mecfeed-serve, setgid 2750) |
| `/etc/mecfeed-serve/tls.crt`, `tls.key` | feed-server TLS material |
| `/etc/mecfeed-serve/snapshot-signing.pub` | trusted snapshot public key (`0644 root`) |

The installer never enables either unit. Create config and credentials first,
then `systemctl enable --now mecfeedmcp.service` (and `mecfeed-serve.service`
once TLS files exist).

## Docker

Images: `ghcr.io/mechubsec/mecfeedmcp` and `ghcr.io/mechubsec/mecfeedmcp/mecfeed-serve`
(and the matching `docker.io/mechub/...` names). Both run as uid **65532**.
The MCP image's `ENTRYPOINT` keeps `--device-mapping`, `--tokens-file`, and
`--audit-hmac-key-file`, and `--snapshot-signing-key-file` so an operator `--host` override cannot drop them.
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

## Snapshot signing

Each published version gets `versions/<N>/snapshot.sig`. `mecfeed-serve` serves
only a current version whose signature verifies against a
`--trusted-snapshot-key`; there is no unsigned mode.

Files: `/var/lib/mecfeedmcp/snapshot-signing.key` (`0600 mecfeedmcp`, never
leaves the host) and `/etc/mecfeed-serve/snapshot-signing.pub` (`0644 root`).
The installer creates both, and its next step 5 prints the public key. To serve
from another host, copy the `.pub` to `/etc/mecfeed-serve/snapshot-signing.pub`
there. To print the public key again:

```sh
runuser -u mecfeedmcp -- mecfeedmcp --snapshot-signing-key-file /var/lib/mecfeedmcp/snapshot-signing.key --print-snapshot-signing-public-key
```

Docker: create the key once, keep the public half, make it readable by the
serve container (uid 65532), and mount it there read-only at
`/etc/mecfeed-serve/snapshot-signing.pub`:

```sh
docker run --rm -v <state_dir>:/var/lib/mecfeedmcp --user 65532:65532 <image> --init-snapshot-signing-key > snapshot-signing.pub
chmod 0644 snapshot-signing.pub
```

```sh
-v "$PWD/snapshot-signing.pub:/etc/mecfeed-serve/snapshot-signing.pub:ro"
```

Rotation (systemd). Each step that changes a unit ends with
`systemctl daemon-reload` and a restart; restart alone keeps the cached unit.
Change flags in a drop-in (`systemctl edit mecfeedmcp`, `systemctl edit
mecfeed-serve`) that sets an empty `ExecStart=` and then the full new
`ExecStart=`.

1. As root, create a new key at a new path and install its public key under
   `/etc/mecfeed-serve` as `root:root` mode `0644`, so serve can read it and no
   unprivileged account can change it:

   ```sh
   pub=$(runuser -u mecfeedmcp -- mecfeedmcp --snapshot-signing-key-file /var/lib/mecfeedmcp/<new-name>.key --init-snapshot-signing-key) \
     && printf '%s\n' "$pub" | install -o root -g root -m 0644 /dev/stdin /etc/mecfeed-serve/<new-name>.pub
   ```

   A failed init installs nothing. If the new key already exists (a retry), use
   `--print-snapshot-signing-public-key` in place of `--init-snapshot-signing-key`
   in the same command.
2. Copy serve's current `ExecStart` (from `systemctl cat mecfeed-serve`) into
   the drop-in and add only `--trusted-snapshot-key /etc/mecfeed-serve/<new-name>.pub`,
   then `systemctl daemon-reload` and restart serve.
3. Copy the MCP unit's current `ExecStart` (from `systemctl cat mecfeedmcp`)
   into the drop-in and change only `--snapshot-signing-key-file` to the new
   key, then `systemctl daemon-reload`
   and restart it.
4. Publish one version.
5. Remove the old `--trusted-snapshot-key` (drop-in), then
   `systemctl daemon-reload` and restart serve.

Re-running the installer resets the units to the default key path. Keep the
rotated key's path in a drop-in, and do not replace the key at the default path
while an old `.pub` sits at the default `.pub` path: the installer stops on a
`.pub` that does not match the key.

Upgrading from an unsigned release (systemd/LXC):

1. `systemctl stop mecfeed-serve mecfeedmcp`
2. Re-run the installer with `MECFEEDMCP_FORCE_UNIT=1` so both units get the new
   flags. This also creates the key and the `.pub`. `MECFEEDMCP_FORCE_UNIT=1`
   overwrites hand-edited unit files: drop-ins in
   `/etc/systemd/system/<unit>.service.d/` survive, direct edits do not. Diff the
   installed units against `packaging/systemd/` first and move local changes into
   drop-ins.
3. `systemctl start mecfeedmcp mecfeed-serve`
4. Publish one new version (plan, approve, apply).

Upgrading from an unsigned release (Docker). The serve image now requires the
mounted `.pub`, so an existing serve container will not start without it:

1. Stop both containers.
2. Run the new mecfeedmcp image once with `--init-snapshot-signing-key` against
   the existing state volume, writing `snapshot-signing.pub`, then
   `chmod 0644` it (as above).
3. Start mecfeedmcp from the new image.
4. Start serve from the new image with the `.pub` mounted read-only.
5. Publish one new version.

Serve answers 503 until that publish (systemd steps 3 to 4, Docker steps 4 to
5), because older versions have no signature. `rollback_feed` cannot be used to
publish, because it refuses the current version.

Serve verifies once per `current` change and serves from memory. A `.sig`
changed after that is noticed at the next publish or serve restart.

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
