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
| `/etc/mecfeed-serve/clients.json` | client list (`0640 root:root`, read through `LoadCredential`) |

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
-v "$PWD/clients.json:/etc/mecfeed-serve/clients.json:ro"
```

`clients.json` is the client list (see "Client authentication").

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

Rotation (Docker). The images fix the key paths in `ENTRYPOINT`, and
`--snapshot-signing-key-file` cannot be given twice, so the new key is made in a
separate directory and moved into place. Arguments after the image name replace
`CMD`, so every argument serve already runs with must be passed again: at least
`--listen 0.0.0.0:8443` and each `--allow-cidr` (with none, serve allows
loopback only).

1. Create the new key in an empty directory owned by 65532 with mode `0700`,
   and keep its public half:

   ```sh
   mkdir -m 0700 next && sudo chown 65532:65532 next
   pub=$(docker run --rm -v "$PWD/next:/var/lib/mecfeedmcp" --user 65532:65532 <mcp image> --init-snapshot-signing-key) \
     && printf '%s\n' "$pub" | install -m 0644 /dev/stdin next.pub
   ```

   A failed init writes no `next.pub`. If `next/snapshot-signing.key` already
   exists (a retry), use `--print-snapshot-signing-public-key` in place of
   `--init-snapshot-signing-key` in the same command.

2. Recreate serve trusting both keys. `docker restart` cannot change mounts or
   arguments, so stop and remove the container, then `docker run` it again with
   its usual options plus `-v "$PWD/next.pub:/etc/mecfeed-serve/next.pub:ro"`
   and, after the image name,
   `--listen 0.0.0.0:8443`, each `--allow-cidr` it already had, and
   `--trusted-snapshot-key /etc/mecfeed-serve/next.pub`.
3. Stop the MCP container, replace the key in its state directory (the host
   path mounted at `/var/lib/mecfeedmcp`), and start it. A plain `cp` as root
   leaves the key owned by root, and the container cannot read it:

   ```sh
   sudo install -o 65532 -g 65532 -m 0600 next/snapshot-signing.key <state dir>/snapshot-signing.key
   ```

4. Publish one version.
5. Replace the mounted `snapshot-signing.pub` with `next.pub` (`0644`) and
   recreate serve with the same arguments as before (`--listen`, each
   `--allow-cidr`), without the extra mount and `--trusted-snapshot-key`. Then
   `sudo rm -r next`.

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

## Client authentication

Every feed request needs a client listed in `--clients-file`. A request with no
or wrong credentials gets 401. A listed client asking for a feed not in its
`feeds` list gets 403. `/healthz` is open to the CIDR allowlist and needs no
credentials. `--allow-cidr` still runs first. `--allow-anonymous-feeds` is the
explicit opt-out: CIDR-only access, and it conflicts with `--clients-file` and
`--client-ca`.

The file:

```json
{"version": 1, "clients": [
  {"name": "panosvm", "basic_sha256": "<64 lowercase hex>", "feeds": ["panos-edl/address", "panos-edl/domain"]},
  {"name": "vsrx-ci", "cert_sha256": "<64 lowercase hex>", "feeds": ["junos-dynamic-address/address"]}
]}
```

Rules, all checked at startup:

- `name` matches `[A-Za-z0-9._-]{1,64}` and is unique. It is the Basic username.
- `basic_sha256` and `cert_sha256` are each exactly 64 lowercase hex characters.
  A client needs at least one. A `cert_sha256` is unique across clients.
- `feeds` is non-empty with no duplicates. Each entry is `<format>/<kind>` from
  the formats and kinds above, so `junos-dynamic-address/domain` is refused.
- Unknown fields are refused, and `version` must be `1`.
- An empty `clients` list is valid and closes every feed (all answer 401).
- The file is at most 1 MiB, and must be a regular file, not a symlink.

Add a Basic client:

1. Run `mecfeed-serve --generate-basic-password`. Stdout is the password: give
   it to the firewall. Stderr is `basic_sha256: <hex>`: put that in the file.
   The password is shown once and never stored.
2. Add the client to `clients.json`, then `systemctl restart mecfeed-serve`.

PAN-OS EDL. The source URL is `https://<serve host>:8443/feeds/panos-edl/<kind>`.
The certificate profile must trust the CA that signed serve's TLS certificate.
Client authentication takes the client's name and password. The option appears
only for an HTTPS source that has a certificate profile.

SRX Basic (Junos 25.2R1+). Set `user-name` and `password` under the feed
server, with the URL
`https://<serve host>:8443/feeds/junos-dynamic-address/<kind>`.

SRX mTLS:

1. Issue the SRX a client certificate from a client CA.
2. Start serve with `--client-ca <ca.pem>`. With systemd, copy the current
   `ExecStart` into a drop-in and add the flag, then `systemctl daemon-reload`
   and restart. With Docker, mount the CA and pass the flag after the image
   name, re-passing `--listen` and every `--allow-cidr`. `--client-ca` is
   required whenever a client has `cert_sha256`.
3. Pin the certificate: run `mecfeed-serve --print-cert-fingerprint <srx-cert.pem>`
   and put the output in the client's `cert_sha256`.
4. On the SRX, reference the local certificate in the SSL initiation profile.

Rotation. Edit the file and restart serve. A new Basic password needs a new
hash. Renewing a certificate changes its fingerprint, so update `cert_sha256`
too.

Upgrading (systemd/LXC):

1. Re-run the installer with `MECFEEDMCP_FORCE_UNIT=1`. It writes the starter
   list `{"version":1,"clients":[]}` (`0640 root:root`) if the file is absent.
2. Add the clients.
3. `systemctl daemon-reload && systemctl restart mecfeed-serve`
4. Set credentials on each firewall.

Until step 2, every feed answers 401.

Upgrading (Docker): create `clients.json`, readable by uid 65532 (`0644` is
fine: it holds only hashes of 32-byte secrets and fingerprints). Mount it at
`/etc/mecfeed-serve/clients.json:ro` and recreate the serve container.

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
