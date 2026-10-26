# mecfeed-serve client authentication (issue #4, auth slice)

mecfeed-serve authenticates each feed client by HTTP Basic or by a pinned
client certificate, and authorizes it per feed. Without an explicit opt-out it
refuses to serve feeds to anonymous clients.

## Goal and threat model

Today any host inside the `--allow-cidr` allowlist can read every feed. Feeds
reveal what the operator blocks, so any host in an allowed range, or a host
spoofing one, learns the block list. After this slice, a client must also prove
an identity, and that identity is limited to the feeds it is listed for.

The clients are lab firewalls with fixed capabilities:

- **PAN-OS 12.1 EDL** (lab `panosvm`). HTTP Basic only. The option appears only
  for an HTTPS source that has a server certificate profile. There is no client
  certificate option.
- **Junos 26.2 vSRX** (lab `vsrx-ci`). HTTP Basic (25.2R1 or later) through
  `user-name`/`password` under the feed server, or mTLS through a local
  certificate in an SSL initiation profile.

Out of scope, handled by later slices of #4:

- request header/size/time limits, a per-client rate limit, connection caps
- the structured access log in the mecmcp audit pipeline
- the threat-model document, fuzzing, and the security review
- hot reload of the client list (a restart applies changes)

## Decisions

- One client list. A client authenticates with Basic, with a pinned client
  certificate, or with either, and is allowed only its listed feeds. Both
  firewalls share one listener.
- Fail closed. Serve starts only with `--clients-file` or with
  `--allow-anonymous-feeds`. The two flags conflict, and exactly one is required.
- Basic secrets are generated, never chosen. `--generate-basic-password` makes 32
  random bytes, and the file stores only their SHA-256. A secret that long does
  not need a slow KDF, and no new crate is needed.
- Certificates: rustls checks the chain against `--client-ca`, and the list pins
  the SHA-256 of the leaf's DER. Renewing a certificate means updating its
  fingerprint.
- No new crate versions. `subtle`, `tokio-rustls`, `base64` and rustls'
  `WebPkiClientVerifier` are already in `Cargo.lock`.
- This builds on PR #25: its regular-file opener (`open_regular`) and the
  installer's `warn_if_exec_start_lacks`. Implementation starts after #25 merges,
  rebased onto it.

## 1. Client list, flags and helpers

`--clients-file <path>` names a JSON file:

```json
{"version": 1, "clients": [
  {"name": "panosvm", "basic_sha256": "<64 lowercase hex>", "feeds": ["panos-edl/address", "panos-edl/domain"]},
  {"name": "vsrx-ci", "cert_sha256": "<64 lowercase hex>", "feeds": ["junos-dynamic-address/address"]}
]}
```

Parsing is strict:

- `deny_unknown_fields` at every level, and `version` must be `1`.
- `name` is the Basic username. It matches `[A-Za-z0-9._-]{1,64}`, so it never
  contains `:` or whitespace. Names are unique.
- A client has `basic_sha256`, `cert_sha256`, or both. Each is exactly 64
  lowercase hex characters. A `cert_sha256` is unique across clients.
- `feeds` is non-empty. Each entry is `<format>/<kind>` using the existing
  route tokens (`parse_format`, `parse_kind`) where `FeedFormat::supports(kind)`
  holds, so a typo fails at startup. Duplicate entries are refused.
- An empty `clients` list is valid: serve starts and every feed answers 401.
- The file is read through the existing no-symlink, regular-file opener, capped
  at 1 MiB.

Flags:

- `--clients-file <path>` and `--allow-anonymous-feeds` conflict, and one is
  required.
- `--client-ca <pem>` is optional. It is required when any client has
  `cert_sha256`, and startup refuses a certificate client without it. It is also
  refused together with `--allow-anonymous-feeds`.
- `--allow-cidr` is unchanged and still runs first.

Helpers run after argument parsing and exit without serving:

- `--generate-basic-password` prints the password (32 random bytes, base64url,
  no padding) on stdout and `basic_sha256: <hex>` on stderr. The hash is the
  SHA-256 of the password's ASCII bytes, exactly as the firewall sends them.
- `--print-cert-fingerprint <pem>` prints the SHA-256 of the first certificate's
  DER as lowercase hex on stdout.

The helpers do not require the serving flags (`--tls-cert`, `--snapshot-dir`, and
so on), because operators run them on a workstation.

## 2. TLS and the request path

TLS:

- With `--client-ca`, the server config uses
  `WebPkiClientVerifier::builder_with_provider(roots, provider).allow_unauthenticated()`.
  A client may present no certificate. A certificate that fails the chain fails
  the handshake.
- Without `--client-ca`, TLS stays `with_no_client_auth()`.

Peer identity: a custom axum-server acceptor wraps the rustls acceptor. After
the handshake it reads `peer_certificates()`, hashes the leaf once per
connection, and adds `PeerCert(Option<[u8; 32]>)` as a request extension to
every request on that connection.

Middleware runs in this order:

1. The existing CIDR gate (403) for every route.
2. For `/feeds/{format}/{kind}`, client auth. It runs before the format and kind
   are parsed, so unauthenticated callers learn nothing about which feeds exist.
   `/healthz` stays CIDR-only.

Identification:

- **Certificate.** The client whose `cert_sha256` equals the peer fingerprint.
- **Basic.** `Authorization: Basic <std base64>` decoding to UTF-8 `user:password`,
  split at the first `:`. Its SHA-256 is compared with `subtle::ConstantTimeEq`
  against the named client's `basic_sha256`. An unknown user, or a client with
  no `basic_sha256`, is compared against a fixed dummy hash so timing does not
  reveal valid names.
- A header over 1 KiB, bad base64, invalid UTF-8, or no `:` counts as no
  credentials.
- A request is identified when either method matches. If both match different
  clients, the request is authorized when either client lists the feed.

Authorization: the request path's `<format>/<kind>` must be in an identified
client's `feeds`. The code compares the percent-decoded path segments, the ones the
handler uses, against the validated list. An unlisted or unknown path is not allowed.

Responses:

| Case | Status | Log reason |
|---|---|---|
| No usable credentials | 401, `WWW-Authenticate: Basic realm="mecfeed", charset="UTF-8"`, empty body | `no-credentials` |
| Basic user unknown | 401, same header | `unknown-user` |
| Basic password wrong | 401, same header | `bad-password` |
| Certificate valid for the CA but not listed, and no Basic match | 401, same header | `cert-not-listed` |
| Identified, feed not listed | 403, empty body | `feed-not-allowed` |
| Allowed | today's handler: 200/304/404/405/503 unchanged | none |

`--allow-anonymous-feeds` skips client auth, which gives today's behavior.

Each 401 and 403 logs a `tracing::info!` line with the client IP, the matched
client name when one exists, and the reason. Neither the `Authorization` header
nor the password is ever logged. HEAD goes through the same path as GET, which
matters because SRX checks freshness with HEAD.

## 3. Packaging, docs and rollout

systemd (`packaging/systemd/mecfeed-serve.service`):

- `LoadCredential=clients.json:/etc/mecfeed-serve/clients.json`
- ExecStart adds `--clients-file ${CREDENTIALS_DIRECTORY}/clients.json`.

Installer (`packaging/lxc/install.sh`):

- Creates `/etc/mecfeed-serve/clients.json` only if it is absent, as
  `{"version":1,"clients":[]}` with mode `0640` and owner `root:root`. It writes
  a temp file in the root-only directory and renames it into place, and never
  overwrites an existing file. `reject_unsafe_file` applies.
- `warn_if_exec_start_lacks` gains an alternative: the serve unit warns only
  when its effective ExecStart has neither `--clients-file` nor
  `--allow-anonymous-feeds`.
- Next steps add a step: generate a password, put the hash in `clients.json`,
  restart serve.
- `scripts/verify-packaging.sh` pins the new unit lines and the expected argv.

Docker (`Dockerfile.serve`): ENTRYPOINT adds
`--clients-file /etc/mecfeed-serve/clients.json`, and operators mount the file
read-only so that uid 65532 can read it. Mode `0644` is acceptable, because the
file holds only hashes of 32-byte secrets and certificate fingerprints. The CI
argv checks and the serve-image steps change to match.

Docs (`docs/operations.md`, new "Client authentication" section):

- the file format
- generating a password, and taking a certificate fingerprint
- PAN-OS EDL: HTTPS source, a certificate profile that trusts serve's CA, and
  client authentication with the name and password
- SRX Basic (25.2R1+)
- SRX mTLS: a local certificate in the SSL initiation profile, plus
  `--client-ca` and its fingerprint
- rotating a password or certificate (edit the file, restart)
- upgrading

CHANGELOG: a breaking bullet. After the upgrade, serve starts with the empty
list and answers 401 on every feed until clients are added.

Upgrade (systemd/LXC):

1. Re-run the installer with `MECFEEDMCP_FORCE_UNIT=1`.
2. Add the clients.
3. `systemctl daemon-reload` and restart serve.
4. Update each firewall's credentials.

Upgrade (Docker): create `clients.json`, mount it, and recreate serve.

## 4. Errors and testing

### Errors

Startup refuses, with a message naming the file and the field:

- a malformed client list
- a duplicate name, feed or certificate pin
- an unsupported feed
- a certificate client without `--client-ca`
- `--client-ca` together with `--allow-anonymous-feeds`
- an unreadable or unparseable CA file

Request-time failures are the 401 and 403 cases above. None of them changes how
the snapshot verify step behaves.

### Tests

Each negative test must fail against the current code.

- **Client-list parsing.** Valid lists load. Each of these is refused: an
  unknown field, a wrong version, a bad name charset, a duplicate name, a bad
  hex length, a client with no credential, empty `feeds`, a duplicate feed, an
  unknown format or kind, and `junos-dynamic-address/domain` (unsupported).
- **Startup.** A certificate client without `--client-ca` is refused, and so is
  `--client-ca` with `--allow-anonymous-feeds`. Neither flag being set is
  refused by clap.
- **Router** (tower `oneshot`):
  - no credentials gives 401 with the header, for a real feed and for an
    unknown path
  - an unknown user gives 401, and so does a wrong password
  - a right password gives 200 and keeps the ETag
  - a right password for an unlisted feed gives 403
  - HEAD without credentials gives 401
  - `/healthz` needs no credentials
  - anonymous mode serves as it does today
  - the response body and logs never contain the password
- **TLS** (a real server on an ephemeral port, rcgen CA and certificates,
  tokio-rustls client):
  - a pinned client certificate gives 200
  - a certificate the CA signed but that is not listed gives 401
  - a certificate from another CA fails the handshake
  - no certificate with good Basic gives 200
- **Helpers.** The generated password's hash matches `basic_sha256`, and the
  fingerprint matches the DER's SHA-256.
- **Package smoke.**
  - The starter `clients.json` is created `0640`, survives a re-run unchanged,
    and an existing file is never overwritten.
  - The serve-unit warning fires without either flag and stays quiet with
    either one.

The live checks with the lab PAN-OS and vSRX belong to #5.
