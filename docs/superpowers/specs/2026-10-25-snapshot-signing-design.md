# Snapshot signing (issue #4, signing slice)

The MCP server signs each published snapshot with Ed25519. mecfeed-serve
verifies the current snapshot's signature against operator-trusted public
keys before serving it.

## Goal and threat model

mecfeed-serve may run on a separate host and read a copied snapshot
directory. Today the digest chain proves the versions are internally
consistent, but anyone who can write that directory can write a new
consistent chain. With a signature, serve only serves a snapshot the MCP
server's key published.

Out of scope:

- how snapshots reach a separate serve host
- feed auth (mTLS/Basic)
- signing feed responses for SRX clients
- signing historical versions on demand

## Decisions

- Topology: serve may be on a separate host. The trust anchor is a public key file on the serve host.
- Key custody: a private key file owned by the MCP server user. No HSM and no KMS.
- Approach: a detached signature per version. Serve verifies only the current version's signature, plus the full digest chain as it does today.
- No unsigned mode. A current version without a valid signature is a 503.

## 1. Signature format

Each version directory gets one new file:

```
<snapshot_dir>/versions/<N>/snapshot.sig   mode 0640, same owner/group as snapshot.json
```

```json
{"version": 1, "key_id": "<16 lowercase hex>", "signature": "<standard base64 Ed25519 signature>"}
```

- `digest` is the snapshot document's existing `digest` field (64 lowercase hex characters, no prefix), decoded to 32 bytes.
- The signed message is `M = SHA-256(b"mecfeedmcp-snapshot-v1\0" || digest)`, 32 bytes. Ed25519 signs `M`.
  - The label keeps a snapshot signature from ever being valid as a mecmcp audit-head signature, or the reverse, if one key were reused.
  - mecmcp-audit's `sign_digest(s, key)` signs the 32 bytes decoded from `s`. The MCP server therefore calls it with `s = "sha256:" + hex(M)`.
- `key_id` is `hex(SHA-256(public_key_bytes)[..8])`.
- Parsing is strict:
  - unknown fields are rejected
  - `version` must be `1`
  - `key_id` must be exactly 16 lowercase hex characters
  - `signature` must base64-decode to 64 bytes
  - the file must be at most 4 KiB
- `snapshot.json`, its digest, `current` and the digest chain are unchanged.

### Shared definition (mecfeedmcp-core)

A new module `mecfeedmcp-core::signature` holds the pure functions, so the signer and the verifier cannot drift:

- `signed_message(digest: &str) -> Result<[u8; 32], SignatureError>`: parses the 64-hex digest and returns `M`.
- `signing_input(digest: &str) -> Result<String, SignatureError>`: `"sha256:" + hex(M)`, the exact string mecmcp-audit's `sign_digest` takes.
- `PublicKey::from_base64(text) -> Result<PublicKey, SignatureError>`: trims, decodes, and rejects weak keys. `PublicKey::key_id()` returns the 16-hex id.
- `parse_signature_file(bytes: &[u8]) -> Result<SignatureFile, SignatureError>`: applies the size cap and strict parse.
- `TrustedKeys::new(Vec<PublicKey>) -> Result<TrustedKeys, SignatureError>`: rejects an empty list and duplicate `key_id`s.
- `TrustedKeys::verify(digest, &SignatureFile) -> Result<(), SignatureError>`:
  - selects the key by `key_id`
  - checks with `ed25519_dalek::VerifyingKey::verify_strict` over `M`
- `SignatureError` variants: `InvalidDigest`, `InvalidKey`, `NoKeys`, `DuplicateKey`, `Malformed`, `UnknownKey`, `BadSignature`.
- `encode_signature_file(key_id: &str, signature_base64: &str) -> Vec<u8>`.

Core gains `ed25519-dalek` (3.0.0), `base64` (0.23.1) and `serde_json`. All three are already in `Cargo.lock`, the first two through mecmcp-audit, so no new crate versions enter the build. mecfeed-serve keeps no dependency on the mecmcp crates.

## 2. MCP server (signer)

- **New flag** `--snapshot-signing-key-file <path>`. It is optional to clap, so `token` and `--validate-package` still work without it, but serving bails without it.
  - Packaged path: `/var/lib/mecfeedmcp/snapshot-signing.key`, mode 0600, owner mecfeedmcp.
  - At startup the key file joins the existing `validate_startup_credentials` check as `CredentialFileRole::Secret` (0600, owner is the running user), then loads with mecmcp-audit `load_signing_key`. If the key is missing or invalid, the server refuses to start and names the path.
  - The server never generates a key.
- **New action flags.** mecmcp's shared CLI owns the subcommand enum, so these follow the existing `--validate-package` pattern. Each acts on `--snapshot-signing-key-file` and exits:
  - `--init-snapshot-signing-key`:
    - creates a new key with mecmcp-audit `generate_keypair` and `encode_signing_key`
    - writes it with create-new at mode 0600
    - refuses if the path exists and never truncates
    - prints the public key and `key_id`
  - `--print-snapshot-signing-public-key`: prints the base64 public key on stdout and the `key_id` on stderr. Its stdout is exactly a valid `.pub` file.
- **Apply order** (`store::write_snapshot_file`, called from `gate.rs`):
  1. Write `snapshot.json`.
  2. Re-read it and check its digest. This already happens.
  3. Write `snapshot.sig` with create-new, re-read it and parse it with `parse_signature_file`.
  4. `set_current`.

  If step 1, 2 or 3 fails, the version directory is removed and `current` doesn't move. The tool returns an error, and the change set stays approved so a retry works.
- **Rollback** goes through the same path, so it is signed too.
- **Open/startup** verifies the chain only and never reads `.sig`. A rotated key therefore can't block the MCP server from starting.
- **Key rotation (documented, no new command):**
  1. Add the new `.pub` to serve's trusted keys and restart serve.
  2. Switch the MCP key file and restart the MCP server.
  3. Publish once.
  4. Drop the old `.pub` from serve.

  There is no re-sign command.

## 3. mecfeed-serve (verifier)

- **New required, repeatable flag** `--trusted-snapshot-key <path>`.
  - Each file holds one base64 public key, the output of `--print-snapshot-signing-public-key`; surrounding whitespace is trimmed.
  - Serve refuses to start when no key is given, when a key is malformed, or when two keys share a `key_id`.
  - Changing trust requires a restart, the same as `--feed-config`.
- **Verification** happens in `snapshots::load`, after the chain and `current` checks pass:
  1. Read `versions/<current>/snapshot.sig` with the existing no-symlink, regular-file rules and the 4 KiB cap.
  2. Parse it with `parse_signature_file`.
  3. Call `TrustedKeys::verify(current_document.digest, &file)`.

  Historical versions' `.sig` files are never read.
- **Failures:** a missing `.sig`, a malformed file, an unknown `key_id` or a bad signature each fail the load. The client gets the same 503 body as any other load failure. The log line names which failure it was.
- **Caching:** the verified `Loaded` stays cached per `current` number, as today. A request re-verifies only when `current` moves.
  - Serve keeps the verified content in memory, so tampering with a file after the load changes nothing until the next load. That happens when `current` moves or serve restarts.

## 4. Packaging and key distribution

- **`packaging/lxc/install.sh` (same host, the packaged default):**
  - Create `/etc/mecfeed-serve` (0755 root) when absent.
  - If `/var/lib/mecfeedmcp/snapshot-signing.key` is absent, run `--init-snapshot-signing-key` as mecfeedmcp with `runuser -u mecfeedmcp --`. A staged install (`MECFEEDMCP_INSTALL_ROOT`) runs it as the invoking user.
  - If `/etc/mecfeed-serve/snapshot-signing.pub` is absent, write it from `--print-snapshot-signing-public-key` (run the same way) as mode 0644, owner root.
  - On re-runs, keep both files. If the `.pub` doesn't match the key, fail rather than overwrite trust.
  - The next steps print the public key and say that a serve on another host needs that `.pub` copied to `/etc/mecfeed-serve/` and named by `--trusted-snapshot-key`.
- **Units:**
  - `mecfeedmcp.service` gains `--snapshot-signing-key-file /var/lib/mecfeedmcp/snapshot-signing.key`.
  - `mecfeed-serve.service` gains `--trusted-snapshot-key /etc/mecfeed-serve/snapshot-signing.pub`. Serve's existing `ReadOnlyPaths=/etc/mecfeed-serve` covers the file.
  - The expected `ExecStart` in `install.sh` and in `scripts/verify-packaging.sh` changes with them.
- **`packaging/tests/package-smoke.sh`** checks the key is 0600 mecfeedmcp and the `.pub` is 0644 root, and that the two match.
- **Docker:**
  - `Dockerfile` ENTRYPOINT gains the signing-key flag. The key lives in the existing `/var/lib/mecfeedmcp` volume and is created with `docker run … mecfeedmcp --init-snapshot-signing-key`.
  - `Dockerfile.serve` ENTRYPOINT gains `--trusted-snapshot-key /etc/mecfeed-serve/snapshot-signing.pub`, mounted by the operator.
  - `server.json` documents the key in the existing volume; no new volume is added.
  - The CI container test runs `--init-snapshot-signing-key` and `--print-snapshot-signing-public-key` and checks the outputs.
- **Upgrade (`docs/operations.md`):**
  1. Stop both services.
  2. Re-run the installer with `MECFEEDMCP_FORCE_UNIT=1` so both units get the new flags.
  3. Start both services.
  4. Publish one new version (plan, approve, apply).

  Until step 4, serve returns 503, because existing versions have no `.sig`. Rollback refuses the current version, so it can't stand in for step 4.
- **CHANGELOG:** a breaking-change bullet for the new required flags and the one-time 503.

## 5. Errors and testing

### Errors

| Where | Condition | Result |
|---|---|---|
| MCP startup | key missing, wrong mode/owner, malformed | refuse to start; message names the path |
| MCP apply | sign or `.sig` write fails | version dir removed, `current` unchanged, tool error, change set still approved |
| `--init-snapshot-signing-key` | path exists | refuse; file untouched |
| serve startup | no trusted key, malformed key, duplicate `key_id` | refuse to start |
| serve load | `.sig` missing / malformed / unknown key / bad signature | 503 (same body as other load failures); log names the reason |

### Tests

- **Core** (`mecfeedmcp-core`):
  - sign then verify round-trips
  - a signature made with ed25519-dalek directly over `M` verifies, so core tests need no mecmcp dependency
  - a different digest, a wrong key, a truncated signature and an unknown `key_id` each fail with the matching error
  - unknown fields, `version != 1`, a bad `key_id` shape and more than 4 KiB are rejected
  - `key_id` is stable for a fixed key
  - duplicate trusted keys are rejected
- **MCP:**
  - a signature made by mecmcp-audit `sign_digest("sha256:"+hex(M))` verifies with core's `TrustedKeys::verify`. This cross-check lives in `mecfeedmcp`, which already depends on mecmcp-audit.
  - apply writes a `.sig` that verifies under the server's public key
  - an injected `.sig` write failure leaves `current` and the versions directory unchanged
  - rollback writes a valid `.sig`
  - the store opens with a `.sig` from a different key present
- **Serve:**
  - a signed current version gives 200
  - each of the following gives 503: a missing `.sig`, a tampered signature, an unknown key, and a `.sig` copied from another version
  - a corrupt `.sig` on a historical version still gives 200
  - with two trusted keys, a signature from either one gives 200
- **CLI:**
  - init then print round-trips, and the printed key parses with `PublicKey::from_base64`
  - init on an existing path fails and leaves the file byte-identical
  - the store refuses a `.sig` that does not parse on re-read and removes the version directory
- **Packaging:** the `verify-packaging.sh` checks, `package-smoke.sh` and the CI container test.
- **Live check on LXC 605** (`test-mecfeedmcp`, disposable):
  1. Upgrade it and confirm serve returns 503.
  2. Apply once and confirm 200.
  3. Tamper with the `.sig`, restart serve, and confirm 503. Without the restart, serve keeps serving the cached result, because `current` didn't move.
  4. Restore the `.sig`, restart serve, and confirm 200.
