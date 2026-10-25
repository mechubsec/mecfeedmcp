# Snapshot Signing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The MCP server signs every published snapshot with Ed25519. mecfeed-serve serves only a current snapshot whose detached signature verifies against an operator-trusted public key.

**Architecture:**

- `mecfeedmcp-core` gains a pure `signature` module that defines the signed bytes, the `snapshot.sig` format and verification. Both binaries use it.
- The MCP server signs through mecmcp-audit's `sign_digest` and writes `snapshot.sig` before `current` moves.
- mecfeed-serve verifies the current version's `.sig` after the existing chain check.
- Packaging creates the key, distributes the public key and wires the new flags.

**Tech Stack:** Rust 2024 workspace, ed25519-dalek 3.0.0, base64 0.23.1, serde_json, mecmcp-audit 0.28.1 (pinned), clap, axum, bash packaging scripts, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-25-snapshot-signing-design.md`

## Global Constraints

- **Signed message:** `M = SHA-256(b"mecfeedmcp-snapshot-v1\0" || D)`. `D` is the 32 bytes decoded from `SnapshotDocument.digest`, which is 64 lowercase hex characters with no prefix. Ed25519 signs `M`.
- **mecmcp signing input:** the MCP server calls mecmcp-audit `sign_digest` with `"sha256:" + hex(M)`. That function signs the 32 decoded bytes, so it signs `M`.
- **`snapshot.sig` format:**
  - JSON `{"version": 1, "key_id": "<16 lowercase hex>", "signature": "<standard base64 of 64 bytes>"}`
  - unknown fields rejected
  - at most 4096 bytes
  - lives beside `snapshot.json`, mode 0640
- **`key_id`:** lowercase hex of the first 8 bytes of SHA-256 of the 32-byte public key.
- **Verification:** with `ed25519_dalek::VerifyingKey::verify_strict`. Weak public keys are rejected when parsed.
- **No unsigned mode.** A current version without a valid `.sig` is a 503.
- **No new crate versions.** `Cargo.lock` may gain dependency edges, but must not gain new package entries. Use `ed25519-dalek = "3"` and `base64 = "0.23"`.
- `mecfeed-serve` must not depend on any `mecmcp-*` crate, not even as a dev-dependency.
- **Paths:**
  - `/var/lib/mecfeedmcp/snapshot-signing.key`: 0600, owner mecfeedmcp
  - `/etc/mecfeed-serve/snapshot-signing.pub`: 0644, owner root
- **Flags (exact names):**
  - mecfeedmcp: `--snapshot-signing-key-file <path>`, `--init-snapshot-signing-key`, `--print-snapshot-signing-public-key`
  - mecfeed-serve: `--trusted-snapshot-key <path>`, required and repeatable
- **Serve failures:** every signature failure returns the same 503 with an empty body that other load failures already produce. The existing `tracing::error!` line carries the reason through the `anyhow` context chain.
- **Style:**
  - doc comments on every public item
  - early returns
  - descriptive names; no single-letter variables except loop indices
  - match the surrounding code
- **Gates on every commit:**
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  - `cargo test --workspace --locked`
  - `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`
- **Shell changes:** `shellcheck` on every touched script, and `scripts/verify-packaging.sh` must pass.
- **Commit messages:**
  - plain imperative sentence, no `feat:` prefix (repo style, e.g. "Verify stored history without the operator allowlists on open")
  - end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`

---

### Task 1: Core signature module

**Files:**
- Modify: `Cargo.toml` (`[workspace.dependencies]`)
- Modify: `crates/mecfeedmcp-core/Cargo.toml`
- Modify: `crates/mecfeedmcp-core/src/version.rs` (make `to_hex` `pub(crate)`, near line 649)
- Modify: `crates/mecfeedmcp-core/src/lib.rs`
- Create: `crates/mecfeedmcp-core/src/signature.rs` (code and inline tests)

**Interfaces:**
- Consumes: nothing new.
- Produces. Every later task relies on these, all exported at the `mecfeedmcp_core` root:
  - `pub const SIGNATURE_FILE_NAME: &str = "snapshot.sig"`
  - `pub const SIGNATURE_FILE_MAX_BYTES: usize = 4096`
  - `pub enum SignatureError { InvalidDigest, InvalidKey, NoKeys, DuplicateKey, Malformed, UnknownKey, BadSignature }`, which is `Debug + Clone + Copy + PartialEq + Eq + std::error::Error`
  - `pub fn signed_message(digest: &str) -> Result<[u8; 32], SignatureError>`
  - `pub fn signing_input(digest: &str) -> Result<String, SignatureError>`, which returns `"sha256:" + hex(M)`
  - `pub struct PublicKey`, with `PublicKey::from_base64(&str) -> Result<PublicKey, SignatureError>` and `PublicKey::key_id(&self) -> &str`
  - `pub struct SignatureFile`, with `SignatureFile::key_id(&self) -> &str`
  - `pub fn parse_signature_file(bytes: &[u8]) -> Result<SignatureFile, SignatureError>`
  - `pub fn encode_signature_file(key_id: &str, signature_base64: &str) -> Vec<u8>`
  - `pub struct TrustedKeys` (`Clone`), with `TrustedKeys::new(Vec<PublicKey>) -> Result<TrustedKeys, SignatureError>` and `TrustedKeys::verify(&self, digest: &str, file: &SignatureFile) -> Result<(), SignatureError>`

- [ ] **Step 1: Add the dependencies**

In root `Cargo.toml` `[workspace.dependencies]`, add these in alphabetical position (after `axum-server`, and after `clap` respectively):

```toml
base64 = "0.23"
```

```toml
ed25519-dalek = "3"
```

In `crates/mecfeedmcp-core/Cargo.toml` `[dependencies]` (keep it alphabetical):

```toml
[dependencies]
base64.workspace = true
ed25519-dalek.workspace = true
ipnet.workspace = true
serde.workspace = true
serde_json.workspace = true
sha2.workspace = true
thiserror.workspace = true
```

In `crates/mecfeedmcp-core/src/version.rs`, change `fn to_hex(bytes: &[u8]) -> String {` to `pub(crate) fn to_hex(bytes: &[u8]) -> String {`.

- [ ] **Step 2: Write the module with failing tests first**

Create `crates/mecfeedmcp-core/src/signature.rs` containing only the `#[cfg(test)] mod tests` block below, plus `use` lines and stub signatures that return `unimplemented!()`. Wire it into `lib.rs` (Step 4) so it compiles. Run `cargo test -p mecfeedmcp-core signature` and expect failures or panics. Then replace the stubs with the implementation in Step 3.

Tests (the bottom of `signature.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const DIGEST: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public(key: &SigningKey) -> PublicKey {
        PublicKey::from_base64(&BASE64_STANDARD.encode(key.verifying_key().as_bytes()))
            .expect("public key")
    }

    fn sign_as(key_id: &str, key: &SigningKey, digest: &str) -> Vec<u8> {
        let signature = key.sign(&signed_message(digest).expect("message"));
        encode_signature_file(key_id, &BASE64_STANDARD.encode(signature.to_bytes()))
    }

    fn sign(key: &SigningKey, digest: &str) -> Vec<u8> {
        sign_as(public(key).key_id(), key, digest)
    }

    fn trusted(keys: &[&SigningKey]) -> TrustedKeys {
        TrustedKeys::new(keys.iter().map(|key| public(key)).collect()).expect("trusted")
    }

    #[test]
    fn a_signature_round_trips() {
        let key = signing_key(1);
        let file = parse_signature_file(&sign(&key, DIGEST)).expect("parse");
        assert_eq!(file.key_id(), public(&key).key_id());
        assert_eq!(trusted(&[&key]).verify(DIGEST, &file), Ok(()));
    }

    #[test]
    fn another_digest_key_or_signer_does_not_verify() {
        let key = signing_key(1);
        let file = parse_signature_file(&sign(&key, DIGEST)).expect("parse");
        let other_digest = DIGEST.replacen("00", "01", 1);
        assert_eq!(
            trusted(&[&key]).verify(&other_digest, &file),
            Err(SignatureError::BadSignature)
        );
        assert_eq!(
            trusted(&[&signing_key(2)]).verify(DIGEST, &file),
            Err(SignatureError::UnknownKey)
        );
        let forged = sign_as(public(&key).key_id(), &signing_key(2), DIGEST);
        let forged = parse_signature_file(&forged).expect("parse");
        assert_eq!(
            trusted(&[&key]).verify(DIGEST, &forged),
            Err(SignatureError::BadSignature)
        );
    }

    #[test]
    fn either_trusted_key_verifies() {
        let (first, second) = (signing_key(1), signing_key(2));
        let keys = trusted(&[&first, &second]);
        for key in [&first, &second] {
            let file = parse_signature_file(&sign(key, DIGEST)).expect("parse");
            assert_eq!(keys.verify(DIGEST, &file), Ok(()));
        }
    }

    #[test]
    fn signed_message_is_labelled_and_needs_lowercase_hex() {
        let mut hasher = Sha256::new();
        hasher.update(b"mecfeedmcp-snapshot-v1\0");
        hasher.update(decode_hex32(DIGEST).expect("hex"));
        let expected = hasher.finalize();
        let message = signed_message(DIGEST).expect("message");
        assert_eq!(message.as_slice(), expected.as_slice());
        assert_eq!(
            signing_input(DIGEST).expect("input"),
            format!("sha256:{}", to_hex(&message))
        );
        for bad in [
            DIGEST.to_uppercase(),
            format!("sha256:{DIGEST}"),
            DIGEST[..62].to_string(),
            format!("{}zz", &DIGEST[..62]),
        ] {
            assert_eq!(signed_message(&bad), Err(SignatureError::InvalidDigest));
        }
    }

    #[test]
    fn malformed_signature_files_are_rejected() {
        let key = signing_key(1);
        let good: serde_json::Value = serde_json::from_slice(&sign(&key, DIGEST)).expect("json");
        let with = |field: &str, value: serde_json::Value| {
            let mut copy = good.clone();
            copy[field] = value;
            copy.to_string().into_bytes()
        };
        for bytes in [
            with("version", 2.into()),
            with("key_id", "ABCDEF0123456789".into()),
            with("key_id", "abc".into()),
            with("signature", "AAAA".into()),
            with("signature", "not base64!".into()),
            with("extra", true.into()),
            b"not json".to_vec(),
            vec![b' '; SIGNATURE_FILE_MAX_BYTES + 1],
        ] {
            assert_eq!(parse_signature_file(&bytes), Err(SignatureError::Malformed));
        }
        let mut padded = sign(&key, DIGEST);
        padded.resize(SIGNATURE_FILE_MAX_BYTES, b' ');
        assert!(parse_signature_file(&padded).is_ok());
    }

    #[test]
    fn public_keys_and_trust_lists_are_checked() {
        let key = signing_key(1);
        let raw = key.verifying_key().to_bytes();
        let hash = Sha256::digest(raw);
        let (prefix, _) = hash.as_slice().split_at(8);
        assert_eq!(public(&key).key_id(), to_hex(prefix));
        let padded = format!("  {}\n", BASE64_STANDARD.encode(raw));
        assert_eq!(
            PublicKey::from_base64(&padded).expect("trimmed").key_id(),
            public(&key).key_id()
        );
        let mut identity = [0u8; 32];
        identity[0] = 1;
        for bad in [
            "not base64".to_string(),
            BASE64_STANDARD.encode([7u8; 31]),
            BASE64_STANDARD.encode(identity),
        ] {
            assert_eq!(
                PublicKey::from_base64(&bad).err(),
                Some(SignatureError::InvalidKey)
            );
        }
        assert_eq!(TrustedKeys::new(Vec::new()).err(), Some(SignatureError::NoKeys));
        assert_eq!(
            TrustedKeys::new(vec![public(&key), public(&key)]).err(),
            Some(SignatureError::DuplicateKey)
        );
    }
}
```

- [ ] **Step 3: Implement the module**

The top of `crates/mecfeedmcp-core/src/signature.rs`:

```rust
//! Detached Ed25519 signatures over published snapshots.
//!
//! The MCP server writes `versions/<N>/snapshot.sig` beside each
//! `snapshot.json`; mecfeed-serve verifies the current version's file before
//! serving it. Both sides use these functions so the format cannot drift.

use base64::prelude::*;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::version::to_hex;

/// File name of a version's detached signature.
pub const SIGNATURE_FILE_NAME: &str = "snapshot.sig";

/// Largest `snapshot.sig` either side accepts, in bytes.
pub const SIGNATURE_FILE_MAX_BYTES: usize = 4096;

/// Domain label, so a snapshot signature never passes as a mecmcp audit-head signature.
const LABEL: &[u8] = b"mecfeedmcp-snapshot-v1\0";

const FORMAT_VERSION: u32 = 1;

/// Why a snapshot signature or key was not accepted.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// The snapshot digest is not 64 lowercase hex characters.
    #[error("snapshot digest is not 64 lowercase hex characters")]
    InvalidDigest,
    /// A public key is not a usable base64 Ed25519 key.
    #[error("public key is not a valid base64 Ed25519 key")]
    InvalidKey,
    /// No trusted key was given.
    #[error("no trusted snapshot key was given")]
    NoKeys,
    /// Two trusted keys share a key id.
    #[error("two trusted snapshot keys share a key id")]
    DuplicateKey,
    /// The signature file is not the expected format.
    #[error("signature file is malformed")]
    Malformed,
    /// The signature names a key that is not trusted.
    #[error("signature names a key that is not trusted")]
    UnknownKey,
    /// The signature does not verify for this digest and key.
    #[error("signature does not verify")]
    BadSignature,
}

/// The 32 bytes Ed25519 signs for a snapshot `digest`: `SHA-256(label || digest bytes)`.
///
/// # Errors
///
/// Returns [`SignatureError::InvalidDigest`] unless `digest` is 64 lowercase hex characters.
pub fn signed_message(digest: &str) -> Result<[u8; 32], SignatureError> {
    let raw = decode_hex32(digest).ok_or(SignatureError::InvalidDigest)?;
    let mut hasher = Sha256::new();
    hasher.update(LABEL);
    hasher.update(raw);
    let mut message = [0u8; 32];
    message.copy_from_slice(hasher.finalize().as_slice());
    Ok(message)
}

/// [`signed_message`] as the `sha256:<hex>` string mecmcp-audit's `sign_digest` takes.
///
/// # Errors
///
/// Returns [`SignatureError::InvalidDigest`] as [`signed_message`] does.
pub fn signing_input(digest: &str) -> Result<String, SignatureError> {
    Ok(format!("sha256:{}", to_hex(&signed_message(digest)?)))
}

/// A trusted Ed25519 public key and its key id.
#[derive(Debug, Clone)]
pub struct PublicKey {
    key: VerifyingKey,
    key_id: String,
}

impl PublicKey {
    /// Parse one standard-base64 public key. Surrounding whitespace is ignored.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::InvalidKey`] for bad base64, a length other
    /// than 32 bytes, bytes that are not a curve point, or a weak key.
    pub fn from_base64(text: &str) -> Result<Self, SignatureError> {
        let bytes = BASE64_STANDARD
            .decode(text.trim())
            .map_err(|_| SignatureError::InvalidKey)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| SignatureError::InvalidKey)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| SignatureError::InvalidKey)?;
        if key.is_weak() {
            return Err(SignatureError::InvalidKey);
        }
        let hash = Sha256::digest(bytes);
        let (prefix, _) = hash.as_slice().split_at(8);
        Ok(Self {
            key,
            key_id: to_hex(prefix),
        })
    }

    /// First 8 bytes of SHA-256 of the key, as 16 lowercase hex characters.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// A parsed `snapshot.sig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFile {
    key_id: String,
    signature: [u8; 64],
}

impl SignatureFile {
    /// Id of the key that made the signature.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureFileJson {
    version: u32,
    key_id: String,
    signature: String,
}

/// Parse a `snapshot.sig`.
///
/// # Errors
///
/// Returns [`SignatureError::Malformed`] when the file exceeds
/// [`SIGNATURE_FILE_MAX_BYTES`], has unknown fields or another format version,
/// a key id that is not 16 lowercase hex characters, or a signature that is
/// not 64 bytes of standard base64.
pub fn parse_signature_file(bytes: &[u8]) -> Result<SignatureFile, SignatureError> {
    if bytes.len() > SIGNATURE_FILE_MAX_BYTES {
        return Err(SignatureError::Malformed);
    }
    let json: SignatureFileJson =
        serde_json::from_slice(bytes).map_err(|_| SignatureError::Malformed)?;
    if json.version != FORMAT_VERSION || !is_key_id(&json.key_id) {
        return Err(SignatureError::Malformed);
    }
    let signature = BASE64_STANDARD
        .decode(&json.signature)
        .map_err(|_| SignatureError::Malformed)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| SignatureError::Malformed)?;
    Ok(SignatureFile {
        key_id: json.key_id,
        signature,
    })
}

/// The `snapshot.sig` bytes for a base64 signature made by key `key_id`.
#[must_use]
pub fn encode_signature_file(key_id: &str, signature_base64: &str) -> Vec<u8> {
    serde_json::json!({
        "version": FORMAT_VERSION,
        "key_id": key_id,
        "signature": signature_base64,
    })
    .to_string()
    .into_bytes()
}

/// The keys mecfeed-serve accepts snapshot signatures from.
#[derive(Debug, Clone)]
pub struct TrustedKeys {
    keys: Vec<PublicKey>,
}

impl TrustedKeys {
    /// Build the trust list.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::NoKeys`] for an empty list and
    /// [`SignatureError::DuplicateKey`] when two keys share a key id.
    pub fn new(keys: Vec<PublicKey>) -> Result<Self, SignatureError> {
        if keys.is_empty() {
            return Err(SignatureError::NoKeys);
        }
        let duplicate = keys.iter().enumerate().any(|(index, key)| {
            keys.iter()
                .skip(index + 1)
                .any(|other| other.key_id == key.key_id)
        });
        if duplicate {
            return Err(SignatureError::DuplicateKey);
        }
        Ok(Self { keys })
    }

    /// Check `file` against the snapshot `digest` with the trusted key it names.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::InvalidDigest`], [`SignatureError::UnknownKey`],
    /// or [`SignatureError::BadSignature`].
    pub fn verify(&self, digest: &str, file: &SignatureFile) -> Result<(), SignatureError> {
        let message = signed_message(digest)?;
        let key = self
            .keys
            .iter()
            .find(|key| key.key_id == file.key_id)
            .ok_or(SignatureError::UnknownKey)?;
        key.key
            .verify_strict(&message, &Signature::from_bytes(&file.signature))
            .map_err(|_| SignatureError::BadSignature)
    }
}

fn is_key_id(text: &str) -> bool {
    text.len() == 16
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn decode_hex32(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let [high, low] = pair else {
            return None;
        };
        *slot = (nibble(*high)? << 4) | nibble(*low)?;
    }
    Some(out)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
```

- [ ] **Step 4: Export from `lib.rs`**

In `crates/mecfeedmcp-core/src/lib.rs`:
- Add `mod signature;` between `mod render;` and `mod two_label_public_suffixes;`.
- Add, after the `pub use render::...` line:

```rust
pub use signature::{
    PublicKey, SIGNATURE_FILE_MAX_BYTES, SIGNATURE_FILE_NAME, SignatureError, SignatureFile,
    TrustedKeys, encode_signature_file, parse_signature_file, signed_message, signing_input,
};
```

Change the crate doc's first line to: `//! Indicator admission, snapshot versions and signatures, and vendor feed renderers.`

- [ ] **Step 5: Run the tests**

Run: `cargo test -p mecfeedmcp-core signature`
Expected: 6 tests pass.

Run: `git diff Cargo.lock`
Expected: only new lines inside the `mecfeedmcp-core` package's `dependencies` list (`"base64 0.23.1"`, `"ed25519-dalek"`, `"serde_json"`). No new `[[package]]` entries. If a `[[package]]` entry appears, stop and report: that would be a new crate version.

Then run the Global Constraints gates.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/mecfeedmcp-core
git commit -m "Define the snapshot signature format in core

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: MCP snapshot key helpers

**Files:**
- Create: `crates/mecfeedmcp/src/snapshot_key.rs` (code and inline tests)
- Modify: `crates/mecfeedmcp/src/lib.rs`

**Interfaces:**
- Consumes: from Task 1, `mecfeedmcp_core::{PublicKey, SignatureError, encode_signature_file, signing_input}`.
- Produces:
  - `pub enum SnapshotKeyError`
  - `pub fn init_key_file(path: &Path) -> Result<(String, String), SnapshotKeyError>`, which returns `(public_base64, key_id)`
  - `pub fn public_key_text(key: &mecmcp_audit::signing::SigningKey) -> Result<(String, String), SnapshotKeyError>`, which returns `(public_base64, key_id)`
  - `pub(crate) fn signature_file(digest: &str, key: &SigningKey) -> Result<Vec<u8>, SnapshotKeyError>`
  - Exported from the crate root: `SnapshotKeyError`, `init_key_file`, `public_key_text`.

- [ ] **Step 1: Write the failing tests**

Create `crates/mecfeedmcp/src/snapshot_key.rs` with stubs that return `unimplemented!()`, plus this test module:

```rust
#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use mecfeedmcp_core::{PublicKey, SignatureError, TrustedKeys, parse_signature_file};
    use mecmcp_audit::signing as audit_signing;

    use super::{SnapshotKeyError, init_key_file, public_key_text, signature_file};

    const DIGEST: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn a_mecmcp_signature_verifies_with_core() {
        let (key, _) = audit_signing::generate_keypair();
        let bytes = signature_file(DIGEST, &key).expect("sign");
        let (text, key_id) = public_key_text(&key).expect("public");
        let file = parse_signature_file(&bytes).expect("parse");
        assert_eq!(file.key_id(), key_id);
        let trusted =
            TrustedKeys::new(vec![PublicKey::from_base64(&text).expect("key")]).expect("trusted");
        assert_eq!(trusted.verify(DIGEST, &file), Ok(()));
        let other_digest = DIGEST.replacen("00", "01", 1);
        assert_eq!(
            trusted.verify(&other_digest, &file),
            Err(SignatureError::BadSignature)
        );
    }

    #[test]
    fn signing_refuses_a_digest_that_is_not_hex() {
        let (key, _) = audit_signing::generate_keypair();
        assert!(matches!(
            signature_file("sha256:00", &key),
            Err(SnapshotKeyError::Format(SignatureError::InvalidDigest))
        ));
    }

    #[test]
    fn init_creates_a_0600_key_and_never_overwrites() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("snapshot-signing.key");
        let created = init_key_file(&path).expect("init");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let loaded = audit_signing::load_signing_key(&path).expect("load");
        assert_eq!(public_key_text(&loaded).expect("public"), created);
        let before = fs::read(&path).expect("read");
        assert!(matches!(
            init_key_file(&path),
            Err(SnapshotKeyError::Exists(_))
        ));
        assert_eq!(fs::read(&path).expect("read"), before);
    }
}
```

Run: `cargo test -p mecfeedmcp snapshot_key`
Expected: it fails (panics in the stubs).

- [ ] **Step 2: Implement**

The top of `crates/mecfeedmcp/src/snapshot_key.rs`:

```rust
//! The snapshot signing key: creating it, its public half, and signing a digest.
//! The signature format lives in `mecfeedmcp_core`.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use mecfeedmcp_core::{PublicKey, SignatureError, encode_signature_file, signing_input};
use mecmcp_audit::signing::{self as audit_signing, SigningError, SigningKey};
use thiserror::Error;

/// Why a snapshot key operation failed.
#[derive(Debug, Error)]
pub enum SnapshotKeyError {
    /// The key file already exists. It is never overwritten.
    #[error("snapshot signing key {} already exists", .0.display())]
    Exists(PathBuf),
    /// The key file could not be created or written.
    #[error("writing snapshot signing key {}: {error}", path.display())]
    Write {
        /// The key file path.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        error: std::io::Error,
    },
    /// mecmcp-audit refused the key or the signing input.
    #[error(transparent)]
    Signing(#[from] SigningError),
    /// The digest or the public key does not fit the snapshot signature format.
    #[error(transparent)]
    Format(#[from] SignatureError),
}

/// Create a new signing key at `path` with mode 0600 and return its
/// `(public_base64, key_id)`. An existing path is refused and left untouched.
///
/// # Errors
///
/// Returns [`SnapshotKeyError::Exists`] when `path` exists, and
/// [`SnapshotKeyError::Write`] when it cannot be created or written.
pub fn init_key_file(path: &Path) -> Result<(String, String), SnapshotKeyError> {
    let (key, _) = audit_signing::generate_keypair();
    let write_error = |error: std::io::Error| SnapshotKeyError::Write {
        path: path.to_path_buf(),
        error,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| match error.kind() {
            ErrorKind::AlreadyExists => SnapshotKeyError::Exists(path.to_path_buf()),
            _ => write_error(error),
        })?;
    file.write_all(audit_signing::encode_signing_key(&key).as_bytes())
        .map_err(write_error)?;
    file.sync_all().map_err(write_error)?;
    public_key_text(&key)
}

/// The public half of `key` as `(public_base64, key_id)`. The base64 text is
/// exactly what a `--trusted-snapshot-key` file holds.
///
/// # Errors
///
/// Returns [`SnapshotKeyError::Format`] if the public key does not parse.
pub fn public_key_text(key: &SigningKey) -> Result<(String, String), SnapshotKeyError> {
    let text = audit_signing::encode_verifying_key(&key.verifying_key());
    let key_id = PublicKey::from_base64(&text)?.key_id().to_string();
    Ok((text, key_id))
}

/// The `snapshot.sig` bytes for snapshot `digest`, signed by `key`.
pub(crate) fn signature_file(digest: &str, key: &SigningKey) -> Result<Vec<u8>, SnapshotKeyError> {
    let signed = audit_signing::sign_digest(&signing_input(digest)?, key)?;
    let (_, key_id) = public_key_text(key)?;
    Ok(encode_signature_file(
        &key_id,
        &audit_signing::encode_signature(&signed),
    ))
}
```

In `crates/mecfeedmcp/src/lib.rs`, add `mod snapshot_key;` after `mod signals;`, and add after the `pub use signals::...` line:

```rust
pub use snapshot_key::{SnapshotKeyError, init_key_file, public_key_text};
```

`signature_file` is `pub(crate)`, and Task 3 uses it from `gate.rs`. Until then it is dead code outside tests. If clippy `-D warnings` flags it, add `#[cfg_attr(not(test), allow(dead_code))] // used by gate.rs from the next commit` above it. Task 3 removes that attribute.

- [ ] **Step 3: Run the tests**

Run: `cargo test -p mecfeedmcp snapshot_key`
Expected: 3 tests pass. Then run the Global Constraints gates.

- [ ] **Step 4: Commit**

```bash
git add crates/mecfeedmcp/src/snapshot_key.rs crates/mecfeedmcp/src/lib.rs
git commit -m "Add snapshot signing key creation and signing helpers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Sign every publish and require the key to serve

**Files:**
- Modify: `crates/mecfeedmcp/src/store.rs`:
  - `write_snapshot_file` (lines 55-70)
  - add `write_signature` beside `write_snapshot` (~line 197)
- Modify: `crates/mecfeedmcp/src/gate.rs`:
  - `Inner` (line 133)
  - `FeedPublisher::open` (line 180)
  - `FeedTransaction::commit` (lines 600-625)
  - the tests module (line 823 onward)
- Modify: `crates/mecfeedmcp/src/handler.rs`: the test fixture at line 788
- Modify: `crates/mecfeedmcp/src/main.rs`:
  - `ServerCli`
  - the destructure at line 444
  - `validate_startup_credentials` (line 389) and its call at line 474
  - the `FeedPublisher::open` call at line 548
- Modify: `crates/mecfeedmcp/src/snapshot_key.rs`: remove the temporary `dead_code` attribute if Task 2 added it

**Interfaces:**
- Consumes:
  - from Task 2: `crate::snapshot_key::signature_file`, `mecfeedmcp::init_key_file` and `mecfeedmcp::public_key_text`
  - from Task 1: `mecfeedmcp_core::{SIGNATURE_FILE_NAME, parse_signature_file, PublicKey, TrustedKeys}`
- Produces:
  - `FeedPublisher::open(snapshot_dir: &Path, state_file: &Path, policy: Policy, device: &str, lab_mode: bool, approval_ttl: Duration, signing_key: mecmcp_audit::signing::SigningKey) -> Result<Self, GateError>`. There is one new last parameter.
  - `store::write_snapshot_file(dir: &Path, document: &SnapshotDocument, signature: &[u8]) -> Result<(), StoreError>`
  - On `ServerCli`: `snapshot_signing_key_file: Option<PathBuf>` (`--snapshot-signing-key-file`)

- [ ] **Step 1: Write the failing gate tests**

In the `gate.rs` tests module:

1. Extend `Fixture` with `key: std::path::PathBuf` and `public: String`.
2. `fixture()` creates the key:

```rust
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("snapshot-signing.key");
        let (public, _) = crate::init_key_file(&key).expect("signing key");
        Fixture {
            snapshots: dir.path().join("snapshots"),
            state: dir.path().join("changeset-state.json"),
            key,
            public,
            _dir: dir,
        }
    }

    fn signing_key(fix: &Fixture) -> mecmcp_audit::signing::SigningKey {
        mecmcp_audit::signing::load_signing_key(&fix.key).expect("load signing key")
    }

    fn assert_signed(fix: &Fixture, version: u64, digest: &str) {
        let path = fix
            .snapshots
            .join(format!("versions/{version}/{}", mecfeedmcp_core::SIGNATURE_FILE_NAME));
        let file = mecfeedmcp_core::parse_signature_file(&fs::read(path).expect("sig"))
            .expect("parse sig");
        let trusted = mecfeedmcp_core::TrustedKeys::new(vec![
            mecfeedmcp_core::PublicKey::from_base64(&fix.public).expect("public key"),
        ])
        .expect("trusted");
        assert_eq!(trusted.verify(digest, &file), Ok(()));
    }
```

3. `open()` and every direct `FeedPublisher::open(` call in this module (about lines 947, 977 and 1101) pass `signing_key(&fix)` (or `signing_key(fix)`) as the new last argument.
4. Add the tests:

```rust
    #[tokio::test]
    async fn apply_writes_a_signature_that_verifies() {
        let fix = fixture();
        let publisher = open(&fix, false);
        let plan = publisher
            .plan("alice", one("1.0.0.1"), NOW)
            .await
            .expect("plan");
        publisher
            .approve("bob", true, &plan.change_set_id, &plan.digest)
            .await
            .expect("approve");
        let published = publisher
            .apply("alice", &attr(), &plan.change_set_id, &plan.digest, NOW)
            .await
            .expect("apply");
        assert_signed(&fix, 1, &published.digest);
    }

    #[tokio::test]
    async fn reopen_with_a_rotated_key_keeps_the_log() {
        let fix = fixture();
        {
            let publisher = open(&fix, true);
            let plan = publisher
                .plan("alice", one("1.0.0.1"), NOW)
                .await
                .expect("plan");
            publisher
                .waive("alice", &plan.change_set_id, &plan.digest)
                .await
                .expect("waive");
            publisher
                .apply("alice", &attr(), &plan.change_set_id, &plan.digest, NOW)
                .await
                .expect("apply");
        }
        let (rotated, _) = mecmcp_audit::signing::generate_keypair();
        let publisher = FeedPublisher::open(
            &fix.snapshots,
            &fix.state,
            policy(),
            "lab",
            true,
            Duration::from_secs(900),
            rotated,
        )
        .expect("open ignores signatures");
        assert!(publisher.latest().expect("lock").is_some());
    }

    #[test]
    fn a_signature_that_does_not_parse_removes_the_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut versions = mecfeedmcp_core::FeedVersions::open(policy());
        versions.publish(&one("1.0.0.1"), NOW).expect("publish");
        let document = versions.document(1).expect("document");
        assert!(crate::store::write_snapshot_file(dir.path(), &document, b"not json").is_err());
        assert!(!dir.path().join("versions/1").exists());
    }
```

5. In `rollback_publishes_the_earlier_rows`, add at the end: `assert_signed(&fix, 3, &published.digest);`.

In `handler.rs` (around line 788), pass `mecmcp_audit::signing::generate_keypair().0` as the new last argument to `FeedPublisher::open`.

Run: `cargo test -p mecfeedmcp`
Expected: a compile error, because `open` takes 6 arguments. That confirms the tests drive the change.

- [ ] **Step 2: Store writes and re-checks the signature**

In `store.rs`, add `SIGNATURE_FILE_NAME, parse_signature_file` to the `mecfeedmcp_core` import. Replace `write_snapshot_file` with:

```rust
/// Write version `document.number` and its detached `signature`, re-reading both.
///
/// # Errors
///
/// Returns [`StoreError`] when a file cannot be written and re-read, or the
/// signature does not parse. A failure removes the version directory.
pub fn write_snapshot_file(
    dir: &Path,
    document: &SnapshotDocument,
    signature: &[u8],
) -> Result<(), StoreError> {
    let version_dir = version_dir(dir, document.number)?;
    if version_dir.symlink_metadata().is_ok() {
        return Err(StoreError::File);
    }
    fs::create_dir_all(&version_dir).map_err(|_| StoreError::File)?;
    let published = write_snapshot(&version_dir, document)
        .and_then(|()| write_signature(&version_dir, signature));
    if published.is_err() {
        let _ = fs::remove_dir_all(&version_dir);
    }
    published
}
```

Add after `write_snapshot`:

```rust
fn write_signature(version_dir: &Path, signature: &[u8]) -> Result<(), StoreError> {
    let partial = version_dir.join(format!("{SIGNATURE_FILE_NAME}.partial"));
    let final_path = version_dir.join(SIGNATURE_FILE_NAME);
    if is_symlink(&partial) || is_symlink(&final_path) {
        return Err(StoreError::File);
    }
    write_new(&partial, signature)?;
    fs::rename(&partial, &final_path).map_err(|_| StoreError::File)?;
    let mut read_back = Vec::new();
    File::open(&final_path)
        .and_then(|mut file| file.read_to_end(&mut read_back))
        .map_err(|_| StoreError::File)?;
    if read_back != signature || parse_signature_file(&read_back).is_err() {
        return Err(StoreError::File);
    }
    // current must never name a version whose signature is not durable.
    sync_dir(version_dir)
}
```

Update the module doc's second line to: `//! A snapshot is current only after its file and signature are re-read and the pointer moves.`

- [ ] **Step 3: The gate holds the key and signs in `commit`**

In `gate.rs`:
- Add `use mecmcp_audit::signing::SigningKey;` to the imports.
- Change `Inner` to:

```rust
struct Inner {
    versions: FeedVersions,
    snapshot_dir: std::path::PathBuf,
    signing_key: SigningKey,
}
```

- `FeedPublisher::open` gains a last parameter `signing_key: SigningKey` and stores it in `Inner`. Add one line to its doc: `/// Every snapshot this publisher writes is signed with signing_key.`
- In `commit`, replace the `store::write_snapshot_file(...)` line with:

```rust
        let document = planned.document();
        let signature = crate::snapshot_key::signature_file(&document.digest, &inner.signing_key)
            .map_err(|_| TxError::Store)?;
        store::write_snapshot_file(&inner.snapshot_dir, &document, &signature)
            .map_err(|_| TxError::Store)?;
```

The existing `let document = planned.document();` line stays; insert the `signature` line after it. Remove the temporary `dead_code` attribute from `snapshot_key.rs` if Task 2 added one.

- [ ] **Step 4: `main.rs` requires the key to serve**

Add to `ServerCli`, after `approval_timeout_secs`:

```rust
    /// Ed25519 key that signs each published snapshot (mode 0600, owned by the service user).
    #[arg(long)]
    snapshot_signing_key_file: Option<PathBuf>,
```

Add `snapshot_signing_key_file,` to the `let ServerCli { ... } = parsed.cli;` destructure.

Give `validate_startup_credentials` a fifth parameter, `snapshot_signing_key: Option<&Path>`, and change `Vec::with_capacity(4)` to `5`. Add:

```rust
    if let Some(path) = snapshot_signing_key {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "snapshot signing key",
            required: true,
        });
    }
```

Pass `snapshot_signing_key_file.as_deref()` at the call site (line 474).

Immediately before `let publisher = FeedPublisher::open(`:

```rust
    let signing_key_file = snapshot_signing_key_file
        .context("--snapshot-signing-key-file is required to publish snapshots")?;
    let signing_key = mecmcp_audit::signing::load_signing_key(&signing_key_file)
        .with_context(|| format!("loading {}", signing_key_file.display()))?;
```

Then pass `signing_key` as the last argument to `FeedPublisher::open`.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p mecfeedmcp`
Expected: all pass, including the three new tests and the extended rollback test. Then run the Global Constraints gates.

- [ ] **Step 6: Commit**

```bash
git add crates/mecfeedmcp
git commit -m "Sign each published snapshot and require the signing key to serve

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Key init and print flags

**Files:**
- Modify: `crates/mecfeedmcp/src/main.rs`:
  - `ServerCli`
  - `main` (early-return block after `validate_package`, ~line 437)
  - a new helper
  - the tests module (line 680)

**Interfaces:**
- Consumes:
  - from Task 2: `mecfeedmcp::{init_key_file, public_key_text}`
  - from Task 3: the `snapshot_signing_key_file` field
- Produces: CLI flags `--init-snapshot-signing-key` and `--print-snapshot-signing-public-key`. Both print the base64 public key alone on stdout and `snapshot signing key id: <id>` on stderr, then exit 0. Task 6 relies on stdout being exactly one base64 line.

- [ ] **Step 1: Write the failing tests**

In the `main.rs` tests module (it already has `use super::*` or an equivalent; follow what is there):

```rust
    #[test]
    fn key_flags_need_the_key_file_and_exclude_each_other() {
        use clap::Parser as _;
        assert!(ServerCli::try_parse_from(["mecfeedmcp", "--init-snapshot-signing-key"]).is_err());
        assert!(
            ServerCli::try_parse_from([
                "mecfeedmcp",
                "--snapshot-signing-key-file",
                "/tmp/k",
                "--init-snapshot-signing-key",
                "--print-snapshot-signing-public-key",
            ])
            .is_err()
        );
        let parsed = ServerCli::try_parse_from([
            "mecfeedmcp",
            "--snapshot-signing-key-file",
            "/tmp/k",
            "--print-snapshot-signing-public-key",
        ])
        .expect("parse");
        assert!(parsed.print_snapshot_signing_public_key);
    }

    #[test]
    fn init_then_print_agree_and_init_never_overwrites() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("snapshot-signing.key");
        let created = snapshot_key_action(&path, true).expect("init");
        assert_eq!(snapshot_key_action(&path, false).expect("print"), created);
        mecfeedmcp_core::PublicKey::from_base64(&created.0).expect("printed key parses");
        let before = fs::read(&path).expect("read");
        assert!(snapshot_key_action(&path, true).is_err());
        assert_eq!(fs::read(&path).expect("read"), before);
    }
```

If `mecfeedmcp_core` is not a direct dependency of the `mecfeedmcp` crate, check `crates/mecfeedmcp/Cargo.toml`. It is: `gate.rs` imports it.

Run: `cargo test -p mecfeedmcp key_flags init_then_print`
Expected: a compile error, because the fields and `snapshot_key_action` don't exist yet.

- [ ] **Step 2: Implement**

Add to `ServerCli`, after `snapshot_signing_key_file`:

```rust
    /// Create a new key at --snapshot-signing-key-file, print its public key, then exit.
    #[arg(
        long,
        requires = "snapshot_signing_key_file",
        conflicts_with = "print_snapshot_signing_public_key"
    )]
    init_snapshot_signing_key: bool,

    /// Print the public key of --snapshot-signing-key-file, then exit.
    #[arg(long, requires = "snapshot_signing_key_file")]
    print_snapshot_signing_public_key: bool,
```

Add the helper next to `validate_package`:

```rust
/// Create (`init`) or load the snapshot signing key and return `(public_base64, key_id)`.
fn snapshot_key_action(path: &Path, init: bool) -> Result<(String, String)> {
    if init {
        return mecfeedmcp::init_key_file(path).map_err(anyhow::Error::from);
    }
    let key = mecmcp_audit::signing::load_signing_key(path)
        .with_context(|| format!("loading {}", path.display()))?;
    mecfeedmcp::public_key_text(&key).map_err(anyhow::Error::from)
}
```

In `main`, right after the `validate_package` early return:

```rust
    let cli = &parsed.cli;
    if cli.init_snapshot_signing_key || cli.print_snapshot_signing_public_key {
        let path = cli
            .snapshot_signing_key_file
            .as_deref()
            .context("--snapshot-signing-key-file is required")?;
        let (public_key, key_id) = snapshot_key_action(path, cli.init_snapshot_signing_key)?;
        println!("{public_key}");
        eprintln!("snapshot signing key id: {key_id}");
        return Ok(());
    }
```

Add `init_snapshot_signing_key: _, print_snapshot_signing_public_key: _,` to the `let ServerCli { ... }` destructure.

- [ ] **Step 3: Run the tests**

Run: `cargo test -p mecfeedmcp`
Expected: all pass. Then run the Global Constraints gates.

Manual check:
1. `cargo run -q -p mecfeedmcp -- --snapshot-signing-key-file "$TMP/k" --init-snapshot-signing-key` prints one base64 line, and the key id on stderr.
2. Running it again fails with "already exists".

- [ ] **Step 4: Commit**

```bash
git add crates/mecfeedmcp/src/main.rs
git commit -m "Add flags that create and print the snapshot signing key

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: mecfeed-serve verifies the current signature

**Files:**
- Modify: `Cargo.toml`: nothing beyond Task 1. `base64` and `ed25519-dalek` are already workspace dependencies.
- Modify: `crates/mecfeed-serve/Cargo.toml`: dev-dependencies
- Modify: `crates/mecfeed-serve/src/snapshots.rs`:
  - the module doc
  - `load`
  - a new `read_signature`
- Modify: `crates/mecfeed-serve/src/main.rs`:
  - `Args`
  - `App`
  - `main`
  - `verified` (line 290)
  - a new `load_trusted_keys`
  - the tests module (424 onward)

**Interfaces:**
- Consumes: from Task 1, `mecfeedmcp_core::{PublicKey, TrustedKeys, SIGNATURE_FILE_NAME, SIGNATURE_FILE_MAX_BYTES, parse_signature_file, SignatureFile, signed_message, encode_signature_file}`.
- Produces:
  - `snapshots::load(dir: &Path, policy: Policy, trusted: &TrustedKeys) -> Result<Loaded>`
  - `--trusted-snapshot-key <path>`, required and repeatable

- [ ] **Step 1: Add the dev-dependencies**

In `crates/mecfeed-serve/Cargo.toml` `[dev-dependencies]` (alphabetical):

```toml
[dev-dependencies]
base64.workspace = true
ed25519-dalek.workspace = true
rcgen = "0.14.10"
tempfile = "3.27.0"
tower = { version = "0.5.3", features = ["util"] }
```

- [ ] **Step 2: Write the failing tests**

In the `main.rs` tests module:

- Add imports:

```rust
    use super::load_trusted_keys;
    use base64::prelude::*;
    use ed25519_dalek::{Signer, SigningKey};
    use mecfeedmcp_core::{PublicKey, TrustedKeys, encode_signature_file, signed_message};
```

- Add helpers:

```rust
    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public_text(key: &SigningKey) -> String {
        BASE64_STANDARD.encode(key.verifying_key().as_bytes())
    }

    fn trusted(keys: &[&SigningKey]) -> TrustedKeys {
        TrustedKeys::new(
            keys.iter()
                .map(|key| PublicKey::from_base64(&public_text(key)).expect("public key"))
                .collect(),
        )
        .expect("trusted")
    }

    /// `snapshot.sig` bytes for `digest`, signed by `key`.
    fn signature_for(key: &SigningKey, digest: &str) -> Vec<u8> {
        let key_id = PublicKey::from_base64(&public_text(key))
            .expect("public key")
            .key_id()
            .to_string();
        let signature = key.sign(&signed_message(digest).expect("message"));
        encode_signature_file(&key_id, &BASE64_STANDARD.encode(signature.to_bytes()))
    }

    fn sig_path(dir: &Path, version: u64) -> std::path::PathBuf {
        dir.join(format!("versions/{version}/snapshot.sig"))
    }
```

- Change `write_layout` so that each version also gets its signature from `test_key(1)`. Add this inside the loop after the `snapshot.json` write:

```rust
            std::fs::write(
                version_dir.join("snapshot.sig"),
                signature_for(&test_key(1), &document.digest),
            )
            .expect("write signature");
```

- Replace `app_with_policy` and add the helpers below:

```rust
    fn app_with_policy(dir: &Path, peer: [u8; 4], policy: Policy) -> axum::Router {
        app_with(dir, peer, policy, trusted(&[&test_key(1)]))
    }

    fn app_with_trust(dir: &Path, keys: TrustedKeys) -> axum::Router {
        app_with(dir, [127, 0, 0, 1], empty_policy(), keys)
    }

    fn app_with(dir: &Path, peer: [u8; 4], policy: Policy, keys: TrustedKeys) -> axum::Router {
        router(App {
            snapshot_dir: dir.to_path_buf(),
            allow: vec!["127.0.0.0/8".parse().expect("loopback")],
            policy,
            trusted: keys,
            reload: std::sync::Arc::default(),
            cache: std::sync::Arc::default(),
        })
        .layer(MockConnectInfo(SocketAddr::from((peer, 1))))
    }

    fn two_version_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let at = now();
        let mut versions = feed_versions();
        publish(&mut versions, at, vec![entry(IndicatorKind::Ip, "1.0.0.1", at, at + DAY)]);
        publish(&mut versions, at, vec![entry(IndicatorKind::Ip, "1.0.0.3", at, at + DAY)]);
        write_layout(dir.path(), &versions, 2, 2);
        dir
    }

    fn feed_document_digest(dir: &Path, version: u64) -> String {
        let bytes = std::fs::read(dir.join(format!("versions/{version}/snapshot.json")))
            .expect("read snapshot");
        serde_json::from_slice::<mecfeedmcp_core::SnapshotDocument>(&bytes)
            .expect("parse snapshot")
            .digest
    }
```

New tests (`URI` = `"/feeds/panos-edl/address"`):

```rust
    async fn status_of(app: &axum::Router) -> StatusCode {
        send(app, Method::GET, "/feeds/panos-edl/address", None).await.0
    }

    #[tokio::test]
    async fn missing_signature_fails_closed() {
        let dir = one_version_dir();
        std::fs::remove_file(sig_path(dir.path(), 1)).expect("remove");
        assert_eq!(status_of(&app(dir.path())).await, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn signature_by_an_untrusted_key_fails_closed() {
        let dir = one_version_dir();
        let digest = feed_document_digest(dir.path(), 1);
        std::fs::write(sig_path(dir.path(), 1), signature_for(&test_key(9), &digest)).expect("write");
        assert_eq!(status_of(&app(dir.path())).await, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn signature_over_another_digest_fails_closed() {
        let dir = one_version_dir();
        let other = "ab".repeat(32);
        std::fs::write(sig_path(dir.path(), 1), signature_for(&test_key(1), &other)).expect("write");
        assert_eq!(status_of(&app(dir.path())).await, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn signature_copied_from_another_version_fails_closed() {
        let dir = two_version_dir();
        std::fs::copy(sig_path(dir.path(), 1), sig_path(dir.path(), 2)).expect("copy");
        assert_eq!(status_of(&app(dir.path())).await, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_bad_historical_signature_is_not_read() {
        let dir = two_version_dir();
        std::fs::write(sig_path(dir.path(), 1), b"garbage").expect("write");
        assert_eq!(status_of(&app(dir.path())).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_symlinked_signature_fails_closed() {
        let dir = one_version_dir();
        let path = sig_path(dir.path(), 1);
        let real = dir.path().join("real.sig");
        std::fs::rename(&path, &real).expect("move");
        std::os::unix::fs::symlink(&real, &path).expect("symlink");
        assert_eq!(status_of(&app(dir.path())).await, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn either_of_two_trusted_keys_verifies() {
        let dir = one_version_dir();
        let digest = feed_document_digest(dir.path(), 1);
        std::fs::write(sig_path(dir.path(), 1), signature_for(&test_key(2), &digest)).expect("write");
        let keys = trusted(&[&test_key(1), &test_key(2)]);
        assert_eq!(status_of(&app_with_trust(dir.path(), keys)).await, StatusCode::OK);
    }

    #[test]
    fn trusted_key_files_are_checked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("good.pub");
        let bad = dir.path().join("bad.pub");
        std::fs::write(&good, format!("{}\n", public_text(&test_key(1)))).expect("write");
        std::fs::write(&bad, "not a key\n").expect("write");
        assert!(load_trusted_keys(std::slice::from_ref(&good)).is_ok());
        assert!(load_trusted_keys(&[]).is_err());
        assert!(load_trusted_keys(&[good.clone(), good.clone()]).is_err());
        assert!(load_trusted_keys(&[good, bad]).is_err());
        assert!(load_trusted_keys(&[dir.path().join("missing.pub")]).is_err());
    }
```

Every existing test must still pass unchanged: `write_layout` now signs, so all the existing happy paths stay 200.

Run: `cargo test -p mecfeed-serve`
Expected: a compile error, because `App.trusted` and `load_trusted_keys` don't exist yet.

- [ ] **Step 3: Implement the snapshots side**

In `snapshots.rs`:

- Extend the module doc's layout block with this line: `<dir>/versions/<N>/snapshot.sig   detached signature; only the current version's is read`
- Import `mecfeedmcp_core::{SIGNATURE_FILE_MAX_BYTES, SIGNATURE_FILE_NAME, SignatureFile, TrustedKeys, parse_signature_file}`.
- Add:

```rust
fn read_signature(version_dir: &Path) -> Result<SignatureFile> {
    let path = version_dir.join(SIGNATURE_FILE_NAME);
    if is_symlink(&path) {
        bail!("snapshot.sig is a symlink");
    }
    let file = File::open(&path).context("opening snapshot.sig")?;
    if !file.metadata().context("inspecting snapshot.sig")?.is_file() {
        bail!("snapshot.sig is not a regular file");
    }
    let mut bytes = Vec::new();
    // One byte past the cap, so an oversized file fails the parse instead of being truncated into one that passes.
    file.take(SIGNATURE_FILE_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("reading snapshot.sig")?;
    parse_signature_file(&bytes).context("parsing snapshot.sig")
}
```

- Change `load`'s signature to `pub fn load(dir: &Path, policy: Policy, trusted: &TrustedKeys) -> Result<Loaded>`. Add `# Errors` wording: "...or the current version's signature does not verify".
- In the loop, before `versions.import_document(document, 0)`, record `latest_digest = Some(document.digest.clone());`. Declare `let mut latest_digest: Option<String> = None;` before the loop.
- After the `if current != numbers.last().copied()` check, add:

```rust
    if let (Some(number), Some(digest)) = (current, latest_digest.as_deref()) {
        let signature = read_signature(&dir.join("versions").join(number.to_string()))?;
        trusted
            .verify(digest, &signature)
            .with_context(|| format!("version {number} signature does not verify"))?;
    }
```

`current == numbers.last()` has just been checked, so `latest_digest` is the current version's digest.

- [ ] **Step 4: Implement the main side**

In `main.rs`:

- Import `mecfeedmcp_core::{PublicKey, TrustedKeys}` (extend the existing `use mecfeedmcp_core::{...}`).
- Add to `Args`:

```rust
    /// Public key trusted to sign snapshots: a file holding one base64 Ed25519 key.
    /// Repeatable; at least one is required.
    #[arg(long = "trusted-snapshot-key", required = true)]
    trusted_snapshot_key: Vec<PathBuf>,
```

- Add:

```rust
/// Load every `--trusted-snapshot-key` file into one trust list.
///
/// # Errors
///
/// Returns an error when a file cannot be read or parsed, when none is given,
/// or when two files hold the same key.
fn load_trusted_keys(paths: &[PathBuf]) -> Result<TrustedKeys> {
    let keys = paths
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading trusted snapshot key {}", path.display()))?;
            PublicKey::from_base64(&text)
                .with_context(|| format!("parsing trusted snapshot key {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    TrustedKeys::new(keys).context("trusted snapshot keys are not acceptable")
}
```

- Add `trusted: TrustedKeys,` to `App`, after `policy`, with the doc comment `/// Keys the current snapshot's signature must verify against.`
- In `main`, after `let policy = load_policy(...)?;`, add `let trusted = load_trusted_keys(&args.trusted_snapshot_key)?;` and set `trusted` in the `App { ... }` literal.
- In `verified`, replace the load closure with:

```rust
    let policy = app.policy.clone();
    let trusted = app.trusted.clone();
    let loaded = Arc::new(
        tokio::task::spawn_blocking(move || snapshots::load(&dir, policy, &trusted))
            .await
            .context("loading snapshots panicked")??,
    );
```

- Change the `Args.snapshot_dir` doc from "Directory of signed, versioned snapshots" to "Directory of versioned snapshots; the current one must carry a trusted signature".

- [ ] **Step 5: Run the tests**

Run: `cargo test -p mecfeed-serve`
Expected: all pass: the existing tests plus 8 new ones. Then run the Global Constraints gates.

Run `cargo tree -p mecfeed-serve -e normal,dev | grep -c mecmcp`. Expected: `0`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/mecfeed-serve
git commit -m "Serve only a current snapshot whose signature a trusted key verifies

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Units and installer create and wire the keys

**Files:**
- Modify: `packaging/systemd/mecfeedmcp.service` (ExecStart, lines 12-22)
- Modify: `packaging/systemd/mecfeed-serve.service` (ExecStart)
- Modify: `packaging/lxc/install.sh`:
  - `validate_service` expected string (line 171)
  - a new key block after the tokens block (~line 366)
  - next steps (line 474)
- Modify: `scripts/verify-packaging.sh`:
  - `expected_exec` (line 186)
  - a new serve-unit check
  - installer content checks near line 243
- Modify: `packaging/tests/package-smoke.sh` (after line 203, and after the stage-root loop)

**Interfaces:**
- Consumes: from Task 4, the flags. `--print-snapshot-signing-public-key` writes exactly one base64 line to stdout.
- Produces: installed files `/var/lib/mecfeedmcp/snapshot-signing.key` (0600) and `/etc/mecfeed-serve/snapshot-signing.pub` (0644).

- [ ] **Step 1: Units**

`mecfeedmcp.service`: change the last ExecStart line from `    --audit-hmac-key-file /etc/mecfeedmcp/audit-hmac.key` to:

```
    --audit-hmac-key-file /etc/mecfeedmcp/audit-hmac.key \
    --snapshot-signing-key-file /var/lib/mecfeedmcp/snapshot-signing.key
```

`mecfeed-serve.service`: change `    --feed-config ${CREDENTIALS_DIRECTORY}/feed.json` to:

```
    --feed-config ${CREDENTIALS_DIRECTORY}/feed.json \
    --trusted-snapshot-key /etc/mecfeed-serve/snapshot-signing.pub
```

In both `install.sh` `validate_service` and `scripts/verify-packaging.sh` `expected_exec`, append exactly ` --snapshot-signing-key-file /var/lib/mecfeedmcp/snapshot-signing.key` to the end of the expected string.

In `scripts/verify-packaging.sh`, next to the other unit checks, add:

```bash
require '    --trusted-snapshot-key /etc/mecfeed-serve/snapshot-signing.pub' packaging/systemd/mecfeed-serve.service
require_contains '--init-snapshot-signing-key' packaging/lxc/install.sh
require_contains '--print-snapshot-signing-public-key' packaging/lxc/install.sh
```

- [ ] **Step 2: Installer key block**

Insert after the tokens ownership block (the `if [[ -e "$tokens_path" ]]; then ... fi` that ends near line 366) and before the unit installs:

```bash
# The MCP server signs snapshots with a key only it can read; serve trusts the
# public half. A key is created once and never replaced; a .pub that no longer
# matches the key is an operator decision, so the installer stops.
signing_key_path=$(target_path /var/lib/mecfeedmcp/snapshot-signing.key)
serve_config_dir=$(target_path /etc/mecfeed-serve)
signing_pub_path="$serve_config_dir/snapshot-signing.pub"
run_as_service_user() {
    if (( live_install )); then
        runuser -u mecfeedmcp -- "$@"
    else
        "$@"
    fi
}
if [[ -L "$serve_config_dir" ]] || { [[ -e "$serve_config_dir" ]] && [[ ! -d "$serve_config_dir" ]]; }; then
    die "unsafe directory: $serve_config_dir"
fi
[[ -d "$serve_config_dir" ]] || install -d -m 0755 "$serve_config_dir"
reject_unsafe_file "$signing_key_path"
reject_unsafe_file "$signing_pub_path"
if [[ ! -e "$signing_key_path" ]]; then
    run_as_service_user "$bin_path" --snapshot-signing-key-file "$signing_key_path" \
        --init-snapshot-signing-key >/dev/null \
        || die 'cannot create the snapshot signing key'
fi
signing_public_key=$(run_as_service_user "$bin_path" --snapshot-signing-key-file "$signing_key_path" \
    --print-snapshot-signing-public-key 2>/dev/null) \
    || die 'cannot read the snapshot signing key'
if [[ -e "$signing_pub_path" ]]; then
    [[ $(tr -d '[:space:]' <"$signing_pub_path") == "$signing_public_key" ]] \
        || die "$signing_pub_path does not match the snapshot signing key; fix trust by hand"
else
    signing_pub_tmp=$(mktemp "$serve_config_dir/.snapshot-signing.pub.XXXXXX")
    printf '%s\n' "$signing_public_key" >"$signing_pub_tmp"
    chmod 0644 "$signing_pub_tmp"
    mv -fT -- "$signing_pub_tmp" "$signing_pub_path"
fi
```

Rules for this block:

- Keep the style of the surrounding script, including `die`, `target_path` and `reject_unsafe_file`.
- If the script defines a cleanup trap, also remove `$signing_pub_tmp` on failure.
- `shellcheck` must stay clean.

Add a next step to the final `printf`, after line 4 and before the `MCP endpoint:` line:

```bash
    "5. Snapshot signing public key (copy $signing_pub_path to any mecfeed-serve on another host): $signing_public_key" \
```

The `printf` arguments are single-quoted strings, so this one must be double-quoted to expand. Keep a literal `'MCP endpoint: ...'` line last.

- [ ] **Step 3: Smoke test**

In `packaging/tests/package-smoke.sh`, after the fresh-root `stat` checks (after line 203):

```bash
fresh_key="$fresh_root/var/lib/mecfeedmcp/snapshot-signing.key"
fresh_pub="$fresh_root/etc/mecfeed-serve/snapshot-signing.pub"
[[ $(stat -c %a "$fresh_key") == 600 ]] || exit 1
[[ $(stat -c %a "$fresh_pub") == 644 ]] || exit 1
[[ $("$fresh_root/usr/local/bin/mecfeedmcp" --snapshot-signing-key-file "$fresh_key" \
    --print-snapshot-signing-public-key 2>/dev/null) == "$(cat "$fresh_pub")" ]] || exit 1
grep -Fq "5. Snapshot signing public key" "$fresh_output"
```

After the stage-root loop and its `sha256sum -c` check, do the following:

1. Assert `"$stage_root/var/lib/mecfeedmcp/snapshot-signing.key"` and `"$stage_root/etc/mecfeed-serve/snapshot-signing.pub"` exist.
2. Record their sha256 sums. The two loop runs already prove a re-run keeps them, because the first run created them. Make that explicit: record the sums after the first run of the loop and check them after the second, by splitting the loop into two runs with the check between. A tidy alternative is to run the installer once more after the loop and compare.
3. Overwrite the stage `.pub` with the one from `$fresh_root`. It is a valid key, but a different one.
4. Assert that a further installer run exits non-zero, and that the key file is byte-identical afterwards.

In the unsafe-root case (line ~241), also plant `ln -s "$sentinel_dir/hmac" "$unsafe_root/etc/mecfeed-serve/snapshot-signing.pub"` after `mkdir -p "$unsafe_root/etc/mecfeed-serve"`. The existing assertions already require the installer to fail and the sentinels to stay 0644 and unchanged. Confirm that `reject_unsafe_file` triggers on it: the run must fail before anything is written through the link. If the run already fails earlier on the tokens symlink, add a separate unsafe-root case containing only the `.pub` symlink.

- [ ] **Step 4: Verify**

Run:

```bash
shellcheck scripts/build-package.sh scripts/verify-packaging.sh packaging/lxc/install.sh packaging/tests/package-smoke.sh
scripts/verify-packaging.sh
scripts/build-package.sh
```

Then run the smoke test the way CI does. Read the `Smoke test package` step in `.github/workflows/ci.yml` for its env and invocation, and copy it.

Expected: everything passes.

- [ ] **Step 5: Commit**

```bash
git add packaging scripts/verify-packaging.sh
git commit -m "Create the snapshot signing key at install and trust it in mecfeed-serve

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Containers, CI, registry metadata and docs

**Files:**
- Modify: `Dockerfile` (ENTRYPOINT, line 42)
- Modify: `Dockerfile.serve` (ENTRYPOINT, line 40)
- Modify: `.github/workflows/ci.yml` (argv checks at lines 55-71, plus a new step after the audit-HMAC step)
- Modify: `server.json` (the `{state_dir}` variable description, around line 50)
- Modify: `docs/operations.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: the Task 4 flags, and the Task 5 `--trusted-snapshot-key`.
- Produces: none for code.

- [ ] **Step 1: Entrypoints**

`Dockerfile` ENTRYPOINT becomes:

```dockerfile
ENTRYPOINT ["/usr/local/bin/mecfeedmcp", \
    "--device-mapping", "/etc/mecfeedmcp/feed.json", \
    "--tokens-file", "/var/lib/mecfeedmcp/tokens.json", \
    "--audit-hmac-key-file", "/var/lib/mecfeedmcp/audit-hmac.key", \
    "--snapshot-signing-key-file", "/var/lib/mecfeedmcp/snapshot-signing.key"]
```

`Dockerfile.serve` ENTRYPOINT becomes:

```dockerfile
ENTRYPOINT ["/usr/local/bin/mecfeed-serve", \
    "--tls-cert", "/etc/mecfeed-serve/tls.crt", \
    "--tls-key", "/etc/mecfeed-serve/tls.key", \
    "--snapshot-dir", "/var/lib/mecfeed-snapshots", \
    "--feed-config", "/etc/mecfeedmcp/feed.json", \
    "--trusted-snapshot-key", "/etc/mecfeed-serve/snapshot-signing.pub"]
```

Update the comment above the serve ENTRYPOINT to "TLS, snapshot and trust paths live in ENTRYPOINT so an operator --listen override cannot drop them."

- [ ] **Step 2: CI**

In the `--host override` argv step, add:

```bash
          echo "$argv" | grep -q -- '/var/lib/mecfeedmcp/snapshot-signing.key' || { echo "FAIL: --snapshot-signing-key-file path missing from argv with --host override"; exit 1; }
```

In the `--listen override` step, add:

```bash
          echo "$argv" | grep -q -- '/etc/mecfeed-serve/snapshot-signing.pub' || { echo "FAIL: --trusted-snapshot-key missing from argv"; exit 1; }
```

Add a new step after "Verify the audit HMAC key is generated on first run":

```yaml
      - name: Verify the snapshot signing key can be created and printed
        run: |
          state_dir=$(mktemp -d)
          chmod 0700 "$state_dir"
          sudo chown 65532:65532 "$state_dir"
          docker run --rm -v "$state_dir:/var/lib/mecfeedmcp" --user 65532:65532 \
            mecfeedmcp:ci --init-snapshot-signing-key > init.out
          docker run --rm -v "$state_dir:/var/lib/mecfeedmcp" --user 65532:65532 \
            mecfeedmcp:ci --print-snapshot-signing-public-key > print.out
          cmp init.out print.out || { echo "FAIL: init and print disagree"; exit 1; }
          [ "$(sudo stat -c %a "$state_dir/snapshot-signing.key")" = 600 ] || { echo "FAIL: key mode is not 0600"; exit 1; }
          if docker run --rm -v "$state_dir:/var/lib/mecfeedmcp" --user 65532:65532 \
            mecfeedmcp:ci --init-snapshot-signing-key; then echo "FAIL: init overwrote a key"; exit 1; fi
          echo "PASS: snapshot signing key created once and printed"
```

- [ ] **Step 3: server.json**

Append this sentence to the `{state_dir}` variable's `description`: ` Holds snapshot-signing.key; create it once with --init-snapshot-signing-key and give mecfeed-serve its public half.`

Run `scripts/verify-packaging.sh`. It validates `server.json`, so it must still pass.

- [ ] **Step 4: docs/operations.md**

Add a section `## Snapshot signing` after the section that describes the shared snapshot directory. Write it in the existing doc's voice. It must contain:

- **What is signed:** each published version gets `versions/<N>/snapshot.sig`, and mecfeed-serve serves only a current version whose signature verifies against a `--trusted-snapshot-key`. There is no unsigned mode.
- **Files:** `/var/lib/mecfeedmcp/snapshot-signing.key` (0600 mecfeedmcp, never leaves the host) and `/etc/mecfeed-serve/snapshot-signing.pub` (0644 root).
- **Install:** the installer creates both, and next step 5 prints the public key.
- **Serve on another host:** copy the `.pub` to `/etc/mecfeed-serve/snapshot-signing.pub` on that host.
- **Print the public key again:**
  `runuser -u mecfeedmcp -- mecfeedmcp --snapshot-signing-key-file /var/lib/mecfeedmcp/snapshot-signing.key --print-snapshot-signing-public-key`
- **Docker:**
  - `docker run --rm -v <state_dir>:/var/lib/mecfeedmcp --user 65532:65532 <image> --init-snapshot-signing-key > snapshot-signing.pub`
  - then mount that file into the serve container at `/etc/mecfeed-serve/snapshot-signing.pub`
- **Rotation:**
  1. Create a new key at a new path.
  2. Add its `.pub` as a second `--trusted-snapshot-key` on serve and restart serve.
  3. Point the MCP unit at the new key and restart it.
  4. Publish one version.
  5. Remove the old `--trusted-snapshot-key` and restart serve.
- **Upgrading from an unsigned release:**
  1. `systemctl stop mecfeed-serve mecfeedmcp`
  2. Re-run the installer with `MECFEEDMCP_FORCE_UNIT=1` so both units get the new flags. This also creates the key and the `.pub`.
  3. `systemctl start mecfeedmcp mecfeed-serve`
  4. Publish one new version (plan, approve, apply).

  Serve answers 503 between steps 3 and 4, because older versions have no signature. `rollback_feed` cannot be used for step 4, because it refuses the current version.
- **Caching:** serve verifies once per `current` change and serves from memory. A `.sig` changed after that is noticed at the next publish or serve restart.

Also add the two new files to the layout table, if the doc has one; it did for the snapshot dir.

- [ ] **Step 5: CHANGELOG.md**

Under the unreleased section, follow the existing bullet style:

```markdown
- **Breaking:** published snapshots are signed with Ed25519 and mecfeed-serve serves only a current snapshot whose signature verifies. New required flags: `--snapshot-signing-key-file` (mecfeedmcp, to publish) and `--trusted-snapshot-key` (mecfeed-serve). The installer creates the key; after upgrading, serve returns 503 until one new version is published. See docs/operations.md, "Snapshot signing".
```

- [ ] **Step 6: Verify and commit**

Run `scripts/verify-packaging.sh`, and the Global Constraints gates; they should be unaffected but run them anyway. If Docker is available locally, also run:

```bash
docker build -t mecfeedmcp:ci . && docker build -f Dockerfile.serve -t mecfeed-serve:ci .
```

followed by the new CI step's script. Otherwise CI covers it.

```bash
git add Dockerfile Dockerfile.serve .github/workflows/ci.yml server.json docs/operations.md CHANGELOG.md
git commit -m "Wire snapshot signing into the images, CI and operations docs

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8 (controller only, not dispatched): live check on LXC 605

This needs root SSH to the lab and it changes a guest, so the controller runs it before opening the PR.

1. Resolve 605 with `pvesh get /cluster/resources --type vm`. Confirm its name is `test-mecfeedmcp`, it is tagged `disposable`, and it is not tagged `protected`.
2. Build the package with `scripts/build-package.sh`, copy it to 605, and run `MECFEEDMCP_FORCE_UNIT=1 packaging/lxc/install.sh` as root.
3. Restart both units. `curl -sk https://127.0.0.1:8443/feeds/panos-edl/address` should return 503, and the journal should say `snapshot.sig`.
4. Publish one version with the scratchpad `mcp_flow.py`, which needs new indicator values, then curl again and expect 200.
5. Tamper with `versions/<current>/snapshot.sig` (flip one base64 character), restart mecfeed-serve, and expect 503. Restore it, restart, and expect 200.
6. Record the outcome in the PR body. Do not print the tokens from `/root/planner.out` or `/root/approver.out`.
