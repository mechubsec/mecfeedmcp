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
    let (pairs, _) = bytes.as_chunks::<2>();
    for (slot, [high, low]) in out.iter_mut().zip(pairs) {
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
        assert_eq!(
            TrustedKeys::new(Vec::new()).err(),
            Some(SignatureError::NoKeys)
        );
        assert_eq!(
            TrustedKeys::new(vec![public(&key), public(&key)]).err(),
            Some(SignatureError::DuplicateKey)
        );
    }
}
