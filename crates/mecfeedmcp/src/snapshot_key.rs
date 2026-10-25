//! The snapshot signing key: creating it, its public half, and signing a digest.
//! The signature format lives in `mecfeedmcp_core`.

use std::fs::{File, OpenOptions, Permissions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
    // `create_new` proved this call made the file, so a failed init may remove it.
    let persisted = persist_key(&mut file, path, &key);
    if let Err(error) = persisted {
        let _ = std::fs::remove_file(path);
        return Err(write_error(error));
    }
    public_key_text(&key)
}

/// Write `key` to the freshly created `file` and make it durable, 0600 under any umask.
fn persist_key(file: &mut File, path: &Path, key: &SigningKey) -> std::io::Result<()> {
    file.set_permissions(Permissions::from_mode(0o600))?;
    file.write_all(audit_signing::encode_signing_key(key).as_bytes())?;
    file.sync_all()?;
    let parent = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    File::open(parent)?.sync_all()
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
#[cfg_attr(not(test), allow(dead_code))] // used by gate.rs from the next commit
pub(crate) fn signature_file(digest: &str, key: &SigningKey) -> Result<Vec<u8>, SnapshotKeyError> {
    let signed = audit_signing::sign_digest(&signing_input(digest)?, key)?;
    let (_, key_id) = public_key_text(key)?;
    Ok(encode_signature_file(
        &key_id,
        &audit_signing::encode_signature(&signed),
    ))
}

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
    fn init_reports_a_write_error_and_leaves_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing").join("snapshot-signing.key");
        assert!(matches!(
            init_key_file(&path),
            Err(SnapshotKeyError::Write { .. })
        ));
        assert!(!path.exists());
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
