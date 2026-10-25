//! Snapshot directory. Writes stay under the directory the caller opened.
//! A snapshot is current only after its file is re-read and the pointer moves.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use mecfeedmcp_core::{FeedVersions, Limits, Policy, SnapshotDocument, VersionError};
use thiserror::Error;

/// Why a snapshot directory operation failed.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The directory is missing, relative, or not a real directory.
    #[error("snapshot directory is not acceptable")]
    Directory,
    /// A snapshot file could not be read or written.
    #[error("snapshot could not be stored")]
    File,
    /// The bytes on disk do not match the digest just written.
    #[error("snapshot digest does not match")]
    Digest,
    /// The documents on disk do not form one feed log.
    #[error("snapshot log is not acceptable")]
    Log,
}

/// Open `dir`, creating it when absent, and load a checked log.
///
/// # Errors
///
/// Returns [`StoreError`] when the directory or the log is not acceptable.
pub fn open_dir(dir: &Path, policy: Policy) -> Result<(PathBuf, FeedVersions), StoreError> {
    if !dir.is_absolute() {
        return Err(StoreError::Directory);
    }
    if dir
        .symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_symlink())
    {
        return Err(StoreError::Directory);
    }
    fs::create_dir_all(dir).map_err(|_| StoreError::Directory)?;
    let canonical = dir.canonicalize().map_err(|_| StoreError::Directory)?;
    if !canonical.is_dir() {
        return Err(StoreError::Directory);
    }
    let versions = load_versions(&canonical, policy)?;
    Ok((canonical, versions))
}

/// Write `document` without moving the current pointer.
///
/// # Errors
///
/// Returns [`StoreError`] when the file cannot be written and re-read.
/// A failure removes the version directory.
pub fn write_snapshot_file(dir: &Path, document: &SnapshotDocument) -> Result<(), StoreError> {
    let version_dir = version_dir(dir, document.number)?;
    if version_dir.symlink_metadata().is_ok() {
        return Err(StoreError::File);
    }
    fs::create_dir_all(&version_dir).map_err(|_| StoreError::File)?;
    let published = write_snapshot(&version_dir, document);
    if published.is_err() {
        let _ = fs::remove_dir_all(&version_dir);
    }
    published
}

/// Make `number` the current snapshot.
///
/// # Errors
///
/// Returns [`StoreError`] when the pointer does not name `number` afterwards.
pub fn set_current(dir: &Path, number: u64) -> Result<(), StoreError> {
    match write_current(dir, number) {
        Ok(()) => Ok(()),
        Err(error) => {
            if current_number(dir)? == Some(number) {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

/// Remove version `number` when it is not the current pointer.
///
/// # Errors
///
/// Returns [`StoreError`] when the directory cannot be removed.
pub fn remove_version(dir: &Path, number: u64) -> Result<(), StoreError> {
    if current_number(dir)? == Some(number) {
        return Err(StoreError::File);
    }
    let version_dir = version_dir(dir, number)?;
    if version_dir.exists() {
        fs::remove_dir_all(version_dir).map_err(|_| StoreError::File)?;
    }
    Ok(())
}

fn load_versions(dir: &Path, policy: Policy) -> Result<FeedVersions, StoreError> {
    let numbers = version_numbers(dir)?;
    if !numbers.iter().enumerate().all(|(index, number)| {
        *number
            == u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .unwrap_or(0)
    }) {
        return Err(StoreError::Log);
    }
    let current = current_number(dir)?;
    // History is verified under the baseline (chain + hard floors) so a new
    // allowlist entry cannot reject old versions; the operator policy then
    // applies to new plans and to render. A recorded broad exception stays
    // valid; the hard prefix floors still apply.
    let baseline = Policy::try_new(
        Vec::new(),
        Vec::new(),
        std::iter::empty::<&str>(),
        Limits {
            permit_explicit_broad: true,
            ..Limits::default()
        },
    )
    .map_err(|_| StoreError::Log)?;
    let mut versions = FeedVersions::open(baseline);
    for number in &numbers {
        let document = read_snapshot(&version_dir(dir, *number)?)?;
        if document.number != *number {
            return Err(StoreError::Log);
        }
        versions.import_document(document, 0).map_err(map_version)?;
    }
    versions.update_policy(policy);
    match (current, numbers.last().copied()) {
        (None, None) => Ok(versions),
        (Some(current), Some(latest)) if current == latest => Ok(versions),
        _ => Err(StoreError::Log),
    }
}

fn map_version(error: VersionError) -> StoreError {
    match error {
        VersionError::Digest => StoreError::Digest,
        _ => StoreError::Log,
    }
}

fn version_numbers(dir: &Path) -> Result<Vec<u64>, StoreError> {
    let versions = dir.join("versions");
    if !versions.exists() {
        return Ok(Vec::new());
    }
    if !versions.is_dir() || is_symlink(&versions) {
        return Err(StoreError::Log);
    }
    let mut numbers = Vec::new();
    for entry in fs::read_dir(&versions).map_err(|_| StoreError::Log)? {
        let entry = entry.map_err(|_| StoreError::Log)?;
        if entry.file_type().map_err(|_| StoreError::Log)?.is_symlink() {
            return Err(StoreError::Log);
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(StoreError::Log);
        };
        if name.starts_with('0') || !name.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(StoreError::Log);
        }
        let number: u64 = name.parse().map_err(|_| StoreError::Log)?;
        if !entry.file_type().map_err(|_| StoreError::Log)?.is_dir() {
            return Err(StoreError::Log);
        }
        numbers.push(number);
    }
    numbers.sort_unstable();
    Ok(numbers)
}

fn version_dir(dir: &Path, number: u64) -> Result<PathBuf, StoreError> {
    if number == 0 {
        return Err(StoreError::File);
    }
    let versions = dir.join("versions");
    if versions.exists() && is_symlink(&versions) {
        return Err(StoreError::File);
    }
    Ok(versions.join(number.to_string()))
}

fn write_snapshot(version_dir: &Path, document: &SnapshotDocument) -> Result<(), StoreError> {
    let partial = version_dir.join("snapshot.json.partial");
    let final_path = version_dir.join("snapshot.json");
    if is_symlink(&partial) || is_symlink(&final_path) {
        return Err(StoreError::File);
    }
    let bytes = serde_json::to_vec(document).map_err(|_| StoreError::File)?;
    write_new(&partial, &bytes)?;
    fs::rename(&partial, &final_path).map_err(|_| StoreError::File)?;
    let read_back = read_snapshot(version_dir)?;
    if read_back.digest != document.digest || read_back.content_digest != document.content_digest {
        return Err(StoreError::Digest);
    }
    Ok(())
}

fn read_snapshot(version_dir: &Path) -> Result<SnapshotDocument, StoreError> {
    let path = version_dir.join("snapshot.json");
    if is_symlink(&path) {
        return Err(StoreError::File);
    }
    let mut file = File::open(&path).map_err(|_| StoreError::File)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| StoreError::File)?;
    serde_json::from_slice(&bytes).map_err(|_| StoreError::File)
}

fn write_current(dir: &Path, number: u64) -> Result<(), StoreError> {
    let partial = dir.join("current.next");
    let final_path = dir.join("current");
    if is_symlink(&partial) || is_symlink(&final_path) {
        return Err(StoreError::File);
    }
    write_new(&partial, format!("{number}\n").as_bytes())?;
    fs::rename(&partial, &final_path).map_err(|_| StoreError::File)?;
    sync_dir(dir)?;
    Ok(())
}

fn current_number(dir: &Path) -> Result<Option<u64>, StoreError> {
    let path = dir.join("current");
    if !path.exists() {
        return Ok(None);
    }
    if is_symlink(&path) {
        return Err(StoreError::File);
    }
    let text = fs::read_to_string(&path).map_err(|_| StoreError::File)?;
    let text = text.trim();
    if text.is_empty() {
        return Err(StoreError::Log);
    }
    let number: u64 = text.parse().map_err(|_| StoreError::Log)?;
    if number == 0 {
        return Err(StoreError::Log);
    }
    Ok(Some(number))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(path)
        .map_err(|_| StoreError::File)?;
    file.write_all(bytes).map_err(|_| StoreError::File)?;
    file.sync_all().map_err(|_| StoreError::File)?;
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    File::open(dir)
        .and_then(|file| file.sync_all())
        .map_err(|_| StoreError::File)
}

fn is_symlink(path: &Path) -> bool {
    path.symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_symlink())
}
