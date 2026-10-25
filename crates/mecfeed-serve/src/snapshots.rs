//! Read-only loader for the snapshot directory.
//!
//! The on-disk layout is owned by `crates/mecfeedmcp/src/store.rs`; this is a
//! read-only reimplementation of its read path, and both must change together:
//!
//! ```text
//! <dir>/current                     "N\n", N >= 1, no leading zero
//! <dir>/versions/<N>/snapshot.json  serde_json of SnapshotDocument
//! ```

use anyhow::{Context, Result, bail};
use mecfeedmcp_core::{FeedVersions, Limits, Policy, SnapshotDocument};
use std::{
    fs::{self, File},
    io::{ErrorKind, Read},
    path::Path,
};

/// A fully verified snapshot set and the `current` number it was loaded for.
pub struct Loaded {
    /// The `current` pointer this set was loaded for; `None` when nothing is published.
    pub current: Option<u64>,
    /// The verified log.
    pub versions: FeedVersions,
}

/// Whether `path` exists as itself. Only `NotFound` means absent; any other
/// error (for example permission denied) propagates so the caller fails closed.
fn exists_no_follow(path: &Path) -> Result<bool> {
    match path.symlink_metadata() {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspecting snapshot path"),
    }
}

fn is_symlink(path: &Path) -> bool {
    path.symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_symlink())
}

/// Read the `current` pointer. `None` when the file does not exist.
///
/// # Errors
///
/// Returns an error when the pointer is a symlink or is not a positive integer.
pub fn current_number(dir: &Path) -> Result<Option<u64>> {
    let path = dir.join("current");
    if !exists_no_follow(&path)? {
        return Ok(None);
    }
    if is_symlink(&path) {
        bail!("current is a symlink");
    }
    let text = fs::read_to_string(&path).context("reading current")?;
    let number: u64 = text.trim().parse().context("parsing current")?;
    if number == 0 {
        bail!("current is zero");
    }
    Ok(Some(number))
}

fn version_numbers(dir: &Path) -> Result<Vec<u64>> {
    let versions = dir.join("versions");
    if !exists_no_follow(&versions)? {
        return Ok(Vec::new());
    }
    if is_symlink(&versions) || !versions.is_dir() {
        bail!("versions is not a real directory");
    }
    let mut numbers = Vec::new();
    for entry in fs::read_dir(&versions).context("listing versions")? {
        let entry = entry.context("listing versions")?;
        let file_type = entry.file_type().context("reading version entry type")?;
        if file_type.is_symlink() || !file_type.is_dir() {
            bail!("version entry is not a real directory");
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            bail!("version name is not UTF-8");
        };
        if name.starts_with('0') || !name.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("version name is not a canonical number");
        }
        numbers.push(name.parse().context("parsing version name")?);
    }
    numbers.sort_unstable();
    Ok(numbers)
}

fn read_snapshot(version_dir: &Path) -> Result<SnapshotDocument> {
    let path = version_dir.join("snapshot.json");
    if is_symlink(&path) {
        bail!("snapshot.json is a symlink");
    }
    let mut bytes = Vec::new();
    File::open(&path)
        .context("opening snapshot.json")?
        .read_to_end(&mut bytes)
        .context("reading snapshot.json")?;
    serde_json::from_slice(&bytes).context("parsing snapshot.json")
}

/// Load and verify every snapshot under `dir`, then apply the operator `policy`.
///
/// Every document is imported in order, so the digest chain and every row are
/// checked by core. Any failure means the set does not verify.
///
/// # Errors
///
/// Returns an error when the layout, the `current` pointer, or the log is not acceptable.
pub fn load(dir: &Path, policy: Policy) -> Result<Loaded> {
    let numbers = version_numbers(dir)?;
    if !numbers
        .iter()
        .zip(1u64..)
        .all(|(number, want)| *number == want)
    {
        bail!("version numbers are not contiguous from 1");
    }
    let current = current_number(dir)?;
    // History is verified under the baseline (chain + hard floors) so a new
    // allowlist entry cannot reject old versions; the operator policy is then
    // applied to the current snapshot at render. A recorded broad exception
    // stays valid; the hard prefix floors still apply.
    let limits = Limits {
        permit_explicit_broad: true,
        ..Limits::default()
    };
    let baseline = Policy::try_new(vec![], vec![], Vec::<&str>::new(), limits)
        .context("building baseline policy")?;
    let mut versions = FeedVersions::open(baseline);
    for number in &numbers {
        let document = read_snapshot(&dir.join("versions").join(number.to_string()))?;
        if document.number != *number {
            bail!("document number does not match its directory");
        }
        versions
            .import_document(document, 0)
            .with_context(|| format!("version {number} does not verify"))?;
    }
    if current != numbers.last().copied() {
        bail!("current does not name the latest version");
    }
    versions.update_policy(policy);
    Ok(Loaded { current, versions })
}
