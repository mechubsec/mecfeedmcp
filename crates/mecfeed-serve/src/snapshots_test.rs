//! Reader tests that need `mkfifo`; the file name keeps it out of the packaging ban on spawning processes.

use super::{current_number, read_signature, read_snapshot};
use std::path::Path;

/// Run `reader` on a thread so an `open(2)` that blocks on a FIFO fails the test instead of hanging it.
fn error_text<T: Send + 'static>(
    reader: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> String {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(reader().map(|_| ()).map_err(|error| format!("{error:#}")));
    });
    receiver
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("reader blocked on the FIFO")
        .expect_err("a FIFO must be rejected")
}

fn make_fifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("mkfifo");
    assert!(status.success());
}

#[test]
fn fifo_signature_is_rejected_without_blocking() {
    let dir = tempfile::tempdir().expect("tempdir");
    make_fifo(&dir.path().join("snapshot.sig"));
    let root = dir.path().to_path_buf();
    assert!(error_text(move || read_signature(&root)).contains("not a regular file"));
}

#[test]
fn fifo_snapshot_is_rejected_without_blocking() {
    let dir = tempfile::tempdir().expect("tempdir");
    make_fifo(&dir.path().join("snapshot.json"));
    let root = dir.path().to_path_buf();
    assert!(error_text(move || read_snapshot(&root)).contains("not a regular file"));
}

#[test]
fn fifo_current_is_rejected_without_blocking() {
    let dir = tempfile::tempdir().expect("tempdir");
    make_fifo(&dir.path().join("current"));
    let root = dir.path().to_path_buf();
    assert!(error_text(move || current_number(&root)).contains("not a regular file"));
}
