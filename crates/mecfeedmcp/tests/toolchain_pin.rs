//! The container builders and `rust-toolchain.toml` must name the same Rust.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path
}

fn toolchain_channel() -> String {
    let text = std::fs::read_to_string(repo_root().join("rust-toolchain.toml"))
        .expect("read rust-toolchain.toml");
    text.lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "channel").then(|| value.trim().trim_matches('"').to_string())
        })
        .expect("rust-toolchain.toml declares a channel")
}

fn dockerfile_builder_version(file: &str) -> String {
    let text =
        std::fs::read_to_string(repo_root().join(file)).unwrap_or_else(|_| panic!("read {file}"));
    text.lines()
        .find_map(|line| {
            let rest = line.strip_prefix("FROM rust:")?;
            let tag = rest.split(['-', '@', ' ']).next()?;
            Some(tag.to_string())
        })
        .unwrap_or_else(|| panic!("{file} has a `FROM rust:<version>` builder stage"))
}

fn assert_builder_matches(file: &str) {
    let channel = toolchain_channel();
    let builder = dockerfile_builder_version(file);
    assert!(
        channel == builder || channel.starts_with(&format!("{builder}.")),
        "{file} builds on Rust {builder} but rust-toolchain.toml pins {channel}"
    );
}

fn assert_digest_pinned(file: &str) {
    let text =
        std::fs::read_to_string(repo_root().join(file)).unwrap_or_else(|_| panic!("read {file}"));
    let builder = text
        .lines()
        .find(|line| line.starts_with("FROM rust:"))
        .unwrap_or_else(|| panic!("{file} has a `FROM rust:` builder stage"));
    assert!(
        builder.contains("@sha256:"),
        "the builder base must be digest-pinned, got: {builder}"
    );
    let runtime = text
        .lines()
        .rfind(|line| line.starts_with("FROM ") && !line.contains(" AS builder"))
        .unwrap_or_else(|| panic!("{file} has a runtime stage"));
    assert!(
        runtime.contains("@sha256:"),
        "the runtime base must be digest-pinned, got: {runtime}"
    );
}

#[test]
fn the_mcp_container_builder_matches_the_pinned_toolchain() {
    assert_builder_matches("Dockerfile");
}

#[test]
fn the_serve_container_builder_matches_the_pinned_toolchain() {
    assert_builder_matches("Dockerfile.serve");
}

#[test]
fn the_mcp_images_are_digest_pinned() {
    assert_digest_pinned("Dockerfile");
}

#[test]
fn the_serve_images_are_digest_pinned() {
    assert_digest_pinned("Dockerfile.serve");
}
