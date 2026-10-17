# Contributing

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo +1.89 check --workspace --all-targets --locked
```

MSRV is 1.89; the pinned toolchain in `rust-toolchain.toml` is 1.99.0.

## Packaging

`scripts/verify-packaging.sh` and `scripts/build-package.sh` are the LXC
package gates. Trivy 0.70.0 is required for the packager's CycloneDX SBOM.

## Releases

Release tags are annotated and signed (`git tag -s`). Agents do not tag.
Image builds use mecmcp `reusable-release-image.yml` pinned at v0.28.1.
