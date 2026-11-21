# mecfeedmcp MCP server container image
#
# Multi-stage build producing a distroless image with no shell and no external
# binaries. Builder glibc generation must be ≤ runtime generation: Debian 13
# (trixie) on both sides.

# Source of libgcc-s1 only; the runtime is base-nossl, which lacks it. Not the
# runtime itself, so keep it ahead of the builder and out of the last FROM.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2 AS libgcc

# Pinned to the multi-arch image index digest resolved on 2026-08-25.
FROM rust:1.100-slim-trixie@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/mecfeedmcp/Cargo.toml crates/mecfeedmcp/
COPY crates/mecfeedmcp-core/Cargo.toml crates/mecfeedmcp-core/
COPY crates/mecfeed-serve/Cargo.toml crates/mecfeed-serve/

RUN mkdir -p crates/mecfeedmcp/src crates/mecfeedmcp-core/src crates/mecfeed-serve/src && \
    echo 'fn main() {}' > crates/mecfeedmcp/src/main.rs && \
    echo '' > crates/mecfeedmcp/src/lib.rs && \
    echo 'fn main() {}' > crates/mecfeed-serve/src/main.rs && \
    echo '' > crates/mecfeedmcp-core/src/lib.rs && \
    cargo build --release -p mecfeedmcp && \
    rm -rf crates/mecfeedmcp/src crates/mecfeedmcp-core/src crates/mecfeed-serve/src

COPY crates/ crates/
RUN touch crates/mecfeedmcp/src/main.rs crates/mecfeedmcp-core/src/lib.rs crates/mecfeed-serve/src/main.rs && \
    cargo build --release --locked -p mecfeedmcp

# libgcc_s.so.1 is the one library the binary needs beyond glibc, and
# base-nossl does not ship it. Stage it with its dpkg records (status.d) so
# Trivy and the SBOM still see libgcc-s1 and gcc-14-base. The multiarch
# directory is taken from the builder's own triplet (x86_64 or aarch64).
COPY --from=libgcc / /cc/
RUN triplet="$(gcc -dumpmachine | sed 's/-pc-/-/')" \
    && install -d "/stage-libgcc/usr/lib/${triplet}" /stage-libgcc/var/lib/dpkg/status.d \
    && cp -a "/cc/usr/lib/${triplet}/libgcc_s.so.1" "/stage-libgcc/usr/lib/${triplet}/" \
    && cp -a /cc/var/lib/dpkg/status.d/libgcc-s1 /cc/var/lib/dpkg/status.d/libgcc-s1.md5sums \
        /cc/var/lib/dpkg/status.d/gcc-14-base /cc/var/lib/dpkg/status.d/gcc-14-base.md5sums \
        /stage-libgcc/var/lib/dpkg/status.d/

# Runtime: distroless base-nossl (no libssl3t64/libcrypto: rustls-only, and
# libssl3t64 carries unfixed CVE-2026-124709).
FROM gcr.io/distroless/base-nossl-debian13:nonroot@sha256:89815d620ac01d8de13cdaf04d19ed874447ca2296d4985b14b818f6e5e47854

COPY --from=builder /stage-libgcc/ /
USER 65532:65532

COPY --from=builder /build/target/release/mecfeedmcp /usr/local/bin/mecfeedmcp

LABEL org.opencontainers.image.title="mecfeedmcp"
LABEL org.opencontainers.image.description="Governed threat-intel feed MCP server"
LABEL org.opencontainers.image.source="https://github.com/mechubsec/mecfeedmcp"
LABEL org.opencontainers.image.licenses="MIT"
LABEL io.modelcontextprotocol.server.name="io.github.mechubsec/mecfeedmcp"

# Config paths live in ENTRYPOINT so an operator --host override cannot drop them.
ENTRYPOINT ["/usr/local/bin/mecfeedmcp", \
    "--device-mapping", "/etc/mecfeedmcp/feed.json", \
    "--tokens-file", "/var/lib/mecfeedmcp/tokens.json", \
    "--audit-hmac-key-file", "/var/lib/mecfeedmcp/audit-hmac.key", \
    "--snapshot-signing-key-file", "/var/lib/mecfeedmcp/snapshot-signing.key"]
CMD ["--transport", "streamable-http", \
    "--host", "127.0.0.1", \
    "--port", "30040"]
