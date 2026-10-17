# mecfeedmcp MCP server container image
#
# Multi-stage build producing a distroless image with no shell and no external
# binaries. Builder glibc generation must be ≤ runtime generation: Debian 13
# (trixie) on both sides.

# Pinned to the amd64 digest resolved on 2026-08-25.
FROM rust:1.99-slim-trixie@sha256:2752b332db73fdbb7dc576f06c82ed1f312005784ef913d7e04a28f5f55dc581 AS builder

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

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2

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
    "--audit-hmac-key-file", "/var/lib/mecfeedmcp/audit-hmac.key"]
CMD ["--transport", "streamable-http", \
    "--host", "127.0.0.1", \
    "--port", "30040"]
