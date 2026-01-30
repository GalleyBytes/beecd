# syntax=docker/dockerfile:1.7
# =============================================================================
# Optimized Agent Dockerfile - Multi-arch support
# =============================================================================
# Supports linux/amd64 and linux/arm64 using rust-musl-cross base images
# =============================================================================

# Use different base images based on target architecture
FROM messense/rust-musl-cross:x86_64-musl AS builder-amd64
FROM messense/rust-musl-cross:aarch64-musl AS builder-arm64

# Select the appropriate builder based on TARGETARCH (automatically set by BuildKit)
# TARGETARCH is a built-in arg that gets set to amd64 or arm64
FROM builder-${TARGETARCH:-amd64} AS builder

# Declare ARG to make it available in RUN commands
ARG TARGETARCH

# Install protobuf compiler, pkg-config, OpenSSL, and update CA certificates
RUN apt-get update && \
    apt-get install -y protobuf-compiler ca-certificates pkg-config libssl-dev && \
    update-ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

# Copy only Cargo manifests first for dependency caching
COPY Cargo.toml Cargo.lock* ./
COPY agent/Cargo.toml agent/
COPY hive/Cargo.toml hive/
COPY hive-hq/api/Cargo.toml hive-hq/api/
COPY hive-hq/types/Cargo.toml hive-hq/types/
COPY diff/Cargo.toml diff/
COPY storage/Cargo.toml storage/

# Create minimal source files to satisfy Cargo
RUN mkdir -p agent/src && echo 'fn main() {}' > agent/src/main.rs && touch agent/src/lib.rs && \
    mkdir -p hive/src && echo 'fn main() {}' > hive/src/main.rs && \
    mkdir -p hive-hq/api/src && echo 'fn main() {}' > hive-hq/api/src/main.rs && touch hive-hq/api/src/lib.rs && \
    mkdir -p hive-hq/types/src && touch hive-hq/types/src/lib.rs && \
    mkdir -p diff/src && touch diff/src/lib.rs && \
    mkdir -p storage/src && touch storage/src/lib.rs

# Build dependencies with architecture-specific cache mounts
RUN --mount=type=cache,target=/root/.cargo/registry,id=cargo-registry-${TARGETARCH} \
    --mount=type=cache,target=/root/.cargo/git,id=cargo-git-${TARGETARCH} \
    --mount=type=cache,target=/usr/src/target,id=agent-target-${TARGETARCH} \
    if [ "$TARGETARCH" = "arm64" ]; then \
        RUST_TARGET="aarch64-unknown-linux-musl"; \
    else \
        RUST_TARGET="x86_64-unknown-linux-musl"; \
    fi && \
    cargo build --release --target $RUST_TARGET -p agent 2>/dev/null || true

# Copy real source files
COPY agent/src ./agent/src
COPY agent/build.rs ./agent/
COPY hive/src ./hive/src
COPY hive/proto ./hive/proto
COPY hive-hq/types/src ./hive-hq/types/src
COPY diff/src ./diff/src
COPY storage/src ./storage/src

ARG BUILD_VERSION
ENV BUILD_VERSION=${BUILD_VERSION}

# Build final binary
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        RUST_TARGET="aarch64-unknown-linux-musl"; \
    else \
        RUST_TARGET="x86_64-unknown-linux-musl"; \
    fi && \
    cargo build --release --target $RUST_TARGET -p agent && \
    cp /usr/src/target/$RUST_TARGET/release/agent /usr/local/bin/agent

# =============================================================================
# Runtime image
# =============================================================================
FROM scratch

ARG IMAGE_SOURCE=https://github.com/galleybytes/beecd
LABEL org.opencontainers.image.source=${IMAGE_SOURCE}

COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /usr/local/bin/agent /usr/local/bin/agent

CMD ["agent"]
