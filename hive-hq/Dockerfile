# syntax=docker/dockerfile:1.7
# =============================================================================
# Optimized Hive-HQ Dockerfile - Multi-arch support
# =============================================================================
# Supports linux/amd64 and linux/arm64
# =============================================================================

# Stage 1: Build the React UI with Node.js
FROM node:22-bookworm-slim AS ui-builder

WORKDIR /ui
COPY hive-hq/ui/package.json hive-hq/ui/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm,id=npm-cache \
    npm ci

COPY hive-hq/ui ./
RUN npm run build

# Stage 2: Build Rust API binary using rust-musl-cross
# Use different base images based on target architecture
FROM messense/rust-musl-cross:x86_64-musl AS builder-amd64
FROM messense/rust-musl-cross:aarch64-musl AS builder-arm64

# Select the appropriate builder based on TARGETARCH (automatically set by BuildKit)
# TARGETARCH is a built-in arg that gets set to amd64 or arm64
FROM builder-${TARGETARCH:-amd64} AS builder

# Declare ARG to make it available in RUN commands
ARG TARGETARCH

# Install dependencies for building OpenSSL from source
RUN apt-get update && \
    apt-get install -y \
        pkg-config \
        libssl-dev \
        perl \
        make \
        && \
    rm -rf /var/lib/apt/lists/*

# Configure OpenSSL for musl static linking with vendored source compilation
ENV OPENSSL_STATIC=yes \
    OPENSSL_VENDORED=yes \
    OPENSSL_NO_PKG_CONFIG=1

WORKDIR /usr/src

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock* ./
COPY agent/Cargo.toml agent/
COPY diff/Cargo.toml diff/
COPY hive/Cargo.toml hive/
COPY hive-hq/api/Cargo.toml hive-hq/api/
COPY hive-hq/types/Cargo.toml hive-hq/types/
COPY storage/Cargo.toml storage/

# Create stub source files for dependency pre-build
RUN mkdir -p agent/src && echo 'fn main() {}' > agent/src/main.rs && touch agent/src/lib.rs && \
    mkdir -p diff/src && touch diff/src/lib.rs && \
    mkdir -p hive/src && echo 'fn main() {}' > hive/src/main.rs && \
    mkdir -p hive-hq/types/src && touch hive-hq/types/src/lib.rs && \
    mkdir -p hive-hq/api/src && echo 'fn main() {}' > hive-hq/api/src/main.rs && touch hive-hq/api/src/lib.rs && \
    mkdir -p storage/src && touch storage/src/lib.rs

# Pre-build dependencies with architecture-specific cache mounts
RUN --mount=type=cache,target=/root/.cargo/registry,id=cargo-registry-${TARGETARCH} \
    --mount=type=cache,target=/root/.cargo/git,id=cargo-git-${TARGETARCH} \
    --mount=type=cache,target=/usr/src/target,id=beecd-target-${TARGETARCH} \
    if [ "$TARGETARCH" = "arm64" ]; then \
        RUST_TARGET="aarch64-unknown-linux-musl"; \
    else \
        RUST_TARGET="x86_64-unknown-linux-musl"; \
    fi && \
    cargo build --release --target $RUST_TARGET -p api 2>/dev/null || true

# Copy real source files
COPY hive-hq/api/src ./hive-hq/api/src
COPY hive-hq/types/src ./hive-hq/types/src
COPY storage/src ./storage/src
COPY hive/proto ./hive/proto

ARG BUILD_VERSION
ENV BUILD_VERSION=${BUILD_VERSION}

RUN if [ "$TARGETARCH" = "arm64" ]; then \
        RUST_TARGET="aarch64-unknown-linux-musl"; \
    else \
        RUST_TARGET="x86_64-unknown-linux-musl"; \
    fi && \
    cargo build --release --target $RUST_TARGET -p api && \
    cp /usr/src/target/$RUST_TARGET/release/api /usr/local/bin/hivehq

# Runtime image
FROM scratch

ARG IMAGE_SOURCE=https://github.com/galleybytes/beecd
LABEL org.opencontainers.image.source=${IMAGE_SOURCE}

COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /usr/local/bin/hivehq /usr/local/bin/hivehq
COPY --from=ui-builder /ui/dist dist
CMD ["hivehq"]
