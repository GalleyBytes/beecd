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

# Select the appropriate builder based on TARGETARCH
ARG TARGETARCH
FROM builder-${TARGETARCH} AS builder

WORKDIR /usr/src

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
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

# Determine Rust target based on architecture
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        echo "aarch64-unknown-linux-musl" > /rust-target; \
    else \
        echo "x86_64-unknown-linux-musl" > /rust-target; \
    fi

# Pre-build dependencies with cache mounts
RUN --mount=type=cache,target=/root/.cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/root/.cargo/git,id=cargo-git \
    --mount=type=cache,target=/usr/src/target,id=beecd-target \
    export RUST_TARGET=$(cat /rust-target) && \
    cargo build --release --target $RUST_TARGET -p api 2>/dev/null || true

# Copy real source files
COPY hive-hq/api/src ./hive-hq/api/src
COPY hive-hq/types/src ./hive-hq/types/src
COPY storage/src ./storage/src
COPY hive/proto ./hive/proto

ARG BUILD_VERSION
ENV BUILD_VERSION=${BUILD_VERSION}

RUN export RUST_TARGET=$(cat /rust-target) && \
    cargo build --release --target $RUST_TARGET -p api && \
    cp /usr/src/target/$RUST_TARGET/release/api /usr/local/bin/hivehq

# Runtime image
FROM scratch
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /usr/local/bin/hivehq /usr/local/bin/hivehq
COPY --from=ui-builder /ui/dist dist
CMD ["hivehq"]
