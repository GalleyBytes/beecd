# syntax=docker/dockerfile:1.7
# =============================================================================
# Optimized Agent Dockerfile - Multi-arch support
# =============================================================================
# Supports linux/amd64 and linux/arm64 using rust-musl-cross base images
# =============================================================================

# Use different base images based on target architecture
FROM messense/rust-musl-cross:x86_64-musl AS builder-amd64
FROM messense/rust-musl-cross:aarch64-musl AS builder-arm64

# Select the appropriate builder based on TARGETARCH
ARG TARGETARCH
FROM builder-${TARGETARCH} AS builder

# Install protobuf compiler and update CA certificates
RUN apt-get update && \
    apt-get install -y protobuf-compiler ca-certificates && \
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

# Determine Rust target based on architecture
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        echo "aarch64-unknown-linux-musl" > /rust-target; \
    else \
        echo "x86_64-unknown-linux-musl" > /rust-target; \
    fi

# Build dependencies with cache mount
RUN --mount=type=cache,target=/root/.cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/root/.cargo/git,id=cargo-git \
    --mount=type=cache,target=/usr/src/target,id=agent-target \
    export RUST_TARGET=$(cat /rust-target) && \
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
RUN export RUST_TARGET=$(cat /rust-target) && \
    cargo build --release --target $RUST_TARGET -p agent && \
    cp /usr/src/target/$RUST_TARGET/release/agent /usr/local/bin/agent

# =============================================================================
# Runtime image
# =============================================================================
FROM scratch

COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /usr/local/bin/agent /usr/local/bin/agent

CMD ["agent"]
