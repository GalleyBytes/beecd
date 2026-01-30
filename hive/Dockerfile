# syntax=docker/dockerfile:1.7
# =============================================================================
# Optimized Hive Dockerfile - Multi-arch support
# =============================================================================
# Supports linux/amd64 and linux/arm64 using rust-musl-cross base images
# =============================================================================

# Declare TARGETARCH at the top level
ARG TARGETARCH

# Use different base images based on target architecture
FROM messense/rust-musl-cross:x86_64-musl AS builder-amd64
FROM messense/rust-musl-cross:aarch64-musl AS builder-arm64

# Select the appropriate builder based on TARGETARCH
FROM builder-${TARGETARCH} AS builder

# Redeclare ARG after FROM
ARG TARGETARCH

# Install protobuf compiler and update CA certificates
RUN apt-get update && \
    apt-get install -y protobuf-compiler ca-certificates && \
    update-ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

# Copy Cargo manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY agent/Cargo.toml agent/
COPY hive/Cargo.toml hive/
COPY hive-hq/api/Cargo.toml hive-hq/api/
COPY hive-hq/types/Cargo.toml hive-hq/types/
COPY diff/Cargo.toml diff/
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
  cargo build --release --target $RUST_TARGET -p hive 2>/dev/null || true

# Copy real source files
COPY agent/src ./agent/src
COPY agent/build.rs ./agent/
COPY hive/src ./hive/src
COPY hive/build.rs ./hive/
COPY hive/proto ./hive/proto
COPY hive/migrations ./hive/migrations
COPY storage/src ./storage/src
COPY diff/src ./diff/src

ARG BUILD_VERSION
ENV BUILD_VERSION=${BUILD_VERSION}

# Build final binary
RUN if [ "$TARGETARCH" = "arm64" ]; then \
      RUST_TARGET="aarch64-unknown-linux-musl"; \
  else \
      RUST_TARGET="x86_64-unknown-linux-musl"; \
  fi && \
  cargo build --release --target $RUST_TARGET -p hive && \
  cp /usr/src/target/$RUST_TARGET/release/hive /usr/local/bin/hive

# Fetch sops binary
FROM alpine:3.19.1 AS sops

ARG TARGETARCH

RUN apk add --no-cache curl && \
  if [ "$TARGETARCH" = "arm64" ]; then \
    curl -LO https://github.com/getsops/sops/releases/download/v3.8.1/sops-v3.8.1.linux.arm64 && \
    mv sops-v3.8.1.linux.arm64 /usr/local/bin/sops; \
  else \
    curl -LO https://github.com/getsops/sops/releases/download/v3.8.1/sops-v3.8.1.linux.amd64 && \
    mv sops-v3.8.1.linux.amd64 /usr/local/bin/sops; \
  fi && \
  chmod +x /usr/local/bin/sops

# Runtime image
FROM alpine:3.19.1
RUN apk add --no-cache gpg gpg-agent ca-certificates
COPY --from=builder /usr/local/bin/hive /usr/local/bin/hive
COPY --from=sops /usr/local/bin/sops /usr/local/bin/sops
CMD ["hive"]
