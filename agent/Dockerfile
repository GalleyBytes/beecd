# syntax=docker/dockerfile:1.7
# =============================================================================
# Optimized Agent Dockerfile - Uses BuildKit cache mounts
# =============================================================================
# Key optimizations:
# 1. Uses BuildKit cache mounts for Cargo registry and target dirs
# 2. Builds natively on host arch, then cross-compiles only the final binary
# 3. Leverages pre-built base image for OpenSSL
# =============================================================================

ARG RUST_VERSION=1.89.0
ARG ALPINE_VERSION=3.19.1

# =============================================================================
# Stage 1: Build OpenSSL for musl (cached layer)
# =============================================================================
FROM rust:${RUST_VERSION} AS openssl-builder

RUN apt-get update -y && apt-get install -y --no-install-recommends \
    musl-tools wget ca-certificates linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/include/x86_64-linux-musl && \
    ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm && \
    ln -sf /usr/include/asm-generic /usr/include/x86_64-linux-musl/asm-generic && \
    ln -sf /usr/include/linux /usr/include/x86_64-linux-musl/linux

WORKDIR /musl
RUN wget -q https://github.com/openssl/openssl/archive/OpenSSL_1_1_1f.tar.gz && \
    tar xzf OpenSSL_1_1_1f.tar.gz && \
    cd openssl-OpenSSL_1_1_1f && \
    CC="musl-gcc -fPIE -pie" ./Configure no-shared no-async --prefix=/musl --openssldir=/musl/ssl linux-x86_64 && \
    make depend && \
    make -j$(nproc) && \
    make install

# =============================================================================
# Stage 2: Build dependencies (cached layer)
# =============================================================================
FROM rust:${RUST_VERSION} AS deps-builder

RUN apt-get update -y && apt-get install -y --no-install-recommends \
    musl-tools protobuf-compiler linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

# Setup musl include paths
RUN mkdir -p /usr/include/x86_64-linux-musl && \
    ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm && \
    ln -sf /usr/include/asm-generic /usr/include/x86_64-linux-musl/asm-generic && \
    ln -sf /usr/include/linux /usr/include/x86_64-linux-musl/linux

RUN rustup target add x86_64-unknown-linux-musl

# Copy pre-built OpenSSL
COPY --from=openssl-builder /musl /musl
ENV OPENSSL_DIR=/musl

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

# Build dependencies with cache mount
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git \
    --mount=type=cache,target=/usr/src/target,id=agent-target \
    cargo build --release --target x86_64-unknown-linux-musl -p agent 2>/dev/null || true

# =============================================================================
# Stage 3: Build actual binary
# =============================================================================
FROM deps-builder AS builder

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
RUN cargo build --release --target x86_64-unknown-linux-musl -p agent && \
    cp /usr/src/target/x86_64-unknown-linux-musl/release/agent /usr/local/bin/agent

# =============================================================================
# Stage 4: Runtime image
# =============================================================================
FROM scratch

ARG IMAGE_SOURCE=https://github.com/galleybytes/beecd
LABEL org.opencontainers.image.source=${IMAGE_SOURCE}

COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /usr/local/bin/agent /usr/local/bin/agent

CMD ["agent"]
