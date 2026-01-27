# syntax=docker/dockerfile:1.7
# =============================================================================
# Optimized Hive-HQ Dockerfile with BuildKit cache mounts
# =============================================================================

# Stage 1: Build the React UI with Node.js
FROM node:22-bookworm-slim AS ui-builder

WORKDIR /ui
COPY hive-hq/ui/package.json hive-hq/ui/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm,id=npm-cache \
    npm ci

COPY hive-hq/ui ./
RUN npm run build

# Stage 2: Build Rust API binary
FROM rust:1.92.0 AS builder

RUN apt-get update -y && apt-get install -y --no-install-recommends \
    musl-tools wget ca-certificates linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

# Setup musl include paths
RUN mkdir -p /usr/include/x86_64-linux-musl && \
    ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm && \
    ln -sf /usr/include/asm-generic /usr/include/x86_64-linux-musl/asm-generic && \
    ln -sf /usr/include/linux /usr/include/x86_64-linux-musl/linux

# Build OpenSSL (cached as a layer)
WORKDIR /musl
RUN wget -q https://github.com/openssl/openssl/archive/OpenSSL_1_1_1f.tar.gz && \
    tar xzf OpenSSL_1_1_1f.tar.gz && \
    cd openssl-OpenSSL_1_1_1f && \
    CC="musl-gcc -fPIE -pie" ./Configure no-shared no-async --prefix=/musl --openssldir=/musl/ssl linux-x86_64 && \
    make depend && make -j$(nproc) && make install && \
    rm -rf /musl/OpenSSL_1_1_1f.tar.gz /musl/openssl-OpenSSL_1_1_1f

# Setup Rust targets
WORKDIR /usr/src
RUN rustup target add x86_64-unknown-linux-musl

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

ENV OPENSSL_DIR=/musl

# Pre-build dependencies with cache mounts
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git \
    --mount=type=cache,target=/usr/src/target,id=beecd-target \
    cargo build --release --target x86_64-unknown-linux-musl -p api 2>/dev/null || true

# Copy real source files
COPY hive-hq/api/src ./hive-hq/api/src
COPY hive-hq/types/src ./hive-hq/types/src
COPY storage/src ./storage/src
COPY hive/proto ./hive/proto

ARG BUILD_VERSION
ENV BUILD_VERSION=${BUILD_VERSION}

RUN cargo build --release --target x86_64-unknown-linux-musl -p api && \
    cp /usr/src/target/x86_64-unknown-linux-musl/release/api /usr/local/bin/hivehq

# Runtime image
FROM scratch

ARG IMAGE_SOURCE=https://github.com/galleybytes/beecd
LABEL org.opencontainers.image.source=${IMAGE_SOURCE}

COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /usr/local/bin/hivehq /usr/local/bin/hivehq
COPY --from=ui-builder /ui/dist dist
CMD ["hivehq"]
