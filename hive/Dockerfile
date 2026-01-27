# syntax=docker/dockerfile:1.7
# =============================================================================
# Optimized Hive Dockerfile with BuildKit cache mounts
# =============================================================================
FROM rust:1.92.0 AS builder

RUN apt-get update -y && apt-get install -y --no-install-recommends \
  musl-tools protobuf-compiler linux-libc-dev wget ca-certificates \
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

# Setup Rust target
WORKDIR /usr/src
RUN rustup target add x86_64-unknown-linux-musl

# Copy manifests first for dependency caching
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

ENV OPENSSL_DIR=/musl

# Pre-build dependencies with cache mounts
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
  --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git \
  --mount=type=cache,target=/usr/src/target,id=beecd-target \
  cargo build --release --target x86_64-unknown-linux-musl -p hive 2>/dev/null || true

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
RUN cargo build --release --target x86_64-unknown-linux-musl -p hive && \
  cp /usr/src/target/x86_64-unknown-linux-musl/release/hive /usr/local/bin/hive

# Fetch sops binary
FROM alpine:3.19.1 AS sops
RUN apk add --no-cache curl && \
  curl -LO https://github.com/getsops/sops/releases/download/v3.8.1/sops-v3.8.1.linux.amd64 && \
  mv sops-v3.8.1.linux.amd64 /usr/local/bin/sops && \
  chmod +x /usr/local/bin/sops

# Runtime image
FROM alpine:3.19.1

ARG IMAGE_SOURCE=https://github.com/galleybytes/beecd
LABEL org.opencontainers.image.source=${IMAGE_SOURCE}

RUN apk add --no-cache gpg gpg-agent ca-certificates
COPY --from=builder /usr/local/bin/hive /usr/local/bin/hive
COPY --from=sops /usr/local/bin/sops /usr/local/bin/sops
CMD ["hive"]
