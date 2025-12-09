# syntax=docker/dockerfile:1.7
# =============================================================================
# Optimized Builder Base Image for beecd
# =============================================================================
# This image contains all build dependencies pre-compiled:
# - Rust toolchain with musl target
# - Pre-built OpenSSL for musl
# - Protobuf compiler
# - Cargo registry cache
#
# Build once, reuse across all service builds.
# =============================================================================

FROM --platform=$BUILDPLATFORM rust:1.92.0 AS builder-base

ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Install cross-compilation tools based on target
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    musl-tools \
    protobuf-compiler \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install cross for efficient cross-compilation (avoids QEMU for Rust builds)
RUN cargo install cross --git https://github.com/cross-rs/cross

# Add musl target for static builds
RUN rustup target add x86_64-unknown-linux-musl
RUN rustup target add aarch64-unknown-linux-musl

# =============================================================================
# Pre-built OpenSSL for musl (x86_64)
# =============================================================================
FROM --platform=linux/amd64 rust:1.92.0 AS openssl-amd64

RUN apt-get update -y && apt-get install -y --no-install-recommends \
    musl-tools wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/include/x86_64-linux-musl && \
    ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm && \
    ln -s /usr/include/asm-generic /usr/include/x86_64-linux-musl/asm-generic && \
    ln -s /usr/include/linux /usr/include/x86_64-linux-musl/linux

WORKDIR /musl
RUN wget -q https://github.com/openssl/openssl/archive/OpenSSL_1_1_1f.tar.gz && \
    tar xzf OpenSSL_1_1_1f.tar.gz && \
    cd openssl-OpenSSL_1_1_1f && \
    CC="musl-gcc -fPIE -pie" ./Configure no-shared no-async --prefix=/musl --openssldir=/musl/ssl linux-x86_64 && \
    make depend && \
    make -j$(nproc) && \
    make install && \
    rm -rf /musl/OpenSSL_1_1_1f.tar.gz /musl/openssl-OpenSSL_1_1_1f

# =============================================================================
# Pre-built OpenSSL for musl (arm64)  
# =============================================================================
FROM --platform=linux/arm64 rust:1.92.0 AS openssl-arm64

RUN apt-get update -y && apt-get install -y --no-install-recommends \
    musl-tools wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/include/aarch64-linux-musl && \
    ln -s /usr/include/aarch64-linux-gnu/asm /usr/include/aarch64-linux-musl/asm && \
    ln -s /usr/include/asm-generic /usr/include/aarch64-linux-musl/asm-generic && \
    ln -s /usr/include/linux /usr/include/aarch64-linux-musl/linux

WORKDIR /musl
RUN wget -q https://github.com/openssl/openssl/archive/OpenSSL_1_1_1f.tar.gz && \
    tar xzf OpenSSL_1_1_1f.tar.gz && \
    cd openssl-OpenSSL_1_1_1f && \
    CC="musl-gcc -fPIE -pie" ./Configure no-shared no-async --prefix=/musl --openssldir=/musl/ssl linux-aarch64 && \
    make depend && \
    make -j$(nproc) && \
    make install && \
    rm -rf /musl/OpenSSL_1_1_1f.tar.gz /musl/openssl-OpenSSL_1_1_1f

# =============================================================================
# Final builder image with pre-built OpenSSL
# =============================================================================
FROM rust:1.92.0 AS beecd-builder

RUN apt-get update -y && apt-get install -y --no-install-recommends \
    musl-tools \
    protobuf-compiler \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Setup musl include paths
RUN mkdir -p /usr/include/x86_64-linux-musl /usr/include/aarch64-linux-musl && \
    ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm 2>/dev/null || true && \
    ln -sf /usr/include/asm-generic /usr/include/x86_64-linux-musl/asm-generic 2>/dev/null || true && \
    ln -sf /usr/include/linux /usr/include/x86_64-linux-musl/linux 2>/dev/null || true && \
    ln -sf /usr/include/aarch64-linux-gnu/asm /usr/include/aarch64-linux-musl/asm 2>/dev/null || true && \
    ln -sf /usr/include/asm-generic /usr/include/aarch64-linux-musl/asm-generic 2>/dev/null || true && \
    ln -sf /usr/include/linux /usr/include/aarch64-linux-musl/linux 2>/dev/null || true

# Add musl targets
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

# Copy pre-built OpenSSL (will be populated by multi-platform build)
COPY --from=openssl-amd64 /musl /musl-amd64
COPY --from=openssl-arm64 /musl /musl-arm64

ENV OPENSSL_DIR_AMD64=/musl-amd64
ENV OPENSSL_DIR_ARM64=/musl-arm64

WORKDIR /usr/src
