FROM rust:1.92.0 AS beecd-base

RUN apt-get update -y
RUN apt install -y musl-tools protobuf-compiler linux-libc-dev

# ------------------------------- -------------------------------
#          Build OpenSSL for the `musl` build target
# ------------------------------- -------------------------------
RUN mkdir -p /usr/include/x86_64-linux-musl
RUN ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm && \
    ln -s /usr/include/asm-generic /usr/include/x86_64-linux-musl/asm-generic && \
    ln -s /usr/include/linux /usr/include/x86_64-linux-musl/linux

WORKDIR /musl

RUN wget https://github.com/openssl/openssl/archive/OpenSSL_1_1_1f.tar.gz
RUN tar zxvf OpenSSL_1_1_1f.tar.gz
WORKDIR /musl/openssl-OpenSSL_1_1_1f/

RUN CC=musl-gcc ./config no-shared no-async no-engine --prefix=/musl --openssldir=/musl/ssl
RUN make depend
RUN make -j$(nproc)
RUN make install

# ------------------------------- -------------------------------
#         Build the rust dependencies to speed cached builds
# ------------------------------- -------------------------------
WORKDIR /usr/src
RUN rustup target add x86_64-unknown-linux-musl

ENV OPENSSL_DIR=/musl
