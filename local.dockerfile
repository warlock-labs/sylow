FROM --platform=linux/amd64 ghcr.io/cross-rs/x86_64-unknown-linux-gnu:latest

RUN apt-get update && \
    apt-get install --assume-yes dpkg-dev && \
    dpkg --add-architecture amd64 && \
    apt-get update && \
    apt-get install --assume-yes pkg-config libsodium-dev:amd64 gcc-multilib && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y  && \
    . $HOME/.cargo/env && cargo install cargo-llvm-cov --locked