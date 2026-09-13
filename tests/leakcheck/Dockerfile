# Native ARM64 validation runtime, separate from all deployment images.
FROM --platform=linux/arm64 ubuntu:24.04@sha256:786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends valgrind build-essential ca-certificates curl xz-utils pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
ARG RUST_VERSION=1.95.0
RUN curl -fsSL "https://static.rust-lang.org/dist/rust-${RUST_VERSION}-aarch64-unknown-linux-gnu.tar.xz" -o /tmp/rust.tar.xz \
 && curl -fsSL "https://static.rust-lang.org/dist/rust-${RUST_VERSION}-aarch64-unknown-linux-gnu.tar.xz.sha256" -o /tmp/rust.sha256 \
 && sed 's#rust-[^ ]*tar.xz#/tmp/rust.tar.xz#' /tmp/rust.sha256 | sha256sum -c - \
 && tar -xf /tmp/rust.tar.xz -C /tmp && /tmp/rust-${RUST_VERSION}-aarch64-unknown-linux-gnu/install.sh --prefix=/usr/local \
 && rm -rf /tmp/rust*
WORKDIR /src
