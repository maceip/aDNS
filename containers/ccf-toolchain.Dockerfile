FROM --platform=linux/amd64 mcr.microsoft.com/azurelinux/base/core:3.0@sha256:c877612270d1ee2d6ab2bc1f64bfe38ab697ac50be325154ee5129fce89c17e4
ARG CCF_VERSION=7.0.15
ARG CCF_RPM_SHA256=2a55ae5f0297499051c5c854554f46ad35a5589dfd1693b7a6de63e0c342c911
RUN tdnf -y install ca-certificates curl tar xz build-essential clang cmake ninja-build openssl-devel libuv-devel nghttp2-devel curl-devel python3 python3-pip libbacktrace-static && tdnf clean all
RUN curl -fsSL "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_devel_${CCF_VERSION}_x86_64.rpm" -o /tmp/ccf.rpm \
 && echo "${CCF_RPM_SHA256}  /tmp/ccf.rpm" | sha256sum -c - \
 && tdnf -y install /tmp/ccf.rpm && rm /tmp/ccf.rpm
ARG RUST_VERSION=1.95.0
RUN curl -fsSL "https://static.rust-lang.org/dist/rust-${RUST_VERSION}-x86_64-unknown-linux-gnu.tar.xz" -o /tmp/rust.tar.xz \
 && curl -fsSL "https://static.rust-lang.org/dist/rust-${RUST_VERSION}-x86_64-unknown-linux-gnu.tar.xz.sha256" -o /tmp/rust.sha256 \
 && sed 's#rust-[^ ]*tar.xz#/tmp/rust.tar.xz#' /tmp/rust.sha256 | sha256sum -c - \
 && tar -xf /tmp/rust.tar.xz -C /tmp && /tmp/rust-${RUST_VERSION}-x86_64-unknown-linux-gnu/install.sh --prefix=/usr/local \
 && rm -rf /tmp/rust*
ENV CCF_INCLUDE_DIR=/opt/ccf/include
ENV CC=clang CXX=clang++
COPY ccf/tests/requirements.txt /tmp/ccf-test-requirements.txt
RUN python3 -m pip install --no-cache-dir --target /opt/agentdns-test-python -r /tmp/ccf-test-requirements.txt
ENV PYTHONPATH=/opt/agentdns-test-python
WORKDIR /src
