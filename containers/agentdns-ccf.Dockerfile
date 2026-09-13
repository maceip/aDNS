# Build containers/ccf-toolchain.Dockerfile first. It pins the base digest, CCF
# RPM digest and Rust version. Record this image's resulting digest for rollout.
ARG TOOLCHAIN_IMAGE=agentdns-ccf-toolchain:7.0.15
FROM ${TOOLCHAIN_IMAGE} AS build
COPY Cargo.toml Cargo.lock /src/
COPY crates /src/crates
COPY ccf /src/ccf
RUN cmake -S /src/ccf -B /build -GNinja -DCMAKE_BUILD_TYPE=Release && cmake --build /build -j4
RUN mkdir -p /out/governance \
 && cat /opt/ccf/bin/actions.js /src/ccf/governance/actions.js /opt/ccf/bin/validate.js /opt/ccf/bin/apply.js /opt/ccf/bin/resolve.js > /out/governance/constitution.js \
 && cp /opt/ccf/share/VERSION /out/CCF_VERSION \
 && sha256sum /build/agentdns /out/governance/constitution.js > /out/build.sha256

FROM mcr.microsoft.com/azurelinux/base/core:3.0@sha256:c877612270d1ee2d6ab2bc1f64bfe38ab697ac50be325154ee5129fce89c17e4
RUN tdnf -y install ca-certificates python3 libuv nghttp2 openssl-libs libcurl libstdc++ && tdnf clean all
COPY --from=build /build/agentdns /usr/local/bin/agentdns
COPY --from=build /out/ /opt/agentdns/
COPY ccf/host_driver.py ccf/run.py /opt/agentdns/
WORKDIR /state
EXPOSE 8000/tcp 8002/tcp 5353/tcp 5353/udp
ENTRYPOINT ["python3","/opt/agentdns/run.py"]
CMD ["--config","/config/node.json"]
