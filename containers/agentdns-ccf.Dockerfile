# Build containers/ccf-toolchain.Dockerfile first. It pins the base digest, CCF
# RPM digest and Rust version. Record this image's resulting digest for rollout.
ARG TOOLCHAIN_IMAGE=agentdns-ccf-toolchain:7.0.15
FROM ${TOOLCHAIN_IMAGE} AS build
COPY ccf/requirements-otel.txt /tmp/requirements-otel.txt
RUN python3 -m pip install --no-cache-dir --target /out/python -r /tmp/requirements-otel.txt
COPY Cargo.toml Cargo.lock /src/
COPY crates /src/crates
COPY ccf /src/ccf
RUN cmake -S /src/ccf -B /build -GNinja -DCMAKE_BUILD_TYPE=Release && cmake --build /build -j4
RUN mkdir -p /out/governance \
 && cp /src/ccf/governance/constitution.js /out/governance/constitution.js \
 && echo "$(cat /src/ccf/governance/constitution.sha256)  /out/governance/constitution.js" | sha256sum -c - \
 && cp /opt/ccf/share/VERSION /out/CCF_VERSION \
 && sha256sum /build/agentdns /out/governance/constitution.js > /out/build.sha256

FROM mcr.microsoft.com/azurelinux/base/core:3.0@sha256:c877612270d1ee2d6ab2bc1f64bfe38ab697ac50be325154ee5129fce89c17e4
RUN tdnf -y install ca-certificates python3 libuv nghttp2 openssl-libs libcurl libstdc++ && tdnf clean all
COPY --from=build /build/agentdns /usr/local/bin/agentdns
COPY --from=build /out/ /opt/agentdns/
COPY ccf/host_driver.py ccf/run.py ccf/telemetry.py /opt/agentdns/
# Direct driver invocations (including the isolated CCF/BIND harness) use the
# same image-owned SDK directory as supervisor-spawned exporters.
ENV PYTHONPATH=/opt/agentdns/python
# Build with --build-context domain-registry=<snapshot directory> from the
# common hosting store. The snapshot is a build input, never a local default.
COPY --from=domain-registry topology.json /etc/agent-hosting/domain-registry.json
COPY tools/domain_registry.py /opt/agentdns/domain_registry.py
RUN python3 /opt/agentdns/domain_registry.py json >/dev/null \
 && sha256sum /etc/agent-hosting/domain-registry.json > /etc/agent-hosting/domain-registry.sha256
WORKDIR /state
EXPOSE 8000/tcp 8002/tcp 5353/tcp 5353/udp
ENTRYPOINT ["python3","/opt/agentdns/run.py"]
CMD ["--config","/config/node.json"]
