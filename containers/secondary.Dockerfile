# Ubuntu24.04 amd64 manifest; final built digest is pinned in the ACI definition.
FROM ubuntu:24.04@sha256:a61567bd31828687156d735ea8eb01ba4e37636e225dd6a48ba94136a70d9d61
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bind9 bind9-utils python3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY tools/secondary_aci.py /app/secondary_aci.py
# Build with --build-context domain-registry=<snapshot directory> from the
# common hosting store. The snapshot is a build input, never a local default.
COPY --from=domain-registry topology.json /etc/agent-hosting/domain-registry.json
COPY tools/domain_registry.py /app/domain_registry.py
RUN python3 /app/domain_registry.py json >/dev/null \
 && sha256sum /etc/agent-hosting/domain-registry.json > /etc/agent-hosting/domain-registry.sha256
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 53/tcp 53/udp
ENTRYPOINT ["python3", "/app/secondary_aci.py"]
