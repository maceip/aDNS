# Ubuntu24.04 amd64 manifest resolved 2026-09-13; no hosting-side image is used.
FROM ubuntu:24.04@sha256:a61567bd31828687156d735ea8eb01ba4e37636e225dd6a48ba94136a70d9d61 AS collector
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev make && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Explicitly exclude the fake-report source and target from the build context copied here.
COPY 3rdparty/get-snp-report/get-snp-report.c 3rdparty/get-snp-report/get-snp-report5.c 3rdparty/get-snp-report/get-snp-report6.c 3rdparty/get-snp-report/helpers.c ./
COPY 3rdparty/get-snp-report/*.h ./
RUN gcc -O2 -Wall -static -o /get-snp-report get-snp-report.c get-snp-report5.c get-snp-report6.c helpers.c

FROM ubuntu:24.04@sha256:a61567bd31828687156d735ea8eb01ba4e37636e225dd6a48ba94136a70d9d61
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-cbor2 python3-cryptography ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=collector /get-snp-report /usr/local/bin/get-snp-report
COPY tools/capture_aci.py /app/capture_aci.py
# Build with --build-context domain-registry=<snapshot directory> from the
# common hosting store. The snapshot is a build input, never a local default.
COPY --from=domain-registry topology.json /etc/agent-hosting/domain-registry.json
COPY tools/domain_registry.py /app/domain_registry.py
RUN python3 /app/domain_registry.py json >/dev/null \
 && sha256sum /etc/agent-hosting/domain-registry.json > /etc/agent-hosting/domain-registry.sha256
# Native SNP character-device access is required; no privileged host mounts or
# software-generated quote paths are provided by this image.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080 25 465 993
ENTRYPOINT ["python3", "/app/capture_aci.py"]
