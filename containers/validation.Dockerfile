FROM ubuntu:24.04@sha256:786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bind9 bind9-utils bind9-dnsutils ldnsutils python3 python3-dnspython python3-cryptography openssl ca-certificates curl dnsperf procps && rm -rf /var/lib/apt/lists/*
WORKDIR /work
