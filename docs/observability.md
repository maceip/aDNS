# AgentDNS observability

AgentDNS emits OpenTelemetry execution spans through the host receiver to an OpenTelemetry Collector, Tempo, and authenticated Grafana. Loki is configured for future structured logs. The native commit boundary and span-link rules are in [ccf/TELEMETRY.md](../ccf/TELEMETRY.md). Backend availability cannot authorize an action, establish attestation, or change a committed response.

The stack follows the architecture in the read-only agent-hosting reference: OTLP to Collector, traces to Tempo, logs to Loki, Grafana as the operator interface. No credentials or configuration files were copied from that deployment.

## Local deployment

[compose.yaml](../infra/observability/compose.yaml) uses the isolated project `agentdns-otel-validation`. Images are official publisher images pinned by tag and digest:

| Component | Version | Immutable digest |
| --- | --- | --- |
| Collector Contrib | 0.160.0 | `sha256:799dc6cf12c96192af37b5bdba804da8c10b3bc563b43cb90c3f3c58d9572ad6` |
| Tempo | 3.0.3 | `sha256:0296560ac66f8a3600d7fb3014a52c189d4d9c3549ad6ff441bf2409855d68d5` |
| Loki | 3.7.7 | `sha256:d70e4659623f3e109af669cae76fe2a5dd5be54e2298fe8aed380d982fbc2500` |
| Grafana | 13.2.1 | `sha256:f772d434e8fab0049deb2b1b30abd43342bcfca1537614aa8d36080232cf4283` |

Generate a new private runtime password file under an ignored directory; never put the value in Compose, an image, an argument, or Git:

```sh
umask 077
mkdir -p .validation/otel-local
openssl rand -base64 36 > .validation/otel-local/grafana-password
```

Copy [runtime.env.example](../infra/observability/runtime.env.example) to that private directory and set `AGENTDNS_GRAFANA_PASSWORD_FILE` to the absolute password-file path. Docker Compose uses a mounted secret and Grafana's `GF_SECURITY_ADMIN_PASSWORD__FILE` setting. The user is `agentdns`; anonymous access and sign-up are disabled. On a Linux deployment ensure the mounted file is readable only by the intended Grafana UID 472 (or its narrowly granted group). Do not make the password world-readable to work around mount permissions.

```sh
docker compose --env-file .validation/otel-local/runtime.env \
  -f infra/observability/compose.yaml up -d
```

Only loopback ports are published. Default OTLP ports are 4317/gRPC and 4318/HTTP. The validation environment changes these host ports to 14317/14318, Tempo query to 13200, and Grafana to 13000. These are host mappings; exporters sharing the Collector's network namespace use `http://127.0.0.1:4318`:

```sh
docker run --network container:agentdns-otel-validation-otel-collector-1 ...
```

The driver uses OTLP HTTP/protobuf, `service.version=0.1.0`, and one-second batches. The Collector batches every two seconds, limits input bodies to 4 MiB, memory to 256 MiB plus a 64 MiB spike allowance, and exporter queues to 128 requests with 15-second retry budgets. Compose separately caps each service's memory/CPU/processes and rotates its Docker logs. Tempo and Loki retention is 24 hours. Named volumes persist until explicitly removed. Tempo's native query API has no authentication and is exposed only on loopback; Grafana's data-source proxy requires login. These defaults are an isolated development stack, not a claim of multi-tenant production hardening.

## Privacy and span links

[otel-collector.yaml](../infra/observability/otel-collector.yaml) accepts only `agentdns-authority`, `agentdns-driver`, and the explicitly synthetic `agentdns-otel-smoke` resource names, and fixed architectural span names. It removes unknown regular span/resource/scope attributes, free-form status messages, tracestate, and all span events. Remaining regular attributes have fixed enum, route, transaction-ID or numeric bounds. The three source-approved public resource labels `deployment.environment`, `service.namespace`, and `service.instance.id` are retained only as strings of 1–128 characters from `[a-zA-Z0-9_.:/-]`; unknown resource fields are dropped. DNS query names, request bodies, evidence, signatures, nonces, key material, authorization headers, and raw errors are not backend attributes. The receiver already restricts these fields before export; the Collector is an additional check.

Real trace/span IDs, parent IDs, timestamps, outcomes, and asynchronous links remain intact. The pinned Collector's OTTL/redaction implementation does not scrub individual link attributes. The application receiver/SDK therefore enforces ID-only links and empty link tracestate before export; the Collector endpoint is restricted to local or authenticated authorized exporters. This configuration is not a general-purpose sanitizing endpoint for arbitrary third-party OTLP. Future exporters must preserve that link contract or add an independently tested link sanitizer.

The optional log pipeline rewrites every body to `agentdns diagnostic event`, drops free-form severity text and attributes, and retains only bounded HTTP status plus trace/span correlation. This proves compatible storage without enabling collection of arbitrary process output or sensitive application logs.

## Verification and current result

[verify.sh](../infra/observability/verify.sh) requires `curl`, `jq`, `openssl`, `xxd`, and `rg`. Export the private password-file path and optional host-port variables, then run it with a fresh private output directory. It posts clearly synthetic spans, queries exact trace IDs from Tempo, checks a preserved asynchronous link and injected-field removal, logs in to Grafana, and retrieves authenticated user, data-source, dashboard and proxied trace resources. Its proof concerns backend transport and resource APIs, not a rendered browser screenshot or a native CCF transaction.

On 2026-09-13, the local stack passed those checks. A separate OTLP log test verified Loki ingestion and body/attribute scrubbing. A separate local TLS ingress test accepted a correctly authenticated request, rejected missing and incorrect credentials with HTTP 401, rejected an untrusted CA, and retrieved the exact accepted trace from Tempo. The initial Tempo config used a removed version-2 `compactor` field and failed startup; it was corrected to Tempo 3's `overrides.defaults.compaction.block_retention`, and readiness then passed. These synthetic tests do not establish native CCF commitment, native attestation, or application-span completeness; those require the rebuilt application's separate acceptance run.

Validation runtime files and complete results are under `.validation/otel-stack-20260913/`. The running stack uses localhost Tempo `http://127.0.0.1:13200` and Grafana `http://127.0.0.1:13000`. Its private runtime environment path is `.validation/otel-stack-20260913/runtime.env`; credentials are not in this document.

## Optional native HTTPS ingress

[compose.native-https.yaml](../infra/observability/compose.native-https.yaml) and [otel-native-https.yaml](../infra/observability/otel-native-https.yaml) prepare a TLS 1.3 OTLP HTTP receiver with Collector Basic Auth. They replace both cleartext published OTLP ports with one explicitly bound HTTPS port. Compose >=2.24.4 is required for `!override`. The base Grafana/Tempo ports remain loopback-only. No native VM/cloud change is implied by preparing or locally testing this overlay.

Before deployment, review the actual listen IP, host firewall/source scope, DNS/IP SAN, certificate validity, and exact runtime configuration. Provide a private runtime directory with `server.pem`, `server-key.pem` and a bcrypt-compatible `htpasswd` file; arrange UID 10001 read access with narrow permissions. Generate a new random exporter password for this deployment. The TLS key and htpasswd file stay on the collector host; only the public CA and private Basic-auth header go to the authorized exporter. None belong in an image or source tree. The local smoke used a two-day, loopback-IP certificate and random credentials; those are not a deployment certificate or credential.

The exporter settings are `OTEL_EXPORTER_OTLP_ENDPOINT=https://<reviewed-host>:<port>`, `OTEL_EXPORTER_OTLP_CERTIFICATE=<absolute-public-CA-path>`, and a private `OTEL_EXPORTER_OTLP_HEADERS=authorization=Basic%20<base64-user-password>` value. The host receiver rejects cleartext use of credentials/custom trust, validates the CA and hostname, and bounds the outbound request. Do not disable TLS verification or add secrets to resource attributes. Merge the native overlay only after reviewing the concrete endpoint/runtime plan; do not run `compose config` into a public artifact if future settings embed secrets.

## Upstream references

The configuration is based on the official [Collector transformation contract](https://opentelemetry.io/docs/collector/transforming-telemetry/), pinned [OTTL transform processor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.160.0/processor/transformprocessor/README.md), [Basic Auth extension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.160.0/extension/basicauthextension/README.md), [Tempo 3.0.3 single-binary configuration](https://github.com/grafana/tempo/blob/v3.0.3/example/docker-compose/single-binary/tempo.yaml), and [Loki native OTLP ingestion](https://grafana.com/docs/loki/latest/send-data/otel/). Version selection was checked against the publishers' release APIs on 2026-09-13, then ordinary image pulls supplied the actual immutable digests above.
