# Isolated genuine ACI evidence capture

`containers/capture.Dockerfile` builds an amd64 worker from a pinned Ubuntu24.04 manifest and the repository's native SNP ioctl collector. The build explicitly copies only the real collector sources; no fake-report program is compiled or included. It does not depend on, read, or modify `agent-hosting`.

At startup `tools/capture_aci.py` generates a fresh P256 private key in process memory, computes DER SPKI, and asks the native device for `SHA256(SPKI) || 32 zero bytes`. It checks all 64 returned binding bytes, VMPL0, disabled debug, and that the returned CCE `host_data` equals SHA256 of the decoded native security-policy file. It wraps the native report, AMD endorsements and Microsoft UVM endorsement in ES256 COSE Sign1 under that same key. The private key is never persisted or exported; crash dumps are disabled. TLS uses the same attested P256 key and a self-signed certificate with SANs for fixed `agentdns-capture.test` and the configured service host, valid for at most 24 hours plus five minutes of initial clock skew. CPython requires a filename to load TLS credentials, so the worker briefly serializes the key into a Linux anonymous `memfd`, loads it through `/proc/self/fd`, and immediately closes both credential descriptors on success or failure. There is no disk-file fallback. TLS 1.2 or newer is required; the listener accepts HTTPS only. HTTPS admits at most eight handlers and imposes an absolute30-second transport deadline across handshake, request headers/body and response writes. A timer shuts down the socket even when a peer trickles bytes below the per-read timeout. Automatic CCF requests use the same absolute30-second HTTP transport deadline,10-second connection/read limits, no proxy and no redirects. A configured hostname still uses the operating system DNS resolver during connection setup; the application checks the deadline again before transmitting an HTTP request. Automatic registration performs at most two individually bounded upstream calls; it can finish/cache the fixed operation after the incoming client socket reaches its own deadline, and an identical retry retrieves that result.

Capture is **not appraisal**. Every readiness response and startup log says `captured_not_appraised`. The Rust `adns-attest` verifier and committed governance policy must independently verify the AMD/Microsoft chains, measurements, CCE policy, TCB and validity. Observed inventory fields are explicitly untrusted; this tool never creates an approving policy from them.

## Startup configuration

The CCE policy must authorize the image, its exact command and startup configuration, the native SNP device and security-context files. ACI supplies `UVM_SECURITY_CONTEXT_DIR`; otherwise the worker requires exactly one `/security-context*` directory containing all three native files. The worker has no report-file override or virtual mode.

Pass base64 of the following JSON as `AGENTDNS_CAPTURE_CONFIG_B64`. It is fixed for the life of the worker; HTTP callers cannot alter the operation, names, audience, addresses, ports, grant, request ID or lease.

```json
{
  "request_id": "aci-capture-2026-09-13",
  "audience": "ccf://agentdns.test",
  "grant_id": "aci-test-owner",
  "zone": "example.test.",
  "role": "mx-edge",
  "mailbox_domain": "example.test.",
  "service_host": "mail.example.test.",
  "addresses": {"ipv4": ["192.0.2.1"], "ipv6": ["2001:db8::1"]},
  "ports": [25, 465, 993],
  "lease_seconds": 3600,
  "listen_address": "0.0.0.0",
  "listen_port": 8080
}
```

`AGENTDNS_CAPTURE_TOKEN` must separately contain 32 cryptographically random bytes in lowercase hex, supplied as a secure ACI environment variable. It authorizes only signing/submitting the fixed test registration. Do not log the token or publish environment dumps. The public listener carries the control token only over verified, pinned TLS.

Only reserved `.test.`, `.invalid.` or documented example zones are accepted. Addresses must be canonical, numerically sorted and distinct. Ports are restricted to 25/465/993 and leases to one day. Canonical signing implements the complete RFC8785 behavior needed for this deliberately ASCII-only, bounded-integer action schema; unknown fields, duplicate keys, floating-point numbers and non-ASCII action strings are rejected.

## Parent-driven flow

1. Fetch `GET /capture` over HTTPS without a control token. This bootstrap fetch may use an untrusted TLS connection solely to obtain public evidence. It returns public SPKI, COSE evidence, SHA256 digests, the fixed action, TLS certificate DER/PEM and fixed server name, and untrusted native report inventory. `GET /action` returns just action and intent hash. `/spki.der`, `/evidence.cose`, `/report.bin`, `/cert.der`, and `/cert.pem` return their public artifacts.
2. Independently inspect/govern the actual CCE policy, UVM identity/measurement/SVN, product TCB and owner grant. The subject digest is `spki_sha256` from the independently appraised SPKI. Merely copying observed fields into a policy is not verification.
3. Require the actual TLS peer certificate SPKI to equal the independently appraised SPKI, then pin that certificate or exact SPKI and verify the fixed name `agentdns-capture.test` for every subsequent request. Do not trust an inventory certificate without checking the peer: a relay can copy public evidence. Never send the control token during an unverified bootstrap request. Send the returned action to the CCF `/service/nonce` API.
4. Send the returned nonce fields to `POST /signed-request`, with `Content-Type: application/json` and `Authorization: Bearer <control token>`:

```json
{
  "nonce": "<64 lowercase hex characters>",
  "nonce_expires_at": 1800000250,
  "intent_hash": "<the fixed action's SHA256>"
}
```

The response is the complete service registration envelope. Its request signature is fixed 64-byte P1363 P256/SHA256 over JCS of exactly `action`, `nonce`, `nonce_expires_at`, and `intent_hash`; evidence is committed through the action's digest. The nonce must be unexpired, no more than 300 seconds ahead, and match the fixed intent. There is no arbitrary-message signing endpoint. Exact retries return the identical cached envelope; a different nonce for the same action is rejected to avoid creating conflicting request history.

5. Submit that exact envelope to CCF `/service/register` and reconcile the transaction through CCF global-commit status and the service request/status APIs. The worker does not promote HTTP 200 or a transaction ID to a global-commit claim.

If CCF is directly reachable from ACI, optional `ccf_url` and `ccf_ca_pem` startup fields enable `POST /register` with an empty JSON object. The URL is an HTTPS base, optionally ending `/app` if needed by the CCF router. TLS requires the explicit trusted CA and normal hostname verification; redirects and environment proxies are disabled. An ambiguous submission is retried with the identical signed request. A successful response is cached for the fixed request ID and returned without another mutation.

## Fixed-scope lifecycle validation

Version2 adds two bearer-authenticated HTTPS endpoints. `POST /lifecycle/action` accepts exactly `operation`, `request_id` and `parameters`, then constructs every signer, audience, grant and zone field internally. It returns `action_id`, `action` and `intent_hash` (the two hashes are identical). Send that action to CCF's nonce endpoint, then `POST /lifecycle/signed-request` with exactly `action_id`, `nonce`, `nonce_expires_at` and `intent_hash`. The response is the normal signed envelope ready for its CCF endpoint.

First sign the worker's fixed registration through `/signed-request`; lifecycle operations cannot precede it. The worker derives its registration ID as `reg-` plus the first32 lowercase hex characters of SHA256 over JCS of the exact signed register body (`action`, `nonce`, `nonce_expires_at`, `intent_hash`). The parent should derive and compare that same ID with the globally committed registration result. Signing is not proof that the operation committed.

Permitted preparation parameters are deliberately narrow:

| Operation | Accepted parameters | Fixed constraints |
|---|---|---|
| `renew` | `requested_lease_seconds` | At most the configured initial lease; fixed native evidence/profile are attached for reappraisal. |
| `deregister` | `selected_ports`, `withdraw_all`, optional `reason` | Sorted subset of configured mail ports; all-withdrawal requires an empty list; reason is bounded printable ASCII. |
| `acme_challenge_create` | `order_id`, `txt_value`, `ttl`, `lifetime_seconds` | The name is always the configured service host; TXT is exactly canonical43-character base64url SHA256; TTL1–300 seconds and no longer than lifetime; lifetime at most one hour and the configured lease. |
| `acme_challenge_delete` | `challenge_id` | Only an ID derived when this worker issued a challenge-create envelope. |

For challenge creation, IDs use `chal-` plus the first32 hex characters of SHA256 of the exact JCS signed body. A supplied registration ID, service name, grant, address, port outside scope, arbitrary action, unknown field or unknown prepared/challenge ID is rejected. Identical preparations and signed retries are stable; reusing a request ID for different parameters or changing an already signed action's nonce is rejected. At most128 lifecycle actions are retained. Registry commitment, grant validity, active registration status and actual deletion remain enforced by CCF; the worker never infers them from signing alone.

A second fresh worker/key can register the same governed service host to exercise key overlap. Each worker can retire only its own derived registration. Two distinct challenge-create actions/order IDs can coexist; deleting one emits only that known challenge ID. No private key needs to leave either worker.

The software suite exercises every lifecycle signature and scope boundary, plus HTTPS authorization for both endpoints. A separate Rust process verifies all five Python-generated operation envelopes through `adns-auth`'s real strict parser, JCS and fixed P256 signature verification; see `docs/evidence/aci-capture-lifecycle-cross-verification.txt`. Those fixtures are explicitly synthetic report data and are not hardware or globally committed lifecycle acceptance.

## Actual-key mail protocol fixtures

The native capture image now exposes constrained mail protocol peers on its configured mail ports, using the **same attested P256 private key and TLS certificate** as HTTPS8080. The certificate includes both `agentdns-capture.test` and the configured service-host SAN. Publish TCP 25/465/993 for the isolated validation workload if the parent plans external interoperability tests; HTTPS8080 remains unchanged.

Port 25 provides SMTP EHLO and STARTTLS. Port 465 provides implicit TLS SMTP. Port 993 provides implicit TLS with minimal IMAP CAPABILITY/NOOP/LOGOUT support. SMTP MAIL, RCPT, DATA and AUTH explicitly fail; IMAP authentication and mailbox commands fail. There is no message queue, recipient delivery, credential store or mailbox. These are controlled protocol fixtures, not an implementation of the project's mail service.

Each listener admits at most eight handlers before starting threads. Sessions have a30-second total deadline, at most16 commands, and512-byte protocol lines; TLS handshakes and socket reads are also bounded. TLS requires1.2 or newer. All public proof artifacts still state `captured_not_appraised`; listeners never turn capture readiness into an appraisal claim. Native evidence is capped at the Rust verifier's1 MiB bound, while HTTP/JSON transport has a2 MiB bound.

Additional real TLS tests trickle both incoming request headers/body and outgoing CCF response headers/body; every connection is terminated by the absolute deadline, and a subsequent healthy request succeeds. Independent software tests perform STARTTLS and implicit TLS handshakes, compare the actual peer SPKI to the report-bound key, enforce the configured service-host name, reject untrusted certificates/wrong hostnames, and verify message/authentication rejection and oversized-line closure. A parent can run a real DANE MTA probe against the DNSSEC-authenticated native registration and validate ports465/993 with the captured, independently appraised public certificate as an explicitly controlled trust anchor. Trusting that certificate is not public ACME issuance. Actual Azure DNSSEC/DANE/PKIX results remain separate from these local software tests.

## Local validation and remaining evidence

```sh
python3 tools/domain_registry.py snapshot .domain-registry/topology.json
docker build --platform linux/amd64 --build-context domain-registry=.domain-registry -f containers/capture.Dockerfile -t agentdns-capture:local .
docker run --rm --platform linux/amd64 -v "$PWD:/work" --entrypoint python3 agentdns-capture:local -m unittest discover -s /work/tools/tests -p test_capture_aci.py -v
cargo run -p adns-attest --example appraise -- azure-aci-snp evidence.cose spki.der governed-policy.json UNIX_TIME
```

The amd64 image builds successfully. Eighteen software tests exercise outer COSE/signature verification, exact report binding, fixed action and signature, malformed/duplicate input rejection, forbidden scope changes and identical retry behavior, and exercised HTTPS capture/authentication/scope enforcement. TLS tests independently verify the certificate signature and exact attested SPKI, bounded validity, public certificate artifacts, rejection of untrusted certificates, wrong hostnames and plaintext HTTP, and closure of anonymous descriptors after both successful loading and a forced failure. Test-only collector monkeypatches are clearly marked as synthetic and never count as hardware acceptance. They are not copied into the image. A separate Rust process also parsed the Python-generated test envelope and validated its JCS action, fixed P256 signature and evidence digest through the actual `adns-auth` APIs; see `docs/evidence/aci-capture-cross-verification.txt`.

Fresh native Azure ACI capture and cryptographic appraisal are recorded in the [native public evidence bundle](evidence/native-aci-20260913/README.md), with verification instant 2026-09-13 01:11:45 UTC. The original real COSE/report binds the actual guest-generated P256 key through all64 REPORT_DATA bytes; Rust and an independent Python/OpenSSL implementation verify its signatures and governed policy. One positive and sixteen rejected variations are preserved. Its approved-release Microsoft endorsement semantics and current AMD-chain requirement are explicit.

That capture used an earlier worker image. Globally committed CCF registration, fresh nonce signing, native lifecycle, and DNSSEC/DANE publication remain separate pending acceptance. Automatic approval review has blocked the next isolated cloud deployment and a token-plus-nonce signing request pending explicit user approval. No local fixture, new image build or historical appraisal reproduction closes those gaps. Updating the worker image requires fresh native evidence and an approved matching CCE policy.

Primary references: [CCF native ACI SNP security context](https://ccf.dev/main/operations/platforms/snp.html), [Microsoft ACI attestation concepts](https://learn.microsoft.com/en-us/azure/container-instances/confidential-containers-attestation-concepts), [Microsoft native SNP collector](https://github.com/microsoft/confidential-sidecar-containers).
