# Controlled native mail connection routing

The ACI validation workload fixes `192.0.2.1` and `2001:db8::1` in its measured registration action because its actual public address is assigned after the workload policy is generated. Those reserved addresses are not publicly routable. The native mail acceptance harness therefore keeps the exact signed DNS answers and applies an explicit destination NAT rule **only inside a disposable client container**. The rule connects the signed IPv4 address's TCP 25 flow to the actual fixture endpoint. It does not change DNS responses, the DNSSEC chain, SMTP bytes or TLS keys.

Stock Postfix `posttls-finger -S` selects LMTP, not a connection override. Its `-s` option controls SNI and is ignored under DANE. Native host lookup does not support DANE because DNSSEC authentication information is unavailable. We retain stock DNS-based Postfix and its normal DANE validation. [Official Postfix manual](https://www.postfix.org/posttls-finger.1.html). DNAT alters packet destination routing; the positive connection remains end-to-end TLS between Postfix and the chosen workload. [Netfilter documentation](https://netfilter.org/projects/nftables/manpage.html).

Build the independent validation images using the existing Dockerfiles, then add the small NAT-tool layer:

```sh
docker build -f containers/validation.Dockerfile -t agentdns-validation:local .
docker build -f tests/rust-integration/Dockerfile -t agentdns-mail-validation:local .
docker build -f tests/rust-integration/remote-mail.Dockerfile -t agentdns-remote-mail-validation:local .
```

Before using remote endpoints, obtain explicit authorization for that isolated execution. The public input directory must contain the independently appraised capture's `spki.der` and TLS `cert.pem`, plus the independently authenticated CCF zone KSK as `trust-anchor.conf`. It must contain no bearer token, member signing key, workload private key, deployment parameters or transfer secret. Appraising the capture and authenticating the CCF service/anchor remain separate required steps; this harness cannot make those trust decisions.

```sh
# Set these to the approved isolated endpoints and public-artifact directories.
docker run --rm --cap-add NET_ADMIN \
  -v "$PWD/tests/rust-integration:/suite:ro" \
  -v "$PUBLIC_INPUT:/public:ro" -v "$PUBLIC_RESULTS:/results" \
  agentdns-remote-mail-validation:local \
  python3 /suite/verify_native_mail.py \
  --dns-server "$BIND_PUBLIC_IPV4" --dns-port 53 \
  --connection-address "$CAPTURE_PUBLIC_IPV4" \
  --published-address 192.0.2.1 --zone example.test. \
  --mailbox-domain example.test. --service-host mail.example.test. \
  --anchor /public/trust-anchor.conf --certificate /public/cert.pem \
  --spki /public/spki.der --output /results
```

Use Docker's ordinary private network namespace. **Never add `--network host` or run the script on the host.** The only extra capability is `NET_ADMIN` in this disposable test container; the harness inserts and removes each exact OUTPUT DNAT rule and never flushes other rules. No inbound Docker ports are published. The script requires a Linux Docker environment.

The harness starts a local BIND validating resolver with the supplied static zone KSK. It authenticates MX, the exact routed A record and all three TLSA RRsets before running Postfix. It requires the MX host to be the tested service host, the sole IPv4 address to be the explicit route, and each TLSA set to authorize the supplied DER SPKI hash. IPv6 is intentionally disabled for this controlled connection test; IPv6 routing is not established by it.

The positive probe uses stock Postfix in `dane-only` mode and requires both `Verified TLS connection established` and its actual peer key fingerprint to match the independently appraised SPKI. The negative probe routes the **same authenticated name and unchanged TLSA data** to a local SMTP STARTTLS peer generated with a different key. It requires an actual TLS handshake with that wrong key and an untrusted result; a timeout or connection refusal does not count. The program checks the TLSA answers remain unchanged afterward. Postfix's diagnostic exit status can be zero for the wrong-key case, so the result is determined from the verified/untrusted TLS outcome and actual peer fingerprint.

Ports 465 and 993 connect explicitly to the actual fixture address, validate its configured service hostname under the supplied controlled certificate trust, and compare the peer DER SPKI with the independently appraised key and authenticated TLSA records. Wrong-hostname and default-system-trust attempts must fail. This proves controlled PKIX validation, not public ACME certificate issuance. No SMTP messages, credentials, IMAP authentication or mailbox operations are submitted.

`native-mail-results.json` records the explicit connection override, input certificate/anchor hashes, expected and observed SPKI fingerprints, DNSSEC validation, matching/mismatching DANE outcomes and implicit TLS checks. Preserve that file with the two Postfix logs and validating resolver log. Correlate it with the actual native appraisal, globally committed registration, and service DNS evidence before making a native acceptance claim.

## Local harness proof

The harness was exercised with a separate genuine DNSSEC-signed **development-memory** zone, a stock BIND authoritative server, a separately generated local TLS peer, and the exact reserved `192.0.2.1` A record. Container-only DNAT produced a verified stock Postfix connection and a rejected wrong-key connection while retaining the authenticated TLSA answers. Ports465/993 passed controlled trust/hostname/SPKI checks and rejected wrong names and untrusted certificates. Public transcripts are in `docs/evidence/controlled-mail-local-20260913/`.

This local run validates the routing and stock-client harness itself. Its TLS key is ordinary test material; it has no hardware evidence or committed CCF registration. Native cloud execution remains pending the separately required authorization and actual endpoint deployment. Neither this test nor a later routed native test proves that the reserved advertised A/AAAA records route on the public Internet, email delivery, or public ACME issuance.
