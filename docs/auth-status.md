# Signed actions and Owner Grant implementation

`crates/adns-auth` implements the stateless WS4 authorization boundary. It uses no unsafe code, no clock source supplied by a client, and no process-local substitute for durable nonce or request-result storage.

Implemented and tested:

- Strict JSON rejects duplicate properties at every depth (including escape-equivalent names), unknown schema fields, negative and floating-point numeric syntax, integer overflow beyond `2^53 - 1`, explicit null where an optional string is expected, malformed encodings, and oversized requests. RFC 8785 canonicalization uses UTF-16 property order and minimal JSON string escaping on the specified nonnegative safe-integer subset.
- Signed operations are `register`, `renew`, `deregister`, `acme_challenge_create`, `acme_challenge_delete`, and `operator_records`. Every operation has a separate typed parameter schema. DNS names must be canonical absolute lowercase ASCII; addresses must be canonical and numerically sorted within each address family; ports are sorted, unique and nonzero. CIDRs use canonical network addresses with no host bits.
- Public keys use exactly the canonical 91-byte DER SubjectPublicKeyInfo encoding for uncompressed P-256. Request verification checks point validity through `ring`, applies SHA-256 once to raw canonical bytes, and admits fixed 64-byte `r || s` signatures only. DER signatures, double-hashed signatures, trailing SPKI data and request/evidence tampering fail.
- Owner Grants bind the key digest to exact zones, mailbox domains, service hosts, roles, CIDRs, ports and operations, plus exact ACME/operator scopes and validity limits. Registration/challenge ownership checks consume trusted stored target metadata. Renewals can recheck original registration scope without requiring registration permission.
- Cryptographically random nonces contain 32 bytes encoded as 64 lowercase hex characters, bind the canonical action intent, and expire after exactly 300 seconds. Validation checks grant/request bindings, expiration and consumption. `NonceRecord` is a persistence schema, not a nonce database.
- Committed request rows store the exact signed-message digest and HTTP result. Signature-verified historical retries can return that committed result despite later nonce expiry or grant revocation. Changed actions or a fresh nonce with the same request ID conflict. Lease expiration is bounded by the requested duration, grant/policy validity and appraisal deadline.

## Exact signed-message contract

The signed bytes are JCS of the object containing exactly `action`, `nonce`, `nonce_expires_at`, and `intent_hash`. `intent_hash` is lowercase hex SHA-256 of JCS of `action`. The signature and evidence payload are excluded from the signed object. An evidence payload is authenticated by its SHA-256 digest inside signed action parameters, and must be canonical unpadded base64url. Nonces are the explicit lowercase-hex exception specified by WS4 and the nonce endpoint.

The renew schema permits optional paired `evidence_profile` and `evidence_digest` string fields; both must be omitted or present together. This makes fresh evidence at a required renewal appraisal cryptographically bound. An unsigned renewal evidence payload is rejected.

The operator endpoint uses the same signed envelope and `operation: "operator_records"`. Its parameters contain `expected_serial` and `mutations`; the zone is the common `action.zone`. The bare operator JSON example in `port.md` describes mutation content, while the signed envelope fulfills its requirement that all mutating requests be signed. Operators require an explicit governed operation/name/type grant. Mutation types are `replace`, `add`, and `delete`; an empty RDATA array is permitted only for delete. The storage layer preserves ownership and discards the complete staged application update if any type-specific RDATA is malformed.

## Required storage/server integration

1. Parse raw ingress with `parse_nonce_request` or `parse_signed_request`; deserializing through a generic JSON map first loses evidence of duplicate keys.
2. Resolve Owner Grants from authenticated CCF governance state. `authorize_action` checks a grant's content, not the provenance of its installation.
3. Commit a newly issued nonce before exposing its response.
4. For a signed mutation, verify the signature before using the stored result. Return only globally committed historical results. On a new request, read and validate the nonce and current grant, verify attestation when required, and check stored target ownership/scope.
5. On successful execution, atomically consume the nonce, update contributions/registration/signatures/serial, and store the request result in one CCF transaction. A returned `VerifiedRequest` performs no mutation and proves no commit. The server overlay discards rejected application updates; eligible authenticated failures may commit only bounded diagnostic metadata and the clock watermark, without consuming the nonce. See [request-reconciliation.md](request-reconciliation.md).
6. Publish committed output and dispatch NOTIFY only after global commit. Expired nonce rows and request retention policy are lifecycle responsibilities; deleting a retained request ID must never permit replay of an old consumed nonce.

Validation: `cargo test -p adns-auth` passes 11 integration tests, including real generated P-256 signatures, ASN.1 rejection, single-hash checks, nested JSON adversarial cases, CIDR boundaries, all owner-scope failures, nonce consumption/expiry/corruption, exact historical replay, target ownership and renewal scope rechecking. `cargo clippy -p adns-auth --all-targets -- -D warnings` passes. Durable global-commit behavior and genuine hardware evidence are separate integration acceptance evidence, not claimed by these unit/integration tests.
