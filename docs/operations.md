# AgentDNS release, operation and recovery runbook

This runbook describes the implemented CCF 7.0.15 service and the recovery
procedure exercised by `ccf/tests/live_smoke.py --recovery`. Local CCF consensus
tests use the explicitly named Virtual platform. They establish transaction,
replication and disk-recovery behavior; they do not establish confidential
hardware execution. Consult [the acceptance ledger](port-progress.md) and the
individual evidence reports for the deployment actually approved for use.

## Current authority and lifecycle boundary

The [September 21 v5 declaration](../infra/authority/azure/20260921-v5/README.md)
is the recorded deployed authority: one CCF voting node, durable AzureFiles
ledger/snapshots and ephemeral node state. Its image is the recorded older base
plus the diagnostic host-driver overlay, **not** a full build of this checkout.
The packaged/active constitution is `6fd2190b…`; the newer source constitution
has additional schema support. A successful source test does not install that
contract. Any constitution upgrade requires exact app-binary compatibility and
member-governed approval; do not submit source-only CVM/UQ/SVCB policy fields to
the existing service.

CCF 7.0.15 does not provide ordinary same-node process restart. The recorded v5
Recover command consumed predecessor CA `225f53f5…`; its resulting CA is
`b0db66b5…`. Re-running that declaration is not a recovery procedure for the
current service. Never change `restartPolicy: Never` to `Always` to mask failure.
On sole-node failure, use the existing governed disk-recovery procedure below,
with the **then-current** CA, complete durable ledger, existing member material,
a fresh node configuration/manifest/CCE and coordinated consumer pins. A lone
Join node needs a live peer; two voters cannot tolerate losing either voter.

Replacement through Join additionally needs proven historical-ledger and private
state continuity. The failed v3 snapshot-only bootstrap reported a missing
historical ledger chunk; it also exited after invalid TSIG provisioning. Do not
infer that a snapshot-only Join can supply all historical endorsements/receipts,
or that local Virtual tests prove the packaged native launch. Keep the existing
writer until a successor is independently appraised, committed, has the same
DNSKEY/TSIG/grants, can produce historical and fresh receipts, renews native
registrations and serves authenticated transfer. Retire only through governance
and confirmed removable-node state. This is a review procedure, not authorization
to create a new topology.

The aDNS lifecycle owner prepares those inputs and fences writers; the recovery
member custodian signs/reconstructs the service; hosting's trust/publisher/Steward
owner updates the existing consumers without resetting their monotonic or
registration state. Public DNS/registrar ownership is separate: the current ACI
BIND serves only `example.test.` over public UDP53, not `agent.hosting.` over
TCP+UDP53. The old validation BIND VM is not an active production spare. Public
provider changes require their own selected serving target and NS/DS review.

## Release and initial genesis bootstrap

1. Build the pinned toolchain and application with the commands in
   [ccf-integration.md](ccf-integration.md). Run Rust checks, the supervisor and
   host-driver tests, the live smoke test, the three-node quorum test, and the
   separate disk-recovery test before promoting a changed binary or SDK.
   Exercise stock BIND, DNSSEC validation, idle refresh and application lifecycle
   tests against the candidate. Retain the failing run if a fix is needed.
2. Record the source revision, dependency lockfile, CCF RPM/base-image digests,
   application OCI manifest digest, executable hash and assembled constitution
   hash. [The frozen validation build](evidence/ccf/build.json) records one tested
   candidate. A tag such as `agentdns-ccf:7.0.15` is a convenience, not an approved
   image identity. A rebuild requires new measured artifacts and review.
3. Prepare the public member certificates and encryption public keys, the
   reviewed constitution and node configuration. Keep member signing and
   recovery-decryption private keys with the members, outside the node image,
   node environment, application logs and public evidence directory. Choose the
   consortium membership and recovery threshold before opening the service;
   the one-member local fixture is only a test configuration. For a **new isolated genesis**, native ACI
   preparation uses `python3 tools/prepare_aci_control.py CONTROL_DIR
   --constitution-sha256 PACKAGED_CONSTITUTION_SHA256 --native-snp`. This
   creates fresh member keys and configures UVM attestation files and Azure/AMD collateral fallback;
   it must not be used to reconstruct an existing service or recovery membership.
   The generic local Virtual configuration deliberately omits them.
4. Produce a strict manifest mapping each absolute bootstrap file path to its
   SHA-256 digest. Include `node.json`, the exact assembled constitution, every
   referenced member certificate/encryption public key/data file, and applicable
   service/node data files. For Join include the trusted service certificate;
   for Recover include the previous service identity. Pin both image digest and
   the command's `--config-manifest-sha256` in the reviewed CCE policy. The
   supervisor verifies and freezes these bytes before CCF opens them. A volume
   mount declaration alone does not authenticate its contents.
5. Configure HTTP1 on every RPC interface. Bind `agentdns-internal` to loopback,
   restrict it to `/app/internal/.*` plus exact `/node/state` for the
   supervisor readiness probe, and keep internal8001 off the public
   interface. Restrict transfer5353 to the approved secondary network where
   possible; the isolated native acceptance exposes its TSIG-protected TCP
   listener for independent AXFR verification. Native CCF routes use the `/app`
   prefix. Public DNS53 belongs to the stock secondary. ACI cannot publish both
   TCP53 and UDP53, so its auxiliary BIND is UDP-only externally and the native
   historical acceptance used a separate BIND VM for ordinary TCP+UDP53;
   that does not establish a currently running public secondary. An approved TLS frontend can map the
   specification's unprefixed logical paths without changing signed actions.
6. Authenticate a new confidential node with
   [the independent native bootstrap audit](ccf-node-bootstrap.md) before
   trusting its service certificate or sending a governance proposal. Select
   the approved policy independently; observed quote fields are not an
   allowlist. Re-audit a new node/release identity and retain its public proof.
7. Activate members and open the service through signed CCF governance. The
   `tools/ccf_control.py ack` and `propose` modes use member COSE signatures and
   verify transaction commitment. A proposal body is a reviewed JSON actions
   array. Install the audience/epoch/time configuration, Owner Grants,
   independently approved appraisal policy, zone metadata and transfer scope.
   Initial DNSSEC keys are generated in the CCF private tables when autonomous
   maintenance initializes the governed zone.

The supervisor command includes these independently supplied paths and
digest; substitute the reviewed manifest digest, rather than this placeholder:

```sh
python3 /opt/agentdns/run.py --config /config/node.json \
  --state-dir /state --listen 0.0.0.0:5353 \
  --config-manifest /config/manifest.json \
  --config-manifest-sha256 REVIEWED_MANIFEST_SHA256
```

Only a new `Start` may additionally use
`--provision-tsig-file /config/transfer-key.json`. Before launch, compare its
canonical key name, zone scope and decoded-secret SHA256 against the approved
governed transfer configuration without logging the secret. Join/Recover reuse
private CCF state; the launcher rejects a provisioning argument for those modes
before starting CCF. Separately verify the secondary's existing secret digest.
Do not update a primary/secondary ACI group to reload a secondary key: group
updates may restart the sole primary.

Production uses the supervisor's restricted child environment and real hardware
platform selection. Explicit `CCF_PLATFORM_OVERRIDE=Virtual` and direct binary
launch are confined to disclosed local consensus tests.

## Existing durable state and single-writer ownership

The current declaration mounts the existing AzureFiles share
`ccf-recovery-20260921-v2` for `/durable` ledger and snapshots; `/state` remains
ephemeral. Host loss does not make that node restartable. Never mount the ledger
writable in a successor before the provider confirms the former writer stopped.
Preserve all chunks, including the current open `ledger_N`: it can contain
committed transactions. Read-only historical directories do not replay open
chunks as the recovery writable ledger does. Do not delete, trim, reset or
replace the existing ledger while repairing availability.

Retain the approved artifact/configuration identities, public service-CA history,
member public identities, existing member signing/recovery key custody, last
independently confirmed commit, zone serials, KSK receipts/DS and governed TSIG
digest/scope. These are recovery inputs, not a new copying or backup workflow.
The existing local disk-recovery fixture copies its stopped test directory to
isolate the test; production v5 used the complete existing durable share after
single-writer fencing. No live-share archive or byte-copy validation is part of
this operating procedure.

The September 21 read-only ARM sample reported 115,172,241 bytes used of 32GiB;
that is a point-in-time capacity observation, not a growth/flush guarantee. Use
existing provider capacity/error observations before an approved recovery;
retain uncertainty about long-term growth and filesystem failure behavior.
Do not change ledger retention to reclaim space without CCF compatibility proof.

## Recover the service from disk

The executable test is [ccf/tests/recovery.py](../ccf/tests/recovery.py). It
preserves actual private CCF state and submits a real RSA-decrypted consortium
recovery share. [Public recovery evidence](evidence/ccf-native-v5-20260913/recovery/summary.json)
records a historical exact-image test: original transaction `2.17`, a new-identity
receipt at `4.43`, and the previously unused nonce's successful transaction at
`4.45`. These IDs are examples from that isolated run, not values to use in a
live recovery. The [build record](evidence/ccf-native-v5-20260913/build.json) binds this evidence to
executable `6bcbf0a885cabdbea18ea3a25e0a3c56a49deaf1cf97e100ec97ff069ada8683`;
older tiny-zone measurements and prior consensus runs retain their original
identities in preserved evidence bundles.

1. Fence the failed deployment so it cannot later accept writes independently.
   Preserve available disks and public service certificates. Establish the
   last confirmed commit and the available complete durable ledger; old signed
   request results and nonces are part of the state that must be recovered.
2. After provider-confirmed single-writer fencing, mount the complete existing
   ledger/snapshots as the successor's writable durable state and use fresh
   ephemeral node state. Start the same approved application and compatible CCF version
   using `command.type = "Recover"`. Set
   `command.recover.previous_service_identity_file` to the authenticated old
   public service certificate and write a new `service_certificate_file`.
   Generate a new manifest/CCE approval for these exact recovery inputs and
   command before confidential deployment. Do not invoke `Start` over the old
   authority or silently initialize a new zone.
3. Wait for `PartOfPublicNetwork`. Independently authenticate the new node and
   service identity. Each required member signs the state-digest update and
   acknowledgement. Submit the governance action
   `transition_service_to_open` with both `previous_service_identity` and
   `next_service_identity` PEM values. Confirm the proposal's global commit.
4. Each participating recovery member retrieves their encrypted share from
   `/gov/recovery/encrypted-shares/<member_id>?api-version=2024-07-01`, decrypts
   it locally using their recovery encryption private key and RSA-OAEP-SHA256,
   and submits the base64 share in a member-signed COSE `recovery_share` message
   to `/gov/recovery/members/<member_id>:recover?api-version=2024-07-01`.
   Do not log plaintext shares or include them in evidence. Wait for the actual
   threshold and private-ledger replay; an accepted proposal alone is not a
   recovered private service.
5. Confirm the service is Open, has a nonempty primary ID and advancing
   committed transactions; `Open` alone is insufficient. Application reads must carry
   `x-agentdns-commit-status: committed`. Compare zone serials and exact DNSKEY
   RDATA to the pre-recovery committed identity evidence. Independently verify a new KSK receipt using
   the authenticated recovered service identity. Check historical request
   reconciliation retains its original transaction and result. The automated
   fixture additionally proves an authenticated failed observation and its nonce
   survive, and a separately unused nonce commits once;
   avoid consuming a real owner's pending action merely as a health probe.
6. Verify the original TSIG identity can authenticate transfer without replacing
   its secret. Resume the driver using the new authenticated service CA, ensure
   automatic signing/expiry progresses, and require each secondary's observed
   serial and external DNSSEC answers to catch up. Rejoin/trust additional
   approved replicas before relying on quorum tolerance again.

Recovery preserves the versioned lifecycle index and bounded usage metadata.
An absent or unsupported lifecycle marker fails closed. Do not patch a marker
into an old ledger, reset an epoch or clock backwards, or invent a migration.
See [lifecycle-bounds.md](lifecycle-bounds.md) for the explicit legacy-format
restriction and current capacity limits.

## Runtime health and incident handling

Poll the CA-pinned `GET /app/zone/status?zone=<absolute-name>` and check both the
committed state and independently observed secondary state. Track the following
as separate signals:

| Signal | Operator response |
| --- | --- |
| Commit header, transaction status and consensus health | A timeout or pending transaction is not success. Reconcile the same request ID and exact signed message; do not generate a different action just to retry. During quorum loss restore replicas/connectivity before serving new committed results. |
| `earliest_rrsig_expiration` and `maintenance_health` | Alert before the expiration margin is exhausted. A brief `refresh_due` at the scheduled boundary is expected; persistent refresh failure needs driver, consensus, time, storage and signing-log investigation. Expired snapshots refuse transfer or yield DNS failure rather than fresh authority. |
| Committed serial versus each `last_observed_serial` | A NOTIFY acknowledgement does not prove the secondary serves the new zone. Require a fresh authenticated SOA observation and external signed queries; inspect BIND transfer logs if it lags. |
| Registration lease and `reappraisal_deadline` | Renew early with the appropriate grant and fresh evidence when required. Expiration/revocation can remove contributions automatically. Keep an independently working service during rotation. |
| Driver liveness, signing spans and memory | Supervise both processes. The wrapper exits on driver failure; the sole CCF node then requires governed recovery, not a blind restart. The recorded v5 image disables OTEL export. Inspect existing startup/driver/provider logs and committed progress; missing exported spans do not prove signing stopped. |

Renewal requests specify a total duration measured from original admission,
bounded by grant/policy validity and the reappraisal deadline. They are not a
fresh duration added to the renewal time. Unchanged records need no immediate
re-signing; the independent lifecycle driver still refreshes their signatures.
Registration GET reports current eligibility in `status`, `active_ports` and
`active_contributions`. If a lease expires or authority is revoked before the
next maintenance commit, these immediately show expired/withdrawn eligibility.
`committed_status` and `committed_contributions` separately retain the rows still
present in the globally committed primary snapshot. Neither field asserts what
a secondary or resolver cache currently serves. Tightening an ACME issuer's
name, zone, key, validity or create-operation scope also withdraws its challenges
during maintenance while preserving independently owned service records.

Clock regression fails closed. Governance configuration changes must increase
the epoch, and the applied time watermark is clamped to at least the current
live watermark. Correct time at its source; do not lower persisted state to
make a failing request pass.

Use the [measurement tools](acceptance-ccf-measurements.md) for actual committed
registration latency, signing spans and an external idle interval crossing
signature lifetimes. Record sample counts, losses, platform, zone size, offered
load and RSS duration. An isolated sample, a short stable RSS interval or a
finite fuzz run does not establish an unlimited capacity or zero-leak claim.

## Key, grant and record changes

DNSSEC private keys and TSIG secrets remain in private CCF tables. The host
driver receives already signed DNS packets, never these keys. Do not attempt to
export keys through internal APIs or place plaintext secrets in a governance
proposal. Govern a TSIG key's canonical name, numeric secondary endpoint, zone
scope and `secret_sha256` first, then provision `{key_name,secret_base64url,zones}`
inside the protected loopback interface. The optional supervisor file accepts
confidential read-only secret volumes; it rejects group/other writable inputs.
An identical genesis provisioning retry is idempotent and never overwrites an existing key. Join/Recover must omit this argument entirely.

For TSIG rollover, govern a **new key name** with the new digest/endpoint,
provision it, configure the secondary, prove transfer and observed serial, then
submit `{"name":"adns_revoke_transfer","args":{"key_name":"old.example.test."}}`
using the member-signed proposal flow and wait for its global commit. Repeating
revocation is idempotent. The identity becomes a permanent tombstone in both
governance and application state: its digest and endpoint cannot change, and
`adns_set_transfer` cannot reactivate it. Retired identities count toward the
512-identity limit. The private secret stays in the confidential ledger history
and is never exported or overwritten.

After revocation commits, the primary rejects that identity's AXFR, UDP SOA,
private provisioning retries, and queued NOTIFY/SOA response callbacks. The next
secondary-work generation removes its pending rows and issues no new work for
it. Already exposed signed datagrams cannot be recalled, so also remove the old
key from the secondary; their replies cannot update committed observations.
Replacement identities and zone contents are preserved. Secondary observation
status describes an endpoint and zone, so revocation does not erase that shared
history or disrupt a replacement identity at the same endpoint. Prove a fresh
replacement-authenticated transfer and observation before retiring the old key.

Appraisal policy IDs permanently identify exact policy contents. Governance
allows an exact repeat (including reordered JSON object fields), and requires a
new nonzero 32-byte `policy_id` for every content change, including allowlists,
TCB/SVN limits, profile, validity, or an explicitly added default field. Arrays
retain their order for this identity comparison. The governance-owned history
retains at most 512 distinct IDs, each at most 64 KiB of canonical UTF-8 JSON,
4,096 visited values/keys, and nesting depth eight. Numeric values must be
nonnegative safe integers; malformed Unicode and negative zero are rejected.
Reusing an older ID with different contents is rejected even after another
policy becomes active. An explicit rollback to the exact older policy still
requires governance and does not restore withdrawn registrations.

Deployments predating the policy-identity mirror require fresh policy IDs and
an explicit reviewed migration and reappraisal before service use; do not apply
this constitution as an unchecked hot upgrade. Seed the mirror with the exact
currently committed policies before enabling updates, then install the reviewed
replacement policies with new IDs. Governance cannot read application tables
to reconstruct prior history, and this change does not retroactively enforce
immutability of previously used IDs. For new services, every policy is recorded
in the mirror on first installation.
A newly selected policy ID invalidates registrations admitted under the previous
ID; allow maintenance and authenticated secondary propagation to finish before
calling the change complete. Grant/policy revocation blocks new authorized use and lifecycle
maintenance removes invalid active contributions; check the resulting committed
serial and secondary propagation before declaring withdrawal complete.

For service TLS-key rotation, appraise and register the new key under an
appropriate grant, preserving old/new TLSA contributions on25,465,993. Validate
the actual served TLS key against the new DNSSEC-authenticated TLSA and wait for
the intended cache/overlap interval. Then deregister only the retiring
registration or selected ports. Concurrent registrations and ACME orders own
separate contributions; use their scoped APIs, not a blanket RRset delete.
Operator grants manage explicitly authorized non-attested records and cannot
replace the attested TLSA/key path.

Withdrawal and expiry remove records from the next committed authoritative
snapshot; they do not invalidate answers already held in resolver caches.
Plan overlap using the published RRset TTLs and DNSSEC expiration bounds, and
keep the retiring listener key available through that interval. The test
registration publishes MX TTL3600 and address/TLSA TTL300. External validators
also bound cached data by its authenticated signature expiration.

KSK receipts bind exact owner name and complete DNSKEY RDATA. Verify a saved
receipt against an independently authenticated service certificate:

```sh
python3 tools/verify_ksk_receipt.py ksk-receipt.json \
  --service-cert authenticated-service-cert.pem --zone example.test.
```

Compare the computed DS with the intended delegation and independently validate
the transferred zone. Publishing/changing a parent DS, NS delegation, public
mail routing or public certificate issuance is a separate domain-owner-approved
cutover. A valid receipt is evidence about the KSK, not authority to change the
registrar.

## KSK rollover (online, RFC 6781 double signature)

Governed by the `adns_ksk_rollover` action in the steward constitution; the app
drains the command in maintenance and never touches the parent DS itself.

1. **start** (`{zone, command:"start", minimum_hold_seconds}`): the enclave
   generates the incoming KSK, publishes both KSKs in the DNSKEY RRset and signs
   that RRset with both. `/app/zone/status`, the KSK receipt (`rollover` field)
   and `/app/governance/anchors` show the incoming key tag and DS. The receipt's
   claims still bind only the current KSK, so v1 verifiers are unaffected.
2. Wait at least the hold (default 2 × the largest base TTL, minimum 2 h) so
   every validator has seen the double-signed DNSKEY RRset, then the **domain
   owner** publishes the incoming DS at the parent (registrar) and waits the
   parent's DS TTL.
3. **complete** (`{zone, command:"complete", new_key_tag, new_ds_sha256}`): the
   proposer attests the parent now names the incoming key; the app refuses the
   command unless the tag and DS equal the incoming key's exactly and the hold
   has elapsed, then makes the incoming key current, deletes the old key and
   re-signs with a single KSK.
4. **abort** is accepted only while double-signing.

Agent-hosting's `infra/trust/pins.json` is updated from the KSK receipt after
completion (the receipt for the new key must verify under the pinned service
identity). Do not recreate a zone to simulate a rollover.

## Live code upgrade

See `docs/upgrade-runbook.md`: D-signed, SVN-gated node join policy
(`adns_set_node_join_policy`), join the new node, verify receipts, retire the
old node, close the window. Published anchors are in `docs/anchors.md`.

## Release rollback and cutover

Keep the previous approved artifacts and the existing durable ledger until the new
release has passed quorum, replay, private-key continuity, transfer, idle and
external validation checks. Test a new binary against the current ledger format
in isolation before an operational rollback. This port contains no arbitrary
backward schema migration. Rolling back a binary must preserve current committed
state, service-identity history, monotonic epoch/time, request results and keys;
replacing current committed state with an older checkpoint is not an ordinary
release rollback and must not be done as part of this procedure.

Do not run two independently writable services for the same authority during
cutover. Keep the old system available until the replacement has independently
verified keys/DS, fresh signatures, current observed secondary serials and
successful client checks. The owner must approve the actual NS/DS/mail changes
and their TTL/overlap schedule. If validation fails before delegation changes,
keep traffic on the established authority. If it fails after changes, use the
reviewed DNSSEC-compatible rollback schedule; casually restoring an old DS or
key while caches retain the new chain can cause validating resolvers to fail.
Retain the transaction IDs, public receipts and external observations needed to
explain the result without exposing member shares or private keys.

Request retries and timeouts follow [the reconciliation contract](request-reconciliation.md). A committed observation reporting `pending` or `failed` is not a committed application mutation. Keep the exact signed envelope for retries, inspect execution state separately from the global-commit header, and expect HTTP404 after an unsuccessful attempt's nonce expires and its diagnostic is pruned. Backup/recovery preserves these bounded observations with their nonce rows and monotonic watermark, along with the immutable successful replay cache.

## Finite validity and deferred platform work

The September 21 readback placed the current node/service certificate horizon at
2026-12-20T20:32:25Z, workload appraisal policy at 2026-12-20T08:23:46Z and node
appraisal policy at 2026-12-20T08:42:26Z. These are observations to reconcile
against then-current governance, not automatic renewal promises. The consortium
member owner must schedule the existing service/node certificate validity and
release-policy actions ahead of the earliest deadline; hosting's consumer owner
must review resulting CA/policy pin changes and demonstrate continuing renewal.
Driver maintenance refreshes DNS signatures and leases, not these certificates.
Do not extend a validity period or replace a key merely to silence expiry.

Periodic transfer warnings with private peers and zero prefix bytes identify
idle transports; the provider source remains unproven. Preserve warning and
successful-transfer evidence. Partial requests/backend stalls must remain
distinguishable; do not enable tracing or suppress warnings as a substitute for
cause evidence.

Current Azure SNP/UVM/CCE approval does not transfer to AWS by changing a DNS
record or image location. No AWS workload verifier is implemented by this
repair. Select an already supported profile and reviewed serving target before
any provider transition. Historical crash-loop groups and inactive secondary VMs
need separate dependency-checked retirement decisions, not automatic recreation.
