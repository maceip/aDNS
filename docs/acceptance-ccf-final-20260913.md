# Final CCF/BIND acceptance, 2026-09-13

The complete local CCF/BIND runner passed its real signature-maintenance window,
sustained query load, operator mutation, durable request reconciliation and TSIG
replacement checks. Run `run-px_xd2d2` reported **1,625.87 seconds before cleanup**;
subsequent cleanup removed every owned container and private CCF state volume. This is real **Virtual CCF**
with stock BIND and independent protocol clients. Native Azure admission and
attested-key lifecycle retain their separate approval and evidence requirements.

The [122 public artifacts](evidence/ccf-runner-final-20260913/sha256.json) were
exported using that run's own frozen allowlist exporter. Every artifact hash was
rechecked, and the primary reviewer independently compared all exported bytes
with the original results. Both private TSIG secrets were absent in raw, standard
base64, base64url and hexadecimal forms. The [complete result](evidence/ccf-runner-final-20260913/runner-results.json)
and [cleanup record](evidence/ccf-runner-final-20260913/cleanup.json) retain the
actual outcomes. Earlier failed attempts and the superseded baseline remain
separate in the [runner history](acceptance-ccf-runner.md).

## Executed identity and review

| Component | Immutable identity |
| --- | --- |
| OCI image index | `sha256:f4f4d4331461c3b9b3283b18db60a35de6c021ce776b576092b30250edf58ab7` |
| AMD64 manifest | `sha256:34bb5ecc0fad0d2a37552b4161d3b3fc366ec7992ce82de10b83c06f202b9e65` |
| Image configuration | `sha256:c15f5dbc24777e6062eab956737ff269a122af1d0889739f490f9a023e712a2d` |
| CCF executable SHA256 | `7b41a3a9c147a923542bdda424d9c669f0d166d5c5c8601934b164928218e888` |
| Constitution SHA256 | `bc18a726e061fcb0b45c64fb4e67e774355c5c0abcfb772966bb9704ee129346` |
| Executed runner SHA256 | `a972b3074ad9e3f7540f4061154b841073e3f0caeb37882467a71c42d3837fc7` |

The [provenance](evidence/ccf-runner-final-20260913/provenance.json) records all
resolved helper images and 19 source hashes. These match the preceding successful
short run. The [independent final review](evidence/ccf-runner-review-20260913/README.md)
compared the ending source inventory with an initial provenance copy held outside
the helpers' writable directory: all 19 files matched, with no extra files or
symlinks, and all 85 production inputs matched the built candidate. It also
independently verified the KSK receipt for key tag **55800**, transaction **2.269**.

Two later test-tool hardening changes were deliberately kept outside the running
source: requiring both observation transaction fields explicitly, and removing
a writable alias to the copied helper source. The actual recorded observation
fields are present and match the confirmed transactions; ending source bytes
match the protected initial hashes. That retrospective verification does not
claim filesystem-enforced immutability throughout the older measured process.
The [future runner's guard and Docker checks](evidence/runner-hardening-20260913/README.md)
have their own source identities and are not represented as part of this window.

## Automatic DNSSEC maintenance

External stock BIND was observed from **03:31:02 through 03:52:04 UTC on
2026-09-13**, a **1,262-second** wall-clock span. All **86 positive/negative DNSSEC
validations** passed, observing serials **8–12** and crossing the initial
signature expiration. The state observer recorded **126 committed, unexpired
samples** over **1,250.04 seconds**, with zero failed samples and a largest gap
of **10.710 seconds**. Secondary status was synchronized in **123 observations**
and briefly lagged in **three**; the external answers remained DNSSEC-valid.
No operator mutation, restart, manual NOTIFY or queue reset occurred during the
window. The [raw external samples](evidence/ccf-runner-final-20260913/frontend/remote-idle-samples.json)
and [state samples](evidence/ccf-runner-final-20260913/status/status-samples.json)
retain these distinct observations.

Four automatic transfers advanced BIND to serials 9–12. Their actual TSIG transfer
timestamps preceded the previous SOA signature expirations by **296.340,
296.707, 297.154 and 296.668 seconds**, respectively. The
[reproducible post-run derivation](evidence/ccf-runner-final-analysis-20260913/README.md)
correlates the BIND log with the preceding serial's sampled expiration. The
primary review separately found the new serials at the next periodic external
observations, still **289–290 seconds** before expiration. These are observations
at different points; neither claims continuous probing of every query instant.

The initial and final idle AXFRs each contained **978 records in ten
TSIG-authenticated messages**. The independent client verified every message,
matched the transferred KSK to the verified receipt, checked the entire zone with
`ldns-verify-zone`, and rejected unsigned and wrong-key transfers. The fixture
retained its **244 base records**, including the apex TXT TTL 60 that exposed the
earlier composition defect. Readiness waited for real authenticated secondary
observation through the normal initial retry; signature validity stayed at
600 seconds with a 300-second refresh threshold.

## Measured load, memory and signing

The DO=1 workload ran for **1,200.076 seconds**, offering 1,000 load queries per
second plus ten sampled queries per second. All **1,200,000 sent load queries
completed**, with **zero loss** and **999.999875 completed qps**. The separate
probe recorded **12,001 successes**, zero failures, **p50 0.498 ms**,
**p99 1.362 ms**, and maximum **17.388 ms**. The [raw load results](evidence/ccf-runner-final-20260913/load/results.json)
describe a fixed offered load, not maximum capacity.

Each actual PID 1 process received 121 RSS samples over 1,200 seconds:

| Process | Minimum KiB | Maximum KiB | First KiB | Last KiB |
| --- | ---: | ---: | ---: | ---: |
| CCF | 76,716 | 81,716 | 81,716 | 80,056 |
| BIND | 38,812 | 40,868 | 40,644 | 39,256 |

The [CCF](evidence/ccf-runner-final-20260913/memory/ccf-rss-results.json) and
[BIND](evidence/ccf-runner-final-20260913/memory/bind-rss-results.json) measurements
cover those processes only. RSS does not establish the absence of memory leaks.

Eight actual signing spans ranged **143.573–163.647 ms**, with median
**153.689 ms**. Six signed 244 source records; the post-window operator and
reconciliation changes signed 249 and 250. These
[recorded spans](evidence/ccf-runner-final-analysis-20260913/signing-metrics.json)
cover `SignedZone::sign_with_keys`, including denial and signature generation,
and exclude surrounding storage and consensus. Eight samples do not establish a
stable tail-latency estimate.

These measurements ran on a shared ARM64/macOS development host with the AMD64
CCF executable under Docker emulation. Older baseline containers had been stopped
before the load. The separate native leak-check workload ended before this
window. A network-disabled Docker mount probe capped at 0.25 CPU overlapped at
**03:38:26.591–03:38:26.859 UTC**; other host activity was not excluded. Final
Python/Node checks started after the load and RSS observers ended and may have
overlapped the later operator measurements. Results are local development-host
measurements, not native Azure, dedicated-host capacity or WAN measurements.

## Committed mutations and transfer identity replacement

After all observers finished, the governed operator mutation committed transaction
**2.1799**, serial **13**. Stock BIND independently served exact SPF, DKIM, DMARC,
TLSRPT and CAA records with valid DNSSEC, preserving DKIM's two TXT strings.
DER signatures failed without consuming the nonce, an identical retry preserved
the original result, and a changed signed action returned HTTP 409. The original
base TXT TTL 60 and operator TXT TTL 300 were retained. The recorded
HTTP-to-confirmed-commit latency was **921.782 ms**, including TLS; this is an
operator request measurement, not native registration latency.

The [reconciliation phase](evidence/ccf-runner-final-20260913/reconciliation/summary.json)
obtained a real nonce and observed committed metadata for pending execution.
Revoking its grant caused the exact signed envelope to receive HTTP 403 with a
durable committed failure, while the zone serial remained unchanged. Restoring
the grant allowed the **same nonce and exact envelope** to commit once as
transaction **2.1830**, serial **14**. Reconciliation and identical retry returned
that historical result. The independent reviewer checked the actual pending
observation transaction **2.1821**, failed observation **2.1827**, and recorded
failure **2.1826** against the retained public `/node/tx` confirmations. Stock BIND
then served the exact single TXT owner, value and TTL 60 with valid DNSSEC.

A fresh governed TSIG identity, `agentdns-transfer-replacement.`, was provisioned
with an independent 32-byte secret through the actual supervisor. Before and
after revoking the original identity, its direct AXFR returned **1,001 records
in ten authenticated messages**, passed full-zone DNSSEC validation and matched
the verified KSK receipt; authenticated UDP SOA also passed. The revoked identity's
AXFR ended with EOF and its UDP SOA timed out, while the replacement still
succeeded afterward. This differential check distinguishes revocation from an
endpoint outage. Repeated revocation succeeded.

Three committed post-revocation work fetches returned **zero packets**. No
nonempty work-batch observation is claimed. The replacement's reserved loopback
endpoint on port 1053 had no replacement BIND instance, so this phase establishes
direct transfer identity continuity rather than frontend key-rotation propagation.
The [before](evidence/ccf-runner-final-20260913/rotation/before/results.json),
[after](evidence/ccf-runner-final-20260913/rotation/after/results.json), and
[commit confirmations](evidence/ccf-runner-final-20260913/rotation/work-commit-confirmations.json)
preserve the actual protocol and commitment results.

This complete local run does not establish native CCF execution, attested-key
registration or lifecycle, public DNS delegation, public ACME issuance or mail
delivery. The [genuine native workload appraisal at its recorded verification time](evidence/native-aci-20260913/README.md)
is separate evidence; cloud publication, deployment and native signing remain
pending explicit authorization.
