# September 21 authority replacement and recovery

The current [v5 declaration](../../../infra/authority/azure/20260921-v5/README.md) is backed by the native and protocol proof under `v5/`. This record includes the failed attempt and intermediate recovery rather than presenting the final healthy state as an uninterrupted upgrade.

## Failure cause and impact

The operator supplied the original September 13 TSIG secret (SHA256 `f16ad9f7845bc158e5b1bde89a92103af2896e0ce71b6567b5782d434fdecd5a`) to the v3 Join candidate. September 21 restoration had already governed and installed a different existing key (`85b474fbaf68cf15b01a2689e69824bb5555527d9ebb91fadc2b3bd7134209e7`) under the same name and scope. The operator did not compare the input against that current governed digest before Trust. This was an input-verification error, not evidence that CCF Join cannot replicate the service.

Trust committed at `6.52383`. The packaged launcher attempted redundant private TSIG provisioning, received HTTP 400, raised an exception and terminated the candidate process at 20:14:57 UTC. It logged only the status, not the response body; the digest mismatch is independently established from the retained parameter files and governed transfer action. The old primary remained alive but the committed two-node configuration lost quorum; its last committed transaction was `6.52384`. The direct-binary Virtual tests had not exercised the packaged launcher with this input.

The failed declaration, policy, committed Trust result, consensus state and bounded fatal log excerpt are retained under `failed-join-v3/`. That declaration is not the desired deployment and its CCE is excluded from the current SVN 10 admission policy.

## Recovery sequence

1. v4 used the complete existing v2 durable ledger after Azure confirmed the old writer stopped. It pinned actual previous CA `6f3b817b…`, omitted TSIG provisioning, passed native audit and recovered with the existing participant. Its new CA was `225f53f5…`; transition/SVN 9 committed at `8.52395`, share submission at `8.52397`. Fresh native readmission and renewal subsequently committed through v4. The secondary still had the erroneous older startup key, so it could not transfer.
2. The correct current key was located in existing owner-only September 21 custody and matched against the governed SHA256. A live authenticated AXFR from v4 using that key succeeded and the full transferred zone passed independent DNSSEC validation. This proved the private ledger's existing TSIG key was intact.
3. v5 uses that correct existing key. Its previous service identity is v4's `225f53f5…`; v4's last recorded commit was `8.52590`. Both v2 and v4 were provider-confirmed `Stopped` before v5 mounted the same durable share writable. No checkpoint was restored over current state. Existing member, DNSSEC and TSIG keys were preserved; the service CA changed through governed Recover.
4. v5 passed independent SNP/TLS audit for exact CCE `60a71e…` and node/SPKI `4940a0c0…`. The existing member approved the `225f…` to `b0db…` service transition and the D-signed SVN 10 node policy at `10.52609`; its recovery share committed at `10.52611`. The new service CA is expected CCF Recover behavior and requires consumer pin updates.

## Live proof and limits

- `v5/anchors-recovered.json` and its independently verified result bind SVN 10 policy `ceb4a8ea5cac0a350dd9352528c4933d04992b5a829c33a30163bc1319f55a7f` at committed transaction `10.52626`. Every pre-existing zone key descriptor and workload appraisal policy was compared unchanged.
- The three `v5/ksk-*.json` receipts verify against the independently audited service CA. Transactions are `10.52648` (example.test), `10.52650` (agent.hosting), and `10.52655` (attestation.agent.hosting). Complete DNSKEY RDATA matches the pre-incident receipts.
- `v5/transfer-check/results.json` passed at 20:35:08 UTC: every AXFR message authenticated, unchanged KSK, full-zone ldns verification, BIND authoritative serial 152 matching the transfer, and validated SOA/DNSKEY/TXT/NXDOMAIN answers. Unsigned and wrong-key transfers were rejected.
- `v5/transfer-warning-excerpt.log` retains the unresolved transport-origin evidence: private peers repeatedly open TCP 5353 and send zero bytes before the first length field. The HTTP 400 entries at 20:35:06–07 correspond to the deliberate unsigned/wrong-key negative tests. Valid transfer traffic succeeds. Exact provider probe ownership is not proven; no warning downgrade or timeout/authentication change was made.

These files establish actual native recovery and DNS serving, not merely Azure `Running` or CCF `Open`. Hosting owns the separate final native registration/renewal and consumer pin acceptance. No future blind restart is implied: another Recover needs the current service CA and a newly reviewed declaration. Trace export remains disabled.
