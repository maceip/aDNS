# Current Azure authority declaration

`recover.template.json` is the exact declaration deployed on September 21, 2026 to `agentdns-ccf-recover-20260921-v5` in `agentdns-port-validation-20260913`. The authority is `https://agentdns-ccf-recover-20260921-v5.northeurope.azurecontainer.io:8000`, observed at `20.166.238.168`. It publishes its own consensus address on port 8002. BIND serves UDP 53 and authenticated transfers use TCP 5353.

The declaration SHA256 is `af019b116a733dfbf965adbd2bf710256ad8362a99ec069c01e4a45035f5be50`; CCE/host_data is `60a71e408fecbdb60b5609f77a1ddace8d8e1806a6aaff8c58d0269778e5dc2c`; configuration manifest is `89e5aa0d1af5d699ae283af524059813c57ebe3ba27ff7acd317a3499c81669b`. `files.sha256.json` identifies its public inputs.

The primary image is the immutable Linux amd64 manifest `f180a8a8e316ded2c8ccc7603e46bc18ded4446fafe2118f6038105fb7debcf4`. Its one added layer contains only the reviewed `host_driver.py` diagnostics from commit `39d854d3fe8d7139aa5fe029c1a9762605956f83`. The CCF binary, launcher and constitution remain those in base image `9bd3f724…`; inherited image source labels describe that base. See `image-provenance.json` and `diagnostic.Dockerfile`.

The existing AzureFiles share `ccf-recovery-20260921-v2` in `adnsrecovery20260921` holds `/durable/ledger` and `/durable/snapshots`. No data was reset or copied. Both previous writer groups were confirmed Azure `Stopped` before this group mounted the share writable. `/state` is ephemeral and the container restart policy is `Never`.

The secondary uses the existing September 21 TSIG key, SHA256 `85b474fbaf68cf15b01a2689e69824bb5555527d9ebb91fadc2b3bd7134209e7`, name `agentdns-transfer.`, scope `example.test.`. Parameters remain private. Reuse the existing storage/workspace credentials and this exact current secret; do not generate keys. This deployment omits `--provision-tsig-file` and its primary secret mount: Recover restores private TSIG material from the ledger.

## Verified deployed identity

The independent actual-peer SNP audit established node/SPKI `4940a0c011bf376dc352ffc18aece1ba9ea30528b8fd759710bcbeda3383b90e`, exact CCE `60a71e…`, the retained approved measurement, UVM SVN 104 and minimum TCB. The recovered service CA DER SHA256 is `b0db66b5c707eb04cd0f29cf29f41ada1c4936dc3e5702647a14c67d69998959` (`current_service_cert.pem`). Governance transaction `10.52609` accepted SVN 10 with only this CCE and the transition from the previous `225f53f5…` service identity. The existing participant submitted its recovery share at `10.52611`; decrypted material was held only in memory.

The [live evidence](../../../../docs/evidence/authority-recovery-20260921/README.md) verifies globally committed anchors, unchanged KSKs for all three zones, authenticated AXFR, stock BIND DNSSEC answers and rejection of unsigned/wrong-key transfers. Hosting separately owns consumer endpoint/policy/CA pins and native registration/renewal evidence.

## Future recovery and admission

This is the exact completed recovery declaration, not a safe generic restart command. Its `previous_service_identity.pem` is `225f53f5…`, the identity before this recovery. A future Recover must bind the then-current service CA (currently `b0db66b5…`), preserve the same latest ledger, use a reviewed new CCE and signed policy, and coordinate consumer CA pins. Never restart this declaration blindly or run two writers on this share.

Before future Join or Recover admission, compare the secondary's decoded TSIG key hash, name and zone scope against the current governed transfer configuration, then prove a signed transfer using that exact key. An old bootstrap parameter file is not evidence of the current key. Omit genesis TSIG provisioning for Join/Recover; retain the existing ledger key. Validate the full packaged launcher and startup configuration before trusting a joining node. The prior Virtual consensus proof ran the CCF binary directly and did not exercise this launcher failure.

CCF 7.0.15 requires both members of a two-node configuration for quorum. Remove a failed trusted candidate through governance while it is still alive; require `/node/network/removable_nodes` to confirm committed retirement before stopping it. If one has already exited, do not assume removal can commit. Follow governed recovery with the current service identity and available participant material.

Diagnostic warnings remain observable. Repeated connections from private peers send zero bytes before the first two-byte DNS TCP length field and time out; authenticated transfer requests succeed. Their exact provider origin is not independently established. The severity, deadlines and authentication were not weakened. aDNS trace export remains disabled.
