# Final CCF commitment and recovery evidence

The exact executable and all 85 frozen production inputs are identified in
[build.json](build.json). These are real local CCF 7.0.15 consensus/governance
runs using the explicit Virtual platform; they are not confidential hardware
execution or native registration acceptance.

[summary.json](summary.json) records ten withheld output paths during quorum
loss, committed success and authenticated failure observations, primary-loss
rollback to previously committed pending nonces, exact retry and replicated
private-key continuity. [request-observations.json](request-observations.json)
contains the actual pending, failed submit and failed query responses.

[Recovery evidence](recovery/summary.json) records a fresh Recover process from
disk ledger/snapshot plus a real decrypted member recovery share. The same
DNSKEY/DS and TSIG identity survived; historical result 2.17 remained unchanged,
committed failed observations survived, a new service-identity receipt verified
at 4.43, and an unused nonce committed once at 4.45.

The primary reviewer independently ran tools/verify_ksk_receipt.py against all
three exported receipts using their corresponding separately supplied service
certificates. Both recovery receipts bind the same key tag 38896 and DS digest.
The separate quorum run's independently generated KSK has key tag 48558.
All 85 production source hashes were also independently matched against the
current tree after building and testing. SHA256 manifest entries cover every
public file in this evidence directory, excluding the manifest itself.

Stock BIND, TSIG replacement, idle validation, load and native Azure checks keep
separate run identities and acceptance boundaries in the top-level ledger.
