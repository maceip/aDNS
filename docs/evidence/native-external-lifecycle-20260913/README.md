# Native registration withdrawal and natural lease expiry

The genuine A and B worker registrations were already admitted to the native CCF authority. These read-only observations used the independently verified KSK receipt anchor against public stock BIND at `20.166.33.141:53` after the completed [idle/load window](../native-external-idle-20260913/README.md).

- A port-25 withdrawal: exact serial 20; B alone at port 25, both original keys at 465 and 993, shared A/AAAA/MX intact.
- Full A withdrawal: exact serial 21; B alone at all three ports, shared A/AAAA/MX intact.
- B natural expiry: exact serial 22; all six dynamic RRsets absent with authoritative NSEC3 denials, independently accepted by stock `delv`.

Every phase validated six exact owner/type/data sets and ran six independent DNSSEC checks. Frozen source and public input hashes remained unchanged, and all observer containers were removed. No credential or private key was mounted. Expected inputs were outside the writable output mount.

B's shortened lease expired at Unix `1789290242`. The first absence probe matched at `1789290354.490018`, 112.490018 seconds later; this is the first observed state, not a measured exact removal latency. Separate signed/committed API records establish each cause. The phase directory `all-withdrawn` is a historical expectation label: B was removed by natural expiry, not by a withdrawal request.

See [summary.json](summary.json) for exact timestamps and expected sets. Earlier [native overlap/mail/ACME evidence](../native-external-preidle-20260913/README.md) and [independent primary appraisal](../native-primary-ready-independent-20260913/README.md) retain their separate trust and execution boundaries. No public routability of the reserved test addresses or public certificate issuance is claimed.
