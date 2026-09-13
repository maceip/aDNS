# Independent final-run review

The primary reviewer checked the completed short and sustained runs separately
from their original test assertions. Both used executable `7b41a3a9…18e888`.

`long.json` binds the sustained review to an initial provenance copy saved outside
the helpers' writable directory before the run completed. All 19 end-of-run source
files match those initial hashes; the bounded inventory has no unexpected files,
directories or symlinks. All 85 production inputs still match the built candidate.
The actual pending and failed observation bodies contain both required transaction
IDs, matching the response header, client confirmation and retained `/node/tx`
responses. Failed HTTP403 metadata has its own confirmed transaction. Successful
reconciliation and exact retry preserve the original result and transaction 2.1830.
Cleanup completed before this audit.

`measurements.json` independently checks all 122 exported files against their
hashes and original result bytes, the raw committed/unexpired state samples,
external DNSSEC checks, actual transfer margins and the independently verified
KSK receipt. `short.json` records the corresponding additional assertions for the
passed short smoke. These are local Virtual CCF results, not native registration
or confidential-hardware acceptance.

The measured runner predates two later test-harness hardening changes: strict
presence of both observation transaction fields, and masking a writable alias to
the source copy. Its ending bytes and actual responses pass the stronger checks;
this does not claim filesystem-enforced immutability throughout that older run.
The [future runner's regression and Docker checks](../runner-hardening-20260913/README.md)
retain their own exact source identities. No running source was patched and no
later assertion was represented as part of the already measured process.
