# Native primary idle measurements

The actual native primary completed the external idle window on the pinned image in `summary.json`. Nineteen private Azure log snapshots have exact suffix/prefix overlap with no gaps; four refresh signing diagnostics cover serials 15–18, each with 260 source records and durations 209.325–216.897 ms. Diagnostic lines carry no event timestamp. Correlation uses independently observed committed serials and preserves actual capture boundaries.

Azure Monitor returned 21 one-minute samples per container and metric. Primary memory was 79,343,616–81,993,728 bytes and CPU 28–41 millicores. These are platform container measurements, not process RSS. The auxiliary ACI secondary is separate from the actual public VM BIND used by the DNS/load proof. The final supplemental snapshot covers the observer finishing later than its nominal 1250-second target. Raw stdout, credentials and private keys are excluded.
