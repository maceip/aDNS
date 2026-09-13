This public bundle records the second Linux CI failure and its helper ownership fix. The failure was in summary/export permissions after the inner CCF/BIND phases, independent of the earlier BIND startup failure.

The Linux regression retains private0700/0600 permissions and excludes private inputs from export. The fresh short Virtual CCF run completed all phases and exported108 allowlisted artifacts. Its exact image and frozen sources are recorded. The later owned-volume cleanup addition has separate actual Docker timeout-boundary coverage. A replacement long GitHub result must be reported separately.

No private member keys, TSIG values, node state volume, credentials, or raw native logs are included.
