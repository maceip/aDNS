# CI Linux private-workspace regression

The original GitHub job ended at Docker-exec137. A fresh Linux volume with the actual runner ownership (uid1001, directory0700) reproduced the underlying BIND configuration permission failure and misleading PID1exit0; OOMKilled was false. The fix preserves private host permissions and gives BIND a private container-local workspace.

Actual stock BIND, multi-message TSIG, ldns/delv DNSSEC, Postfix DANE, PKIX and IXFR checks passed under those Linux ownership conditions. A deliberately malformed named configuration now records child and PID1 exit1 before cleanup. Eleven focused unit/policy tests and actionlint1.7.12 passed. The replacement long GitHub job and remote CodeQL results are separate pending checks. Only explicit public results/exit state are exported; runtime keys and raw container output stay private.
