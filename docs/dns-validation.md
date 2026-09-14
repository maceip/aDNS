# DNS validation: proving the signer is correct

Three independent implementations check zones produced by our own signer.
No layer trusts our code; each uses a different validator.

## Layers

1. **RFC known-answer vectors** (`crates/adns-dnssec/tests/dnssec.rs`,
   runs in the normal `cargo test` CI gate):
   - `rfc4034_dskey_key_tag_vector` — RFC 4034 §5.4 states key tag **60485**
     for the `dskey.example.com` DNSKEY; we recompute it.
   - `rfc5155_hash_vectors_and_limits` — all 12 RFC 5155 Appendix A NSEC3
     hashes (salt `aabbccdd`, 12 iterations).
   - `rfc6605_p384_key_tag_ds_and_signature_vector` — P-384 key tag 10771,
     DS-SHA384 digest, and verification of the RFC's own RRSIG.
2. **Fixture validation with delv** (`crates/adns-dnssec/tests/validate_packets.py`,
   CI `safe-core` job): every exported response wire is served byte-for-byte
   to ISC delv with our KSK as trust anchor (`+root=example.`). Positive
   answers must fully validate; corrupted denial proofs and altered
   signatures must be rejected. Needs `dnsutils` (delv), *not* `bind9-utils`.
3. **Differential wire oracle** (`tools/differential_wire.py`, CI `safe-core`
   job): 2000 seeded mutations over the fuzz corpus; our parser
   (`crates/adns-wire/examples/parse_wire.rs`) must never accept what
   dnspython rejects nor disagree on rcode/sections/first question.
4. **Live zone validation** (`tools/validate_live_zone.sh`, manual — needs
   docker): exports a fresh zone, serves it from BIND9, and runs delv,
   DNSViz (`probe` + `print`), and the Zonemaster Engine undelegated suite
   (fake delegation + fake DS). Run per denial mode:
   `tools/validate_live_zone.sh --mode nsec3` (and `--mode nsec`).

## Reading a live-validation report

- **delv**: exit 0 on positive and on validated-NXDOMAIN. Anything else fails.
- **DNSViz**: `print` output must contain no `[!]` line touching DNSSEC
  material (`RRSIG`, `DNSKEY`, `NSEC`/`NSEC3`, `DS`) — `[!]` is the print
  rendering of BOGUS/EXPIRED/INVALID_SIG/INVALID_DIGEST/INVALID — and must
  contain `RRSIG:` and denial-proof lines at all (non-vacuity). The DS is
  injected with `-D`; without it the island has no chain to root. Do NOT
  pass `-4`: the `-N`/`-D` flow serves its synthesized parent on IPv6
  loopback, and `-4` filters those servers ("No IPv4 servers to query").
  An `[!] NS: TIMEOUT` line is expected: it records the probe dutifully
  trying the zone's unroutable TEST-NET-1 glue, not our server failing
  (verify: the same NS query against the testbed server answers).
- **Zonemaster gate** (`zm_gate.py`): fails on any CRITICAL and on any
  ERROR from the DNSSEC/DS/Zone modules. The following residue is expected
  and carries no product signal — it is inherent to undelegated loopback
  testing with documentation addresses:
  - `Address` errors/warnings: NS glue is RFC 5737 TEST-NET-1 space
    (unroutable by design) and the fake parent lives on 127.0.0.1.
  - `Connectivity` no-response warnings for the documentation glue.
  - `Delegation`/`Consistency` mismatches between the fake parent
    (loopback) and the zone's documentation glue.
  - `NO_IPV6_*` notices (IPv4-only testbed), missing reverse DNS.

## delv trust-anchor notes (learned the hard way)

- delv (9.18) only loads anchors whose name matches `+root=<name>`; without
  `+root=example.` it reports "No trusted keys were loaded" even with a
  correct `-a` file.
- Acceptable anchor statements: `trust-anchors { example. static-key ...; };`.
  `initial-key` needs RFC 5011 timers and loads nothing; `trusted-keys` /
  `managed-keys` are rejected as deprecated.
- macOS ships delv 9.10, which predates `trust-anchors` — local runs on macOS
  fail for that reason alone; use the docker validator or Linux CI.

## Public DoH test endpoint (live since 2026-09-14)

- **URL**: `https://axp.computer/dns-query` (GET `?dns=` base64url and
  POST `application/dns-message`). Serves the proof zone
  (`proof.dns.secure.build`) from **our code**: `adns-dev` built from this
  tree (`cargo build --locked --release -p adns-server --bin adns-dev`,
  Linux x86_64), behind Caddy (auto LE cert, CAA-authorized).
- **Host layout** (`azureuser@axp.computer`, nothing else on the box touched):
  `/opt/adns-doh/` (binary + `config.json` + sealed state, owned by system
  user `adns-doh`), systemd unit `adns-doh.service` (enabled, auto-restart),
  Caddy vhost `axp.computer` in `/etc/caddy/Caddyfile` (backup
  `Caddyfile.bak.*` next to it).
- **Caddy proxies ONLY `/dns-query`**; every other path gets a 404 from
  Caddy. This is load-bearing, not tidy: adns-dev's remaining HTTP surface
  is an unauthenticated dev governance API (state reads via GET, zone
  mutation via POST `application/json`), and `crates/adns-server/src/bin/adns-dev.rs`
  (`http()`) exposes it on the same listener. Verify any Caddy change keeps
  the `handle /dns-query*` + fallback shape.
- **Key separation**: the DoH zone is the same *data* as the port-53 Knot
  proof zone but signed with the service's own testbed KSK/ZSK (generated at
  `adns-dev init`). Validate DoH answers against the DoH DNSKEY anchor, not
  the parent DS. Likewise the served SOA serial is server-managed
  (`soa.serial = metadata.serial` in `crates/adns-server/src/zone.rs`,
  genesis 1) — mname/rname/timers match the port-53 zone, the serial does
  not.
- **Operational notes**: this box runs Caddy with `admin off`, so
  `systemctl reload caddy` can never work (admin API absent) — config changes
  need `systemctl restart caddy`. Do NOT add per-vhost `log { output file …
  }` blocks unless the file/dir is pre-created writable for the `caddy`
  user; a bad log path fails config load and crash-loops Caddy for ALL
  sites (seen 2026-09-14, fixed by dropping the block).
- **Validation** (independent dnspython over public HTTPS; script kept with
  the operator, re-run: `uv run --with dnspython --no-project python3
  /tmp/doh_validate.py`): GET+POST agreement, SOA/mail/wildcard/NXDOMAIN/
  NODATA parity, RRSIG(SOA)+RRSIG(A)+RRSIG(NSEC3) verify under dnspython
  against the DoH DNSKEY, tampered serial rejected, and the single-NSEC3
  NXDOMAIN denial independently recomputed (base32hex SHA1, empty salt) to
  satisfy all three RFC 5155 §7.2.1 proofs in one span. All pass.
- **2026-09-14 move**: endpoint renamed to `https://dns.secure.build/dns-query`
  (was `axp.computer`); delegation NS moved `dns.secure.build` →
  `ns1.stare.network`, port-53 zone re-signed with fresh our-code keys
  (KSK tag **27004**, DS `27004 14 2 572A…`, serial back to 42), DoH zone
  rebuilt with 11 records (added the `child` cut + glue to match port 53).
- **Incident during the move (read before touching Knot)**: the proof zone is
  a plain master file carrying OUR signatures — Knot does NOT re-sign on
  `knotc zone-set`, so editing NS/SOA in place served stale RRSIGs (BOGUS,
  ~15 min). Worse, `knotc -f zone-purge` DELETES the zone file, and the
  reload then SERVFAILed until the file was rewritten (as `knot:knot 660`,
  matching siblings) and reloaded. Recovery was a full re-sign with
  `crates/adns-dnssec/examples/export.rs` + DS roll in the parent.
  Operational consequences: (a) never `zone-set` data inside this zone —
  always re-export + reload + roll DS; (b) `export.rs` generates EPHEMERAL
  keys (privates discarded), so every re-sign is a KSK rollover with a
  DS-propagation window — persist keys or automate CDS before making this
  routine; (c) RRSIG validity is 24 h from signing, so the zone needs a
  daily re-sign pipeline or it goes dark on expiry.
- **IPv6 (same day)**: Knot on the DNS box now serves `2a05:f480:1400:25f6::53`
  (static, netplan-persisted; needs `systemctl restart knot`, not just
  `reload`, to take effect) and `ns1.stare.network` has a matching AAAA
  (Knot-policy-signed). v6 firewall is policy-accept with empty UFW chains,
  so no filter change was needed. External v6 reachability still to be
  confirmed by a v6-capable prober (DNSViz run); local v6 queries validate.
