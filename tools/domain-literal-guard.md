# Managed-domain regression guard

Run from the repository root after making the common registry available:

```sh
python3 tools/test_domain_literals.py -v
python3 tools/check_domain_literals.py
```

Standalone aDNS or Steward checkouts can first run
`python3 tools/domain_registry.py fetch`. `AH_DOMAIN_REGISTRY` or the guard's
`--registry FILE` selects an explicit public registry snapshot; missing explicit
configuration fails. CI must fetch the coordinated registry revision before the
guard. The same guard and tests are maintained in all three repositories.

The guard inventories tracked and nonignored untracked files using Git. It
checks source, build scripts, configuration and CI, including live smoke and
integration harnesses under `tests/`. Ignored generated output is not scanned.
Binary assets and nonregular files are classified separately. The canonical
registry at the exact own-repository path `infra/production/topology.json` is
always a configuration input, including when an alternate registry is selected.
The selected registry and this guard's classification JSON are inputs too;
other JSON configuration remains checked.

Needles come from the common registry keys `domain`, `public_dns_host`,
`ccf_rpc_hostname`, `mail_relay_host`, `secondary_registry` and
`anycast_validation_domain`, all five `ses_*_host` destinations, and the two
`caa_*_domain` values. Retired endpoints are explicit additional names in
`tools/domain-literal-exceptions.json`, with reasons. When retiring a registry
name, add its previous value there to prevent it returning to source defaults.
This is a regression boundary for managed identities, not a universal detector
of DNS names. Unrelated external services, newly added provider destinations
and every new naming role still require a broad source/configuration audit.

Per-repository path classifications cover narrative Markdown, dated evidence
and incident archives, vendored code, conventional isolated unit tests and
fixed fixtures. These categories are visible in the JSON report. There is no
blanket exclusion for a `tests/` directory: executable cloud or deployment
smoke harnesses remain checked. A unit-test path must not become an operational
entry point while retaining that classification.

An exceptional literal in a checked file needs its exact relative path and the
SHA-256 of that exact UTF-8 line, excluding its newline. Every exception has a
category and a concrete reason. Permitted categories are immutable protocol
identifiers, module/telemetry namespaces, comments/branding, signed trust data
and fixed test vectors embedded in an otherwise checked source file. A new
operational endpoint must be migrated to the registry, not added as an
exception. Signed pins and composed constitution bytes stay unchanged.

`--json` reports file/line, matching names and line hashes without printing
complete source lines. Exit status is 0 for no violations, 1 for detected
literals, and 2 for configuration/audit errors. Unused exact-line exceptions
are reported for cleanup; they do not authorize new line contents. The tests
prove that tracked and new operational literals fail, ignored artifacts stay
excluded, live harnesses remain checked, and exceptions cannot cover another
file or changed line.
