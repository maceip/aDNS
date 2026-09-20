# Stock BIND frontend in the isolated CCF ACI group

`containers/secondary.Dockerfile` builds a stock BIND authoritative secondary on a pinned Ubuntu24.04 amd64 base. The image performs no DNSSEC signing and receives no DNSSEC private keys. Its only transfer credential is a 32-byte HMAC-SHA256 TSIG secret shared with the CCF-governed transfer key named `agentdns-transfer.`.

The validation topology puts the CCF primary/host driver and this BIND container in the same Confidential ACI group. The fixed primary is `127.0.0.1:5353`; the zone is `example.test`. Govern the CCF secondary endpoint as `127.0.0.1:53`. Publish only CCF HTTPS8000 and authoritative BIND TCP/UDP53. Transfer5353 and CCF internal8001 remain unexposed. Containers share the SNP VM and kernel, so this is separate-process protocol interoperability on a common attested hardware boundary, not an independently attested second machine.

Supply exactly one of the following through a secure ACI environment value or mounted secret:

- `AGENTDNS_TRANSFER_KEY_B64`: canonical standard base64 of the governed 32-byte TSIG key.
- `AGENTDNS_TRANSFER_KEY_FILE`: a file containing that base64 value, optionally followed by one newline.

The entrypoint removes secret environment fields before starting BIND, disables core dumps, and writes a mode0600 configuration owned by the unprivileged `bind` user on the container's ephemeral filesystem. BIND drops privileges to that user. Configuration fixes authoritative service on53, disables recursion, accepts NOTIFY only authenticated by the governed TSIG, and prohibits downstream AXFR. There is no control-channel listener, zone-update API, image-baked key, inline signing or DNSSEC signing policy.

```sh
python3 tools/domain_registry.py snapshot .domain-registry/topology.json
docker build --platform linux/amd64 --build-context domain-registry=.domain-registry -f containers/secondary.Dockerfile -t agentdns-secondary:local .
docker run --rm --platform linux/amd64 -v "$PWD:/work" --entrypoint python3 agentdns-secondary:local -m unittest discover -s /work/tools/tests -p test_secondary_aci.py -v
```

The local image ID is recorded in the deployment handoff; the registry image digest must be pinned in the ACI policy. Software tests validate canonical secret handling, fixed primary/scope and the full generated config through stock `named-checkconf`. Azure public DNS transfer/NOTIFY, governed CCF commitment and external DNSSEC validation remain separate runtime evidence.
