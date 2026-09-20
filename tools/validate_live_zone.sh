#!/bin/bash
# Live DNSSEC validation for agentdns-signed zones.
#
# Exports a freshly signed zone from our own code, serves it from BIND9,
# then validates it with three independent implementations:
#   1. ISC delv (positive + negative answers, exit-code verdict)
#   2. DNSViz probe+print (full-chain analysis incl. NSEC/NSEC3 proofs)
#   3. Zonemaster Engine undelegated suite (fake delegation + fake DS)
#
# Needs: cargo, docker. Images are pulled on first run.
# Usage: tools/validate_live_zone.sh [--mode nsec|nsec3] [--keep]
set -euo pipefail

MODE=nsec3
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --mode) MODE="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "usage: $0 [--mode nsec|nsec3] [--keep]"; exit 2 ;;
    esac
done
[ "$MODE" = nsec ] || [ "$MODE" = nsec3 ] || { echo "bad --mode"; exit 2; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$(mktemp -d)}"
SERVER_C=agentdns-live-bind
VALID_C=agentdns-live-validator
echo "workdir: $WORK"

cleanup() {
    if [ "$KEEP" = 0 ]; then
        docker rm -f "$VALID_C" "$SERVER_C" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
docker rm -f "$VALID_C" "$SERVER_C" >/dev/null 2>&1 || true

echo "== export $MODE zone from our signer"
cargo run --quiet --locked -p adns-dnssec --example export -- --caa-issuer "$(python3 "$ROOT/tools/domain_registry.py" get caa_primary_domain)" "$WORK/zones"
ZONE="$WORK/zones/$MODE.zone"
KEYFILE="$WORK/zones/$MODE.key"

echo "== serve via BIND9 (ports 53+5353)"
mkdir -p "$WORK/srv"
cp "$ZONE" "$WORK/srv/example.zone"
cat > "$WORK/srv/named.conf" <<'EOF'
options {
    directory "/zones";
    recursion no;
    listen-on port 53 { any; };
    listen-on port 5353 { any; };
    listen-on-v6 { none; };
    dnssec-validation no;
    notify no;
    pid-file "/zones/named.pid";
    session-keyfile "/zones/session.key";
};
controls {};
zone "example" {
    type primary;
    file "/zones/example.zone";
};
EOF
docker run -d --name "$SERVER_C" --platform linux/amd64 \
    -v "$WORK/srv:/zones" \
    internetsystemsconsortium/bind9:9.20 -c /zones/named.conf -u root -g >/dev/null
docker run -d --name "$VALID_C" --network "container:$SERVER_C" --platform linux/amd64 \
    ubuntu:22.04 sleep 3600 >/dev/null
echo "== validator tooling"
docker exec "$VALID_C" bash -c 'apt-get update -qq 2>&1 | tail -n 1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dnsutils python3-pip bind9 graphviz libgraphviz-dev pkg-config >/tmp/apt.log 2>&1'
docker exec "$VALID_C" pip3 install --quiet dnsviz dnspython cryptography pygraphviz 2>&1 | tail -n 1 || true
echo "== wait for DNS"
for i in $(seq 1 30); do
    if docker exec "$VALID_C" dig @127.0.0.1 -p 5353 example. SOA +short +time=2 >/dev/null 2>&1; then
        break
    fi
    sleep 5
done
docker exec "$VALID_C" dig @127.0.0.1 -p 5353 example. SOA +short +time=5

echo "== trust anchor + DS from our KSK"
KEY=$(awk '{print $NF}' "$KEYFILE")
printf 'trust-anchors {\n    example. static-key 257 3 14 "%s";\n};\n' "$KEY" > "$WORK/anchor.conf"
docker cp "$WORK/anchor.conf" "$VALID_C:/tmp/anchor.conf"
cat > "$WORK/mkds.py" <<'EOF'
import dns.name, dns.rdata, dns.dnssec, sys
key_text = open('/tmp/apex.key').read()
r = dns.rdata.from_text('IN', 'DNSKEY', key_text.split('IN DNSKEY', 1)[1])
print(dns.dnssec.make_ds(dns.name.from_text('example.'), r, 'SHA256').to_text())
EOF
docker cp "$KEYFILE" "$VALID_C:/tmp/apex.key"
docker cp "$WORK/mkds.py" "$VALID_C:/tmp/mkds.py"
DS=$(docker exec "$VALID_C" python3 /tmp/mkds.py)
echo "DS: $DS"

echo "== 1. delv positive + negative"
docker exec "$VALID_C" delv @127.0.0.1 -p 5353 -a /tmp/anchor.conf +root=example. mail.example. A +trust +short
docker exec "$VALID_C" delv @127.0.0.1 -p 5353 -a /tmp/anchor.conf +root=example. nx.example. A +trust +short
echo "delv: positive and validated-NXDOMAIN both exit 0"

echo "== 2. DNSViz full-chain analysis"
# NOTE: no -4. The -N/-D flow serves a synthesized parent on IPv6 loopback;
# -4 filters those servers and the run dies with "No IPv4 servers to query".
docker exec "$VALID_C" dnsviz probe -A \
    -x 'example.:127.0.0.1:5353' \
    -N 'example.:ns.example.=127.0.0.1:5353,ns2.example.=127.0.0.1:5353' \
    -D "example.:$DS" \
    -o /tmp/probe.json \
    example. mail.example. alias.example. nx.example.
docker exec "$VALID_C" dnsviz print -r /tmp/probe.json | tee "$WORK/dnsviz.txt"
# In print output [!] marks BOGUS/EXPIRED/INVALID_SIG/INVALID_DIGEST/INVALID.
# Gate only on DNSSEC material (an NS TIMEOUT against unroutable TEST-NET
# glue also renders [!] and is environmental, documented in
# docs/dns-validation.md). Then prove the run was non-vacuous.
if grep -E '\[!].*(RRSIG|DNSKEY|NSEC3?:|DS:)' "$WORK/dnsviz.txt"; then
    echo "DNSViz flags DNSSEC material as BOGUS/invalid"; exit 1
fi
grep -q 'RRSIG:' "$WORK/dnsviz.txt" || { echo "DNSViz output vacuous (no signatures)"; exit 1; }
grep -qE 'NSEC3?:' "$WORK/dnsviz.txt" || { echo "DNSViz output vacuous (no denial proofs)"; exit 1; }
echo "DNSViz: signatures and denial proofs present, none BOGUS/invalid"

echo "== 3. Zonemaster undelegated suite"
read -r DSTAG DSALG DSTYPE DSDIGEST <<< "$DS"
# Quoted heredoc: no shell expansion inside the Perl; DS travels via argv.
cat > "$WORK/zm.pl" <<'PERLEOF'
use strict; use warnings;
use Zonemaster::Engine;
use JSON::PP;
my $zone = 'example';
Zonemaster::Engine->add_fake_delegation( $zone => { 'ns.example' => ['127.0.0.1'], 'ns2.example' => ['127.0.0.1'] } );
Zonemaster::Engine->add_fake_ds( $zone => [ { keytag => $ARGV[0], algorithm => $ARGV[1], type => $ARGV[2], digest => $ARGV[3] } ] );
my @out;
for my $e ( Zonemaster::Engine->test_zone( $zone ) ) {
    my $msg = eval { $e->message } // "$e";
    push @out, { level => $e->level . '', tag => $e->tag . '', message => "$msg" };
}
my %count; $count{ $_->{level} }++ for @out;
print JSON::PP->new->canonical->encode( { summary => \%count, entries => \@out } ), "\n";
PERLEOF
docker run --rm --network "container:$SERVER_C" --platform linux/amd64 \
    -v "$WORK:/work" --entrypoint perl zonemaster/cli:latest \
    /work/zm.pl "$DSTAG" "$DSALG" "$DSTYPE" "$DSDIGEST" > "$WORK/zm.json"
cat > "$WORK/zm_gate.py" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
print("summary:", d["summary"])
bad = [e for e in d["entries"]
       if e["level"] == "CRITICAL"
       or (e["level"] == "ERROR" and e["message"].split(":")[0] in ("DNSSEC", "DS", "Zone"))]
for e in bad:
    print("GATE", e["level"], e["tag"], "|", e["message"][:200])
# Known environmental residue of undelegated loopback testing (no product
# signal): documentation-TEST-NET glue is unroutable, the fake parent lives
# on loopback, reverse DNS is absent. Anything DNSSEC-related fails above.
sys.exit(1 if bad else 0)
EOF
python3 "$WORK/zm_gate.py" "$WORK/zm.json"
echo "ALL LIVE VALIDATION PASSED ($MODE)"
