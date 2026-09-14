#!/usr/bin/env python3
"""Differential oracle: our wire parser (via parse_wire example) vs dnspython.

Deterministic seeded mutations over the fuzz seed corpus plus synthetic
messages. Fails only on unsound outcomes:
  * we ACCEPT a packet dnspython rejects, or
  * both accept but disagree on rcode/sections/first question.
We-reject-they-accept is strictness, counted separately (does not fail).

Usage:
  tools/differential_wire.py --binary target/debug/examples/parse_wire \
      --cases 2000 --seed 20260914
Requires: dnspython (CI installs python3-dnspython via apt).
"""

import argparse
import json
import pathlib
import random
import subprocess
import sys

try:
    import dns.message
    import dns.rdatatype
    import dns.rrset
except ImportError:
    sys.exit("dnspython is required (apt: python3-dnspython)")


def synthetic_corpus(rng):
    out = []
    for name in ("example.", "a.example.", "*.wild.example.", "x.y.ent.example."):
        q = dns.message.make_query(name, "A")
        out.append(q.to_wire())
        q2 = dns.message.make_query(name, "MX")
        out.append(q2.to_wire())
        resp = dns.message.make_response(q)
        rr = dns.rrset.from_text(name, 300, "IN", "A", "192.0.2.1")
        resp.answer.append(rr)
        out.append(resp.to_wire())
    return out


def mutate(rng, data):
    data = bytearray(data)
    choice = rng.randrange(6)
    if choice == 0 or len(data) == 0:
        return bytes(data[: rng.randrange(len(data) + 1)])
    if choice == 1:
        for _ in range(1 + rng.randrange(4)):
            data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
        return bytes(data)
    if choice == 2:
        pos = rng.randrange(len(data) + 1)
        data[pos:pos] = bytes([rng.randrange(256)])
        return bytes(data)
    if choice == 3:
        pos = rng.randrange(len(data))
        del data[pos : pos + 1 + rng.randrange(3)]
        return bytes(data)
    if choice == 4:
        pos = rng.randrange(len(data) + 1)
        width = rng.randrange(1, 5)
        data[pos:pos] = data[pos : pos + width][::-1] if pos < len(data) else b"\x00"
        return bytes(data)
    pos = rng.randrange(len(data) + 1)
    return bytes(data[:pos] + data[pos:])


def rust_verdict(binary, path):
    proc = subprocess.run([binary, str(path)], capture_output=True, text=True, timeout=20)
    return json.loads(proc.stdout.strip().splitlines()[-1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--seed-dir", default="fuzz/seeds/wire")
    ap.add_argument("--cases", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=20260914)
    ap.add_argument("--workdir", default=".validation/differential")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    corpus = []
    for path in sorted(pathlib.Path(args.seed_dir).glob("*")):
        if path.is_file():
            corpus.append(path.read_bytes())
    corpus.extend(synthetic_corpus(rng))
    corpus = [c for c in corpus if c]
    if not corpus:
        sys.exit("empty corpus")

    workdir = pathlib.Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    unsound = strict = agree = 0
    failures = []
    for i in range(args.cases):
        base = corpus[rng.randrange(len(corpus))]
        if i % 3 == 0:
            packet = bytes(base)
        else:
            other = corpus[rng.randrange(len(corpus))]
            packet = mutate(rng, base + other[: rng.randrange(len(other) + 1)])
        tmp = workdir / f"case-{i}.wire"
        tmp.write_bytes(packet)
        try:
            pymsg = dns.message.from_wire(packet)
            py_ok = True
        except Exception:
            py_ok = False
        rs = rust_verdict(args.binary, tmp)
        rs_ok = bool(rs.get("ok"))
        if rs_ok and not py_ok:
            unsound += 1
            failures.append((i, "accepts-rejected", rs))
        elif rs_ok and py_ok:
            # dnspython coalesces same-owner/type/class/TTL records into one
            # RRset per section; we keep individual RRs. Compare RR totals.
            q = pymsg.question[0] if pymsg.question else None
            py_an = sum(len(r) for r in pymsg.answer)
            py_ns = sum(len(r) for r in pymsg.authority)
            py_ar = sum(len(r) for r in pymsg.additional)
            same = (
                rs.get("rcode") == pymsg.rcode()
                and rs.get("qd") == len(pymsg.question)
                and rs.get("an") == py_an
                and rs.get("ns") == py_ns
                and rs.get("ar") == py_ar
                and (q is None or (rs.get("qname") == str(q.name).lower()
                                   and rs.get("qtype") == q.rdtype))
            )
            if same:
                agree += 1
            else:
                unsound += 1
                failures.append((i, "content-divergence", rs))
        else:
            if not rs_ok and py_ok:
                strict += 1
            else:
                agree += 1
    print(f"cases={args.cases} agree={agree} strict-we-reject={strict} unsound={unsound}")
    for i, kind, rs in failures[:10]:
        print(f"FAIL case-{i} {kind}: {rs}")
    return 1 if unsound else 0


if __name__ == "__main__":
    sys.exit(main())
