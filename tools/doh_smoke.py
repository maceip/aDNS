#!/usr/bin/env python3
"""DoH transport + DNSSEC smoke test for adns-dev (CI-friendly, no network).

Starts adns-dev on loopback with a small signed zone, then checks over plain
HTTP (TLS termination is Caddy's job in production, exercised live):
GET/POST agreement, record content, NXDOMAIN/NODATA, RRSIG validation with
dnspython against the live DNSKEY anchor (positive + NSEC3 denial), and
tamper rejection. Exits nonzero on the first failure; always stops the server.
"""

import argparse
import base64
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import dns.dnssec
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset


def checked(*args, **kwargs):
    kwargs.setdefault("timeout", 300)
    return subprocess.run(args, check=True, **kwargs)


def rr(name, rtype, rdata, ttl=300):
    return {
        "name": name,
        "rclass": "In",
        "rdata": {rtype: rdata},
        "rtype": rtype,
        "ttl": ttl,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--binary", required=True)
    p.add_argument("--work", required=True)
    p.add_argument("--zone", default="doh.example.")
    p.add_argument("--port", type=int, default=18053)
    a = p.parse_args()
    zone = a.zone if a.zone.endswith(".") else a.zone + "."
    zname = dns.name.from_text(zone)
    work = pathlib.Path(a.work)
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    server = None
    try:
        checked(a.binary, "init", str(work), zone)
        cfg_path = work / "config.json"
        cfg = json.loads(cfg_path.read_text())
        cfg["http_listen"] = f"127.0.0.1:{a.port}"
        cfg["transfer_listen"] = f"127.0.0.1:{a.port + 1}"
        ns = f"ns.{zone}"
        cfg["initial_records"] = [
            rr(zone, "Soa", {"mname": ns, "rname": f"hostmaster.{zone}",
                             "serial": 1, "refresh": 300, "retry": 60,
                             "expire": 86400, "minimum": 60}),
            rr(zone, "Ns", ns),
            rr(f"www.{zone}", "A", "192.0.2.1"),
            rr(f"txt.{zone}", "Txt", [[116, 101, 115, 116]]),
            rr(f"*.wild.{zone}", "A", "192.0.2.2"),
        ]
        cfg_path.write_text(json.dumps(cfg, indent=2) + "\n")

        log = open(work / "server.log", "ab", buffering=0)
        server = subprocess.Popen([a.binary, str(cfg_path)],
                                  stdout=log, stderr=log)
        base = f"http://127.0.0.1:{a.port}/dns-query"

        def fetch(qname, qtype, method="GET"):
            q = dns.message.make_query(qname, qtype, want_dnssec=True)
            if method == "POST":
                req = urllib.request.Request(
                    base, data=q.to_wire(),
                    headers={"content-type": "application/dns-message",
                             "accept": "application/dns-message"},
                    method="POST")
            else:
                param = base64.urlsafe_b64encode(q.to_wire()).rstrip(b"=").decode()
                req = urllib.request.Request(
                    f"{base}?dns={param}",
                    headers={"accept": "application/dns-message"})
            with urllib.request.urlopen(req, timeout=10) as r:
                assert r.status == 200, r.status
                assert r.headers.get_content_type() == "application/dns-message"
                return dns.message.from_wire(r.read())

        deadline = time.monotonic() + 60
        while True:
            if server.poll() is not None:
                raise RuntimeError("server exited during startup")
            try:
                fetch(zname, "SOA")
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError("server did not answer /dns-query")
                time.sleep(0.2)

        results = {}

        def check(name, cond, detail=""):
            results[name] = bool(cond)
            print(("PASS " if cond else "FAIL ") + name)
            if not cond:
                raise RuntimeError(f"{name}: {detail}")

        r_get = fetch(zname, "SOA")
        r_post = fetch(zname, "SOA", "POST")
        check("get-post-agree", r_get.answer == r_post.answer, "wire mismatch")
        a_www = fetch(dns.name.from_text(f"www.{zone}"), "A")
        check("a-content", [r.address for r in a_www.answer[0]] == ["192.0.2.1"])
        a_wild = fetch(dns.name.from_text(f"q.wild.{zone}"), "A")
        check("wildcard", [r.address for r in a_wild.answer[0]] == ["192.0.2.2"])
        nx = fetch(dns.name.from_text(f"nope.{zone}"), "A")
        check("nxdomain", nx.rcode() == dns.rcode.NXDOMAIN, str(nx.rcode()))
        nodata = fetch(dns.name.from_text(f"www.{zone}"), "TXT")
        check("nodata", nodata.rcode() == dns.rcode.NOERROR and not nodata.answer)

        keys = {zname: [r for r in fetch(zname, "DNSKEY").answer
                        if r.rdtype == dns.rdatatype.DNSKEY][0]}

        def sig(resp, section, rtype):
            sigs = [r for r in section if r.rdtype == dns.rdatatype.RRSIG
                    and r[0].type_covered == rtype]
            assert sigs, f"missing RRSIG for {rtype}"
            return sigs[0]

        soa_rr = [r for r in r_get.answer if r.rdtype == dns.rdatatype.SOA][0]
        dns.dnssec.validate(soa_rr, sig(r_get, r_get.answer, dns.rdatatype.SOA), keys)
        check("rrsig-soa", True)
        a_rr = [r for r in a_www.answer if r.rdtype == dns.rdatatype.A][0]
        dns.dnssec.validate(a_rr, sig(a_www, a_www.answer, dns.rdatatype.A), keys)
        check("rrsig-a", True)
        nsec3s = [r for r in nx.authority if r.rdtype == dns.rdatatype.NSEC3]
        assert nsec3s, "missing NSEC3 denial"
        for n in nsec3s:
            own = [r for r in nx.authority
                   if r.rdtype == dns.rdatatype.RRSIG
                   and r[0].type_covered == dns.rdatatype.NSEC3
                   and r.name == n.name]
            assert own, f"missing RRSIG for NSEC3 {n.name}"
            dns.dnssec.validate(n, own[0], keys)
        check(f"rrsig-denial-{len(nsec3s)}", True)

        bad = dns.rrset.from_text(
            zone, 300, "IN", "SOA",
            f"{ns} hostmaster.{zone} 999 300 60 86400 60")
        try:
            dns.dnssec.validate(
                bad, sig(r_get, r_get.answer, dns.rdatatype.SOA), keys)
        except dns.dnssec.ValidationFailure:
            check("tamper-rejected", True)
        else:
            check("tamper-rejected", False, "forged SOA validated")

        (work / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print(f"doh-smoke: {len(results)} checks passed")
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    main()
