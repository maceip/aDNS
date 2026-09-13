#!/usr/bin/env python3
"""Independently validate Rust-generated response packets with ISC delv.

Run inside agentdns-validation:local. Each fixture is served byte-for-byte
except request ID; delv performs cryptographic and denial-proof validation.
"""
import pathlib
import socket
import subprocess
import sys
import threading

import dns.message
import dns.rdatatype
import dns.rcode

root = pathlib.Path(sys.argv[1])
failed = False
for mode in ("nsec", "nsec3"):
    packet_map = {}
    for path in root.glob(f"{mode}-*.wire"):
        wire = path.read_bytes()
        message = dns.message.from_wire(wire)
        question = message.question[0]
        packet_map[(str(question.name), question.rdtype)] = wire
    key = (root / f"{mode}.key").read_text().split()
    anchor = root / f"{mode}.trusted.conf"
    anchor.write_text(f'trust-anchors {{ "example." static-key {key[4]} {key[5]} {key[6]} "{key[7]}"; }};\n')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    done = threading.Event()

    def serve():
        while not done.is_set():
            try:
                request, peer = sock.recvfrom(65535)
            except socket.timeout:
                continue
            message = dns.message.from_wire(request)
            question = message.question[0]
            wire = packet_map.get((str(question.name), question.rdtype))
            if wire is None:
                # Corrupted proof tests can trigger extra insecurity lookups.
                # The finite fixture authority explicitly refuses unavailable data.
                response = dns.message.make_response(message)
                response.set_rcode(dns.rcode.SERVFAIL)
                sock.sendto(response.to_wire(), peer)
                continue
            sock.sendto(request[:2] + wire[2:], peer)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        for (owner, rtype), packet in sorted(packet_map.items()):
            if rtype == 48:
                continue
            command = ["delv", "@127.0.0.1", "-p", str(sock.getsockname()[1]),
                       "-a", str(anchor), "+root=example.", "+nocrypto", owner, dns.rdatatype.to_text(rtype)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            output = result.stdout + result.stderr
            ok = "fully validated" in output and "broken trust chain" not in output
            print(f"{mode} {owner} TYPE{rtype}: {'PASS' if ok else 'FAIL'}")
            print(output)
            failed |= not ok
        # A validator must reject a response whose denial proof was removed.
        qkey = ("x.y.ent.example.", 1)
        original = packet_map[qkey]
        altered = dns.message.from_wire(original)
        altered.authority = [rrset for rrset in altered.authority if rrset.rdtype == 6 or
                             (rrset.rdtype == 46 and rrset.covers == 6)]
        packet_map[qkey] = altered.to_wire()
        result = subprocess.run(["delv", "@127.0.0.1", "-p", str(sock.getsockname()[1]),
                                 "-a", str(anchor), "+root=example.", "+nocrypto", qkey[0], "A"],
                                capture_output=True, text=True, timeout=20)
        output = result.stdout + result.stderr
        rejected = "fully validated" not in output and ("broken trust chain" in output or "RRSIG failed to verify" in output)
        print(f"{mode} missing denial proof: {'PASS (rejected)' if rejected else 'FAIL'}")
        print(output)
        failed |= not rejected
        packet_map[qkey] = original
        # Corrupt the wildcard answer signature while leaving the proof intact.
        qkey = ("foo.bar.wild.example.", 1)
        original = packet_map[qkey]
        altered = dns.message.from_wire(original)
        for rrset in altered.answer:
            if rrset.rdtype == 46:
                old = list(rrset)
                rrset.clear()
                for rdata in old:
                    rrset.add(rdata.replace(signature=bytes(96)), rrset.ttl)
        packet_map[qkey] = altered.to_wire()
        result = subprocess.run(["delv", "@127.0.0.1", "-p", str(sock.getsockname()[1]),
                                 "-a", str(anchor), "+root=example.", "+nocrypto", qkey[0], "A"],
                                capture_output=True, text=True, timeout=20)
        output = result.stdout + result.stderr
        rejected = "fully validated" not in output and ("broken trust chain" in output or "RRSIG failed to verify" in output)
        print(f"{mode} altered signature: {'PASS (rejected)' if rejected else 'FAIL'}")
        print(output)
        failed |= not rejected
        packet_map[qkey] = original
    finally:
        done.set()
        thread.join()
        sock.close()
sys.exit(1 if failed else 0)
