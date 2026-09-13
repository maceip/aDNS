#!/usr/bin/env python3
"""Independent dnspython verification of real Rust TSIG transfer bytes.

Run prepare DIR in the validation image, cargo run -p adns-transfer --example
interop_vectors -- DIR on the host, then verify DIR in the validation image.
The fixed 32-byte test key is public fixture material.
"""
import base64
import pathlib
import sys
import dns.exception
import dns.message
import dns.tsigkeyring
import dns.zone

mode, path = sys.argv[1:]
root = pathlib.Path(path)
keys = dns.tsigkeyring.from_text({'test-transfer.': base64.b64encode(bytes([7]) * 32).decode()})
if mode == 'prepare':
    root.mkdir(parents=True, exist_ok=True)
    query = dns.message.make_query('example.test.', 'AXFR')
    query.use_tsig(keys, 'test-transfer.', algorithm='hmac-sha256')
    (root / 'query.bin').write_bytes(query.to_wire())
    print('dnspython generated authenticated AXFR request')
elif mode == 'verify':
    query = dns.message.from_wire((root / 'query.bin').read_bytes(), keyring=keys)
    stream = (root / 'stream.bin').read_bytes()
    packets = []
    position = 0
    while position < len(stream):
        size = int.from_bytes(stream[position:position + 2], 'big')
        assert 12 <= size <= 4096
        position += 2
        assert len(stream) - position >= size
        packets.append(stream[position:position + size])
        position += size
    assert len(packets) > 10
    messages = []
    context = None
    for packet in packets:
        message = dns.message.from_wire(packet, keyring=keys, request_mac=query.mac,
                                        tsig_ctx=context, multi=True, xfr=True,
                                        one_rr_per_rrset=True)
        assert message.had_tsig
        context = message.tsig_ctx
        messages.append(message)
    zone = dns.zone.from_xfr(iter(messages), relativize=False, check_origin=False)
    assert zone.get_rdataset('example.test.', 'SOA')[0].serial == 7
    assert len(zone.nodes) == 1001
    for i in range(1000):
        txt = zone.get_rdataset(f'record{i}.example.test.', 'TXT')[0]
        assert txt.strings == (b'x' * 200, b'y' * 200)
    for tampered in (packets[1], packets[-1]):
        # Replay a continuation as the first response loses the authenticated
        # stream prefix and must fail even though its bytes are unchanged.
        try:
            dns.message.from_wire(tampered, keyring=keys, request_mac=query.mac, multi=True, xfr=True)
        except dns.exception.DNSException:
            pass
        else:
            raise AssertionError('out-of-order continuation accepted')
    print(f'dnspython authenticated all {len(packets)} Rust packets, recovered all 1001 records, rejected two reordered continuations')
else:
    raise SystemExit('mode must be prepare or verify')
