#!/usr/bin/env python3
"""One authenticated NOTIFY for documented recovery checks; no zone mutation."""
import base64,pathlib,dns.flags,dns.message,dns.opcode,dns.query,dns.tsigkeyring
root=pathlib.Path('/work');q=dns.message.make_query('example.test.','SOA');q.set_opcode(dns.opcode.NOTIFY)
q.use_tsig(dns.tsigkeyring.from_text({'agentdns-transfer.':base64.b64encode((root/'tsig.key').read_bytes()).decode()}),'agentdns-transfer.',algorithm='hmac-sha256')
a=dns.query.udp(q,'127.0.0.1',port=1053,timeout=3)
assert a.had_tsig and a.rcode()==0
print('Authenticated recovery NOTIFY acknowledged')
