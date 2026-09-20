#!/usr/bin/env python3
"""One authenticated NOTIFY for documented recovery checks; no zone mutation."""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import TRANSFER_KEY_NAME, VALIDATION_DOMAIN
import base64,pathlib,dns.flags,dns.message,dns.opcode,dns.query,dns.tsigkeyring
root=pathlib.Path('/work');q=dns.message.make_query((VALIDATION_DOMAIN + '.'),'SOA');q.set_opcode(dns.opcode.NOTIFY)
q.use_tsig(dns.tsigkeyring.from_text({(TRANSFER_KEY_NAME):base64.b64encode((root/'tsig.key').read_bytes()).decode()}),(TRANSFER_KEY_NAME),algorithm='hmac-sha256')
a=dns.query.udp(q,'127.0.0.1',port=1053,timeout=3)
assert a.had_tsig and a.rcode()==0
print('Authenticated recovery NOTIFY acknowledged')
