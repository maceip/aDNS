#!/usr/bin/env python3
"""Independent dnspython AXFR and BIND-delv/ldns validation, then DANE setup."""
import base64,json,pathlib,socket,subprocess,time
import dns.dnssec,dns.flags,dns.message,dns.query,dns.rdatatype,dns.tsigkeyring,dns.zone
from bind_workspace import workspace,launch
root=pathlib.Path('/work');master=(root/'container-ready').read_text().strip() if (root/'container-ready').exists() else socket.gethostbyname('host.docker.internal');origin='example.test.'
keyname='agentdns-transfer.';keyring=dns.tsigkeyring.from_text({keyname:base64.b64encode((root/'tsig.key').read_bytes()).decode()})
messages=list(dns.query.xfr(master,origin,port=18535,keyring=keyring,keyname=keyname,keyalgorithm='hmac-sha256',timeout=10,lifetime=30,relativize=False))
assert len(messages)>1,'must exercise multi-message TSIG chaining'
assert all(m.had_tsig for m in messages),'every stream message must authenticate'
zone=dns.zone.from_xfr(iter(messages),relativize=False)
zone.to_file(str(root/'transferred.zone'),relativize=False)
serial=zone.get_rdataset(origin,'SOA')[0].serial
result={'initial_time':int(time.time()),'initial_serial':serial,'axfr_messages':len(messages),'axfr_records':sum(len(r) for m in messages for r in m.answer),'every_message_tsig_verified':True}
# Strict unauthenticated and wrong-key rejection, verified by independent client.
for label,key in [('unsigned',None),('wrong-key',dns.tsigkeyring.from_text({keyname:base64.b64encode(bytes(32)).decode()}))]:
    try:list(dns.query.xfr(master,origin,port=18535,keyring=key,keyname=keyname if key else None,keyalgorithm='hmac-sha256',timeout=2,lifetime=3))
    except (EOFError,OSError,dns.exception.DNSException):result[label+'_axfr_rejected']=True
    else:raise AssertionError(label+' transfer was accepted')
# Wait for a stock secondary to obtain the zone from the Rust primary.
for _ in range(60):
    try:
        response=dns.query.udp(dns.message.make_query(origin,'SOA'), '127.0.0.1',port=1053,timeout=2)
        if response.answer and response.answer[0][0].serial>=serial:break
    except (OSError,dns.exception.DNSException):pass
    time.sleep(1)
else:raise RuntimeError('BIND secondary did not obtain the zone; inspect bind-secondary.log')
result['bind_serial']=response.answer[0][0].serial
result['bind_authoritative']=bool(response.flags & dns.flags.AA)
assert result['bind_authoritative']
# Trust the exact KSK returned through authenticated transfer, isolated test anchor.
ksk=next(k for k in zone.get_rdataset(origin,'DNSKEY') if k.flags==257)
anchor=f'trust-anchors {{ "{origin}" static-key {ksk.flags} {ksk.protocol} {ksk.algorithm} "{base64.b64encode(ksk.key).decode()}"; }};\n'
(root/'trust-anchor.conf').write_text(anchor)
(root/'trusted.key').write_text(f'{origin} IN DNSKEY {ksk.to_text()}\n')
# Independent full-zone validation, not our Rust implementation's verifier.
check=subprocess.run(['ldns-verify-zone','-k',str(root/'trusted.key'),str(root/'transferred.zone')],capture_output=True,text=True)
(root/'ldns-verify-zone.log').write_text(check.stdout+check.stderr)
assert check.returncode==0,check.stdout+check.stderr
for name,kind in [('example.test.','SOA'),('mail-good.example.test.','A'),('absent.branch.example.test.','A'),('mail-good.example.test.','TXT'),('missing.wild.example.test.','A')]:
    check=subprocess.run(['delv','@127.0.0.1','-p','1053','-a',str(root/'trust-anchor.conf'),'+root=example.test.',name,kind],capture_output=True,text=True)
    (root/('delv-'+name+kind+'.log')).write_text(check.stdout+check.stderr)
    assert check.returncode==0 and ('fully validated' in check.stdout or 'negative response, fully validated' in check.stdout),check.stdout+check.stderr
result['external_dnssec_validated']=True
# Local validating recursive resolver allows Postfix to enforce DNSSEC DANE.
resolver=workspace('resolver')
configuration=f'''
{anchor}
options {{ directory "{resolver}"; listen-on port 53 {{ 127.0.0.1; }}; listen-on-v6 {{ none; }}; recursion yes; allow-recursion {{ 127.0.0.1; }}; dnssec-validation yes; empty-zones-enable no; pid-file "{resolver}/named.pid"; session-keyfile "{resolver}/session.key"; }};
controls {{ }};
zone "example.test" {{ type forward; forward only; forwarders {{ 127.0.0.1 port 1053; }}; }};
'''
launch(root,resolver,'resolver',configuration,detached=True)
for _ in range(50):
    try:
        response=dns.query.udp(dns.message.make_query(origin,'SOA',want_dnssec=True),'127.0.0.1',timeout=1)
        if response.flags & dns.flags.AD:break
    except (OSError,dns.exception.DNSException):pass
    time.sleep(.1)
else:raise RuntimeError('isolated DNSSEC validating resolver did not become ready')
(root/'initial-results.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2),flush=True)
