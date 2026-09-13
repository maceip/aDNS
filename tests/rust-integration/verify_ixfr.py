#!/usr/bin/env python3
"""Exercise stock-client IXFR requests and the RFC 1995 full-transfer fallback."""
import base64,json,pathlib,socket,time
import dns.flags,dns.message,dns.query,dns.rdatatype,dns.tsigkeyring,dns.zone
root=pathlib.Path('/work');master=(root/'container-ready').read_text().strip() if (root/'container-ready').exists() else socket.gethostbyname('host.docker.internal');name='agentdns-transfer.'
keys=dns.tsigkeyring.from_text({name:base64.b64encode((root/'tsig.key').read_bytes()).decode()})
query=dns.message.make_query('example.test.','SOA');query.use_tsig(keys,name,algorithm='hmac-sha256')
response=dns.query.udp(query,master,port=18535,timeout=3);assert response.had_tsig
current=response.answer[0][0].serial
messages=list(dns.query.xfr(master,'example.test.',rdtype='IXFR',serial=current-1,port=18535,keyring=keys,keyname=name,keyalgorithm='hmac-sha256',relativize=False,timeout=3,lifetime=10))
assert len(messages)>1 and all(m.had_tsig for m in messages)
zone=dns.zone.from_xfr(iter(messages),relativize=False);assert zone.get_rdataset('example.test.','SOA')[0].serial==current
same=list(dns.query.xfr(master,'example.test.',rdtype='IXFR',serial=current,port=18535,keyring=keys,keyname=name,keyalgorithm='hmac-sha256',relativize=False,timeout=3,lifetime=10))
assert len(same)==1 and same[0].had_tsig and len(same[0].answer)==1 and same[0].answer[0].rdtype==dns.rdatatype.SOA
result={'unix_seconds':int(time.time()),'serial':current,'authenticated_udp_soa':True,'ixfr_older_serial_full_axfr_fallback_messages':len(messages),'all_fallback_messages_tsig_verified':True,'equal_serial_single_authenticated_soa':True}
(root/'ixfr-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2),flush=True)
