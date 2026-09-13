#!/usr/bin/env python3
"""Use Postfix's real DANE SMTP TLS probe and standard PKIX TLS validation."""
import hashlib,json,pathlib,ssl,socket,subprocess
import dns.flags,dns.message,dns.query
root=pathlib.Path('/work')
pathlib.Path('/etc/resolv.conf').write_text('nameserver 127.0.0.1\noptions timeout:2 attempts:2 trust-ad\n')
q=dns.message.make_query('_25._tcp.mail-good.example.test.','TLSA',want_dnssec=True)
a=dns.query.udp(q,'127.0.0.1',timeout=5)
assert a.flags & dns.flags.AD,'Postfix must see cryptographically authenticated TLSA DNS'
results={'dnssec_validated_tlsa':True,'postfix':{}}
for flavour in ['good','bad']:
    command=['posttls-finger','-l','dane-only','-L','summary,verbose','-t','5','-T','5','-o','inet_protocols=ipv4','-o','smtp_dns_support_level=dnssec',f'{flavour}.example.test']
    p=subprocess.run(command,capture_output=True,text=True,timeout=30)
    output=p.stdout+p.stderr;(root/f'postfix-dane-{flavour}.log').write_text(output)
    if flavour=='good':assert 'Verified TLS connection established' in output,output
    else:assert 'Untrusted TLS connection established' in output or 'Server certificate not trusted' in output,output
    results['postfix'][flavour]={'exit_code':p.returncode,'authenticated':flavour=='good','log':f'postfix-dane-{flavour}.log'}
context=ssl.create_default_context(cafile=str(root/'ca.pem'))
results['pkix']={}
for port in [465,993]:
    with socket.create_connection(('127.0.0.1',port),5) as raw:
        with context.wrap_socket(raw,server_hostname='mail-good.example.test') as tls:
            certificate=tls.getpeercert(binary_form=True)
            public_pem=subprocess.run(['openssl','x509','-inform','DER','-pubkey','-noout'],input=certificate,capture_output=True,check=True).stdout
            spki=subprocess.run(['openssl','pkey','-pubin','-outform','DER'],input=public_pem,capture_output=True,check=True).stdout
            digest=hashlib.sha256(spki).digest()
            response=dns.query.udp(dns.message.make_query(f'_{port}._tcp.mail-good.example.test.','TLSA',want_dnssec=True),'127.0.0.1',timeout=5)
            assert response.flags & dns.flags.AD,'implicit TLS peer needs authenticated DNSSEC TLSA'
            assert any(record.usage==3 and record.selector==1 and record.mtype==1 and record.cert==digest for rrset in response.answer if rrset.rdtype==dns.rdatatype.TLSA for record in rrset),'TLSA does not bind actual TLS listener SPKI'
            results['pkix'][str(port)]={'verified':True,'protocol':tls.version(),'cipher':tls.cipher()[0],'dnssec_tlsa_matches_peer_spki':True}
    try:
        with socket.create_connection(('127.0.0.1',port),5) as raw:
            with context.wrap_socket(raw,server_hostname='unmatched.example.test'):pass
    except ssl.SSLCertVerificationError:results['pkix'][str(port)]['wrong_hostname_rejected']=True
    else:raise AssertionError('PKIX hostname mismatch accepted')
(root/'mail-results.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results,indent=2),flush=True)
