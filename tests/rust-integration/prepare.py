#!/usr/bin/env python3
"""Prepare isolated, disposable signed-zone and real TLS test inputs."""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import VALIDATION_DOMAIN
import argparse, base64, hashlib, json, pathlib, subprocess

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

def main():
    p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('directory');a=p.parse_args()
    directory=pathlib.Path(a.directory).resolve();directory.mkdir(parents=True,exist_ok=True)
    run(a.binary,'init',str(directory),(VALIDATION_DOMAIN + '.'))
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(directory/'ca.key'),'-out',str(directory/'ca.pem'),'-days','2','-subj','/CN=agentdns isolated acceptance CA','-addext','basicConstraints=critical,CA:TRUE')
    run('openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(directory/'mail.key'),'-out',str(directory/'mail.csr'),'-subj',('/CN=mail-good.' + VALIDATION_DOMAIN))
    (directory/'mail.ext').write_text(('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:mail-good.' + VALIDATION_DOMAIN + ',DNS:mail-bad.' + VALIDATION_DOMAIN + '\n'))
    run('openssl','x509','-req','-in',str(directory/'mail.csr'),'-CA',str(directory/'ca.pem'),'-CAkey',str(directory/'ca.key'),'-CAcreateserial','-out',str(directory/'mail.pem'),'-days','2','-extfile',str(directory/'mail.ext'))
    public=subprocess.check_output(['openssl','pkey','-in',str(directory/'mail.key'),'-pubout','-outform','DER'])
    digest=hashlib.sha256(public).digest();(directory/'mail-spki.sha256').write_text(digest.hex()+'\n')
    config=json.loads((directory/'config.json').read_text())
    config.update(http_listen='127.0.0.1:18080',transfer_listen='0.0.0.0:18535',signature_validity=600,refresh_before=300,secondaries=['127.0.0.1:1053'])
    def record(name,kind,data,ttl=60):return dict(name=name,rclass='In',rtype=kind,ttl=ttl,rdata={kind:data})
    records=config['initial_records']
    for flavour in ['good','bad']:
        mail=f'mail-{flavour}.{VALIDATION_DOMAIN}.'
        records += [record(f'{flavour}.{VALIDATION_DOMAIN}.','Mx',dict(preference=10,exchange=mail)),record(mail,'A','127.0.0.1'),record(mail,'Aaaa','::1')]
        for port in [25,465,993]:
            records.append(record(f'_{port}._tcp.{mail}','Tlsa',dict(usage=3,selector=1,matching_type=1,certificate_association_data=list(digest if flavour=='good' else bytes(32)))))
    # Ensure several >16KB AXFR messages rather than a single self-consistent packet.
    for i in range(240):records.append(record(f'bulk-{i:04}.{VALIDATION_DOMAIN}.','Txt',[list((f'load-{i:04}:'+('x'*160)).encode())]))
    # Names exercise closest encloser and wildcard paths under external validation.
    records += [record(('leaf.branch.' + VALIDATION_DOMAIN + '.'),'A','192.0.2.10'),record(('*.wild.' + VALIDATION_DOMAIN + '.'),'A','192.0.2.11')]
    (directory/'config.json').write_text(json.dumps(config,indent=2)+'\n')
    (directory/'fixture-summary.json').write_text(json.dumps({'tlsa_sha256':digest.hex(),'records':len(records),'zone':(VALIDATION_DOMAIN + '.'),'signature_validity':600,'refresh_before':300},indent=2)+'\n')
    for key in ['ca.key','mail.key','seal.key','tsig.key','bind-key.conf','config.json']:(directory/key).chmod(0o600)
    print(directory)
if __name__=='__main__':main()
