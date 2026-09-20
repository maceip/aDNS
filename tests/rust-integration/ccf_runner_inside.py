#!/usr/bin/env python3
"""Container-side phases for the isolated Virtual CCF+BIND runner only."""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import CCF_AUDIENCE, VALIDATION_NS_HOSTNAME, VALIDATION_DOMAIN
import argparse
import base64
import importlib.util
import json
import socket
from pathlib import Path
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=('govern', 'provision', 'bind-ready', 'ready', 'receipt'))
    args = parser.parse_args()
    public = Path('/work/control/public')
    private = Path('/work/control/private')
    results = Path('/work/results')
    results.mkdir(exist_ok=True)
    certificate = results/'service_cert.pem'
    if args.phase == 'bind-ready':
        deadline=time.monotonic()+30
        while True:
            try:
                with socket.create_connection(('127.0.0.1',53),timeout=1):
                    return
            except OSError:
                if time.monotonic()>=deadline:
                    raise TimeoutError('stock BIND listener did not become ready before driver startup')
                time.sleep(0.1)
    if args.phase == 'provision':
        spec = importlib.util.spec_from_file_location('supervisor', '/opt/agentdns/run.py')
        supervisor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(supervisor)
        body = supervisor.load_transfer_secret(private/'transfer-key.json')
        deadline = time.monotonic() + 45
        while not supervisor.provision_transfer_secret('127.0.0.1:8001', certificate, body):
            if time.monotonic() >= deadline:
                raise TimeoutError('governed TSIG provisioning did not commit')
            time.sleep(0.2)
        if not supervisor.provision_transfer_secret('127.0.0.1:8001', certificate, body):
            raise AssertionError('identical TSIG provisioning retry failed')
        (results/'provision.json').write_text(json.dumps({'status':'passed', 'globally_committed':True,
            'identical_retry_confirmed':True, 'secret_exported_in_result':False}, indent=2)+'\n')
        return

    sys.path.insert(0, '/src/tools')
    import ccf_control
    client = ccf_control.Client('https://127.0.0.1:8000', None, certificate)
    if args.phase == 'govern':
        deadline = time.monotonic() + 45
        while True:
            try:
                if client.request('GET', '/node/state')['http_status'] == 200:
                    break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise TimeoutError('local CCF did not become ready')
            time.sleep(0.1)
        governance = ccf_control.Governance(client, private/'member0_privk.pem', public/'member0_cert.pem')
        ack = governance.ack()
        opened = governance.propose([{'name':'transition_service_to_open',
            'args':{'next_service_identity':certificate.read_text()}}])
        def rr(name, kind, value):
            return {'name':name, 'rclass':'In', 'rtype':kind, 'ttl':60, 'rdata':{kind:value}}
        records = [rr((VALIDATION_DOMAIN + '.'),'Soa',{'mname':(VALIDATION_NS_HOSTNAME + '.'),'rname':('hostmaster.' + VALIDATION_DOMAIN + '.'),
            'serial':7,'refresh':60,'retry':30,'expire':600,'minimum':60}),
            rr((VALIDATION_DOMAIN + '.'),'Ns',(VALIDATION_NS_HOSTNAME + '.')), rr((VALIDATION_NS_HOSTNAME + '.'),'A','192.0.2.1'),
            rr((VALIDATION_DOMAIN + '.'),'Txt',[list(b'Virtual CCF governed initial test zone; no attested registration')])]
        for index in range(240):
            records.append(rr(f'bulk-{index:04}.{VALIDATION_DOMAIN}.','Txt',[list((f'{index:04}:'+160*'x').encode())]))
        metadata = {'id':1,'origin':(VALIDATION_DOMAIN + '.'),'serial':7,'base_records':records,'signed_records':[],
            'signature_validity':600,'refresh_before':300,'last_signed_at':0,
            'earliest_signature_expiration':0,'maintenance_health':'initializing','ksk_dnskey_rdata':[]}
        bootstrap = json.loads((public/'bootstrap-summary.json').read_text())
        configured = governance.propose([
            {'name':'adns_set_configuration','args':{'audience':(CCF_AUDIENCE),'epoch':1,'last_time':int(time.time())}},
            {'name':'adns_create_zone','args':{'metadata':metadata}},
            {'name':'adns_set_transfer','args':{'key_name':bootstrap['transfer_key_name'],
                'endpoint':'127.0.0.1:53','zones':[(VALIDATION_DOMAIN + '.')],'secret_sha256':bootstrap['transfer_secret_sha256']}}])
        result = {'platform':'Virtual; local CCF protocol test only','member_ack_tx_id':ack['confirmed_ccf_transaction_id'],
            'service_open_tx_id':opened['confirmed_ccf_transaction_id'],'configuration_tx_id':configured['confirmed_ccf_transaction_id'],
            'zone':(VALIDATION_DOMAIN + '.'),'initial_serial':7,'base_records':len(records),
            'signature_validity_seconds':600,'refresh_before_seconds':300,
            'service_registration_created':False,'hardware_appraisal_claimed':False}
        (results/'governance.json').write_text(json.dumps(result,indent=2)+'\n')
    elif args.phase == 'ready':
        deadline = time.monotonic()+420
        while True:
            response = client.request('GET',('/app/zone/status?zone=' + VALIDATION_DOMAIN + '.'))
            body = response.get('body')
            (results/'latest-readiness.json').write_text(json.dumps(response,indent=2)+'\n')
            if response['http_status']==200 and response['headers'].get('x-agentdns-commit-status')=='committed':
                client.require_committed(response)
                state=body.get('committed_state',{})
                peers=body.get('frontend_propagation',{}).get('secondaries',[])
                if state.get('earliest_rrsig_expiration',0)>time.time() and peers and all(p['in_sync'] for p in peers):
                    (results/'ready.json').write_text(json.dumps(response,indent=2)+'\n')
                    return
            if time.monotonic()>=deadline:
                (results/'readiness-failure.json').write_text(json.dumps(response,indent=2)+'\n')
                raise TimeoutError('CCF and BIND did not reach a committed signed in-sync state')
            time.sleep(2)
    else:
        import verify_ksk_receipt
        response=client.request('GET',('/app/governance/ksk-receipt?zone=' + VALIDATION_DOMAIN + '.'))
        if response['headers'].get('x-agentdns-commit-status')!='committed':
            raise ValueError('KSK receipt response is not committed')
        client.require_committed(response)
        receipt=response['body']
        verify_ksk_receipt.verify(receipt,certificate.read_bytes(),expected_zone=(VALIDATION_DOMAIN + '.'))
        (results/'ksk-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        rdata=bytes.fromhex(receipt['dnskey_rdata_hex'])
        text=f'{int.from_bytes(rdata[:2],"big")} {rdata[2]} {rdata[3]} "{base64.b64encode(rdata[4:]).decode()}"'
        (results/'trust-anchor.conf').write_text(f'trust-anchors {{ "{VALIDATION_DOMAIN}." static-key {text}; }};\n')
        (results/'trusted-dnskey.txt').write_text((VALIDATION_DOMAIN + '. IN DNSKEY ')+text.replace('"','')+'\n')
        (results/'receipt-verification.json').write_text(json.dumps({'independently_verified':True,
            'externally_selected_identity':'public certificate copied from this controlled local Virtual node',
            'tx_id':receipt['tx_id'],'hardware_identity_established':False},indent=2)+'\n')


if __name__=='__main__':
    main()
