#!/usr/bin/env python3
"""Exercise public control tools against an isolated real Virtual CCF node.

Run in the pinned toolchain with /src read-only and an existing /build binary.
No Virtual quote is accepted as hardware evidence. All state is disposable.
"""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import CCF_RPC_HOSTNAME, VALIDATION_DOMAIN
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
sys.path.insert(0, '/src/tools')
import prepare_aci_control
import ccf_control


def main():
    probe = '--probe' in sys.argv
    work = Path(tempfile.mkdtemp(prefix='control-smoke-', dir='/build'))
    constitution = work/'constitution.js'
    import packaged_constitution
    constitution.write_bytes(packaged_constitution.load())
    import hashlib
    sys.argv = ['prepare_aci_control.py', str(work/'control'), '--constitution-sha256', hashlib.sha256(constitution.read_bytes()).hexdigest()]
    prepare_aci_control.main()
    public, private = work/'control/public', work/'control/private'
    config = json.loads((public/'node.json').read_text())
    config['network']['node_to_node_interface']['bind_address'] = '127.0.0.1:18002'
    for name, port in [('primary_rpc_interface',18000),('agentdns-internal',18001)]:
        config['network']['rpc_interfaces'][name]['bind_address'] = f'127.0.0.1:{port}'
    config['network']['rpc_interfaces']['primary_rpc_interface']['published_address'] = (CCF_RPC_HOSTNAME + ':18000')
    config['command']['start']['constitution_files'] = [str(constitution)]
    config['command']['start']['members'] = [{'certificate_file':str(public/'member0_cert.pem'),'encryption_public_key_file':str(public/'member0_enc_pubk.pem')}]
    (work/'node.json').write_text(json.dumps(config))
    with open(work/'node.log','wb') as log:
        process = subprocess.Popen(['/build/agentdns','--config',str(work/'node.json')], cwd=work, stdout=log, stderr=subprocess.STDOUT, env={**os.environ,'CCF_PLATFORM_OVERRIDE':'Virtual'})
        try:
            for _ in range(200):
                if process.poll() is not None: raise RuntimeError((work/'node.log').read_text())
                if (work/'service_cert.pem').exists(): break
                time.sleep(.1)
            client = ccf_control.Client(('https://' + CCF_RPC_HOSTNAME + ':18000'),'127.0.0.1',work/'service_cert.pem')
            for _ in range(100):
                try:
                    if client.request('GET','/node/state')['http_status']==200: break
                except OSError: pass
                time.sleep(.1)
            if probe:
                for path in ['/node/tx?transaction_id=2.2','/app/tx?transaction_id=2.2','/gov/tx?transaction_id=2.2']:
                    print(path, json.dumps(client.request('GET',path)),flush=True)
                return
            gov = ccf_control.Governance(client,private/'member0_privk.pem',public/'member0_cert.pem')
            ack = gov.ack()
            opened = gov.propose([{'name':'transition_service_to_open','args':{'next_service_identity':(work/'service_cert.pem').read_text()}}])
            configured = gov.propose([{'name':'adns_set_configuration','args':{'audience':'ccf://control-client-smoke','epoch':1,'last_time':int(time.time())}}])
            assert ack['http_status']==204 and opened['body']['proposalState']=='Accepted'
            assert configured['body']['proposalState']=='Accepted'
            for result in [ack,opened,configured]: assert result['confirmed_ccf_transaction_id']
            supervisor_spec=importlib.util.spec_from_file_location('agentdns_supervisor','/src/ccf/run.py')
            supervisor=importlib.util.module_from_spec(supervisor_spec);supervisor_spec.loader.exec_module(supervisor)
            # Fresh local fixture material; never read cloud deployment parameters.
            provision=(private/'transfer-key.json').read_bytes()
            assert not supervisor.provision_transfer_secret('127.0.0.1:18001',work/'service_cert.pem',provision)
            summary=json.loads((public/'bootstrap-summary.json').read_text())
            transfer=gov.propose([{'name':'adns_set_transfer','args':{'key_name':summary['transfer_key_name'],'endpoint':summary['secondary_endpoint'],'zones':[(VALIDATION_DOMAIN + '.')],'secret_sha256':summary['transfer_secret_sha256']}}])
            assert transfer['body']['proposalState']=='Accepted'
            assert supervisor.provision_transfer_secret('127.0.0.1:18001',work/'service_cert.pem',provision)
            assert supervisor.provision_transfer_secret('127.0.0.1:18001',work/'service_cert.pem',provision)
            def rejected(actions):
                try:
                    gov.propose(actions)
                except ValueError:
                    return
                raise AssertionError('invalid governance proposal was accepted')

            def revoked_provision_rejected():
                try:
                    supervisor.provision_transfer_secret('127.0.0.1:18001',work/'service_cert.pem',provision)
                except RuntimeError as error:
                    assert str(error)=='TSIG provisioning rejected (HTTP 403)'
                    return
                raise AssertionError('revoked provisioning did not fail with HTTP 403')

            # The actual constitution may write app tables but cannot read them:
            # these calls exercise the governance mirrors and CCF rollback.
            revoked=gov.propose([{'name':'adns_revoke_transfer','args':{'key_name':summary['transfer_key_name']}}])
            assert revoked['body']['proposalState']=='Accepted'
            revoked_provision_rejected()
            gov.propose([{'name':'adns_revoke_transfer','args':{'key_name':summary['transfer_key_name']}}])
            rejected([{'name':'adns_set_transfer','args':{'key_name':summary['transfer_key_name'],'endpoint':summary['secondary_endpoint'],'zones':[(VALIDATION_DOMAIN + '.')],'secret_sha256':summary['transfer_secret_sha256']}}])
            revoked_provision_rejected()
            import base64
            replacement_secret=os.urandom(32)
            replacement_name=('replacement.' + VALIDATION_DOMAIN + '.')
            replacement=gov.propose([{'name':'adns_set_transfer','args':{'key_name':replacement_name,'endpoint':summary['secondary_endpoint'],'zones':[(VALIDATION_DOMAIN + '.')],'secret_sha256':hashlib.sha256(replacement_secret).hexdigest()}}])
            replacement_body=json.dumps({'key_name':replacement_name,'zones':[(VALIDATION_DOMAIN + '.')],'secret_base64url':base64.urlsafe_b64encode(replacement_secret).decode().rstrip('=')}).encode()
            assert supervisor.provision_transfer_secret('127.0.0.1:18001',work/'service_cert.pem',replacement_body)

            policy={'policy_id':[1]*32,'release_id':'control-smoke','active_profiles':['azure-aci-snp'],'valid_from':1,'valid_until':2000000000,'max_appraisal_lifetime':600,'minimum_tcb':{},'approved_measurements':['ab'*48],'approved_host_data':['cd'*32],'uvm':[]}
            def policy_action(value):
                return [{'name':'adns_set_appraisal_policy','args':{'zone':(VALIDATION_DOMAIN + '.'),'policy':value}}]
            installed=gov.propose(policy_action(policy))
            repeated=gov.propose(policy_action(dict(reversed(list(policy.items())))))
            changed={**policy,'approved_host_data':['ef'*32]}
            rejected(policy_action(changed))
            updated=gov.propose(policy_action({**changed,'policy_id':[2]*32}))
            rejected(policy_action(changed)) # Old IDs stay immutable after replacement.
            rejected(policy_action({**policy,'valid_until':2**53}))
            for result in [revoked,replacement,installed,repeated,updated]:
                assert result['confirmed_ccf_transaction_id']
            print(json.dumps({'status':'passed','platform':'Virtual; control protocol only','member_ack_tx_id':ack['confirmed_ccf_transaction_id'],'service_open_tx_id':opened['confirmed_ccf_transaction_id'],'configuration_tx_id':configured['confirmed_ccf_transaction_id'],'transfer_governance_tx_id':transfer['confirmed_ccf_transaction_id'],'transfer_revocation_tx_id':revoked['confirmed_ccf_transaction_id'],'replacement_transfer_tx_id':replacement['confirmed_ccf_transaction_id'],'policy_initial_tx_id':installed['confirmed_ccf_transaction_id'],'policy_exact_repeat_tx_id':repeated['confirmed_ccf_transaction_id'],'policy_new_id_tx_id':updated['confirmed_ccf_transaction_id'],'supervisor_provisioned_and_repeated_with_global_commit':True,'ungoverned_transfer_secret_rejected':True,'revoked_transfer_reprovision_and_reactivation_rejected':True,'replacement_transfer_provisioned':True,'policy_same_id_trust_change_and_unsafe_number_rejected':True,'dns_sni_with_numeric_connect_ip':True}),flush=True)
        finally:
            process.terminate()
            try: process.wait(timeout=15)
            except subprocess.TimeoutExpired: process.kill();process.wait()

if __name__=='__main__':main()
