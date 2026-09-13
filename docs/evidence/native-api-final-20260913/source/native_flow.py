#!/usr/bin/env python3
"""Execute approved native acceptance against real CCF and appraised workers."""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import urlencode

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ROOT = Path('/Users/mac/agentdns')
sys.path.insert(0, str(ROOT/'tools'))
sys.path.insert(0, str(ROOT/'tests/rust-integration'))
from ccf_control import Client, Governance
from reconcile_ccf_inside import validate_observation_identity


class Run:
    def __init__(self, context, worker_name, out):
        self.context = json.loads(context.read_text())
        self.worker = self.context['workers'][worker_name]
        self.out = out
        out.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.client = Client('https://agentdns.test:8000', self.context['node_ip'], Path(self.context['service_cert']))
        self.governor = Governance(self.client, Path(self.context['member_key']), Path(self.context['member_cert']))
        self.counter = 0
        self.history = []
        original = self.client.request

        def recorded(method, path, body=None, *args, **kwargs):
            started = time.perf_counter_ns()
            response = original(method, path, body, *args, **kwargs)
            self.history.append({'method': method, 'path': path, 'at_unix_seconds': time.time(),
                'elapsed_ms': (time.perf_counter_ns()-started)/1e6, 'response': copy.deepcopy(response)})
            self.save('http-history', self.history)
            return response
        self.client.request = recorded

    def save(self, name, value):
        path = self.out/(name+'.json')
        fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2); stream.write('\n')
        return value

    def request(self, name, method, path, body=None, expected=200):
        result = self.save(name, self.client.request(method, path, body))
        assert result['http_status'] == expected, f'{name}: unexpected HTTP {result["http_status"]}; retained response'
        if 200 <= expected < 300:
            assert result['headers'].get('x-agentdns-commit-status') == 'committed', name+': missing commit gate'
            result = self.client.require_committed(result)
            self.save(name, result)
        return result

    def govern(self, name, grant):
        return self.save(name, self.governor.propose([{'name':'adns_set_owner_grant','args':{'grant':grant}}]))

    def lookup(self, action):
        return '/app/service/request?'+urlencode({k:action[k] for k in ('grant_id','request_id')})

    def state(self, name):
        return self.request(name, 'GET', '/app/zone/status?zone=example.test.')['body']['committed_state']

    def worker_call(self, name, path, body):
        self.save(name+'-input', body)
        command = [sys.executable, str(ROOT/'tools/sign_capture_request.py'), '--ip', self.worker['ip'],
            '--capture', self.worker['capture'], '--policy', self.context['workload_policy'],
            '--appraiser', str(ROOT/'target/debug/examples/appraise'), '--token-parameters', self.worker['parameters'],
            '--body', str(self.out/(name+'-input.json')), '--path', path, '--output', str(self.out/(name+'.json'))]
        result = subprocess.run(command, capture_output=True, timeout=65)
        self.save(name+'-transport', {'returncode':result.returncode, 'stdout':result.stdout.decode(), 'stderr':result.stderr.decode()})
        assert result.returncode == 0, name+': worker call failed; bounded diagnostics retained'
        return json.loads((self.out/(name+'.json')).read_text())

    def verify(self, envelope):
        message = {k:envelope[k] for k in ('action','nonce','nonce_expires_at','intent_hash')}
        assert hashlib.sha256(rfc8785.dumps(envelope['action'])).hexdigest() == envelope['intent_hash']
        spki = (Path(self.worker['capture'])/'spki.der').read_bytes()
        assert base64.urlsafe_b64decode(envelope['action']['signer_spki_der']+'='*(-len(envelope['action']['signer_spki_der'])%4)) == spki
        encoded = envelope['client_signature']
        signature = base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4))
        assert len(signature) == 64
        key = serialization.load_der_public_key(spki)
        key.verify(encode_dss_signature(int.from_bytes(signature[:32],'big'),int.from_bytes(signature[32:],'big')),
            rfc8785.dumps(message), ec.ECDSA(hashes.SHA256()))
        if 'evidence_payload' in envelope:
            encoded = envelope['evidence_payload']
            payload = base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4))
            assert payload == (Path(self.worker['capture'])/'evidence.cose').read_bytes()
        return hashlib.sha256(rfc8785.dumps(message)).hexdigest()

    def nonce(self, name, action):
        nonce = self.request(name, 'POST', '/app/service/nonce', {'action':action})['body']
        assert nonce['intent_hash'] == hashlib.sha256(rfc8785.dumps(action)).hexdigest()
        assert nonce['expires_at']-time.time() > 240
        return {'nonce':nonce['nonce'], 'nonce_expires_at':nonce['expires_at'], 'intent_hash':nonce['intent_hash']}

    def observe(self, name, action, status, nonce):
        result = self.request(name, 'GET', self.lookup(action))
        assert result['body']['status'] == status
        assert result['body']['execution_state'] == status
        validate_observation_identity(result)
        body=result['body']; latest=body['latest_observation']
        assert body['grant_id']==action['grant_id'] and body['request_id']==action['request_id']
        assert latest['nonce']==nonce['nonce'] and latest['intent_hash']==nonce['intent_hash']
        assert body['matching_nonces']==1 and body['multiple_nonce_ambiguity'] is False and body['retryable'] is True
        assert body['phase']==('awaiting_committed_result' if status=='pending' else 'last_authenticated_attempt')
        return result

    def verify_prepared(self, prepared, requested):
        original=json.loads((Path(self.worker['capture'])/'action.json').read_text())['action']
        action=prepared['action']
        assert all(action[k]==original[k] for k in ('audience','grant_id','zone','signer_spki_der'))
        assert action['operation']==requested['operation'] and action['request_id']==requested['request_id']
        expected=dict(requested['parameters'])
        op=requested['operation']
        if op!='acme_challenge_delete':expected['registration_id']=self.worker['registration_id']
        if op=='renew':
            expected['evidence_profile']=original['parameters']['evidence_profile']
            expected['evidence_digest']=original['parameters']['evidence_digest']
        elif op=='deregister':expected.setdefault('reason','validation_lifecycle')
        elif op=='acme_challenge_create':expected['name']=original['parameters']['service_host']
        assert action['parameters']==expected
        digest=hashlib.sha256(rfc8785.dumps(action)).hexdigest()
        assert prepared['action_id']==digest and prepared['intent_hash']==digest

    def submit_success(self, name, envelope):
        route = {'register':('POST','/app/service/register'), 'renew':('POST','/app/service/renew'),
            'deregister':('POST','/app/service/deregister'), 'acme_challenge_create':('POST','/app/zone/acme-challenge'),
            'acme_challenge_delete':('DELETE','/app/zone/acme-challenge')}[envelope['action']['operation']]
        digest = self.verify(envelope)
        before = len(self.history)
        result = self.request(name, *route, envelope)
        elapsed = self.history[before]['elapsed_ms']
        assert result['body']['status'] == 'committed'
        historical = self.request(name+'-history', 'GET', self.lookup(envelope['action']))
        retry = self.request(name+'-retry', *route, envelope)
        for row in (historical,retry):
            assert row['body'] == result['body']
            assert row['confirmed_ccf_transaction_id'] == result['confirmed_ccf_transaction_id']
        self.save(name+'-measurement', {'operation':envelope['action']['operation'], 'samples':1,
            'submission_to_globally_committed_response_ms_including_tls':elapsed,
            'signed_message_digest':digest, 'transaction_id':result['confirmed_ccf_transaction_id'],
            'historical_result_exactly_matches':True, 'exact_retry_matches':True})
        return result

    def registration(self, scopes):
        action = json.loads((Path(self.worker['capture'])/'action.json').read_text())['action']
        grant = json.loads(Path(self.worker['grant']).read_text())
        state = self.state('before-registration')
        assert state['earliest_rrsig_expiration']-time.time() > 430, 'wait for fresh signature window before issuing nonce'
        nonce = self.nonce('registration-nonce', action)
        self.observe('registration-pending', action, 'pending', nonce)
        envelope = self.worker_call('registration-envelope','/signed-request',nonce)
        digest = self.verify(envelope)
        assert envelope['action'] == action and all(envelope[k] == v for k,v in nonce.items())
        if scopes:
            raw=base64.urlsafe_b64decode(envelope['client_signature']+'='*(-len(envelope['client_signature'])%4))
            der=encode_dss_signature(int.from_bytes(raw[:32],'big'),int.from_bytes(raw[32:],'big'))
            malformed=copy.deepcopy(envelope)
            malformed['client_signature']=base64.urlsafe_b64encode(der).rstrip(b'=').decode()
            self.save('der-signature-envelope',malformed)
            rejected=self.request('der-signature-rejection','POST','/app/service/register',malformed,expected=403)
            assert 'INVALID_FIELD: base64url length' in json.dumps(rejected['body'])
            self.observe('pending-after-invalid-signature',action,'pending',nonce)
            invalid=copy.deepcopy(envelope)
            corrupt=bytearray(raw);corrupt[-1]^=1
            invalid['client_signature']=base64.urlsafe_b64encode(corrupt).rstrip(b'=').decode()
            self.save('invalid-fixed-signature-envelope',invalid)
            rejected=self.request('invalid-fixed-signature-rejection','POST','/app/service/register',invalid,expected=403)
            assert 'INVALID_SIGNATURE' in json.dumps(rejected['body'])
            self.observe('pending-after-invalid-fixed-signature',action,'pending',nonce)
            altered=copy.deepcopy(envelope)
            payload=bytearray(base64.urlsafe_b64decode(altered['evidence_payload']+'='*(-len(altered['evidence_payload'])%4)))
            payload[-1]^=1
            altered['evidence_payload']=base64.urlsafe_b64encode(payload).rstrip(b'=').decode()
            self.save('altered-evidence-envelope',altered)
            rejected=self.request('altered-evidence-rejection','POST','/app/service/register',altered,expected=403)
            assert 'EVIDENCE_DIGEST_MISMATCH' in json.dumps(rejected['body'])
            self.observe('pending-after-altered-evidence',action,'pending',nonce)
            assert self.state('after-invalid-requests')['serial']==state['serial']
            variants = []
            for field in ('service_hosts','roles','address_cidrs','ports'):
                bad = copy.deepcopy(grant); bad[field] = []; variants.append((field,bad))
            bad = copy.deepcopy(grant); bad.update(valid_from=int(time.time())-120,valid_until=int(time.time())-60)
            variants.append(('expired',bad))
            bad = copy.deepcopy(grant); bad['revoked'] = True; variants.append(('revoked',bad))
            for name,bad in variants:
                assert nonce['nonce_expires_at']-time.time() > 60, 'insufficient nonce time; preserve failed attempt'
                self.govern(name+'-restrict-grant',bad)
                try:
                    failed = self.request(name+'-reject','POST','/app/service/register',envelope,expected=403)
                    assert 'GRANT_DENIED' in json.dumps(failed['body'])
                    txid = failed['headers'].get('x-agentdns-transaction-id')
                    confirm = self.save(name+'-failure-commit',self.client.request('GET','/node/tx?transaction_id='+str(txid)))
                    assert confirm['http_status']==200 and confirm['body']=={'transaction_id':txid,'status':'Committed'}
                    failed['confirmed_ccf_transaction_id']=txid; validate_observation_identity(failed)
                    self.save(name+'-reject',failed)
                    observed=self.observe(name+'-failed-observation',action,'failed',nonce)
                    latest=observed['body']['latest_observation']
                    assert latest['nonce']==nonce['nonce'] and latest['signed_message_digest']==digest
                    assert latest['http_status']==403
                    assert self.state(name+'-zone-after-rejection')['serial']==state['serial']
                finally:
                    self.govern(name+'-restore-grant',grant)
        result = self.submit_success('registration',envelope)
        assert result['body']['registration_id']=='reg-'+digest[:32]
        self.worker['registration_id']=result['body']['registration_id']
        if scopes:
            after=self.state('before-consumed-nonce-test')
            prepare_body={'operation':'renew','request_id':'native-consumed-nonce-20260913-a','parameters':{'requested_lease_seconds':3600}}
            prepared=self.worker_call('consumed-nonce-action','/lifecycle/action',prepare_body)
            self.verify_prepared(prepared,prepare_body)
            negative=self.worker_call('consumed-nonce-envelope','/lifecycle/signed-request',
                {'action_id':prepared['action_id'],'nonce':nonce['nonce'],'nonce_expires_at':nonce['nonce_expires_at'],
                 'intent_hash':prepared['intent_hash']})
            self.verify(negative)
            assert time.time()<nonce['nonce_expires_at'], 'consumed-nonce test missed original deadline'
            rejected=self.request('consumed-nonce-rejection','POST','/app/service/renew',negative,expected=403)
            assert 'INVALID_NONCE' in json.dumps(rejected['body'])
            self.request('consumed-nonce-no-observation','GET',self.lookup(negative['action']),expected=404)
            assert self.state('after-consumed-nonce-test')['serial']==after['serial']
            assert self.request('original-history-after-negative','GET',self.lookup(action))['body']==result['body']
        return {'status':'passed','operation':'registration','owner_scope_negatives':6 if scopes else 0,
            'invalid_signature_and_evidence_negatives':3 if scopes else 0,
            'consumed_nonce_negative':scopes,'registration_id':result['body']['registration_id'],
            'transaction_id':result['confirmed_ccf_transaction_id']}

    def lifecycle(self, body):
        prepared=self.worker_call('prepared-action','/lifecycle/action',body)
        self.verify_prepared(prepared,body)
        nonce=self.nonce('nonce',prepared['action'])
        envelope=self.worker_call('signed-envelope','/lifecycle/signed-request',dict(nonce,action_id=prepared['action_id']))
        assert envelope['action']==prepared['action'] and all(envelope[k]==v for k,v in nonce.items())
        result=self.submit_success('operation',envelope)
        if body['operation']=='acme_challenge_create':
            assert result['body']['challenge_id']=='chal-'+self.verify(envelope)[:32]
        return {'status':'passed','operation':body['operation'],'result':result['body']}

    def conflict(self, original_result_path, original_envelope_path):
        original=json.loads(original_result_path.read_text())
        old=json.loads(original_envelope_path.read_text())
        action=json.loads((Path(self.worker['capture'])/'action.json').read_text())['action']
        assert all(action[k]==old['action'][k] for k in ('grant_id','request_id','audience','zone'))
        assert action['signer_spki_der']!=old['action']['signer_spki_der']
        assert action['parameters']['evidence_digest']!=old['action']['parameters']['evidence_digest']
        registration=self.request('original-registration-terminal','GET','/app/service/registration?'+urlencode({'registration_id':original['body']['registration_id']}))['body']
        assert registration['committed_status']=='withdrawn' and registration['status']=='withdrawn'
        assert registration['committed_contributions']==[] and registration['active_contributions']==[]
        before=self.state('before-conflict')
        prior=self.request('original-history-before-conflict','GET',self.lookup(action))
        assert prior['body']==original['body']
        nonce=self.nonce('conflict-nonce',action)
        envelope=self.worker_call('conflict-envelope','/signed-request',nonce)
        assert envelope['action']==action and all(envelope[k]==v for k,v in nonce.items())
        digest=self.verify(envelope)
        response=self.request('conflict-rejection','POST','/app/service/register',envelope,expected=409)
        assert 'REQUEST_ID_CONFLICT' in json.dumps(response['body'])
        historical=self.request('original-history-after-conflict','GET',self.lookup(action))
        assert historical['body']==original['body'] and historical['confirmed_ccf_transaction_id']==original['confirmed_ccf_transaction_id']
        assert self.state('after-conflict')['serial']==before['serial']
        return {'status':'passed','http_status':409,'operation':'native_changed_key_registration_conflict',
            'original_transaction_id':historical['confirmed_ccf_transaction_id'],'signed_message_digest':digest,
            'new_key_signature_verified':True,'original_result_unchanged':True,'zone_serial_unchanged':True}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--context',type=Path,required=True); parser.add_argument('--worker',choices=('a','b'),required=True)
    parser.add_argument('--out',type=Path,required=True); parser.add_argument('--mode',choices=('register','lifecycle','conflict'),required=True)
    parser.add_argument('--scope-negatives',action='store_true'); parser.add_argument('--body',type=Path)
    parser.add_argument('--original-result',type=Path); parser.add_argument('--original-envelope',type=Path)
    args=parser.parse_args(); run=Run(args.context,args.worker,args.out)
    try:
        if args.mode=='register':result=run.registration(args.scope_negatives)
        elif args.mode=='lifecycle':result=run.lifecycle(json.loads(args.body.read_text()))
        else:result=run.conflict(args.original_result,args.original_envelope)
        run.save('summary',result); print(json.dumps(result))
    except Exception as error:
        run.save('failure',{'status':'failed','exception_type':type(error).__name__,'message':str(error)})
        raise


if __name__=='__main__':main()
