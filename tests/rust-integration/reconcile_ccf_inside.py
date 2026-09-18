#!/usr/bin/env python3
"""Exercise durable request observations on one reserved local CCF fixture.

This runs after the idle window. It governs one fresh operator key, keeps that
key only in memory, and writes only public signed requests and responses.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import time
import uuid

def validate_observation_identity(response):
    """Every explicit observation field must bind the confirmed transaction."""
    confirmed = response.get('confirmed_ccf_transaction_id')
    if (not isinstance(confirmed, str)
            or re.fullmatch(r'(?:0|[1-9][0-9]{0,19})\.(?:0|[1-9][0-9]{0,19})', confirmed) is None
            or any(int(part) >= 2**64 for part in confirmed.split('.'))):
        raise ValueError('missing canonical confirmed observation transaction')
    body, headers = response.get('body', {}), response.get('headers', {})
    if (not isinstance(body, dict) or not isinstance(headers, dict)
            or headers.get('x-agentdns-commit-status') != 'committed'
            or headers.get('x-agentdns-transaction-id') != confirmed
            or body.get('observation_status') != 'committed'
            or body.get('observation_tx_id') != confirmed
            or body.get('tx_id') != confirmed):
        raise ValueError('observation body and header do not bind the confirmed transaction')


def main():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    sys.path.insert(0, '/src/tools')
    sys.path.insert(0, '/src/ccf/tests')
    from ccf_control import Client, Governance
    from operator_mail import b64, canonical, sign
    root = Path('/work')
    out = root/'results/reconciliation'
    out.mkdir(mode=0o700, exist_ok=False)
    client = Client('https://127.0.0.1:8000', None, root/'results/service_cert.pem')
    governor = Governance(client, root/'control/private/member0_privk.pem', root/'control/public/member0_cert.pem')

    def save(name, value):
        (out/(name+'.json')).write_text(json.dumps(value, indent=2)+'\n')
        return value

    history = []
    original_request = client.request

    def recorded_request(method, path, *args, **kwargs):
        response = original_request(method, path, *args, **kwargs)
        history.append({'method':method, 'path':path, 'response':copy.deepcopy(response)})
        save('http-history', history)
        return response

    client.request = recorded_request

    def request(name, method, path, body=None, *, status=200):
        response = save(name, client.request(method, path, body))
        if response['http_status'] != status:
            raise ValueError(f'{name}: expected HTTP {status}; actual response retained')
        if 200 <= status < 300:
            if response['headers'].get('x-agentdns-commit-status') != 'committed':
                raise ValueError(name+': missing global commitment')
            response = client.require_committed(response)
            save(name, response)
        return response

    def govern(name, grant):
        result = governor.propose([{'name':'adns_set_owner_grant', 'args':{'grant':grant}}])
        return save(name, result)

    key = ec.generate_private_key(ec.SECP256R1())
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    now = int(time.time())
    grant_id = 'reconcile-'+uuid.uuid4().hex[:16]
    grant = {'grant_id':grant_id, 'subject_spki_sha256':hashlib.sha256(spki).hexdigest(),
        'zones':['example.test.'], 'mailbox_domains':[], 'service_hosts':[], 'roles':[],
        'address_cidrs':[], 'ports':[], 'allowed_operations':['operator_records'], 'acme_names':[],
        'operator_names':['reconcile.example.test.'], 'operator_record_types':['TXT'],
        'attested_names':[], 'attested_record_types':[],
        'max_lease_seconds':3600, 'max_challenge_lifetime_seconds':3600,
        'valid_from':now-60, 'valid_until':now+3600, 'revoked':False}
    save('grant', grant)
    govern('grant-created', grant)
    state = request('state-before', 'GET', '/app/zone/status?zone=example.test.')['body']['committed_state']
    # The preceding operator mutation signs a fresh zone. Avoid manufacturing a
    # stale-serial failure by attempting this sequence across a scheduled refresh.
    if state['earliest_rrsig_expiration']-time.time() < 390:
        raise ValueError('reconciliation requires at least 90 seconds before scheduled refresh')
    action = {'operation':'operator_records', 'request_id':uuid.uuid4().hex,
        'audience':'ccf://agentdns.test', 'grant_id':grant_id, 'zone':'example.test.',
        'signer_spki_der':b64(spki), 'parameters':{'expected_serial':state['serial'],
        'mutations':[{'action':'replace', 'name':'reconcile.example.test.', 'type':'TXT',
            'ttl':60, 'rdata_strings':['durable authenticated request reconciliation']} ]}}
    nonce = request('nonce', 'POST', '/app/service/nonce', {'action':action})['body']
    envelope = sign(key, {'action':action, 'nonce':nonce['nonce'],
        'nonce_expires_at':nonce['expires_at'], 'intent_hash':nonce['intent_hash']})
    save('signed-request', envelope)
    lookup = '/app/service/request?grant_id='+grant_id+'&request_id='+action['request_id']

    def observation(name, expected):
        response = request(name, 'GET', lookup)
        body = response['body']
        if body.get('status') != expected or body.get('execution_state') != expected:
            raise ValueError(name+': wrong execution observation')
        validate_observation_identity(response)
        if body.get('grant_id') != grant_id or body.get('request_id') != action['request_id']:
            raise ValueError(name+': observation scope mismatch')
        latest = body.get('latest_observation', {})
        if latest.get('nonce') != nonce['nonce'] or latest.get('intent_hash') != nonce['intent_hash']:
            raise ValueError(name+': observation does not bind the issued request')
        if body.get('matching_nonces') != 1 or body.get('multiple_nonce_ambiguity') is not False:
            raise ValueError(name+': unexpected nonce ambiguity')
        if body.get('retryable') is not True:
            raise ValueError(name+': missing retryable observation semantics')
        return response

    pending = observation('pending', 'pending')
    if pending['body'].get('phase') != 'awaiting_committed_result':
        raise ValueError('issued nonce was not reported as awaiting a result')
    revoked = copy.deepcopy(grant)
    revoked['revoked'] = True
    govern('grant-revoked', revoked)
    failed = request('failed-submit', 'POST', '/app/zone/operator/records', envelope, status=403)
    failure_body = failed['body']
    failure_txid = failed['headers'].get('x-agentdns-transaction-id')
    if (failed['headers'].get('x-agentdns-commit-status') != 'committed'
            or not isinstance(failure_txid, str)
            or re.fullmatch(r'(?:0|[1-9][0-9]{0,19})\.(?:0|[1-9][0-9]{0,19})', failure_txid) is None
            or any(int(part) >= 2**64 for part in failure_txid.split('.'))
            or failure_body.get('status') != 'failed' or failure_body.get('execution_state') != 'failed'
            or failure_body.get('observation_status') != 'committed'
            or failure_body.get('observation_tx_id') != failure_txid or failure_body.get('tx_id') != failure_txid):
        raise ValueError('failed response omitted exact globally committed failure observation metadata')
    # require_committed deliberately rejects 4xx responses. Confirm this
    # authenticated failure's transaction directly through the real CCF API.
    confirmation = save('failed-transaction', client.request('GET', '/node/tx?transaction_id='+failure_txid))
    if (confirmation['http_status'] != 200 or confirmation['body'].get('transaction_id') != failure_txid
            or confirmation['body'].get('status') != 'Committed'):
        raise ValueError('authenticated failed attempt transaction is not globally committed')
    failed_observation = observation('failed-observation', 'failed')
    latest = failed_observation['body']['latest_observation']
    signed_digest = hashlib.sha256(canonical({k:v for k,v in envelope.items() if k != 'client_signature'})).hexdigest()
    if latest.get('http_status') != 403 or latest.get('signed_message_digest') != signed_digest or not latest.get('error'):
        raise ValueError('authenticated failed request details were not persisted')
    before_retry = request('state-after-failure', 'GET', '/app/zone/status?zone=example.test.')['body']['committed_state']
    if before_retry['serial'] != state['serial']:
        raise ValueError('failed request altered the zone or the sequence crossed a refresh')
    govern('grant-restored', grant)
    result = request('committed-retry', 'POST', '/app/zone/operator/records', envelope)
    reconciled = request('committed-reconciliation', 'GET', lookup)
    duplicate = request('identical-retry', 'POST', '/app/zone/operator/records', envelope)
    for response in (reconciled, duplicate):
        if response['body'] != result['body'] or response['confirmed_ccf_transaction_id'] != result['confirmed_ccf_transaction_id']:
            raise ValueError('historical committed request result changed')
    if result['body']['zone_serial'] != (state['serial']+1) % 2**32:
        raise ValueError('restored exact request did not produce exactly one serial increment')
    save('expected-records', [['reconcile.example.test.', 'TXT', 'durable authenticated request reconciliation']])
    summary = {'status':'passed', 'scope':'real signed operator request; no native registration claim',
        'request_id':action['request_id'], 'grant_id':grant_id, 'pending_observation_committed':True,
        'authenticated_failure_durable':True, 'failure_http_status':failed['http_status'],
        'same_nonce_and_envelope_retry_succeeded':True, 'historical_result_precedes_observation':True,
        'identical_retry_preserves_original_result':True, 'zone_serial_increment':1,
        'committed_transaction_id':result['confirmed_ccf_transaction_id'], 'zone_serial':result['body']['zone_serial']}
    save('summary', summary)
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
