#!/usr/bin/env python3
"""Govern/provision/revoke only the isolated runner's reserved TSIG identities."""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import TRANSFER_KEY_NAME, VALIDATION_DOMAIN
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sys
import time

OLD = (TRANSFER_KEY_NAME)
NEW = 'agentdns-transfer-replacement.'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('create', 'provision', 'revoke', 'work'))
    args = parser.parse_args()
    root = Path('/work')
    out = root/'results/rotation'
    out.mkdir(mode=0o700, exist_ok=True)
    private = root/'control/private'
    certificate = root/'results/service_cert.pem'

    def save(name, value):
        (out/(name+'.json')).write_text(json.dumps(value, indent=2)+'\n')
        return value

    if args.phase == 'provision':
        spec = importlib.util.spec_from_file_location('supervisor', '/opt/agentdns/run.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        exchanges = []
        original_exchange = module.bounded_http

        def recorded_exchange(*arguments, **kwargs):
            status, headers, raw = original_exchange(*arguments, **kwargs)
            try:
                body = json.loads(raw)
            except (ValueError, UnicodeError):
                body = {'non_json_sha256':hashlib.sha256(raw).hexdigest()}
            exchanges.append({'http_status':status, 'headers':headers, 'body':body})
            save('provision-http', exchanges)
            return status, headers, raw

        module.bounded_http = recorded_exchange
        body = module.load_transfer_secret(private/'replacement-transfer-key.json')
        deadline = time.monotonic()+45
        while not module.provision_transfer_secret('127.0.0.1:8001', certificate, body):
            if time.monotonic() >= deadline:
                raise TimeoutError('replacement transfer secret did not commit')
            time.sleep(0.2)
        if not module.provision_transfer_secret('127.0.0.1:8001', certificate, body):
            raise ValueError('replacement provisioning exact retry failed')
        save('provisioned', {'key_name':NEW, 'globally_committed':True, 'identical_retry_confirmed':True})
        return

    sys.path.insert(0, '/src/tools')
    from ccf_control import Client, Governance
    client = Client('https://127.0.0.1:8000', None, certificate)
    if args.phase == 'work':
        internal = Client('https://127.0.0.1:8001', None, certificate)
        responses = []
        confirmations = []
        original_public_request = client.request

        def public_confirmation(method, path, *arguments, **kwargs):
            response = original_public_request(method, path, *arguments, **kwargs)
            confirmations.append({'method':method, 'path':path, 'response':copy.deepcopy(response)})
            save('work-commit-confirmations', confirmations)
            return response

        client.request = public_confirmation
        for _ in range(3):
            response = internal.request('POST', '/app/internal/secondary/requests', {})
            responses.append(response)
            save('issued-work', responses)
            if response['http_status'] != 200 or response['headers'].get('x-agentdns-commit-status') != 'committed':
                raise ValueError('secondary work lacked confirmed commitment')
            # /node/tx belongs to the public interface; the restricted internal
            # listener exposes only the host protocol. Confirm the exact body
            # and header transaction through the same CA-pinned public node.
            client.require_committed(response)
            save('issued-work', responses)
            time.sleep(1)
        return

    history = []
    original_request = client.request

    def recorded_request(method, path, *arguments, **kwargs):
        response = original_request(method, path, *arguments, **kwargs)
        history.append({'method':method, 'path':path, 'response':copy.deepcopy(response)})
        save('governance-http-'+args.phase, history)
        return response

    client.request = recorded_request
    governor = Governance(client, private/'member0_privk.pem', root/'control/public/member0_cert.pem')
    if args.phase == 'create':
        secret = secrets.token_bytes(32)
        encoded = base64.b64encode(secret)
        provision = {'key_name':NEW, 'secret_base64url':base64.urlsafe_b64encode(secret).rstrip(b'=').decode(),
                     'zones':[(VALIDATION_DOMAIN + '.')]}
        for name, data in [('replacement-transfer-key.b64', encoded+b'\n'),
                           ('replacement-transfer-key.json', json.dumps(provision).encode()+b'\n')]:
            descriptor = os.open(private/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(data)
        arguments = {'key_name':NEW, 'endpoint':'127.0.0.1:1053', 'zones':[(VALIDATION_DOMAIN + '.')],
                     'secret_sha256':hashlib.sha256(secret).hexdigest()}
        save('configuration', arguments)
        result = governor.propose([{'name':'adns_set_transfer', 'args':arguments}])
        save('governed', result)
    else:
        for label in ('revoked', 'revoked-identical-retry'):
            result = governor.propose([{'name':'adns_revoke_transfer', 'args':{'key_name':OLD}}])
            save(label, result)
        save('revocation-summary', {'key_name':OLD, 'globally_committed':True,
            'idempotent_repeat_accepted':True, 'replacement_key_name':NEW,
            'scope':'replacement authenticated AXFR; no replacement BIND frontend is claimed'})


if __name__ == '__main__':
    main()
