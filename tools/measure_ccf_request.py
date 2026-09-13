#!/usr/bin/env python3
"""Measure an already authorized signed request through real CCF commitment.

No keys or new signatures are created. This submits exactly the supplied
request envelope once, then verifies its globally committed historical result.
"""
import argparse
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import time
from urllib.parse import urlencode, urlsplit

from http_limits import SocketDeadline, read_bounded

ROUTES = {
    'register': ('POST', '/app/service/register'),
    'renew': ('POST', '/app/service/renew'),
    'deregister': ('POST', '/app/service/deregister'),
    'acme_challenge_create': ('POST', '/app/zone/acme-challenge'),
    'acme_challenge_delete': ('DELETE', '/app/zone/acme-challenge'),
}
MAX_BYTES = 2 * 1024 * 1024
REQUEST_SECONDS = 30


def strict_object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError('nonfinite JSON number')

    result = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
    if not isinstance(result, dict):
        raise ValueError('JSON object required')
    return result


def exchange(host, port, context, method, path, body=None, connect_ip=None):
    try:
        destination = str(ipaddress.ip_address(connect_ip if connect_ip is not None else host))
    except ValueError:
        raise ValueError('DNS-name URL requires a numeric --connect-ip override') from None
    connection = http.client.HTTPConnection(host, port, timeout=REQUEST_SECONDS)
    started = time.perf_counter_ns()
    deadline = time.monotonic() + REQUEST_SECONDS
    raw_socket = None
    try:
        raw_socket = socket.create_connection((destination, port), timeout=REQUEST_SECONDS)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('CCF connection deadline exceeded')
        raw_socket.settimeout(remaining)
        connection.sock = context.wrap_socket(raw_socket, server_hostname=host)
        with SocketDeadline(connection.sock, deadline):
            connection.request(method, path, body=body, headers={'Content-Type': 'application/json'})
            response = connection.getresponse()
            raw = read_bounded(response, MAX_BYTES, deadline)
            headers = {}
            for key, value in response.getheaders():
                key = key.lower()
                if key in headers and key in ('x-agentdns-transaction-id', 'x-agentdns-commit-status', 'x-ms-ccf-transaction-id'):
                    raise ValueError('duplicate CCF commitment header')
                headers[key] = value
        elapsed_ms = (time.perf_counter_ns() - started) / 1e6
        return response.status, headers, strict_object(raw), elapsed_ms
    finally:
        connection.close()
        if raw_socket is not None:
            raw_socket.close()


def canonical_txid(value):
    return isinstance(value, str) and re.fullmatch(r'(?:0|[1-9][0-9]{0,19})\.(?:0|[1-9][0-9]{0,19})', value) is not None and all(int(n) < 2**64 for n in value.split('.'))


def committed(status, headers, result):
    if status != 200 or not isinstance(result, dict) or headers.get('x-agentdns-commit-status') != 'committed' or result.get('status') != 'committed':
        raise ValueError('request did not return a globally committed successful result')
    txid = headers.get('x-agentdns-transaction-id')
    if not canonical_txid(txid) or result.get('tx_id') != txid:
        raise ValueError('CCF transaction identity is missing or inconsistent')
    # A historical result retains its original application ID. CCF may attach
    # a newer read transaction in its framework header, so equality is wrong.
    if 'x-ms-ccf-transaction-id' in headers and not canonical_txid(headers['x-ms-ccf-transaction-id']):
        raise ValueError('CCF framework transaction identity is malformed')
    return txid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--connect-ip', type=ipaddress.ip_address, help='numeric destination; --url retains authenticated TLS name and HTTP Host')
    parser.add_argument('--cacert', required=True)
    parser.add_argument('--envelope', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    url = urlsplit(args.url)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
        parser.error('URL must be a verified HTTPS origin')
    with args.envelope.open('rb') as source:
        raw = source.read(MAX_BYTES + 1)
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError('signed envelope size is invalid')
    request = strict_object(raw)
    action = request['action']
    if not isinstance(action, dict) or action.get('operation') not in ROUTES or not all(isinstance(action.get(field), str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', action[field]) for field in ('grant_id', 'request_id')):
        raise ValueError('invalid signed action identity or operation')
    method, path = ROUTES[action['operation']]
    context = ssl.create_default_context(cafile=args.cacert)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(['http/1.1'])
    measured_at = time.time()
    status, headers, result, latency = exchange(url.hostname, url.port or 443, context, method, path, raw, connect_ip=args.connect_ip)
    txid = committed(status, headers, result)
    query = urlencode({'grant_id': action['grant_id'], 'request_id': action['request_id']})
    reconcile_status, reconcile_headers, reconciled, reconcile_latency = exchange(url.hostname, url.port or 443, context, 'GET', '/app/service/request?' + query, connect_ip=args.connect_ip)
    if committed(reconcile_status, reconcile_headers, reconciled) != txid or reconciled != result:
        raise ValueError('historical request reconciliation does not match the committed result')
    output = {'source': 'actual-CCF-globally-committed-request', 'operation': action['operation'],
              'request_id': action['request_id'], 'transaction_id': txid, 'measured_at_unix_seconds': measured_at,
              'signed_envelope_sha256': hashlib.sha256(raw).hexdigest(),
              'submission_to_global_commit_ms_including_tls': latency,
              'historical_reconciliation_ms_including_tls': reconcile_latency,
              'historical_result_exactly_matches': True,
              'committed_result': result,
              'samples': 1, 'signing_duration_inferred_from_request_time': False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()
