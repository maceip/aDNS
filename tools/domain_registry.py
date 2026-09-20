#!/usr/bin/env python3
"""Read names from the shared hosting topology; never supply local DNS defaults.

This dependency-free reader is identical in the three repositories. The data
has one owner: agent-hosting/infra/production/topology.json. fetch explicitly
retrieves a versioned snapshot; ordinary reads never access the network.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
INSTALLED = Path('/etc/agent-hosting/domain-registry.json')
TOKEN = re.compile(r'\$\{([a-z][a-z0-9_]*)\}')
NAME = re.compile(r'[a-z][a-z0-9_]*')


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate registry field: ' + key)
        result[key] = value
    return result


def _read(path):
    raw = Path(path).read_bytes()
    if not 0 < len(raw) <= 65536:
        raise ValueError('domain registry must be a nonempty file no larger than 64KiB')
    return raw, json.loads(raw, object_pairs_hook=_object)


def registry_path(path=None):
    explicit = path if path is not None else os.environ.get('AH_DOMAIN_REGISTRY')
    if explicit is not None:
        if not str(explicit).strip() or not Path(explicit).is_file():
            raise ValueError('AH_DOMAIN_REGISTRY must name an existing registry file')
        return Path(explicit).resolve()
    candidates = [ROOT / 'infra/production/topology.json',
                  ROOT.parent / 'agent-hosting/infra/production/topology.json',
                  Path(__file__).resolve().with_name('domain-registry.json'),
                  INSTALLED, ROOT / '.domain-registry/topology.json']
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise ValueError('No common domain registry. Set AH_DOMAIN_REGISTRY or run tools/domain_registry.py fetch')


def resolve_registry(data):
    if not isinstance(data, dict) or type(data.get('schema_version')) is not int or data['schema_version'] != 1:
        raise ValueError('unsupported domain registry schema')
    domain = data.get('domain')
    if not isinstance(domain, str) or len(domain) > 253 or '.' not in domain or not all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
            for part in domain.split('.')):
        raise ValueError('invalid domain registry apex')
    naming = data.get('naming')
    if not isinstance(naming, dict) or not naming:
        raise ValueError('domain registry is missing its naming contract; fetch the coordinated registry revision')
    values = {'domain': domain, 'zone': domain + '.'}
    services = data.get('services', {})
    if not isinstance(services, dict):
        raise ValueError('invalid registry services')
    for role, service in services.items():
        if not NAME.fullmatch(role) or not isinstance(service, dict):
            raise ValueError('invalid registry service')
        label = service.get('label')
        if label != '@' and (not isinstance(label, str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)):
            raise ValueError('invalid registry service label')
        values['service_' + role + '_host'] = domain if label == '@' else label + '.' + domain
    for key, value in naming.items():
        if not isinstance(key, str) or not NAME.fullmatch(key) or key in values:
            raise ValueError('invalid or reserved registry naming key')
        if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('registry values must be bounded nonempty strings without control characters')
        values[key] = value
    resolved = {}

    def expand(key, chain=()):
        if key in resolved:
            return resolved[key]
        if key not in values or key in chain or len(chain) > 32:
            raise ValueError('missing or cyclic domain registry reference: ' + key)
        value = TOKEN.sub(lambda match: expand(match[1], chain + (key,)), values[key])
        if '${' in value or len(value) > 4096:
            raise ValueError('invalid domain registry expansion: ' + key)
        resolved[key] = value
        return value

    for key in values:
        expand(key)
    def dns(value, trailing=False):
        if trailing:
            if not value.endswith('.'):
                return False
            value = value[:-1]
        return len(value) <= 253 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.'))
    for key, value in resolved.items():
        if key == 'zone' or key.endswith('_zone') or key == 'transfer_key_name':
            valid = dns(value, trailing=True)
        elif key == 'domain' or key.endswith(('_domain', '_host', '_hostname', '_registry')):
            valid = dns(value)
        elif key.endswith(('_address', '_email')):
            local, separator, host = value.rpartition('@')
            valid = bool(separator and re.fullmatch(r'[A-Za-z0-9.!#$%&*+/=?^_`{|}~-]+', local) and dns(host))
        elif key.endswith(('_url', '_audience')):
            parsed = urlsplit(value)
            valid = bool(parsed.scheme in {'https', 'ccf', 'aamp'} and parsed.hostname and dns(parsed.hostname) and not parsed.username and not parsed.password and not parsed.fragment)
            try:
                parsed.port
            except ValueError:
                valid = False
        elif key == 'release_authority_common_name':
            valid = bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._ -]{0,127}', value))
        else:
            valid = True
        if not valid:
            raise ValueError('invalid resolved domain registry value: ' + key)
    pairs = [('mail_host', 'service_mail_host'), ('operator_host', 'service_operator_host'),
             ('website_host', 'service_apex_host'), ('www_host', 'service_www_host')]
    for left, right in pairs:
        if left in resolved and right in resolved and resolved[left] != resolved[right]:
            raise ValueError('domain registry service alias mismatch: ' + left)
    for zone, domain in [('validation_zone', 'validation_domain'), ('native_relay_zone', 'native_relay_domain')]:
        if zone in resolved and domain in resolved and resolved[zone] != resolved[domain] + '.':
            raise ValueError('domain registry zone mismatch: ' + zone)
    if 'worker_label' in resolved and 'worker_host' in resolved and resolved['worker_host'] != resolved['worker_label'] + '.' + resolved['domain']:
        raise ValueError('domain registry worker label and hostname mismatch')
    if 'ccf_rpc_url' in resolved and 'ccf_rpc_hostname' in resolved and urlsplit(resolved['ccf_rpc_url']).hostname != resolved['ccf_rpc_hostname']:
        raise ValueError('domain registry CCF URL and TLS hostname mismatch')
    return resolved


def load_registry(path=None):
    return resolve_registry(_read(registry_path(path))[1])


def get(key, path=None):
    values = load_registry(path)
    if key not in values:
        raise ValueError('missing common domain registry key: ' + key)
    return values[key]


def registry_sha256(path=None):
    return hashlib.sha256(_read(registry_path(path))[0]).hexdigest()


def _write(path, raw):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(raw)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def snapshot(output, path=None):
    source = registry_path(path)
    raw, data = _read(source)
    resolve_registry(data)
    metadata = {'schema_version': 1, 'source': str(source),
                'sha256': hashlib.sha256(raw).hexdigest()}
    provenance = Path(str(source) + '.provenance.json')
    if provenance.is_file():
        provenance_raw, previous = _read(provenance)
        if previous.get('sha256') != metadata['sha256']:
            raise ValueError('domain registry source provenance hash mismatch')
        for key in ('repository', 'commit', 'path', 'requested_ref'):
            if key in previous:
                metadata[key] = previous[key]
        metadata['source_provenance_sha256'] = hashlib.sha256(provenance_raw).hexdigest()
    _write(output, raw)
    _write(str(output) + '.provenance.json', (json.dumps(metadata, indent=2) + '\n').encode())
    return metadata


def fetch_registry(output=None, ref=None, repository=None):
    _, locator = _read(ROOT / 'domain-registry.source.json')
    repository = repository or os.environ.get('AH_DOMAIN_REGISTRY_REPOSITORY') or locator['repository']
    ref = ref or os.environ.get('AH_DOMAIN_REGISTRY_REF') or locator['ref']
    source_path = locator['path']
    if not isinstance(ref, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./-]{0,199}', ref):
        raise ValueError('invalid domain registry source revision')
    if not isinstance(source_path, str) or source_path.startswith('/') or '..' in Path(source_path).parts:
        raise ValueError('invalid domain registry source path')
    with tempfile.TemporaryDirectory(prefix='domain-registry-') as temporary:
        def git(*args):
            return subprocess.run(['git', '-C', temporary, *args], check=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120).stdout
        git('init', '--quiet')
        git('remote', 'add', 'origin', repository)
        git('fetch', '--quiet', '--depth=1', 'origin', ref)
        commit = git('rev-parse', 'FETCH_HEAD').decode().strip()
        raw = git('show', 'FETCH_HEAD:' + source_path)
    if len(raw) > 65536:
        raise ValueError('fetched domain registry exceeds 64KiB')
    resolve_registry(json.loads(raw, object_pairs_hook=_object))
    output = Path(output) if output else ROOT / '.domain-registry/topology.json'
    metadata = {'schema_version': 1, 'repository': repository, 'requested_ref': ref,
                'commit': commit, 'path': source_path, 'sha256': hashlib.sha256(raw).hexdigest(),
                'fetched_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    _write(output, raw)
    _write(str(output) + '.provenance.json', (json.dumps(metadata, indent=2) + '\n').encode())
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registry', help='explicit common registry file')
    subs = parser.add_subparsers(dest='command', required=True)
    one = subs.add_parser('get'); one.add_argument('key')
    subs.add_parser('json')
    env = subs.add_parser('env'); env.add_argument('keys', nargs='*'); env.add_argument('--prefix', default='')
    copy = subs.add_parser('snapshot'); copy.add_argument('output')
    fetch = subs.add_parser('fetch'); fetch.add_argument('--output'); fetch.add_argument('--ref'); fetch.add_argument('--repository')
    args = parser.parse_args()
    try:
        if args.command == 'fetch':
            print(json.dumps(fetch_registry(args.output, args.ref, args.repository), indent=2))
        elif args.command == 'snapshot':
            print(json.dumps(snapshot(args.output, args.registry), indent=2))
        elif args.command == 'get':
            print(get(args.key, args.registry))
        elif args.command == 'env':
            if not re.fullmatch(r'[A-Z_]*', args.prefix):
                raise ValueError('invalid environment prefix')
            values = load_registry(args.registry)
            for key in args.keys or sorted(values):
                print(args.prefix + key.upper() + '=' + shlex.quote(values[key]))
        else:
            print(json.dumps(load_registry(args.registry), indent=2))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Domain registry unavailable or invalid: ' + (str(error) if not isinstance(error, subprocess.SubprocessError) else 'source fetch failed') + '\n')


if __name__ == '__main__':
    main()
