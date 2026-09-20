#!/usr/bin/env python3
"""Build an aDNS runtime image with a snapshot of the common domain registry.

Reads the selected local registry (or one previously fetched at the declared
revision), records its digest and supplies a temporary BuildKit named context.
This builds locally; it does not push an image or deploy infrastructure.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from domain_registry import snapshot

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = {'primary': 'containers/agentdns-ccf.Dockerfile',
               'secondary': 'containers/secondary.Dockerfile',
               'capture': 'containers/capture.Dockerfile'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', choices=DOCKERFILES)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--provenance', type=Path, required=True)
    args = parser.parse_args()
    if args.tag.startswith('-') or any(char.isspace() for char in args.tag):
        parser.error('image tag must be a single Docker image reference')
    with tempfile.TemporaryDirectory(prefix='adns-domain-build-') as temporary:
        metadata = snapshot(Path(temporary)/'topology.json')
        command = ['docker', 'build', '--platform', 'linux/amd64',
                   '--build-context', 'domain-registry='+temporary,
                   '-f', str(ROOT/DOCKERFILES[args.image]), '-t', args.tag, str(ROOT)]
        subprocess.run(command, check=True, timeout=3600)
        image = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', args.tag],
                               check=True, capture_output=True, text=True, timeout=30).stdout.strip()
        result = {'image': args.tag, 'image_id': image, 'domain_registry': metadata,
                  'dockerfile': DOCKERFILES[args.image],
                  'dockerfile_sha256': hashlib.sha256((ROOT/DOCKERFILES[args.image]).read_bytes()).hexdigest()}
        args.provenance.parent.mkdir(parents=True, exist_ok=True)
        args.provenance.write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
