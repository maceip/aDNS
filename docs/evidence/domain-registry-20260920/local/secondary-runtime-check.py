"""Run inside the built secondary image, with no source or registry bind mount."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, '/app')
import secondary_aci
from domain_registry import registry_sha256

assert secondary_aci.ZONE == 'alternate.test'
assert secondary_aci.KEY_NAME == 'transfer.alternate.test.'
with tempfile.TemporaryDirectory() as temporary:
    path = Path(temporary) / 'named.conf'
    # Public test-only bytes, not a deployed TSIG key. Never print the config.
    path.write_text(secondary_aci.configuration(base64.b64encode(bytes(32)).decode(), temporary, temporary))
    path.chmod(0o600)
    subprocess.run(['named-checkconf', str(path)], check=True, capture_output=True)

print(json.dumps({
    'zone': secondary_aci.ZONE,
    'key_name': secondary_aci.KEY_NAME,
    'named_checkconf': 'passed',
    'registry_sha256': registry_sha256(),
    'image_files_sha256': {name: hashlib.sha256(Path(name).read_bytes()).hexdigest()
        for name in ['/app/secondary_aci.py', '/app/domain_registry.py']},
}, indent=2))
