"""Generated control and runtime names must follow one selected registry."""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_aci_template
import build_images
import domain_registry
import prepare_aci_control
import release_authority

TOOLS = Path(__file__).resolve().parents[1]


class DomainConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        registry = json.loads(domain_registry.registry_path().read_text())
        registry['domain'] = 'alternate.invalid'
        registry['naming'].update({
            'ccf_rpc_hostname': 'ccf.alternate.invalid',
            'validation_domain': 'suite.invalid',
            'capture_tls_hostname': 'capture.alternate.invalid',
            'transfer_key_name': 'transfer.suite.invalid.',
            'secondary_registry': 'images.alternate.invalid',
            'caa_primary_domain': 'ca.alternate.invalid',
        })
        self.registry = self.root/'topology.json'
        self.registry.write_text(json.dumps(registry))
        self.environment = mock.patch.dict(os.environ, {'AH_DOMAIN_REGISTRY': str(self.registry)})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def prepare(self):
        control = self.root/'control'
        with mock.patch.object(sys, 'argv', ['prepare_aci_control.py', str(control),
                '--constitution-sha256', 'ab'*32, '--native-snp']), contextlib.redirect_stdout(io.StringIO()):
            prepare_aci_control.main()
        return control

    def test_one_registry_drives_pinned_ccf_and_transfer_configuration(self):
        control = self.prepare()
        public, summary, _, provision = build_aci_template.validated_control(control)
        node = json.loads(public['node.json'])
        self.assertEqual(node['network']['rpc_interfaces']['primary_rpc_interface']['published_address'],
                         'ccf.alternate.invalid:8000')
        self.assertIn('dNSName:ccf.alternate.invalid', node['node_certificate']['subject_alt_names'])
        self.assertEqual(json.loads(provision)['zones'], ['suite.invalid.'])
        self.assertEqual(json.loads(provision)['key_name'], 'transfer.suite.invalid.')
        self.assertEqual(public['domain-registry.json'], self.registry.read_bytes())
        digest = hashlib.sha256(self.registry.read_bytes()).hexdigest()
        self.assertEqual(summary['domain_registry_sha256'], digest)
        self.assertEqual(json.loads(public['manifest.json'])['/config/domain-registry.json'], digest)
        self.registry.write_text(self.registry.read_text() + '\n')
        with self.assertRaisesRegex(ValueError, 'domain registry differs'):
            build_aci_template.validated_control(control)

    def test_runtime_secondary_and_acceptance_names_follow_same_registry(self):
        script = '''import json,base64
import secondary_aci, secondary_vm, validation_names, capture_aci
print(json.dumps({
  "bind":secondary_aci.configuration(base64.b64encode(bytes(32)).decode(),"/run/test","/tmp/test"),
  "vm":secondary_vm.configuration("192.0.2.1"), "registry":secondary_vm.REGISTRY,
  "capture_tls":capture_aci.TLS_SERVER_NAME,
  "zone":validation_names.VALIDATION_ZONE,"nameserver":validation_names.VALIDATION_NS_HOSTNAME,
  "audience":validation_names.CCF_AUDIENCE,"caa_issuer":validation_names.CAA_ISSUER}))'''
        result = subprocess.run([sys.executable, '-B', '-c', script], cwd=TOOLS,
                                check=True, capture_output=True, text=True, timeout=15)
        names = json.loads(result.stdout)
        self.assertIn('zone "suite.invalid"', names['bind'])
        self.assertIn('file "suite.invalid.zone"', names['bind'])
        self.assertIn('key "transfer.suite.invalid."', names['bind'])
        self.assertIn('zone "suite.invalid"', names['vm'])
        self.assertEqual(names['registry'], 'images.alternate.invalid')
        self.assertEqual(names['capture_tls'], 'capture.alternate.invalid')
        self.assertEqual(names['zone'], 'suite.invalid.')
        self.assertEqual(names['nameserver'], 'ns.suite.invalid')
        self.assertEqual(names['audience'], 'ccf://ccf.alternate.invalid')
        self.assertEqual(names['caa_issuer'], 'ca.alternate.invalid')

    def test_image_builder_supplies_same_snapshot_and_records_digest(self):
        calls = []
        def docker(command, **kwargs):
            calls.append(command)
            if command[1] == 'build':
                context = command[command.index('--build-context')+1].split('=', 1)[1]
                self.assertEqual((Path(context)/'topology.json').read_bytes(), self.registry.read_bytes())
                self.assertTrue((Path(context)/'topology.json.provenance.json').is_file())
                return subprocess.CompletedProcess(command, 0)
            return subprocess.CompletedProcess(command, 0, 'sha256:'+'ab'*32+'\n')
        proof = self.root/'build.json'
        with mock.patch.object(sys, 'argv', ['build_images.py', 'secondary', '--tag', 'test:local',
                '--provenance', str(proof)]), mock.patch.object(build_images.subprocess, 'run', side_effect=docker), contextlib.redirect_stdout(io.StringIO()):
            build_images.main()
        self.assertEqual(len(calls), 2)
        self.assertEqual(json.loads(proof.read_text())['domain_registry']['sha256'],
                         hashlib.sha256(self.registry.read_bytes()).hexdigest())

    def test_authority_mint_uses_registry_but_existing_certificate_keeps_identity(self):
        cert = self.root/'authority.pem'
        minted = release_authority.mint_d(self.root/'authority.key', cert)
        self.assertTrue(minted['did'].endswith('::subject:CN:alternate.invalid-release-authority'))
        registry = json.loads(self.registry.read_text())
        registry['domain'] = 'changed.invalid'
        self.registry.write_text(json.dumps(registry))
        self.assertEqual(release_authority.get_did(cert), minted['did'])


if __name__ == '__main__':
    unittest.main()
