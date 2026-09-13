"""Configuration boundary tests; live CCF transfer requires separate Azure proof."""
import base64
import importlib.util
from pathlib import Path
import tempfile
import subprocess
import unittest

spec=importlib.util.spec_from_file_location('secondary_aci',Path(__file__).resolve().parents[1]/'secondary_aci.py')
secondary=importlib.util.module_from_spec(spec);spec.loader.exec_module(secondary)

class SecondaryTests(unittest.TestCase):
    def test_secret_rejects_malformed_noncanonical_or_injected_values(self):
        good=base64.b64encode(bytes(range(32))).decode()
        self.assertEqual(secondary.decode_secret(good),good)
        for bad in [None,'',good+'\n',good[:-1],good[:-2]+'B=',base64.b64encode(bytes(31)).decode(),'"; include "/etc/passwd";']:
            with self.assertRaises(ValueError):secondary.decode_secret(bad)

    def test_fixed_authoritative_scope_and_no_zone_signer(self):
        conf=secondary.configuration(base64.b64encode(bytes(32)).decode(),'/tmp/runtime','/tmp/zone')
        self.assertIn('primaries { 127.0.0.1 port 5353 key "agentdns-transfer."; };',conf)
        self.assertIn('type secondary;',conf)
        self.assertIn('recursion no;',conf)
        self.assertIn('allow-transfer { none; };',conf)
        self.assertIn('allow-notify { key "agentdns-transfer."; };',conf)
        self.assertNotIn('inline-signing',conf)
        self.assertNotIn('dnssec-policy',conf)
        with tempfile.TemporaryDirectory() as directory:
            conf=secondary.configuration(base64.b64encode(bytes(32)).decode(),directory,directory)
            path=Path(directory)/'named.conf';path.write_text(conf)
            result=subprocess.run(['named-checkconf',str(path)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

if __name__=='__main__':unittest.main()
