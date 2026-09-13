"""Regressions for confcom's first-image-of-archive mapping hazard."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import check_aci_template as preflight


def archive_fixture(path, *, combined=False, damage=False):
    files={}
    def blob(value):
        raw=json.dumps(value,separators=(',',':')).encode() if isinstance(value,dict) else value
        digest=hashlib.sha256(raw).hexdigest();name='blobs/sha256/'+digest;files[name]=raw
        return {'digest':'sha256:'+digest,'size':len(raw)}
    layer=blob(b'layer bytes for fixture')
    config=blob({'architecture':'amd64','os':'linux'})
    manifest=blob({'schemaVersion':2,'config':config,'layers':[layer]})
    descriptor={**manifest,'platform':{'architecture':'amd64','os':'linux'}}
    index=blob({'schemaVersion':2,'manifests':[descriptor]})
    files['index.json']=json.dumps({'manifests':[index]}).encode()
    docker={'Config':'blobs/sha256/'+config['digest'][7:],'RepoTags':['example.azurecr.io/primary:test'],'Layers':['blobs/sha256/'+layer['digest'][7:]]}
    files['manifest.json']=json.dumps([docker,docker] if combined else [docker]).encode()
    if damage:files['blobs/sha256/'+layer['digest'][7:]]=b'X'*layer['size']
    with tarfile.open(path,'w') as archive:
        for name,raw in files.items():
            info=tarfile.TarInfo(name);info.size=len(raw);archive.addfile(info,io.BytesIO(raw))
    return 'example.azurecr.io/primary@'+manifest['digest']


class ArchivePreflightTests(unittest.TestCase):
    def test_native_readiness_acl_does_not_deny_probe_or_broaden_node_routes(self):
        def node(endpoints):
            return {'network': {'rpc_interfaces': {'agentdns-internal': {'accepted_endpoints': endpoints}}}}
        preflight.validate_native_internal_readiness(node(['/app/internal/.*', '/node/state']))
        for endpoints in (['/app/internal/.*'], ['/app/internal/.*', '/node/.*'], ['.*']):
            with self.assertRaisesRegex(ValueError, 'exact supervisor readiness'):
                preflight.validate_native_internal_readiness(node(endpoints))

    def test_aci_port_numbers_unique_across_protocols_and_containers(self):
        def properties(public, *containers):
            return {'ipAddress': {'ports': public}, 'containers': [
                {'properties': {'ports': ports}} for ports in containers]}
        tcp = {'port': 53, 'protocol': 'TCP'}
        udp = {'port': 53, 'protocol': 'UDP'}
        https = {'port': 8000, 'protocol': 'TCP'}
        transfer = {'port': 5353, 'protocol': 'TCP'}
        preflight.validate_ports(properties([https, udp, transfer], [https, transfer], [udp]))
        for value in (properties([tcp, udp], [udp]),
                      properties([udp], [tcp, udp]),
                      properties([udp], [tcp], [udp])):
            with self.assertRaisesRegex(ValueError, 'unique regardless of protocol'):
                preflight.validate_ports(value)
        with self.assertRaisesRegex(ValueError, 'also be declared'):
            preflight.validate_ports(properties([tcp], [udp]))

    def test_distinct_single_image_archive_and_actual_layer_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'primary.tar';image=archive_fixture(path)
            self.assertEqual(preflight.archive_image(path,image,'example.azurecr.io/primary:test')['layer_count'],1)
            archive_fixture(path,damage=True)
            with self.assertRaisesRegex(ValueError,'layer digest mismatch'):
                preflight.archive_image(path,image,'example.azurecr.io/primary:test')

    def test_combined_archive_and_wrong_platform_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'combined.tar';image=archive_fixture(path,combined=True)
            with self.assertRaisesRegex(ValueError,'single-image archive'):
                preflight.archive_image(path,image,'example.azurecr.io/primary:test')
            archive_fixture(path)
            with self.assertRaisesRegex(ValueError,'linux/amd64 manifest'):
                preflight.archive_image(path,'example.azurecr.io/primary@sha256:'+'00'*32,'example.azurecr.io/primary:test')

    def test_two_names_cannot_alias_one_archive_even_via_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            primary=Path(directory)/'primary.tar';secondary=Path(directory)/'secondary.tar'
            primary.write_bytes(b'x');secondary.hardlink_to(primary)
            mappings={'example.azurecr.io/primary:test':'/primary.tar','example.azurecr.io/secondary:test':'/secondary.tar'}
            with self.assertRaisesRegex(ValueError,'same archive file'):
                preflight.validate_archives({'primary':primary,'secondary':secondary},mappings)
            mappings['example.azurecr.io/secondary:test']='/primary.tar'
            with self.assertRaisesRegex(ValueError,'same archive'):
                preflight.validate_archives({'primary':primary,'secondary':secondary},mappings)

if __name__=='__main__':unittest.main()
