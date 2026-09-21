"""Regressions for confcom's first-image-of-archive mapping hazard."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import base64
import datetime
import copy
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import check_aci_template as preflight
import build_aci_template as builder


def archive_fixture(path, *, combined=False, damage=False, omit_platform=False, architecture="amd64"):
    files={}
    def blob(value):
        raw=json.dumps(value,separators=(',',':')).encode() if isinstance(value,dict) else value
        digest=hashlib.sha256(raw).hexdigest();name='blobs/sha256/'+digest;files[name]=raw
        return {'digest':'sha256:'+digest,'size':len(raw)}
    layer=blob(b'layer bytes for fixture')
    config=blob({'architecture':architecture,'os':'linux'})
    manifest=blob({'schemaVersion':2,'config':config,'layers':[layer]})
    descriptor={**manifest,'platform':{'architecture':'amd64','os':'linux'}}
    if omit_platform:descriptor.pop('platform')
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
    def test_optional_oci_descriptor_platform_uses_verified_image_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'primary.tar'
            image=archive_fixture(path,omit_platform=True)
            self.assertEqual(preflight.archive_image(path,image,'example.azurecr.io/primary:test')['layer_count'],1)
            image=archive_fixture(path,omit_platform=True,architecture='arm64')
            with self.assertRaisesRegex(ValueError,'linux/amd64 manifest'):
                preflight.archive_image(path,image,'example.azurecr.io/primary:test')

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


class TelemetryPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key=ec.generate_private_key(ec.SECP256R1());now=datetime.datetime.now(datetime.timezone.utc)
        subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'preflight OTLP CA fixture')])
        cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(322)
            .not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()))
        cls.ca=cert.public_bytes(serialization.Encoding.PEM)

    def fixture(self):
        labels=dict(zip(builder.OTEL_LABEL_KEYS,('native-validation','agentdns','fixture-run')))
        env=builder.otel_environment('https://20.166.33.141:4318',labels)
        template={'parameters':{'transferKeyB64':{'type':'secureString'},'transferKeyJson':{'type':'secureString'},
                               'otelExporterHeaders':{'type':'secureString'}}}
        primary={'environmentVariables':[{'name':k,'value':v}for k,v in env.items()]+
            [{'name':'OTEL_EXPORTER_OTLP_HEADERS','secureValue':"[parameters('otelExporterHeaders')]"}],
            'volumeMounts':[{'name':'otel-public-ca','mountPath':'/otel','readOnly':True}]}
        containers={'primary':primary,'secondary':{}}
        volumes={'otel-public-ca':{'name':'otel-public-ca','secret':{'exporter-ca.pem':base64.b64encode(self.ca).decode()}}}
        policy={'primary':{'env_rules':builder.otel_policy_rules(env),
            'mounts':[{'destination':'/otel','options':['rbind','rshared','ro'],'source':'sandbox:///tmp/atlas/secretsVolume/.+','type':'bind'}]}}
        return template,containers,volumes,policy

    def test_optional_public_only_preflight_and_ordinary_template(self):
        values=self.fixture();result=preflight.validate_otel(*values)
        self.assertTrue(result['configured']);self.assertEqual(result['public_ca_sha256'],hashlib.sha256(self.ca).hexdigest())
        template={'parameters':{'transferKeyB64':{'type':'secureString'},'transferKeyJson':{'type':'secureString'}}}
        self.assertEqual(preflight.validate_otel(template,{'primary':{},'secondary':{}},{},{}),{'configured':False})

    def test_literal_secret_broad_policy_wrong_ca_and_writable_mount_are_rejected(self):
        for change in ('literal','parameter-default','duplicate','http','broad-policy','literal-policy','policy-mount','mount','extra-label','ca'):
            template,containers,volumes,policy=self.fixture();primary=containers['primary']
            if change=='literal':primary['environmentVariables'][-1]={'name':'OTEL_EXPORTER_OTLP_HEADERS','value':'authorization=Basic%20fixture-secret'}
            elif change=='parameter-default':template['parameters']['otelExporterHeaders']['defaultValue']='fixture-secret'
            elif change=='duplicate':primary['environmentVariables'].append(copy.deepcopy(primary['environmentVariables'][0]))
            elif change=='http':primary['environmentVariables'][0]['value']='http://20.166.33.141:4318'
            elif change=='broad-policy':policy['primary']['env_rules'].append({'pattern':'.*=.*','strategy':'re2','required':False})
            elif change=='literal-policy':policy['primary']['env_rules'][-1]={'pattern':'OTEL_EXPORTER_OTLP_HEADERS=authorization=Basic%20fixture-secret','strategy':'string','required':True}
            elif change=='policy-mount':policy['primary']['mounts'][0]['options'][-1]='rw'
            elif change=='mount':primary['volumeMounts'][0]['readOnly']=False
            elif change=='extra-label':primary['environmentVariables'][3]['value']+=',secret=fixture-secret'
            elif change=='ca':volumes['otel-public-ca']['secret']['exporter-ca.pem']=base64.b64encode(b'not a certificate').decode()
            with self.subTest(change=change),self.assertRaises(ValueError) as rejected:
                preflight.validate_otel(template,containers,volumes,policy)
            self.assertNotIn('fixture-secret',str(rejected.exception))

if __name__=='__main__':unittest.main()
