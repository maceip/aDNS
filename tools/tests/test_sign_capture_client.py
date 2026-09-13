"""No control-token request before native appraisal and actual TLS pin equality."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import sign_capture_request as signing

class SigningClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.root=Path(self.temporary.name)
        key=ec.generate_private_key(ec.SECP256R1());subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'agentdns-capture.test')]);now=datetime.datetime.now(datetime.timezone.utc)
        cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(1).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1)).sign(key,hashes.SHA256()))
        self.spki=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        (self.root/'spki.der').write_bytes(self.spki);(self.root/'peer.der').write_bytes(cert.public_bytes(serialization.Encoding.DER));(self.root/'body.json').write_text('{}')
        self.argv=['sign_capture_request.py','--ip','127.0.0.1','--capture',str(self.root),'--policy',str(self.root/'policy.json'),'--appraiser',str(self.root/'appraiser'),'--token-parameters',str(self.root/'token.json'),'--body',str(self.root/'body.json'),'--path','/signed-request','--output',str(self.root/'output.json')]
    def tearDown(self):self.temporary.cleanup()

    def test_failed_appraisal_does_not_even_open_token_file(self):
        with mock.patch.object(sys,'argv',self.argv),mock.patch.object(signing.subprocess,'run',side_effect=subprocess.CalledProcessError(1,['appraiser'])),mock.patch.object(Path,'read_text',side_effect=AssertionError('must not read token')) as read,mock.patch.object(signing.socket,'create_connection') as connect:
            with self.assertRaises(subprocess.CalledProcessError):signing.main()
        read.assert_not_called();connect.assert_not_called()

    def test_changed_actual_peer_is_closed_without_posting_token(self):
        (self.root/'token.json').write_text(json.dumps({'parameters':{'captureToken':{'value':'42'*32}}}))
        appraisal=mock.Mock(stdout=json.dumps({'spki_sha256':list(hashlib.sha256(self.spki).digest()),'valid_until':int(signing.time.time())+30}).encode())
        context=mock.Mock();stream=context.wrap_socket.return_value;stream.getpeercert.return_value=b'different public certificate'
        raw=mock.Mock();connection=mock.Mock()
        with mock.patch.object(sys,'argv',self.argv),mock.patch.object(signing.subprocess,'run',return_value=appraisal),mock.patch.object(signing.ssl,'create_default_context',return_value=context),mock.patch.object(signing.socket,'create_connection',return_value=raw),mock.patch.object(signing.http.client,'HTTPConnection',return_value=connection):
            with self.assertRaisesRegex(ValueError,'TLS peer changed'):signing.main()
        connection.request.assert_not_called();connection.close.assert_called_once();raw.close.assert_called_once()

if __name__=='__main__':unittest.main()
