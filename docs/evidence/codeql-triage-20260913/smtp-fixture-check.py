import json
import pathlib
import smtplib
import socket
import ssl
import subprocess
import sys
import time
import warnings

child = subprocess.Popen([sys.executable, '/src/tests/rust-integration/smtp_fixture.py'])
try:
    deadline = time.monotonic() + 10
    while True:
        if child.poll() is not None:
            raise RuntimeError('fixture exited before readiness')
        try:
            for port in (25, 465, 993):
                with socket.create_connection(('127.0.0.1', port), timeout=.2):
                    pass
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise TimeoutError('SMTP fixture readiness')
            time.sleep(.05)
    listeners = {}
    for line in pathlib.Path('/proc/net/tcp').read_text().splitlines()[1:]:
        columns = line.split()
        address, port = columns[1].split(':')
        if columns[3] == '0A' and int(port, 16) in (25, 465, 993):
            listeners[int(port, 16)] = address
    assert listeners == {25:'0100007F', 465:'0100007F', 993:'0100007F'}, listeners
    context = ssl.create_default_context(cafile='/work/mail.pem')
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    protocols = {}
    with smtplib.SMTP('127.0.0.1', 25, timeout=2) as smtp:
        smtp._host = 'mail-fixture.test'
        smtp.ehlo()
        smtp.starttls(context=context)
        protocols[25] = smtp.sock.version()
    for port in (465, 993):
        with socket.create_connection(('127.0.0.1', port), timeout=2) as raw:
            with context.wrap_socket(raw, server_hostname='mail-fixture.test') as peer:
                protocols[port] = peer.version()
                assert peer.recv(256)
    legacy = ssl.create_default_context(cafile='/work/mail.pem')
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        legacy.minimum_version = ssl.TLSVersion.TLSv1_1
        legacy.maximum_version = ssl.TLSVersion.TLSv1_1
    legacy.set_ciphers('DEFAULT:@SECLEVEL=0')
    with socket.create_connection(('127.0.0.1', 465), timeout=2) as raw:
        try:
            legacy.wrap_socket(raw, server_hostname='mail-fixture.test')
        except ssl.SSLError as error:
            assert 'PROTOCOL_VERSION' in str(error).upper(), str(error)
        else:
            raise AssertionError('legacy protocol accepted')
    print(json.dumps({'status':'passed', 'actual_listeners':listeners,
        'authenticated_tls_versions':protocols, 'tls11_rejected':True,
        'scope':'isolated Ubuntu SMTP fixture; no mail delivery or native appraisal'}))
finally:
    child.terminate()
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=3)
