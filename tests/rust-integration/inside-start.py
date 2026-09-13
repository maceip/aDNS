#!/usr/bin/env python3
"""Launch authoritative BIND secondary and controlled TLS peers in one container."""
import pathlib,socket,subprocess,time
root=pathlib.Path('/work');(root/'bind-secondary').mkdir(exist_ok=True)
master=socket.gethostbyname('host.docker.internal')
(root/'named-secondary.conf').write_text(f'''
include "/work/bind-key.conf";
options {{ directory "/work/bind-secondary"; listen-on port 1053 {{ any; }}; listen-on-v6 {{ none; }}; recursion no; dnssec-validation no; pid-file "/work/named-secondary.pid"; session-keyfile "/work/bind-secondary/session.key"; }};
controls {{ }};
zone "example.test" {{ type secondary; primaries {{ {master} port 18535 key "agentdns-transfer."; }}; file "example.test.zone"; masterfile-format text; allow-notify {{ key "agentdns-transfer."; }}; allow-transfer {{ key "agentdns-transfer."; }}; }};
''')
log=open(root/'bind-secondary.log','ab',buffering=0)
children=[subprocess.Popen(['named','-g','-n','1','-c',str(root/'named-secondary.conf')],stdout=log,stderr=log),subprocess.Popen(['python3','/suite/smtp_fixture.py'])]
(root/'container-ready').write_text(master+'\n')
try:
    while all(p.poll() is None for p in children):time.sleep(1)
finally:
    for p in children:p.terminate()
