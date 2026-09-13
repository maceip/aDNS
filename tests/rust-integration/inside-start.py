#!/usr/bin/env python3
"""Launch authoritative BIND secondary and controlled TLS peers in one container."""
import json,pathlib,socket,subprocess,time
from bind_workspace import workspace,launch

def main():
    root=pathlib.Path('/work')
    master=socket.gethostbyname('host.docker.internal')
    directory=workspace('secondary',root/'bind-key.conf')
    configuration=f'''
include "{directory}/key.conf";
options {{ directory "{directory}"; listen-on port 1053 {{ any; }}; listen-on-v6 {{ none; }}; recursion no; dnssec-validation no; pid-file "{directory}/named.pid"; session-keyfile "{directory}/session.key"; }};
controls {{ }};
zone "example.test" {{ type secondary; primaries {{ {master} port 18535 key "agentdns-transfer."; }}; file "example.test.zone"; masterfile-format text; allow-notify {{ key "agentdns-transfer."; }}; allow-transfer {{ key "agentdns-transfer."; }}; }};
'''
    children={}
    try:
        children['named']=launch(root,directory,'secondary',configuration)
        children['smtp']=subprocess.Popen(['python3','/suite/smtp_fixture.py'])
        # Expose readiness only after the actual listener and both children exist.
        for _ in range(100):
            if any(p.poll() is not None for p in children.values()):
                raise RuntimeError('fixture child exited before readiness')
            try:
                with socket.create_connection(('127.0.0.1',1053),.1):pass
                with socket.create_connection(('127.0.0.1',25),.1):pass
                break
            except OSError:time.sleep(.1)
        else:raise RuntimeError('fixture listeners did not become ready')
        (root/'container-ready').write_text(master+'\n')
        while all(p.poll() is None for p in children.values()):time.sleep(.1)
        raise RuntimeError('fixture child exited')
    finally:
        (root/'container-children.json').write_text(json.dumps({name:{'pid':p.pid,'returncode':p.poll()} for name,p in children.items()},indent=2)+'\n')
        for p in children.values():
            if p.poll() is None:p.terminate()
        for p in children.values():
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)

if __name__=='__main__':main()
