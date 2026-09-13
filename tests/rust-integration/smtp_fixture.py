#!/usr/bin/env python3
"""Controlled SMTP STARTTLS and implicit TLS peers; never delivers mail."""
import concurrent.futures, pathlib, socket, ssl, threading, time
root=pathlib.Path('/work')
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'mail.pem',root/'mail.key')
context.minimum_version=ssl.TLSVersion.TLSv1_2

def line(sock):
    out=bytearray()
    while len(out)<4096:
        b=sock.recv(1)
        if not b:return bytes(out)
        out.extend(b)
        if b==b'\n':return bytes(out)
    raise RuntimeError('oversized SMTP command')

def smtp(sock):
    sock.settimeout(10);sock.sendall(b'220 mail-good.example.test ESMTP acceptance fixture\r\n')
    while True:
        command=line(sock).upper()
        if command.startswith((b'EHLO',b'HELO')):sock.sendall(b'250-mail-good.example.test\r\n250-STARTTLS\r\n250 SIZE 1024\r\n')
        elif command.startswith(b'STARTTLS'):
            sock.sendall(b'220 Go ahead\r\n');sock=context.wrap_socket(sock,server_side=True)
        elif command.startswith(b'QUIT'):sock.sendall(b'221 Bye\r\n');return
        elif not command:return
        else:sock.sendall(b'502 Test fixture accepts only EHLO, STARTTLS and QUIT\r\n')

def serve(port,implicit):
    listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',port));listener.listen(20)
    while True:
        sock,_=listener.accept()
        def client(sock=sock):
            try:
                if implicit:
                    sock.settimeout(10)
                    with context.wrap_socket(sock,server_side=True) as secure:secure.sendall(b'* OK acceptance TLS peer\r\n' if port==993 else b'220 implicit TLS peer\r\n')
                else:smtp(sock)
            except (OSError,ssl.SSLError):pass
            finally:sock.close()
        threading.Thread(target=client,daemon=True).start()
for port in [25,465,993]:threading.Thread(target=serve,args=(port,port!=25),daemon=True).start()
while True:time.sleep(60)
