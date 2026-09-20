#!/usr/bin/env python3
"""Provision the isolated BIND VM with a pinned image and a runtime TSIG file.

Run as root through protected Azure VM provisioning. Only the existing pull
identity is used; registry tokens stay in memory or a temporary Docker config.
This frontend receives signed zones and never receives DNSSEC private keys.
"""
import argparse
from domain_registry import get
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import threading
import time
import urllib.parse

REGISTRY = get("secondary_registry")
IMAGE = REGISTRY + "/secondary@sha256:dfd9158f60a9a0cd67b445b001ee636a0389c66ce926af3c386588d886976861"
NAME = "agentdns-secondary"
ROOT = Path("/opt/agentdns-secondary")


def run(command, *, timeout=60, data=None, environment=None):
    result = subprocess.run(command, input=data, capture_output=True, timeout=timeout, env=environment)
    if result.returncode:
        # Never return credential-bearing command arguments or response bodies.
        raise RuntimeError("provisioning command failed: " + command[0])
    return result.stdout


def request_json(url, *, fields=None, headers=None):
    data = None if fields is None else urllib.parse.urlencode(fields).encode()
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password or parsed.fragment or parsed.port:
        raise ValueError("unexpected identity URL components")
    if (parsed.scheme, parsed.hostname) not in (("http", "169.254.169.254"), ("https", REGISTRY)):
        raise ValueError("unexpected identity endpoint")
    connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(parsed.hostname, timeout=10)
    deadline = time.monotonic() + 30
    timer = None
    try:
        connection.connect()
        stream = connection.sock
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("identity connection deadline")
        def shutdown():
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(remaining, shutdown)
        timer.daemon = True
        timer.start()
        request_headers = dict(headers or {})
        if data is not None:
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        path = parsed.path + (("?" + parsed.query) if parsed.query else "")
        # Direct HTTP clients neither follow redirects nor use proxy settings.
        connection.request("GET" if data is None else "POST", path, data, request_headers)
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError("identity endpoint rejected request")
        raw = response.read(1024 * 1024 + 1)
        if time.monotonic() >= deadline:
            raise TimeoutError("identity response deadline")
    finally:
        if timer is not None:
            timer.cancel()
            timer.join()
        connection.close()
    if len(raw) > 1024 * 1024:
        raise ValueError("identity response exceeds bound")
    return json.loads(raw)


def secret_from_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("TSIG input must be a private regular file")
        raw = stream.read(46)
    if len(raw) > 45:
        raise ValueError("TSIG input exceeds bound")
    encoded = raw.rstrip(b"\n")
    secret = base64.b64decode(encoded, validate=True)
    if len(secret) != 32 or base64.b64encode(secret) != encoded:
        raise ValueError("expected canonical 32-byte TSIG secret")
    return encoded.decode()


def configuration(primary):
    primary = str(ipaddress.IPv4Address(primary))
    return f'''include "/config/transfer.key";
options {{
    directory "/var/cache/bind";
    listen-on port 53 {{ any; }};
    listen-on-v6 {{ none; }};
    recursion no;
    dnssec-validation no;
    allow-query {{ any; }};
    allow-transfer {{ none; }};
    notify no;
    version "agentdns acceptance secondary";
    pid-file "/run/agentdns/named.pid";
    session-keyfile "/run/agentdns/session.key";
}};
controls {{ }};
zone "{get("validation_domain")}" {{
    type secondary;
    primaries {{ {primary} port 5353 key "{get("transfer_key_name")}"; }};
    allow-notify {{ key "{get("transfer_key_name")}"; }};
    file "{get("validation_domain")}.zone";
    masterfile-format text;
}};
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--primary", type=ipaddress.IPv4Address, required=True)
    parser.add_argument("--identity-client-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--secret-file", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise PermissionError("root provisioning required")
    if subprocess.run(["docker", "container", "inspect", NAME], capture_output=True, timeout=15).returncode == 0:
        raise RuntimeError("refusing to replace an existing secondary container")
    os.umask(0o077)
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret = secret_from_file(args.secret_file)
    query = urllib.parse.urlencode({"api-version": "2018-02-01", "resource": "https://management.azure.com/", "client_id": args.identity_client_id})
    token = request_json("http://169.254.169.254/metadata/identity/oauth2/token?" + query, headers={"Metadata": "true"})["access_token"]
    refresh = request_json("https://" + REGISTRY + "/oauth2/exchange", fields={"grant_type": "access_token", "service": REGISTRY, "tenant": args.tenant_id, "access_token": token})["refresh_token"]
    del token
    with tempfile.TemporaryDirectory(prefix="registry-", dir=ROOT) as config:
        environment = dict(os.environ, DOCKER_CONFIG=config)
        run(["docker", "login", REGISTRY, "--username", "00000000-0000-0000-0000-000000000000", "--password-stdin"], data=refresh.encode(), environment=environment)
        del refresh
        run(["docker", "pull", "--platform", "linux/amd64", IMAGE], timeout=600, environment=environment)
    image = json.loads(run(["docker", "image", "inspect", IMAGE]))[0]
    if IMAGE not in image.get("RepoDigests", []):
        raise ValueError("pulled manifest differs from approved immutable image")
    identity = json.loads(run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "python3", image["Id"], "-c", "import pwd,json; p=pwd.getpwnam('bind'); print(json.dumps([p.pw_uid,p.pw_gid]))"]))
    uid, gid = identity
    for name in ("config", "data", "run"):
        path = ROOT / name
        path.mkdir(mode=0o700, exist_ok=True)
        os.chown(path, uid, gid)
    for name, content in (("named.conf", configuration(args.primary)), ("transfer.key", 'key "' + get('transfer_key_name') + '" { algorithm hmac-sha256; secret "' + secret + '"; };\n')):
        path = ROOT / "config" / name
        with path.open("x") as stream:
            stream.write(content)
        os.chmod(path, 0o600)
        os.chown(path, uid, gid)
    del secret
    mounts = ["-v", str(ROOT / "config") + ":/config:ro", "-v", str(ROOT / "data") + ":/var/cache/bind", "-v", str(ROOT / "run") + ":/run/agentdns"]
    run(["docker", "run", "--rm", "--network", "none", *mounts, "--entrypoint", "named-checkconf", image["Id"], "/config/named.conf"])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((str(args.primary), 5353))
        private_ip = str(ipaddress.IPv4Address(sock.getsockname()[0]))
    # Bind the VM's NIC address, preserving the OS's loopback-only DNS stub.
    run(["docker", "run", "-d", "--name", NAME, "--restart", "unless-stopped", "--read-only", "--pids-limit", "64", "--memory", "512m", "--cpus", "1", "--ulimit", "core=0", "--log-opt", "max-size=10m", "--log-opt", "max-file=3", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m", "-p", private_ip + ":53:53/tcp", "-p", private_ip + ":53:53/udp", *mounts, "--entrypoint", "named", image["Id"], "-g", "-n", "1", "-u", "bind", "-c", "/config/named.conf"])
    state = json.loads(run(["docker", "container", "inspect", NAME]))[0]
    version = run(["docker", "exec", NAME, "named", "-V"]).decode()
    result = {"status": "container_started_not_zone_ready", "image_manifest": IMAGE, "image_id": image["Id"], "container_id": state["Id"], "host_pid": state["State"]["Pid"], "primary": str(args.primary), "primary_port": 5353, "listen_private_ip": private_ip, "public_protocols": ["TCP53", "UDP53"], "named_version": version, "docker_version": run(["docker", "version", "--format", "{{.Server.Version}}"]).decode().strip(), "configuration_sha256": hashlib.sha256((ROOT / "config" / "named.conf").read_bytes()).hexdigest(), "boundary": "Stock secondary only; no DNSSEC private keys and no native VM appraisal claim."}
    (ROOT / "provision-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
