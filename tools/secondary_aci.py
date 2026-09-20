#!/usr/bin/env python3
"""Stock authoritative BIND frontend for the isolated CCF ACI acceptance group.

CCF is the sole zone signer. This process receives only a transfer TSIG secret;
its primary is local and its reserved validation zone comes from the shared registry.
"""
import base64
from domain_registry import get
import binascii
import os
from pathlib import Path
import pwd
import resource
import subprocess

ZONE = get("validation_domain")
KEY_NAME = get("transfer_key_name")
PRIMARY = "127.0.0.1"
PRIMARY_PORT = 5353


def decode_secret(encoded):
    if not isinstance(encoded, str) or len(encoded) != 44:
        raise ValueError("transfer secret must be canonical base64 of 32 random bytes")
    try:
        secret = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("invalid transfer secret encoding") from error
    if len(secret) != 32 or base64.b64encode(secret).decode("ascii") != encoded:
        raise ValueError("transfer secret must be canonical base64 of 32 random bytes")
    return encoded


def configuration(secret, runtime, zone_directory):
    secret = decode_secret(secret)
    return f'''key "{KEY_NAME}" {{ algorithm hmac-sha256; secret "{secret}"; }};
options {{
    directory "{zone_directory}";
    listen-on port 53 {{ any; }};
    listen-on-v6 port 53 {{ any; }};
    recursion no;
    dnssec-validation no;
    allow-query {{ any; }};
    allow-transfer {{ none; }};
    notify no;
    version "agentdns acceptance secondary";
    pid-file "{runtime}/named.pid";
    session-keyfile "{runtime}/session.key";
}};
controls {{ }};
zone "{ZONE}" {{
    type secondary;
    primaries {{ {PRIMARY} port {PRIMARY_PORT} key "{KEY_NAME}"; }};
    allow-notify {{ key "{KEY_NAME}"; }};
    file "{ZONE}.zone";
    masterfile-format text;
}};
'''


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Remove the secret from the environment inherited by named. Configuration
    # remains readable only by the bind UID on the container's ephemeral volume.
    secret = os.environ.pop("AGENTDNS_TRANSFER_KEY_B64", None)
    secret_file = os.environ.pop("AGENTDNS_TRANSFER_KEY_FILE", None)
    if (secret is None) == (secret_file is None):
        raise ValueError("supply exactly one secure transfer-key environment value or secret-file path")
    if secret_file is not None:
        with open(secret_file, "rb") as stream:
            encoded = stream.read(46)
        if len(encoded) > 45:
            raise ValueError("transfer secret file is oversized")
        secret = encoded.decode("ascii").rstrip("\n")
    secret = decode_secret(secret)
    runtime = Path("/run/agentdns-secondary")
    zone_directory = Path("/var/lib/bind/agentdns")
    account = pwd.getpwnam("bind")
    for directory in (runtime, zone_directory):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
        os.chown(directory, account.pw_uid, account.pw_gid)
    path = runtime / "named.conf"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(configuration(secret, runtime, zone_directory))
    os.chmod(path, 0o600)
    os.chown(path, account.pw_uid, account.pw_gid)
    del secret
    # Check without printing configuration, which contains the TSIG secret.
    subprocess.run(["named-checkconf", str(path)], check=True)
    os.execvp("named", ["named", "-g", "-n", "1", "-u", "bind", "-c", str(path)])


if __name__ == "__main__":
    main()
