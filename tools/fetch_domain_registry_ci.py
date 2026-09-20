#!/usr/bin/env python3
"""Fetch the declared private registry revision with a step-scoped read-only key."""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

import domain_registry

ROOT = Path(__file__).resolve().parents[1]
KEY_ENV = "DOMAIN_REGISTRY_SSH_KEY"


def declared_source():
    locator = json.loads((ROOT / "domain-registry.source.json").read_text())
    parsed = urlsplit(locator["repository"])
    if (parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query or parsed.fragment
            or not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", parsed.path)):
        raise ValueError("CI registry source must be a declared HTTPS GitHub repository")
    if not re.fullmatch(r"[0-9a-f]{40}", locator.get("ref", "")):
        raise ValueError("CI registry source must pin a full Git commit ID")
    return "git@github.com:" + parsed.path.lstrip("/"), locator["ref"]


def fetch_ci():
    # Remove the secret before any child process, including Git, can inherit it.
    key = os.environ.pop(KEY_ENV, None)
    if not key or not key.strip():
        raise ValueError("DOMAIN_REGISTRY_SSH_KEY is missing. Configure a dedicated read-only deploy key on the registry source repository and put its private half in this consumer repository's Actions secret of that name; see tools/private-domain-registry-ci.md. No credentials are created automatically.")
    if len(key) > 65536 or "\0" in key:
        raise ValueError("DOMAIN_REGISTRY_SSH_KEY is not a bounded SSH private key")
    repository, ref = declared_source()
    known_hosts = ROOT / "tools/github-known-hosts"
    if not known_hosts.is_file():
        raise ValueError("Reviewed GitHub SSH known-hosts file is missing")
    with tempfile.TemporaryDirectory(prefix="registry-ci-ssh-") as temporary:
        key_path = Path(temporary) / "identity"
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(key.rstrip() + "\n")
        key = None
        command = shlex.join([
            "ssh", "-F", "/dev/null", "-i", str(key_path),
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(known_hosts),
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=20",
        ])
        environment = {
            "GIT_SSH_COMMAND": command, "GIT_SSH_VARIANT": "ssh", "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_COUNT": "0", "GIT_CONFIG_PARAMETERS": "",
        }
        previous = {name: os.environ.get(name) for name in environment}
        try:
            os.environ.update(environment)
            # Explicit arguments prevent ambient source/ref overrides. The shared
            # reader retains the declared path and writes only public provenance.
            return domain_registry.fetch_registry(repository=repository, ref=ref)
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value


def main():
    try:
        metadata = fetch_ci()
    except ValueError as error:
        print(f"Registry CI fetch unavailable: {error}", file=sys.stderr)
        raise SystemExit(1)
    except (OSError, KeyError, subprocess.SubprocessError):
        # Git/SSH diagnostics can contain caller-controlled credential material.
        print("Registry CI fetch failed. Check the declared revision, the dedicated source read-only deploy key, and the reviewed GitHub host keys; see tools/private-domain-registry-ci.md.", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
