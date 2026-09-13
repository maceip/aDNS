"""Private, container-local BIND files, independent of host bind-mount ownership.

named drops filesystem capabilities even when started as root. A GitHub runner's
0700, uid-1001 /work therefore cannot be traversed by named. Keep test credentials
private and copy only the named key into a root-owned 0700 directory in /tmp.
Python opens the diagnostic log and mirrors the child PID before privilege drop.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def workspace(label, key_source=None):
    if label not in ("secondary", "resolver"):
        raise ValueError("unknown BIND fixture role")
    directory = Path(tempfile.mkdtemp(prefix="agentdns-bind-" + label + "-"))
    if key_source is not None:
        key = directory / "key.conf"
        descriptor = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output, Path(key_source).open("rb") as source:
            shutil.copyfileobj(source, output)
    return directory


def launch(root, directory, label, configuration, *, detached=False):
    config = directory / "named.conf"
    config.write_text(configuration)
    config.chmod(0o600)
    with (root / ("bind-" + label + ".log")).open("ab", buffering=0) as log:
        child = subprocess.Popen(
            ["named", "-g", "-n", "1", "-c", str(config)],
            stdout=log, stderr=log, start_new_session=detached,
        )
    (root / ("named-" + label + ".pid")).write_text(str(child.pid) + "\n")
    return child
