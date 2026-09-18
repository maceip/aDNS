"""Read the reviewed Steward artifact; tests must not reconstruct removed sources."""
import hashlib
import json
from pathlib import Path


def load(root=None):
    directory = (Path(root) if root is not None else Path(__file__).resolve().parents[1]) / "ccf/governance"
    raw = (directory / "constitution.js").read_bytes()
    expected = (directory / "constitution.sha256").read_text().strip()
    source = json.loads((directory / "constitution.source.json").read_text())
    if hashlib.sha256(raw).hexdigest() != expected or source["sha256"] != expected:
        raise ValueError("packaged Steward constitution digest mismatch")
    return raw
