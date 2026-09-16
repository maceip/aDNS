#!/usr/bin/env python3
"""Verify a claims-bearing agentdns receipt (anchor, appraisal policy, anchors document).

The response body carries a `claims` (or `anchor`) object and a CCF receipt
under `proof`. This tool recomputes the claims digest with the endpoint's
domain separator over canonical JSON of that object, then reuses the CCF v1
Merkle/endorsement checks from verify_ksk_receipt.py against an EXTERNALLY
trusted service certificate. Receipt-supplied certificates are never anchors.

    python3 tools/verify_claims_receipt.py response.json --service-cert service_cert.pem \\
        [--type agentdns-anchor-v1|agentdns-appraisal-policy-v1|agentdns-anchors-v1]
"""
import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_ksk_receipt as ksk  # noqa: E402

TYPES = {"agentdns-anchor-v1": "anchor", "agentdns-appraisal-policy-v1": "claims", "agentdns-anchors-v1": "claims"}


def canonical_json(value):
    """RFC 8785 for the value space these claims use: str, safe int, bool, null, list, dict."""
    def walk(v):
        if v is None or isinstance(v, bool) or isinstance(v, str):
            return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
        if isinstance(v, int):
            if abs(v) > 2**53 - 1:
                raise ValueError("integer outside safe range")
            return str(v)
        if isinstance(v, float):
            raise ValueError("floats are not permitted in claims")
        if isinstance(v, list):
            return "[" + ",".join(walk(x) for x in v) + "]"
        if isinstance(v, dict):
            return "{" + ",".join(json.dumps(k, ensure_ascii=False, separators=(",", ":")) + ":" + walk(v[k]) for k in sorted(v)) + "}"
        raise ValueError(f"unsupported claims value {type(v).__name__}")
    return walk(value).encode("utf-8")


def claims_digest(claims_type, claims):
    canonical = canonical_json(claims)
    return hashlib.sha256(claims_type.encode() + b"\0" + len(canonical).to_bytes(4, "big") + canonical).digest()


def verify(response, trusted_service_pem, expected_type=None):
    if not isinstance(response, dict):
        raise ValueError("response object required")
    claims = response.get("claims", response.get("anchor"))
    if not isinstance(claims, dict) or "type" not in claims:
        raise ValueError("response carries no typed claims")
    claims_type = claims["type"]
    if claims_type not in TYPES or (expected_type and claims_type != expected_type):
        raise ValueError(f"unexpected claims type {claims_type!r}")
    trusted = ksk.certificate(trusted_service_pem)
    announced = ksk.certificate(response["ccf_service_identity"])
    if announced.public_bytes(ksk.serialization.Encoding.DER) != trusted.public_bytes(ksk.serialization.Encoding.DER):
        raise ValueError("receipt CCF identity is not the trusted service")
    proof = response["proof"]
    leaf = proof["leaf_components"]
    claim = claims_digest(claims_type, claims)
    if ksk.hexbytes(leaf["claims_digest"], 32) != claim:
        raise ValueError("claims digest mismatch: body claims differ from the receipted leaf")
    evidence = leaf["commit_evidence"]
    match = re.fullmatch(r"ce:((?:0|[1-9][0-9]*)\.[1-9][0-9]*):[0-9a-f]{64}", evidence if isinstance(evidence, str) else "")
    if match is None or response.get("tx_id") != match[1]:
        raise ValueError("transaction ID does not match authenticated commit evidence")
    accumulator = ksk.digest(ksk.hexbytes(leaf["write_set_digest"], 32) + ksk.digest(evidence.encode("utf-8")) + claim)
    path = proof["proof"]
    if not isinstance(path, list) or len(path) > 64:
        raise ValueError("invalid Merkle proof path")
    for step in path:
        if not isinstance(step, dict) or len(step) != 1:
            raise ValueError("ambiguous Merkle proof step")
        if "left" in step:
            accumulator = ksk.digest(ksk.hexbytes(step["left"], 32) + accumulator)
        elif "right" in step:
            accumulator = ksk.digest(accumulator + ksk.hexbytes(step["right"], 32))
        else:
            raise ValueError("unknown Merkle proof direction")
    node = ksk.certificate(proof["cert"])
    current = node
    for pem in proof.get("service_endorsements", []) or []:
        parent = ksk.certificate(pem)
        ksk.endorse(current, parent)
        current = parent
    ksk.endorse(current, trusted)
    key = node.public_key()
    key.verify(base64.b64decode(proof["signature"], validate=True), accumulator, ksk.ec.ECDSA(ksk.utils.Prehashed(ksk.hashes.SHA256())))
    return {"type": claims_type, "claims": claims, "claims_digest": claim.hex(), "tx_id": response["tx_id"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("response", type=Path)
    parser.add_argument("--service-cert", type=Path, required=True)
    parser.add_argument("--type", choices=sorted(TYPES))
    args = parser.parse_args()
    if args.response.stat().st_size > 1024 * 1024:
        parser.error("response exceeds 1MiB")
    response = json.loads(args.response.read_text(), object_pairs_hook=ksk.unique_object)
    print(json.dumps(verify(response, args.service_cert.read_text(), args.type), indent=2))


if __name__ == "__main__":
    main()
