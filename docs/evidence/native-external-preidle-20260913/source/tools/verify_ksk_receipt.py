#!/usr/bin/env python3
"""Independently verify a KSK receipt against an EXTERNALLY trusted CCF cert.

Implements the CCF v1 SHA256 Merkle leaf/root and service endorsement checks;
see https://github.com/microsoft/CCF/blob/ccf-7.0.15/python/src/ccf/receipt.py .
Receipt-supplied certificates are never treated as trust anchors.
"""
import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


def digest(data):
    return hashlib.sha256(data).digest()


def hexbytes(value, size=None):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", value):
        raise ValueError("noncanonical hexadecimal value")
    decoded = bytes.fromhex(value)
    if size is not None and len(decoded) != size:
        raise ValueError("wrong digest length")
    return decoded


def owner_wire(owner):
    if not isinstance(owner, str) or not owner.endswith(".") or len(owner) > 254:
        raise ValueError("noncanonical owner")
    encoded = bytearray()
    for label in owner[:-1].split("."):
        if not 1 <= len(label) <= 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label):
            raise ValueError("noncanonical owner label")
        encoded.append(len(label))
        encoded.extend(label.encode("ascii"))
    encoded.append(0)
    if len(encoded) > 255:
        raise ValueError("owner too long")
    return bytes(encoded)


def claims_digest(owner, dnskey):
    wire = owner_wire(owner)
    return digest(b"agentdns.ksk.receipt.v1\0" + len(wire).to_bytes(2, "big") + wire + len(dnskey).to_bytes(4, "big") + dnskey)


def certificate(pem):
    if isinstance(pem, bytes):
        pem = pem.decode("ascii")
    if not isinstance(pem, str) or len(pem) > 65536:
        raise ValueError("invalid certificate")
    return x509.load_pem_x509_certificate(pem.encode("ascii"))


def endorse(child, parent):
    key = parent.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("CCF service must use an EC identity")
    if child.issuer != parent.subject:
        raise ValueError("CCF certificate issuer mismatch")
    # These are ledger identity endorsements, which remain verifiable for
    # historical transactions after certificate expiry. The trust anchor is
    # explicitly selected by the verifier; this does not establish live TLS.
    key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))


def verify(receipt, trusted_service_pem, expected_zone=None):
    if not isinstance(receipt, dict):
        raise ValueError("receipt object required")
    zone = receipt["zone"]
    if zone != receipt["owner_name"] or expected_zone is not None and zone != expected_zone:
        raise ValueError("zone/owner mismatch")
    wire = owner_wire(zone)
    rdata = hexbytes(receipt["dnskey_rdata_hex"], 100)
    if rdata[:4] != bytes([1, 1, 3, 14]) or receipt["algorithm"] != 14:
        raise ValueError("requires KSK flags257, protocol3, algorithm14")
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), b"\x04" + rdata[4:])
    checksum = sum(value << 8 if index % 2 == 0 else value for index, value in enumerate(rdata))
    tag = (checksum + (checksum >> 16)) & 65535
    if receipt["key_tag"] != tag:
        raise ValueError("DNSKEY key tag mismatch")
    ds = digest(wire + rdata)
    if receipt["ds_digest"]["digest_type"] != 2 or hexbytes(receipt["ds_digest"]["digest_hex"], 32) != ds:
        raise ValueError("DS does not bind exact owner and DNSKEY RDATA")
    trusted = certificate(trusted_service_pem)
    announced = certificate(receipt["ccf_service_identity"])
    if announced.public_bytes(serialization.Encoding.DER) != trusted.public_bytes(serialization.Encoding.DER):
        raise ValueError("receipt CCF identity is not the trusted service")
    proof = receipt["proof"]
    leaf = proof["leaf_components"]
    claim = claims_digest(zone, rdata)
    if hexbytes(leaf["claims_digest"], 32) != claim:
        raise ValueError("KSK claim mismatch")
    evidence = leaf["commit_evidence"]
    if not isinstance(evidence, str) or len(evidence) > 4096:
        raise ValueError("invalid commit evidence")
    # CCF 7.0.15 src/kv/kv_types.h: authenticated evidence is
    # ce:<view>.<sequence>:<32-byte commit nonce>. Bind the displayed ID too.
    match = re.fullmatch(r"ce:((?:0|[1-9][0-9]*)\.[1-9][0-9]*):[0-9a-f]{64}", evidence)
    if match is None or receipt["tx_id"] != match[1]:
        raise ValueError("transaction ID does not match authenticated commit evidence")
    if any(int(part) >= 1 << 64 for part in match[1].split(".")):
        raise ValueError("transaction ID exceeds CCF bounds")
    accumulator = digest(hexbytes(leaf["write_set_digest"], 32) + digest(evidence.encode("utf-8")) + claim)
    path = proof["proof"]
    if not isinstance(path, list) or len(path) > 64:
        raise ValueError("invalid Merkle proof path")
    for step in path:
        if not isinstance(step, dict) or len(step) != 1:
            raise ValueError("ambiguous Merkle proof step")
        if "left" in step:
            accumulator = digest(hexbytes(step["left"], 32) + accumulator)
        elif "right" in step:
            accumulator = digest(accumulator + hexbytes(step["right"], 32))
        else:
            raise ValueError("unknown Merkle proof direction")
    node = certificate(proof["cert"])
    endorsements = proof.get("service_endorsements", [])
    if not isinstance(endorsements, list) or len(endorsements) > 16:
        raise ValueError("invalid identity endorsement chain")
    current = node
    for pem in endorsements:
        parent = certificate(pem)
        endorse(current, parent)
        current = parent
    endorse(current, trusted)
    key = node.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("CCF node must use an EC key")
    signature = base64.b64decode(proof["signature"], validate=True)
    key.verify(signature, accumulator, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    return {"zone": zone, "key_tag": tag, "ds_sha256": ds.hex(), "claims_digest": claim.hex(), "tx_id": receipt["tx_id"]}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--service-cert", type=Path, required=True)
    parser.add_argument("--zone", required=True)
    args = parser.parse_args()
    if args.receipt.stat().st_size > 1024 * 1024:
        parser.error("receipt exceeds 1MiB")
    receipt = json.loads(args.receipt.read_text(), object_pairs_hook=unique_object)
    print(json.dumps(verify(receipt, args.service_cert.read_text(), args.zone), indent=2))


if __name__ == "__main__":
    main()
