#!/usr/bin/env python3
"""Pinned-TLS CCF validation client with signed member governance.

Use only after native node bootstrap authenticated the service certificate.
Member private keys are read locally and never sent or printed.
"""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import re
from pathlib import Path
import socket
import ssl
import time
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from http_limits import SocketDeadline, read_bounded


class Client:
    def __init__(self, url, connect_ip, service_cert):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/") or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("CCF URL must be a TLS origin")
        self.host, self.port = parsed.hostname, parsed.port or 443
        self.ip = str(ipaddress.ip_address(connect_ip)) if connect_ip else self.host
        self.context = ssl.create_default_context(cafile=str(service_cert))
        self.context.set_alpn_protocols(["http/1.1"])
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def request(self, method, path, body=None, content_type="application/json", deadline=None):
        if not isinstance(path, str) or len(path) > 8192 or not path.startswith("/") or path.startswith("//") or any(ord(c) <= 32 or ord(c) >= 127 for c in path):
            raise ValueError("relative ASCII absolute-path request required")
        if body is not None and not isinstance(body, bytes):
            body = json.dumps(body, separators=(",", ":")).encode()
        if body is not None and len(body) > 4 * 1024 * 1024:
            raise ValueError("CCF request exceeds bound")
        deadline = min(deadline, time.monotonic() + 30) if deadline is not None else time.monotonic() + 30
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("CCF request deadline exceeded")
        raw = None
        conn = http.client.HTTPConnection(self.host, self.port, timeout=remaining)
        try:
            raw = socket.create_connection((self.ip, self.port), timeout=remaining)
            raw.settimeout(max(0.001, deadline - time.monotonic()))
            conn.sock = self.context.wrap_socket(raw, server_hostname=self.host)
            with SocketDeadline(conn.sock, deadline):
                conn.request(method, path, body, {"Content-Type": content_type})
                response = conn.getresponse()
                data = read_bounded(response, 4 * 1024 * 1024, deadline)
                headers = {}
                for name, value in response.getheaders():
                    name = name.lower()
                    if name in headers and name in ("x-ms-ccf-transaction-id", "x-agentdns-transaction-id", "x-agentdns-commit-status"):
                        raise ValueError("duplicate CCF commitment header")
                    headers[name] = value
                try:
                    parsed = json.loads(data) if data else None
                except (ValueError, UnicodeDecodeError):
                    parsed = {"non_json_sha256": hashlib.sha256(data).hexdigest()}
                return {"http_status": response.status, "headers": headers, "body": parsed}
        finally:
            conn.close()
            if raw is not None:
                raw.close()

    def require_committed(self, response):
        if not 200 <= response.get("http_status", 0) < 300:
            raise ValueError("failed CCF response cannot confirm commitment")
        body = response.get("body")
        # Application retries retain their original transaction ID in the body;
        # its historic commitment must be confirmed rather than a newer read ID.
        txid = body.get("tx_id") if isinstance(body, dict) else None
        application_txid = response.get("headers", {}).get("x-agentdns-transaction-id")
        if txid and application_txid and txid != application_txid:
            raise ValueError("CCF body and application transaction IDs disagree")
        txid = txid or application_txid or response.get("headers", {}).get("x-ms-ccf-transaction-id")
        if not isinstance(txid, str) or re.fullmatch(r"(?:0|[1-9][0-9]{0,19})\.(?:0|[1-9][0-9]{0,19})", txid) is None or any(int(n) >= 2**64 for n in txid.split('.')):
            raise ValueError("CCF response omitted a canonical transaction ID")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            # Node transaction status is available during member activation and
            # service opening. /app/tx returns FrontendNotOpen at that stage.
            state = self.request("GET", "/node/tx?transaction_id=" + txid, deadline=deadline)
            value = state.get("body")
            if state["http_status"] != 200 or not isinstance(value, dict) or value.get("transaction_id") != txid:
                raise ValueError("invalid CCF transaction-status response")
            if value.get("status") == "Committed":
                response["confirmed_ccf_transaction_id"] = txid
                return response
            if value.get("status") == "Invalid":
                raise ValueError("CCF transaction rolled back")
            if value.get("status") not in ("Unknown", "Pending"):
                raise ValueError("unknown CCF transaction status")
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
        raise TimeoutError("CCF transaction not globally committed before deadline")


class Governance:
    def __init__(self, client, member_key, member_cert):
        self.client = client
        self.key = member_key.read_text()
        self.cert = member_cert.read_text()
        self.id = x509.load_pem_x509_certificate(self.cert.encode()).fingerprint(hashes.SHA256()).hex()

    def post(self, path, body, message_type, proposal_id=None):
        headers = {"ccf.gov.msg.type": message_type, "ccf.gov.msg.created_at": int(time.time())}
        if proposal_id:
            headers["ccf.gov.msg.proposal_id"] = proposal_id
        import ccf.cose
        signed = ccf.cose.create_cose_sign1(b"" if body is None else json.dumps(body).encode(), self.key, self.cert, headers)
        result = self.client.request("POST", path + "?api-version=2024-07-01", signed, "application/cose")
        if result["http_status"] not in (200, 204):
            raise ValueError(f"signed governance request failed (HTTP {result['http_status']})")
        return self.client.require_committed(result)

    def ack(self):
        digest = self.post(f"/gov/members/state-digests/{self.id}:update", None, "state_digest")
        return self.post(f"/gov/members/state-digests/{self.id}:ack", digest["body"], "ack")

    def propose(self, actions, abstain=False):
        result = self.post("/gov/members/proposals:create", {"actions": actions}, "proposal")
        proposal = result["body"]
        if not isinstance(proposal, dict) or proposal.get("proposalState") not in ("Open", "Accepted"):
            raise ValueError("proposal failed or returned an invalid state")
        if abstain:
            # Leave the decision to the other governors (agent-led governance, ADR 0002).
            return result
        if proposal["proposalState"] != "Accepted":
            proposal_id = proposal.get("proposalId")
            if not isinstance(proposal_id, str) or re.fullmatch(r"[0-9a-f]{64}", proposal_id) is None:
                raise ValueError("invalid proposal ID")
            result = self.post(f"/gov/members/proposals/{proposal['proposalId']}/ballots/{self.id}:submit",
                               {"ballot": "export function vote(proposal, proposer_id) { return true; }"},
                               "ballot", proposal["proposalId"])
            if result["body"]["proposalState"] != "Accepted":
                raise ValueError("proposal did not reach accepted state")
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("ack", "propose", "request"))
    parser.add_argument("--url", required=True)
    parser.add_argument("--connect-ip")
    parser.add_argument("--service-cert", type=Path, required=True)
    parser.add_argument("--member-key", type=Path)
    parser.add_argument("--member-cert", type=Path)
    parser.add_argument("--body", type=Path)
    parser.add_argument("--method", default="GET", choices=("GET", "POST", "DELETE"))
    parser.add_argument("--path")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--abstain", action="store_true", help="create the proposal without casting the proposer's ballot")
    args = parser.parse_args()
    client = Client(args.url, args.connect_ip, args.service_cert)
    if args.mode == "request":
        if not args.path:
            parser.error("request requires --path")
        result = client.request(args.method, args.path, None if args.body is None else args.body.read_bytes())
        if 200 <= result["http_status"] < 300 and args.path.startswith("/app/") and args.path.split("?", 1)[0] != "/app/tx":
            if result["headers"].get("x-agentdns-commit-status") != "committed":
                raise ValueError("application response lacks global-commit confirmation")
            result = client.require_committed(result)
    else:
        if not args.member_key or not args.member_cert:
            parser.error("governance requires member key and certificate")
        gov = Governance(client, args.member_key, args.member_cert)
        if args.mode == "ack":
            result = gov.ack()
        else:
            if args.body is None:
                parser.error("propose requires a reviewed JSON actions array in --body")
            result = gov.propose(json.loads(args.body.read_text()), abstain=args.abstain)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w") as output:
        output.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"http_status": result["http_status"], "confirmed_ccf_transaction_id": result.get("confirmed_ccf_transaction_id"),
                      "commit_status": result["headers"].get("x-agentdns-commit-status"), "output": str(args.output)}))
    if not 200 <= result["http_status"] < 300:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
