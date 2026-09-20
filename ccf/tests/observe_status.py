#!/usr/bin/env python3
"""Record committed zone status during an idle CCF/BIND acceptance interval."""

import sys as _sys
from pathlib import Path as _Path
for _parent in _Path(__file__).resolve().parents:
    if (_parent / "tools/domain_registry.py").is_file():
        _sys.path.insert(0, str(_parent / "tools"))
        break
from validation_names import VALIDATION_DOMAIN
import argparse
import http.client
import json
import pathlib
import ssl
import sys
import time
from urllib.parse import urlsplit

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "tools"))
from http_limits import SocketDeadline, read_bounded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--service-cert", type=pathlib.Path, required=True)
    parser.add_argument("--seconds", type=int, default=1200)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    origin = urlsplit(args.url)
    if origin.scheme != "https" or not origin.hostname or origin.path not in ("", "/") or origin.username or origin.password or origin.query or origin.fragment:
        parser.error("CA-pinned TLS origin required")
    if not 30 <= args.seconds <= 3600:
        parser.error("duration outside bounds")
    args.output.mkdir(parents=True, exist_ok=True)
    context = ssl.create_default_context(cafile=str(args.service_cert))
    context.set_alpn_protocols(["http/1.1"])
    samples, failures = [], []
    start = time.monotonic()
    while True:
        conn = http.client.HTTPSConnection(origin.hostname, origin.port or 443, context=context, timeout=5)
        sample = {"unix_seconds": time.time(), "elapsed_seconds": time.monotonic() - start}
        try:
            deadline = time.monotonic() + 5
            conn.connect()
            with SocketDeadline(conn.sock, deadline):
                conn.request("GET", ('/app/zone/status?zone=' + VALIDATION_DOMAIN + '.'))
                response = conn.getresponse()
                raw = read_bounded(response, 65536, deadline)
                sample.update({"http_status": response.status, "body": json.loads(raw),
                               "commit_status": response.getheader("x-agentdns-commit-status"),
                               "transaction_id": response.getheader("x-agentdns-transaction-id")})
            if response.status != 200 or sample["commit_status"] != "committed":
                raise ValueError("zone status was not confirmed committed")
            body = sample["body"]
            if body["tx_id"] != sample["transaction_id"]:
                raise ValueError("transaction identity mismatch")
            if body["committed_state"]["earliest_rrsig_expiration"] <= sample["unix_seconds"]:
                raise ValueError("expired authority snapshot")
        except Exception as error:
            sample["error"] = type(error).__name__ + ": " + str(error)
            failures.append(sample)
        finally:
            conn.close()
        samples.append(sample)
        path = args.output / "status-samples.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(samples, indent=2) + "\n")
        temporary.replace(path)
        if time.monotonic() - start >= args.seconds:
            break
        time.sleep(min(10, max(0, args.seconds - (time.monotonic() - start))))
    result = {"samples": len(samples), "failures": len(failures),
              "elapsed_seconds": time.monotonic() - start,
              "observed_serials": sorted({s["body"]["committed_state"]["serial"] for s in samples if "error" not in s}),
              "all_samples_committed_unexpired": not failures}
    (args.output / "status-results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
