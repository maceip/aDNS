#!/usr/bin/env python3
"""Existing active member requests only snapshot/chunk rotation before a backup.

Explicit separate governance step: no role changes, key copies, service restart,
or arbitrary action input. Run with the existing Steward's credential custody.
"""
import argparse
import json
from pathlib import Path
import sys

import committed_backup as backup
from azure_files_backup import atomic_json, exclusive
from ccf_control import Client, Governance
from durable_recovery import capture_receipt


def rotate(client, governance, service_pem, zone):
    network = client.request("GET", "/node/network")
    if network["http_status"] != 200 or network["body"].get("service_status") != "Open":
        raise ValueError("rotation requires an Open authority")
    if backup.service_id(network["body"]["service_certificate"].encode()) != backup.service_id(service_pem):
        raise ValueError("configured certificate is not the current service identity")
    def action(name):
        result = governance.propose([{"name": name, "args": {}}])
        if result["body"].get("proposalState") != "Accepted" or not result.get("confirmed_ccf_transaction_id"):
            raise ValueError("fixed backup action was not accepted and committed")
        return result["confirmed_ccf_transaction_id"]
    snapshot = action("trigger_snapshot")
    receipt = capture_receipt(client, service_pem, zone)
    rotation = action("trigger_ledger_chunk")
    return {"created_at": backup.utcnow().isoformat(),
            "actions": ["trigger_snapshot", "trigger_ledger_chunk"],
            "service_der_sha256": backup.service_id(service_pem),
            "snapshot_tx_id": snapshot, "rotation_tx_id": rotation,
            "receipt": receipt, "transaction_inclusion_verified": False}


def run(config):
    root = Path(config["backup_root"])
    with exclusive(root):
        try:
            rotation = config["rotation"]
            service = Path(config["service_cert"])
            client = Client(rotation["url"], rotation.get("connect_ip"), service)
            governance = Governance(client, Path(rotation["member_key"]), Path(rotation["member_cert"]))
            record = rotate(client, governance, backup.read_small(service), config["zone"])
            atomic_json(root / "rotation.json", record)
            return {"rotation_actions_committed": True, "rotation_tx_id": record["rotation_tx_id"],
                    "transaction_inclusion_verified": False}
        except Exception as error:
            atomic_json(root / "status.json", {"evaluated_at": backup.utcnow().isoformat(),
                        "status": "failed", "alerts": ["rotation_failed"],
                        "transaction_inclusion_verified": False, "recovery_exercised": False,
                        "error_type": type(error).__name__})
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(backup.strict_json(backup.read_small(args.config))), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("backup rotation failed: " + type(error).__name__, file=sys.stderr)
        sys.exit(1)
