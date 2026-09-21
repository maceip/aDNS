"""Offline failure boundaries; actual CCF/member recovery runs in ccf-consensus."""
import base64
import copy
import datetime
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import durable_recovery as recovery
import prepare_aci_recovery as template_recovery
import prepare_aci_durable_candidate as candidate
import verify_ksk_receipt as verifier


def receipt_fixture(ksk=None):
    service = ec.generate_private_key(ec.SECP384R1())
    node = ec.generate_private_key(ec.SECP384R1())
    ksk = ksk or ec.generate_private_key(ec.SECP384R1())
    now = datetime.datetime(2026, 1, 1)

    def certificate(key, name, issuer, signing):
        return (x509.CertificateBuilder().subject_name(name).issuer_name(issuer)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
                .sign(signing, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())

    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test service")])
    node_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test node")])
    service_pem = certificate(service, name, name, service)
    node_pem = certificate(node, node_name, name, service)
    data = bytes([1, 1, 3, 14]) + ksk.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)[1:]
    checksum = sum(v << 8 if i % 2 == 0 else v for i, v in enumerate(data))
    leaf = {"write_set_digest": "ab" * 32, "commit_evidence": "ce:2.42:" + "ef" * 32,
            "claims_digest": verifier.claims_digest("example.test.", data).hex()}
    root = verifier.digest(bytes.fromhex(leaf["write_set_digest"]) + verifier.digest(leaf["commit_evidence"].encode()) + bytes.fromhex(leaf["claims_digest"]))
    receipt = {"zone": "example.test.", "owner_name": "example.test.", "dnskey_rdata_hex": data.hex(),
               "key_tag": (checksum + (checksum >> 16)) & 65535, "algorithm": 14,
               "ds_digest": {"digest_type": 2, "digest_hex": verifier.digest(verifier.owner_wire("example.test.") + data).hex()},
               "tx_id": "2.42", "ccf_service_identity": service_pem,
               "proof": {"cert": node_pem, "leaf_components": leaf, "proof": [],
                         "signature": base64.b64encode(node.sign(root, ec.ECDSA(utils.Prehashed(hashes.SHA256())))).decode()}}
    return receipt, service_pem.encode(), ksk


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "download"
        (self.source / "ledger").mkdir(parents=True)
        (self.source / "snapshots").mkdir()
        (self.source / "ledger/ledger_1-10.committed").write_bytes(b"historical chunk")
        (self.source / "ledger/ledger_11").write_bytes(b"current signed transactions")
        (self.source / "snapshots/snapshot_10_11.committed").write_bytes(b"snapshot fixture")
        self.before, self.previous, self.ksk = receipt_fixture()
        self.backup = self.root / "backup"

    def seal(self):
        return recovery.archive(self.source, self.backup, self.previous, self.before,
                                "example.test.", {"kind": "immutable-snapshot-fixture"})

    def test_complete_archive_and_distinct_restore_preserve_open_chunk_and_permissions(self):
        manifest = self.seal()
        self.assertIn("ledger/ledger_11", manifest["files"])
        self.assertEqual(recovery.verify_archive(self.backup), manifest)
        destination = self.root / "restore"
        recovery.restore_copy(self.backup, destination)
        self.assertEqual((destination / "ledger/ledger_11").read_bytes(), b"current signed transactions")
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
        self.assertEqual((destination / "ledger/ledger_11").stat().st_mode & 0o777, 0o600)
        self.assertTrue(recovery.verify_state(self.backup, destination)["exact_backup_match"])
        (destination / "ledger/ledger_11").write_bytes(b"wrong copied bytes")
        with self.assertRaises(ValueError): recovery.verify_state(self.backup, destination)
        with self.assertRaises(FileExistsError):
            recovery.restore_copy(self.backup, destination)
        with self.assertRaises(ValueError):
            recovery.restore_copy(self.backup, self.backup / "in-place")

    def test_archive_rejects_file_directory_and_state_root_symlinks(self):
        target = self.root / "other"
        target.write_bytes(b"do not follow")
        for kind in ("file", "directory", "root"):
            with self.subTest(kind=kind):
                link = self.source / "ledger/link"
                if kind == "root":
                    link = self.root / "linked-root"
                    link.symlink_to(self.source, target_is_directory=True)
                    source = link
                else:
                    link.symlink_to(self.source / "snapshots" if kind == "directory" else target,
                                    target_is_directory=kind == "directory")
                    source = self.source
                with self.assertRaises(ValueError):
                    recovery.archive(source, self.backup, self.previous, self.before, "example.test.", {})
                link.unlink()

    def test_archive_tampering_missing_files_and_extra_files_fail(self):
        self.seal()
        chunk = self.backup / "state/ledger/ledger_11"
        original = chunk.read_bytes()
        chunk.write_bytes(b"corrupt")
        with self.assertRaises(ValueError): recovery.verify_archive(self.backup)
        chunk.unlink()
        with self.assertRaises(ValueError): recovery.verify_archive(self.backup)
        chunk.write_bytes(original)
        (self.backup / "state/unlisted").write_bytes(b"unexpected")
        with self.assertRaises(ValueError): recovery.verify_archive(self.backup)

    def test_recover_config_drops_start_and_uses_complete_writable_ledger(self):
        config = {"command": {"type": "Start", "start": {"members": ["old"]}},
                  "ledger": {"directory": "old", "read_only_directories": ["committed-only"]},
                  "snapshots": {"directory": "old"}}
        actual = recovery.recovery_config(config)
        self.assertEqual(actual["command"]["type"], "Recover")
        self.assertNotIn("start", actual["command"])
        self.assertEqual(actual["ledger"], {"directory": "/durable/ledger", "read_only_directories": []})
        self.assertEqual(config["command"]["type"], "Start")

    def test_receipts_require_real_identity_change_and_exact_same_ksk(self):
        after, current, _ = receipt_fixture(self.ksk)
        self.assertTrue(recovery.verify_continuity(self.before, self.previous, after, current, "example.test.")["exact_dnskey_rdata_preserved"])
        other, other_ca, _ = receipt_fixture()
        with self.assertRaisesRegex(ValueError, "changed the zone KSK"):
            recovery.verify_continuity(self.before, self.previous, other, other_ca, "example.test.")
        with self.assertRaisesRegex(ValueError, "identity did not change"):
            recovery.verify_continuity(self.before, self.previous, self.before, self.previous, "example.test.")

    def test_acceptance_waits_for_public_ledger_and_binds_both_identities(self):
        _, current, _ = receipt_fixture(self.ksk)
        client, governance = Mock(), Mock()
        client.request.return_value = {"http_status": 200, "body": {"state": "ReadingPublicLedger"}}
        with self.assertRaises(ValueError): recovery.accept_recovery(client, governance, self.previous, current)
        governance.ack.assert_not_called()
        client.request.return_value["body"]["state"] = "PartOfPublicNetwork"
        governance.propose.return_value = {"body": {"proposalState": "Accepted"}, "confirmed_ccf_transaction_id": "3.1"}
        recovery.accept_recovery(client, governance, self.previous, current)
        args = governance.propose.call_args.args[0][0]["args"]
        self.assertEqual(args["previous_service_identity"], self.previous.decode())
        self.assertEqual(args["next_service_identity"], current.decode())

    def test_stopped_writer_check_rejects_second_mount_and_automatic_restart(self):
        group = {"id": "/candidate", "restartPolicy": "Never", "instanceView": {"state": "Stopped"},
                 "volumes": [{"name": "public", "azureFile": None}, {"name": "durable", "azureFile": {"storageAccountName": "account", "shareName": "share"}}],
                 "containers": [{"volumeMounts": [{"name": "durable"}], "instanceView": {"currentState": {"state": "Terminated"}}}]}
        recovery.require_stopped_writer([group], "/candidate", "account", "share")
        for change in ("restart", "running", "other", "missing"):
            invalid = copy.deepcopy(group)
            if change == "restart": invalid["restartPolicy"] = "Always"
            if change == "running": invalid["containers"][0]["instanceView"]["currentState"]["state"] = "Running"
            groups = [invalid, copy.deepcopy(invalid)] if change == "other" else [] if change == "missing" else [invalid]
            with self.assertRaises(ValueError): recovery.require_stopped_writer(groups, "/candidate", "account", "share")

    def candidate(self):
        baseline = json.loads((ROOT / "docs/evidence/startup-repair-20260919/deployment/template.json").read_text())
        keys = ROOT / "docs/evidence/azure-native-v5-ready-20260913/bootstrap"
        template = candidate.prepare(baseline, (keys / "member0_cert.pem").read_bytes(),
                                     (keys / "member0_enc_pubk.pem").read_bytes(), "20260921")[0]
        containers = {c["name"]: c["properties"] for c in template["resources"][0]["properties"]["containers"]}
        entries = [{"name": name, "command": containers[name]["command"], "allow_stdio_access": True,
                    "env_rules": copy.deepcopy(candidate.PLATFORM_ENV_RULES) if name == "primary" else [],
                    "mounts": [{"destination": "/durable", "options": ["rbind", "rshared", "rw"],
                                "source": "sandbox:///tmp/atlas/azureFileVolume/.+", "type": "bind"}] if name == "primary" else []}
                   for name in ("primary", "secondary")]
        entries.append({"name": "pause-container", "command": ["/pause"], "allow_stdio_access": True})
        template["resources"][0]["properties"]["confidentialComputeProperties"]["ccePolicy"] = base64.b64encode(("package policy\ncontainers := " + json.dumps(entries) + "\n").encode()).decode()
        return template

    def test_recover_template_preserves_logging_and_refuses_unsafe_policy_or_template_delta(self):
        self.seal()
        start = self.candidate()
        rendered, _ = template_recovery.prepare(start, self.backup, "agentdns-ccf-recovery-20260921", "ccf-recovery-20260921")
        props = rendered["resources"][0]["properties"]
        self.assertEqual(props["diagnostics"], start["resources"][0]["properties"]["diagnostics"])
        prefix, entries, suffix = template_recovery.policies(start)
        entries[0]["command"] = props["containers"][0]["properties"]["command"]
        props["confidentialComputeProperties"]["ccePolicy"] = base64.b64encode((prefix + json.dumps(entries) + suffix).encode()).decode()
        self.assertEqual(template_recovery.check(start, self.backup, rendered)["mode"], "Recover")
        props["restartPolicy"] = "Always"
        with self.assertRaises(ValueError): template_recovery.check(start, self.backup, rendered)
        props["restartPolicy"] = "Never"
        entries[0]["exec_processes"] = [{"command": ["sh"]}]
        props["confidentialComputeProperties"]["ccePolicy"] = base64.b64encode((prefix + json.dumps(entries) + suffix).encode()).decode()
        with self.assertRaises(ValueError): template_recovery.check(start, self.backup, rendered)


if __name__ == "__main__":
    unittest.main()
