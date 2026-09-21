"""Provider-reader safety using fake HTTP; no cloud tokens or resources used."""
from contextlib import contextmanager
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import azure_files_backup as azure
import backup_rotate
from test_durable_recovery import receipt_fixture


class Response(io.BytesIO):
    def __init__(self, body=b"", **headers):
        super().__init__(body)
        self.headers = headers


def listing(names, marker="", directory=False):
    kind = "Directory" if directory else "File"
    return ("<EnumerationResults><Entries>" + "".join(
        f"<{kind}><Name>{name}</Name><Properties><Content-Length>0</Content-Length></Properties></{kind}>"
        for name in names) + f"</Entries><NextMarker>{marker}</NextMarker></EnumerationResults>").encode()


class MemoryReader(azure.AzureReader):
    def __init__(self):
        super().__init__("testaccount", "testshare")
        self.data = {"ledger/ledger_1-50.committed": b"ledger fixture", "snapshots/snapshot_40_41.committed": b"snapshot fixture"}
        self.calls = []

    def request(self, method, path, query=None):
        self.calls.append((method, path, query))
        if query:
            names = [p.split("/", 1)[1] for p in self.data if p.startswith(path + "/")]
            if path == "ledger": names.append("ledger_51")
            return Response(listing(names))
        value = self.data[path]
        return Response(value if method == "GET" else b"", **{"Content-Length": str(len(value)), "ETag": '"stable"'})


class AzureBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.receipt, self.service, _ = receipt_fixture()

    def test_imds_token_stays_in_memory_and_storage_uses_only_pinned_read_methods(self):
        identity = "a1b25f23-c78f-4337-a840-71d7e687c2fa"
        reader = azure.AzureReader("testaccount", "testshare", object_id=identity)
        requests = []
        def open_request(request, timeout):
            requests.append(request)
            if request.full_url.startswith("http://169.254.169.254/"):
                return Response(json.dumps({"access_token": "fixture-token", "expires_on": int(time.time()) + 3600}).encode())
            return Response()
        with patch.object(reader.opener, "open", side_effect=open_request):
            with reader.request("HEAD", "ledger/ledger_1-50.committed"): pass
            with reader.request("GET", "ledger", {"comp": "list"}): pass
        self.assertEqual(len(requests), 3)
        self.assertEqual(requests[0].get_header("Metadata"), "true")
        self.assertEqual(parse_qs(urlsplit(requests[0].full_url).query)["resource"], ["https://storage.azure.com/"])
        self.assertEqual(parse_qs(urlsplit(requests[0].full_url).query)["object_id"], [identity])
        self.assertEqual(requests[1].get_header("Authorization"), "Bearer fixture-token")
        self.assertEqual(requests[1].get_header("X-ms-file-request-intent"), "backup")
        self.assertEqual(urlsplit(requests[1].full_url).hostname, "testaccount.file.core.windows.net")
        with self.assertRaises(ValueError): reader.request("DELETE", "ledger/ledger_1-50.committed")
        with self.assertRaises(ValueError): reader.request("GET", "../other")
        with self.assertRaises(ValueError): azure.AzureReader("host.invalid", "testshare")
        with self.assertRaises(ValueError): azure.AzureReader("testaccount", "testshare", client_id=identity, object_id=identity)
        with self.assertRaises(ValueError): azure.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other")

    def test_pagination_ignores_stale_listing_lengths_and_refuses_loops_or_paths(self):
        reader = MemoryReader()
        pages = [Response(listing(["ledger_1-50.committed", "ledger_51"], "next")), Response(listing(["ledger_51-60.committed"]))]
        with patch.object(reader, "request", side_effect=pages) as request:
            self.assertEqual(reader.names("ledger"), ["ledger/ledger_1-50.committed", "ledger/ledger_51-60.committed"])
            self.assertEqual(request.call_args_list[1].args[2]["marker"], "next")
        for body in (listing(["../ledger_1-50.committed"]), listing(["nested"], directory=True), b"<!DOCTYPE x><EnumerationResults/>"):
            with patch.object(reader, "request", return_value=Response(body)):
                with self.assertRaises(ValueError): reader.names("ledger")
        pages = [Response(listing([], "same")), Response(listing([], "same"))]
        with patch.object(reader, "request", side_effect=pages):
            with self.assertRaises(ValueError): reader.names("ledger")

    def test_download_uses_file_properties_and_detects_changes_or_truncation(self):
        reader = MemoryReader()
        provenance = azure.download_source(reader, self.root / "source", 1024, 2048)
        self.assertEqual(len(provenance["files"]), 2)
        self.assertTrue(all("ledger/ledger_51" != path for _, path, _ in reader.calls))
        self.assertGreater(provenance["files"]["ledger/ledger_1-50.committed"]["bytes"], 0)
        with patch.object(reader, "properties", side_effect=[{"bytes": 14, "etag": '"stable"'}, {"bytes": 14, "etag": '"changed"'}]):
            with self.assertRaises(ValueError): reader.download("ledger/ledger_1-50.committed", self.root / "changed", 1024)
        with patch.object(reader, "request", return_value=Response(b"short", **{"Content-Length": "14", "ETag": '"stable"'})):
            with self.assertRaises(ValueError): reader.download("ledger/ledger_1-50.committed", self.root / "short", 1024)
        with self.assertRaises(ValueError): azure.download_source(MemoryReader(), self.root / "bounded", 5, 10)

    def config(self):
        state = self.root / "backups"
        state.mkdir(mode=0o700)
        cert, receipt = self.root / "service.pem", self.root / "receipt.json"
        cert.write_bytes(self.service)
        receipt.write_text(json.dumps(self.receipt))
        return {"account": "testaccount", "share": "testshare", "backup_root": str(state),
                "service_cert": str(cert), "receipt": str(receipt), "zone": "example.test.",
                "max_age_seconds": 900, "max_file_bytes": 1024, "max_total_bytes": 2048}

    def test_rotation_accepts_only_current_open_identity_and_fixed_committed_actions(self):
        client, governance = Mock(), Mock()
        client.request.return_value = {"http_status": 200, "body": {
            "service_status": "Open", "service_certificate": self.service.decode()}}
        governance.propose.side_effect = [
            {"body": {"proposalState": "Accepted"}, "confirmed_ccf_transaction_id": "2.30"},
            {"body": {"proposalState": "Accepted"}, "confirmed_ccf_transaction_id": "2.60"}]
        with patch.object(backup_rotate, "capture_receipt", return_value=self.receipt):
            result = backup_rotate.rotate(client, governance, self.service, "example.test.")
        self.assertEqual([call.args[0] for call in governance.propose.call_args_list], [
            [{"name": "trigger_snapshot", "args": {}}], [{"name": "trigger_ledger_chunk", "args": {}}]])
        config = self.config()
        azure.atomic_json(Path(config["backup_root"]) / "rotation.json", result)
        self.assertEqual(azure.rotation_checkpoint(config), result)
        reader = MemoryReader()
        with self.assertRaises(TimeoutError): azure.wait_for_rotation(reader, result, timeout=0)
        reader.data["ledger/ledger_51-70.committed"] = b"next chunk"
        ready = azure.wait_for_rotation(reader, result, timeout=0)
        self.assertTrue(ready["rotation_file_names_observed"])
        self.assertFalse(ready["transaction_inclusion_verified"])
        result["created_at"] = "2020-01-01T00:00:00+00:00"
        azure.atomic_json(Path(config["backup_root"]) / "rotation.json", result)
        with self.assertRaises(ValueError): azure.rotation_checkpoint(config)
        client.request.return_value["body"]["service_status"] = "Recovering"
        with self.assertRaises(ValueError): backup_rotate.rotate(client, governance, self.service, "example.test.")

    def test_runner_requires_explicit_initial_preserves_chain_and_publishes_sanitized_failure(self):
        config = self.config()
        root = Path(config["backup_root"])
        with self.assertRaises(ValueError): azure.cycle(config, reader=MemoryReader())
        self.assertEqual(json.loads((root / "status.json").read_text())["status"], "failed")
        first = azure.cycle(config, initial=True, reader=MemoryReader())
        self.assertEqual(first["status"], "copied_coverage_unverified")
        first_name = json.loads((root / "latest.json").read_text())["directory"]
        self.assertFalse((root / first_name / "source").exists())
        second = azure.cycle(config, reader=MemoryReader())
        second_name = json.loads((root / "latest.json").read_text())["directory"]
        manifest = azure.backup.verify(root / second_name / "backup")
        self.assertIsNotNone(manifest["previous_manifest_sha256"])
        self.assertFalse(second["transaction_inclusion_verified"])
        with self.assertRaises(ValueError): azure.cycle(config, initial=True, reader=MemoryReader())
        previous_pointer = (root / "latest.json").read_bytes()
        reader = MemoryReader()
        with patch.object(reader, "names", side_effect=RuntimeError("secret fixture must not reach report")):
            with self.assertRaises(RuntimeError): azure.cycle(config, reader=reader)
        self.assertEqual((root / "latest.json").read_bytes(), previous_pointer)
        self.assertNotIn("secret fixture", (root / "status.json").read_text())
        with azure.exclusive(root):
            with self.assertRaises(BlockingIOError): azure.cycle(config, reader=MemoryReader())


if __name__ == "__main__":
    unittest.main()
