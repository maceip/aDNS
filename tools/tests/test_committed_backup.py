"""Live-copy safety; fixtures are deliberately not valid CCF ledger bytes."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import committed_backup as backup
from test_durable_recovery import receipt_fixture


class CommittedBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        (self.source / "ledger").mkdir(parents=True)
        (self.source / "snapshots").mkdir()
        self.chunk = self.source / "ledger/ledger_1-50.committed"
        self.chunk.write_bytes(b"not a parsed or verified CCF ledger")
        (self.source / "ledger/ledger_51").write_bytes(b"mutable transactions")
        (self.source / "snapshots/snapshot_40_41.committed").write_bytes(b"snapshot fixture")
        (self.source / "snapshots/snapshot_55_56.committed").write_bytes(b"newer than closed chunks")
        self.receipt, self.service, _ = receipt_fixture()
        self.now = datetime(2026, 9, 21, tzinfo=timezone.utc)

    def copy(self, name="backup", **kw):
        return backup.archive(self.source, self.root / name, self.service, self.receipt,
                              "example.test.", {"scope": "fixture"}, **{"now": self.now, **kw})

    def test_copy_only_committed_bytes_and_never_promotes_filename_or_receipt_to_coverage(self):
        manifest = self.copy()
        target = self.root / "backup"
        self.assertEqual(len(manifest["files"]), 2)
        self.assertNotIn("ledger/ledger_51", manifest["files"])
        self.assertNotIn("snapshots/snapshot_55_56.committed", manifest["files"])
        self.assertEqual(backup.verify(target), manifest)
        self.assertEqual(manifest["verified_receipt_tx_id"], "2.42")
        self.assertEqual(manifest["declared_filename_last_seqno"], 50)
        self.assertFalse(manifest["transaction_inclusion_verified"])
        self.assertFalse(manifest["recovery_exercised"])
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        self.assertEqual((target / "state/ledger/ledger_1-50.committed").stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError): self.copy()

    def test_reject_gaps_overlaps_empty_chunks_and_uncovered_snapshot(self):
        for name in ("ledger_52-60.committed", "ledger_50-60.committed", "ledger_70-60.committed"):
            path = self.source / "ledger" / name
            path.write_bytes(b"bad range")
            with self.assertRaises(ValueError): self.copy()
            path.unlink()
        self.chunk.write_bytes(b"")
        with self.assertRaises(ValueError): self.copy("empty")
        self.assertFalse((self.root / "empty/manifest.json").exists())
        self.chunk.write_bytes(b"fixture")
        (self.source / "snapshots/snapshot_40_41.committed").unlink()
        with self.assertRaises(ValueError): self.copy("uncovered")

    def test_reject_links_and_archive_inside_live_source(self):
        target = self.source / "ledger/link"
        target.symlink_to(self.chunk)
        with self.assertRaises(ValueError): self.copy()
        target.unlink()
        with self.assertRaises(ValueError): self.copy("source/backup")
        link = self.root / "source-link"
        link.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ValueError): backup.select(link)

    def test_selected_file_mutation_fails_without_completion_manifest(self):
        original = backup.hash_file
        def changing(path, destination=None):
            result = original(path, destination)
            if destination is not None and path == self.chunk:
                self.chunk.write_bytes(b"changed after copying")
            return result
        with patch.object(backup, "hash_file", side_effect=changing):
            with self.assertRaises(ValueError): self.copy()
        self.assertFalse((self.root / "backup/manifest.json").exists())

    def test_new_live_chunk_during_copy_does_not_mix_into_selected_cycle(self):
        original = backup.hash_file
        def growing(path, destination=None):
            result = original(path, destination)
            if destination is not None and path == self.chunk:
                (self.source / "ledger/ledger_51-60.committed").write_bytes(b"new immutable chunk")
            return result
        with patch.object(backup, "hash_file", side_effect=growing): manifest = self.copy()
        self.assertNotIn("ledger/ledger_51-60.committed", manifest["files"])
        self.assertEqual(backup.verify(self.root / "backup"), manifest)

    def test_tampering_missing_extra_and_false_coverage_fail_verification(self):
        self.copy()
        target = self.root / "backup"
        chunk = target / "state/ledger/ledger_1-50.committed"
        original = chunk.read_bytes()
        chunk.write_bytes(b"tampered")
        with self.assertRaises(ValueError): backup.verify(target)
        chunk.unlink()
        with self.assertRaises(ValueError): backup.verify(target)
        chunk.write_bytes(original)
        extra = target / "state/ledger/ledger_51"
        extra.write_bytes(b"mutable injected")
        with self.assertRaises(ValueError): backup.verify(target)
        extra.unlink()
        manifest = backup.strict_json((target / "manifest.json").read_bytes())
        manifest["transaction_inclusion_verified"] = True
        (target / "manifest.json").write_bytes(backup.encoded(manifest))
        with self.assertRaises(ValueError): backup.verify(target)

    def test_fresh_copy_of_unchanged_chunks_does_not_reset_staleness(self):
        self.copy()
        later = self.now + timedelta(seconds=120)
        self.copy("second", previous=self.root / "backup", now=later)
        report = backup.report(self.root / "second", 60, now=later)
        self.assertEqual(report["copy_age_seconds"], 0)
        self.assertEqual(report["ledger_content_unchanged_seconds"], 120)
        self.assertEqual(report["alerts"], ["ledger_content_not_advancing"])
        self.assertEqual(report["status"], "stale")
        (self.source / "ledger/ledger_51-60.committed").write_bytes(b"rotated next chunk")
        self.copy("third", previous=self.root / "second", now=later)
        fresh = backup.report(self.root / "third", 60, now=later)
        self.assertEqual(fresh["status"], "copied_coverage_unverified")
        self.assertFalse(fresh["transaction_inclusion_verified"])
        old = backup.report(self.root / "third", 60, now=later + timedelta(seconds=61))
        self.assertEqual(old["alerts"], ["copy_stale", "ledger_content_not_advancing"])
        with self.assertRaises(ValueError): backup.report(self.root / "third", 60, now=self.now)

    def test_prior_chunk_replacement_and_untrusted_receipt_fail(self):
        self.copy()
        self.chunk.write_bytes(b"replacement of committed history")
        with self.assertRaises(ValueError): self.copy("changed", previous=self.root / "backup")
        self.receipt["tx_id"] = "2.1"
        with self.assertRaises(ValueError): self.copy("bad-proof")


if __name__ == "__main__":
    unittest.main()
