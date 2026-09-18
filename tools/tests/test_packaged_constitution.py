import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("packaged_constitution", Path(__file__).resolve().parents[1] / "packaged_constitution.py")
artifact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifact)


class PackagedConstitutionTests(unittest.TestCase):
    def test_repository_artifact_matches_its_provenance(self):
        self.assertIn(b"export function resolve", artifact.load())

    def test_changed_artifact_or_source_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            d = Path(temp) / "ccf/governance"
            d.mkdir(parents=True)
            raw = b"reviewed constitution\n"
            digest = hashlib.sha256(raw).hexdigest()
            (d / "constitution.js").write_bytes(raw)
            (d / "constitution.sha256").write_text(digest)
            (d / "constitution.source.json").write_text(json.dumps({"sha256": digest}))
            self.assertEqual(artifact.load(temp), raw)
            (d / "constitution.js").write_bytes(raw + b"tampered")
            with self.assertRaises(ValueError):
                artifact.load(temp)
            (d / "constitution.js").write_bytes(raw)
            (d / "constitution.source.json").write_text(json.dumps({"sha256": "0" * 64}))
            with self.assertRaises(ValueError):
                artifact.load(temp)
