"""Ensure artifact export cannot copy private fixtures or follow path escapes."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('export_ccf_results',Path(__file__).with_name('export_ccf_results.py'))
exporter=importlib.util.module_from_spec(spec);spec.loader.exec_module(exporter)


class ExportTests(unittest.TestCase):
    def test_only_public_allowlist_is_copied_and_hashed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'results';source.mkdir()
            (source/'runner-results.json').write_text('{"status":"passed"}')
            (source/'source-integrity.json').write_text('{"status":"passed","verified_source_files":19}')
            (source/'member0_privk.pem').write_text('private fixture')
            with mock.patch.object(sys,'argv',['export',str(source),str(root/'public')]):exporter.main()
            self.assertEqual(set(json.loads((root/'public/sha256.json').read_text())),{'runner-results.json','source-integrity.json'})
            self.assertEqual(json.loads((root/'public/source-integrity.json').read_text())['verified_source_files'],19)
            self.assertFalse((root/'public/member0_privk.pem').exists())

    def test_public_named_symlink_cannot_escape_to_private_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'results';source.mkdir()
            private=root/'member.key';private.write_text('private fixture')
            (source/'runner-results.json').symlink_to(private)
            with mock.patch.object(sys,'argv',['export',str(source),str(root/'public')]):
                with self.assertRaises(ValueError):exporter.main()
            self.assertFalse((root/'public/runner-results.json').exists())

    def test_private_key_marker_cannot_be_published_under_log_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'results';source.mkdir()
            (source/'node-container.log').write_text('-----BEGIN PRIVATE KEY-----\nprivate fixture')
            with mock.patch.object(sys,'argv',['export',str(source),str(root/'public')]):
                with self.assertRaises(ValueError):exporter.main()
            self.assertFalse((root/'public/node-container.log').exists())


if __name__=='__main__':unittest.main()
