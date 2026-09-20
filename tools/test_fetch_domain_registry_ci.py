"""Private CI fetch isolation tests; Git and SSH are never contacted."""
import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import fetch_domain_registry_ci as helper


class RegistryCiFetchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="registry ci tests ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "tools").mkdir()
        (self.root / "tools/github-known-hosts").write_bytes((helper.ROOT / "tools/github-known-hosts").read_bytes())
        self.ref = "a" * 40
        self.locator = {"schema_version": 1, "repository": "https://github.com/example-owner/registry-source.git", "ref": self.ref, "path": "config/common-topology.json"}
        self.write_locator()
        self.secret = "TEST PRIVATE KEY MATERIAL\nnot-a-real-key\n"
        for target in (helper, helper.domain_registry):
            scope = patch.object(target, "ROOT", self.root)
            scope.start(); self.addCleanup(scope.stop)

    def write_locator(self):
        (self.root / "domain-registry.source.json").write_text(json.dumps(self.locator))

    def check_ssh_environment(self):
        self.assertNotIn(helper.KEY_ENV, os.environ)
        command = shlex.split(os.environ["GIT_SSH_COMMAND"])
        key_path = Path(command[command.index("-i") + 1])
        self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(key_path.parent.stat().st_mode), 0o700)
        self.assertEqual(key_path.read_text(), self.secret)
        for option in ("StrictHostKeyChecking=yes", "IdentitiesOnly=yes", "IdentityAgent=none", "BatchMode=yes", "GlobalKnownHostsFile=/dev/null"):
            self.assertIn(option, command)
        self.assertIn("UserKnownHostsFile=" + str(self.root / "tools/github-known-hosts"), command)
        self.assertEqual(os.environ["GIT_CONFIG_COUNT"], "0")
        self.assertEqual(os.environ["GIT_CONFIG_PARAMETERS"], "")
        return key_path

    def test_git_sees_only_temporary_key_and_declared_repository_ref_path(self):
        observed = []
        key_paths = []
        raw = json.dumps({"schema_version": 1, "domain": "fixture.example", "naming": {"operator_email": "operator@${domain}"}}).encode()
        def fake_git(command, **kwargs):
            key_paths.append(self.check_ssh_environment())
            args = command[3:]
            observed.append(args)
            if args[0] == "rev-parse":
                output = (self.ref + "\n").encode()
            elif args[0] == "show":
                output = raw
            else:
                output = b""
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b"")
        with patch.dict(os.environ, {helper.KEY_ENV: self.secret, "GIT_SSH_COMMAND": "previous-command", "AH_DOMAIN_REGISTRY_REPOSITORY": "https://invalid.example/override", "AH_DOMAIN_REGISTRY_REF": "other-ref"}), patch.object(helper.domain_registry.subprocess, "run", side_effect=fake_git):
            metadata = helper.fetch_ci()
            self.assertNotIn(helper.KEY_ENV, os.environ)
            self.assertEqual(os.environ["GIT_SSH_COMMAND"], "previous-command")
        self.assertIn(["remote", "add", "origin", "git@github.com:example-owner/registry-source.git"], observed)
        self.assertIn(["fetch", "--quiet", "--depth=1", "origin", self.ref], observed)
        self.assertIn(["show", "FETCH_HEAD:config/common-topology.json"], observed)
        self.assertTrue(key_paths)
        for path in key_paths:
            self.assertFalse(path.exists())
            self.assertFalse(path.parent.exists())
        self.assertNotIn(self.secret, json.dumps(metadata))
        self.assertNotIn("identity", metadata)
        self.assertEqual((self.root / ".domain-registry/topology.json").read_bytes(), raw)

    def test_failure_removes_key_and_does_not_log_child_diagnostics(self):
        key_paths = []
        def fail(**kwargs):
            key_paths.append(self.check_ssh_environment())
            raise subprocess.CalledProcessError(128, ["git", "fetch"], stderr=self.secret)
        stderr = io.StringIO()
        with patch.dict(os.environ, {helper.KEY_ENV: self.secret}), patch.object(helper.domain_registry, "fetch_registry", side_effect=fail), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as error:
                helper.main()
            self.assertEqual(error.exception.code, 1)
            self.assertNotIn(helper.KEY_ENV, os.environ)
        self.assertNotIn(self.secret, stderr.getvalue())
        self.assertIn("read-only deploy key", stderr.getvalue())
        self.assertFalse(key_paths[0].parent.exists())

    def test_missing_key_fails_before_fetch_with_setup_instructions(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(helper.domain_registry, "fetch_registry") as fetch:
            with self.assertRaisesRegex(ValueError, "DOMAIN_REGISTRY_SSH_KEY is missing.*read-only deploy key"):
                helper.fetch_ci()
            fetch.assert_not_called()

    def test_locator_cannot_redirect_the_key_to_another_host_or_unpinned_ref(self):
        for repository, ref in (("https://github.com.invalid/owner/repo", self.ref),
                                ("https://user:password@github.com/owner/repo", self.ref),
                                ("https://github.com/owner/repo", "main")):
            self.locator.update(repository=repository, ref=ref)
            self.write_locator()
            with patch.dict(os.environ, {helper.KEY_ENV: self.secret}), patch.object(helper.domain_registry, "fetch_registry") as fetch:
                with self.assertRaises(ValueError):
                    helper.fetch_ci()
                self.assertNotIn(helper.KEY_ENV, os.environ)
                fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
