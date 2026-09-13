"""Host ownership and failed-container evidence regressions for the CI fixture."""
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import bind_workspace

spec=importlib.util.spec_from_file_location('memory_runner',Path(__file__).with_name('run.py'))
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)


class PrivateBindTests(unittest.TestCase):
    def test_named_key_copy_does_not_weaken_private_host_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            host=Path(directory)/'host';host.mkdir(mode=0o700)
            key=host/'bind-key.conf';key.write_bytes(b'private-test-key');key.chmod(0o600)
            with mock.patch.object(bind_workspace.tempfile,'tempdir',directory):
                target=bind_workspace.workspace('secondary',key)
            self.assertNotEqual(target.parent,host)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE((target/'key.conf').stat().st_mode),0o600)
            self.assertEqual((target/'key.conf').read_bytes(),key.read_bytes())
            self.assertEqual(stat.S_IMODE(host.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE(key.stat().st_mode),0o600)

    def test_diagnostics_select_only_state_and_keep_raw_logs_private(self):
        state={'Status':'exited','Running':False,'OOMKilled':False,'ExitCode':0,'Env':['PRIVATE=value']}
        replies=[subprocess.CompletedProcess([],0,json.dumps(state),''),
                 subprocess.CompletedProcess([],0,b'rawstdout',b'rawstderr')]
        with tempfile.TemporaryDirectory() as directory,mock.patch.object(runner.subprocess,'run',side_effect=replies) as run:
            root=Path(directory);runner.diagnostics(root,'isolated-case')
            public=json.loads((root/'container-state.json').read_text())
            self.assertFalse(public['OOMKilled']);self.assertEqual(public['ExitCode'],0)
            self.assertNotIn('Env',public)
            self.assertEqual(run.call_args_list[0].args[0],['docker','inspect','--format','{{json .State}}','isolated-case'])
            for path in root.glob('*.private.log'):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)

    def test_dead_container_cannot_reuse_early_readiness_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'container-ready').write_text('host\n')
            response=subprocess.CompletedProcess([],0,'{"Running":false}','')
            with mock.patch.object(runner,'checked',return_value=response),self.assertRaisesRegex(RuntimeError,'exited before readiness'):
                runner.wait_container(root,'dead')

    def test_stalled_docker_cleanup_does_not_mask_test_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with mock.patch.object(runner.subprocess,'run',side_effect=subprocess.TimeoutExpired('docker',15)):
                self.assertFalse(runner.remove_container(root,'stalled'))

    def test_timed_out_creation_still_tracks_owned_container(self):
        container=runner.OwnedContainer(Path('/run-unique'),'unique-name')
        with mock.patch.object(runner,'checked',side_effect=subprocess.TimeoutExpired('docker',180)) as command:
            with self.assertRaises(subprocess.TimeoutExpired):container.start('-d','test-image')
        self.assertTrue(container.attempted)
        self.assertEqual(command.call_args.args[:6],('docker','run','--name','unique-name','--label','agentdns.acceptance.run=run-unique'))

    def test_missing_container_is_harmless_but_other_owner_cannot_be_removed(self):
        variants=[(subprocess.CompletedProcess([],1,'','Error: No such object: unique'),True),
                  (subprocess.CompletedProcess([],0,'{"agentdns.acceptance.run":"another-run"}',''),False)]
        for reply,expected in variants:
            with self.subTest(expected=expected),mock.patch.object(runner.subprocess,'run',return_value=reply) as run:
                self.assertEqual(runner.remove_container(Path('/run-unique'),'unique'),expected)
                self.assertEqual(run.call_count,1)

    def test_monitor_failure_does_not_skip_container_or_runtime_and_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);container=runner.OwnedContainer(root,'owned');container.attempted=True
            monitor=mock.Mock();monitor.poll.return_value=None;monitor.terminate.side_effect=OSError('test failure')
            runtime=mock.Mock();runtime.poll.return_value=None
            with mock.patch.object(runner,'diagnostics'),mock.patch.object(runner,'remove_container',return_value=False) as remove:
                errors=runner.cleanup(root,container,[monitor],runtime)
            runtime.terminate.assert_called_once();runtime.wait.assert_called_once();remove.assert_called_once()
            self.assertEqual(len(errors),2)
            with self.assertRaisesRegex(RuntimeError,'cleanup failed'):runner.publish_success(root,{'tests':'passed'},errors)
            self.assertFalse((root/'acceptance-results.json').exists())
            self.assertEqual(json.loads((root/'failure.json').read_text())['phase'],'cleanup')

    def test_original_test_error_survives_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);container=runner.OwnedContainer(root,'owned');container.attempted=True
            original=AssertionError('original validation failure')
            with mock.patch.object(runner,'diagnostics'),mock.patch.object(runner,'remove_container',return_value=False):
                with self.assertRaises(AssertionError) as raised:
                    try:raise original
                    finally:runner.cleanup(root,container,[],None)
            self.assertIs(raised.exception,original)


if __name__=='__main__':unittest.main()
