"""No-Docker regression checks for the reproducible CCF integration driver."""
import hashlib
import importlib.util
import io
import json
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('run_ccf',Path(__file__).with_name('run_ccf.py'))
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
spec=importlib.util.spec_from_file_location('reconcile_ccf_inside',Path(__file__).with_name('reconcile_ccf_inside.py'))
reconciliation=importlib.util.module_from_spec(spec);spec.loader.exec_module(reconciliation)


class RunnerGuardTests(unittest.TestCase):
    def test_rejects_mutable_image_and_unsupported_duration_before_docker(self):
        cases=[['--ccf-image','agentdns-ccf:latest'],
               ['--ccf-image','sha256:'+'ab'*32,'--seconds','31'],
               ['--ccf-image','sha256:'+'ab'*32,'--seconds','1199'],
               ['--ccf-image','sha256:'+'ab'*32,'--seconds','3601']]
        for args in cases:
            with self.subTest(args=args),mock.patch.object(sys,'argv',['run_ccf.py',*args]),mock.patch.object(runner,'image_id') as inspect,mock.patch.object(sys,'stderr',new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as failure:runner.main()
                self.assertEqual(failure.exception.code,2)
                inspect.assert_not_called()

    def test_snapshot_is_exact_allowlist_and_survives_source_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'repository';snapshot=Path(directory)/'snapshot'
            expected={}
            for index,name in enumerate(runner.SOURCES):
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
                data=f'fixture-{index}'.encode();path.write_bytes(data)
                expected[name]=hashlib.sha256(data).hexdigest()
            private=root/'.validation/control/member0_privk.pem';private.parent.mkdir(parents=True);private.write_text('unlisted private fixture')
            with mock.patch.object(runner,'REPOSITORY',root):actual=runner.snapshot_sources(snapshot)
            self.assertEqual(actual,expected)
            (root/runner.SOURCES[0]).write_text('later host edit')
            self.assertEqual(hashlib.sha256((snapshot/runner.SOURCES[0]).read_bytes()).hexdigest(),expected[runner.SOURCES[0]])
            self.assertEqual({str(p.relative_to(snapshot)) for p in snapshot.rglob('*') if p.is_file()},set(runner.SOURCES))
            self.assertTrue(all((snapshot/name).stat().st_mode & 0o222 == 0 for name in runner.SOURCES))
            self.assertFalse((snapshot/'.validation').exists())

    def test_every_synchronous_docker_command_has_a_bounded_default(self):
        with mock.patch.object(runner.subprocess,'run') as command:
            runner.execute(['docker','inspect','fixture'])
            self.assertEqual(command.call_args.kwargs['timeout'],60)
            self.assertTrue(command.call_args.kwargs['check'])
            runner.execute(['docker','run','fixture'],timeout=180)
            self.assertEqual(command.call_args.kwargs['timeout'],180)

    def test_control_mount_masks_both_aliases_to_source_read_only(self):
        work=Path('/fixture/work');source=work/'source';results=work/'results'
        options=runner.helper_mounts(work,source,results,'control')
        mounts=options[1::2]
        self.assertIn(str(source)+':/src:ro',mounts)
        self.assertIn(str(work)+':/work',mounts)
        self.assertIn(str(source)+':/work/source:ro',mounts)
        for access in (False,'provision','transfer','replacement-provision','rotation-transfer'):
            mounts=runner.helper_mounts(work,source,results,access)[1::2]
            self.assertIn(str(source)+':/src:ro',mounts)
            self.assertNotIn(str(work)+':/work',mounts)

    def test_final_source_integrity_is_recorded_in_provenance_and_result(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'source';results=Path(directory)/'results'
            source.mkdir();results.mkdir();(source/'helper.py').write_bytes(b'unchanged')
            expected={'helper.py':hashlib.sha256(b'unchanged').hexdigest()}
            provenance={'initial':expected};summary={'status':'passed'}
            report=runner.finalize_source_integrity(source,expected,results,provenance,summary)
            self.assertEqual(report['status'],'passed')
            self.assertEqual(report['verified_source_files'],1)
            self.assertEqual(json.loads((results/'source-integrity.json').read_text()),report)
            self.assertEqual(json.loads((results/'provenance.json').read_text())['post_execution_source_integrity'],report)
            self.assertEqual(json.loads((results/'runner-results.json').read_text())['source_integrity'],report)

    def test_changed_missing_aliased_and_unlisted_source_fail_closed(self):
        for kind in ('changed','missing','symlink','unexpected','unlisted-directory','root-symlink'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);source=root/'source';results=root/'results'
                source.mkdir();results.mkdir();target=source/'helper.py';target.write_bytes(b'expected')
                expected={'helper.py':hashlib.sha256(b'expected').hexdigest()}
                if kind=='changed':target.write_bytes(b'different')
                elif kind=='missing':target.unlink()
                elif kind=='symlink':
                    (root/'outside.py').write_bytes(b'expected');target.unlink();target.symlink_to(root/'outside.py')
                elif kind=='unlisted-directory':
                    (source/'unlisted').mkdir();(source/'unlisted/nested.py').write_bytes(b'extra code')
                elif kind=='root-symlink':
                    source.rename(root/'actual-source');source.symlink_to(root/'actual-source',target_is_directory=True)
                else:(source/'unlisted.py').write_bytes(b'extra code')
                with self.assertRaisesRegex(ValueError,'integrity mismatch'):
                    runner.finalize_source_integrity(source,expected,results,{}, {'status':'passed'})
                self.assertEqual(json.loads((results/'source-integrity.json').read_text())['status'],'failed')
                self.assertEqual(json.loads((results/'runner-results.json').read_text())['status'],'failed')


class ObservationIdentityTests(unittest.TestCase):
    def response(self):
        return {'confirmed_ccf_transaction_id':'2.17',
            'headers':{'x-agentdns-commit-status':'committed','x-agentdns-transaction-id':'2.17'},
            'body':{'observation_status':'committed','observation_tx_id':'2.17','tx_id':'2.17'}}

    def test_all_explicit_fields_match_actual_confirmation(self):
        reconciliation.validate_observation_identity(self.response())

    def test_missing_body_ids_and_mismatched_confirmations_are_rejected(self):
        missing=self.response();missing['body'].pop('observation_tx_id');missing['body'].pop('tx_id')
        variants=[missing]
        for group,field in [('body','observation_tx_id'),('body','tx_id'),('headers','x-agentdns-transaction-id')]:
            for value in (None,'2.18'):
                response=copy.deepcopy(self.response())
                if value is None:response[group].pop(field)
                else:response[group][field]=value
                variants.append(response)
        invalid=self.response();invalid['confirmed_ccf_transaction_id']='18446744073709551616.1';variants.append(invalid)
        for response in variants:
            with self.subTest(response=response),self.assertRaises(ValueError):
                reconciliation.validate_observation_identity(response)


if __name__=='__main__':unittest.main()
