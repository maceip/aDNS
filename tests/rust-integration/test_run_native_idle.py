"""Offline orchestration guards; fake observers are never acceptance evidence."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('run_native_idle',Path(__file__).with_name('run_native_idle.py'))
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)


class Process:
    def __init__(self,code):self.returncode=code
    def poll(self):return self.returncode


class NativeIdleGuards(unittest.TestCase):
    def test_result_waits_for_cleanup_and_source_integrity(self):
        for outcome in ('success','relative-output','observer-failure','source-tamper','public-tamper','public-extra'):
            with self.subTest(outcome=outcome),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);output=root/'run'
                cert=root/'cert.pem';cert.write_text('public certificate fixture')
                anchor=root/'anchor.conf';anchor.write_text('public anchor fixture')
                cleanup_calls=[]
                def spawn(arguments,**kwargs):
                    self.assertTrue(all(value.startswith('/') for value in arguments if ':/src:ro' in value or ':/public:ro' in value or value.endswith(':/results')))
                    mount=next(value for value in arguments if value.endswith(':/results'))
                    result=Path(mount[:-len(':/results')]);label=result.name
                    name={'status':'status-results.json','dnssec':'remote-idle-results.json','load':'results.json'}[label]
                    (result/name).write_text(json.dumps({'fixture_only':True}))
                    if outcome=='source-tamper':
                        (output/'source/unlisted.py').write_text('unexpected importable code')
                    elif outcome=='public-tamper':
                        (output/'public/trust-anchor.conf').write_text('changed anchor')
                    elif outcome=='public-extra':
                        (output/'public/unlisted.pem').write_text('unexpected public trust input')
                    return Process(1 if outcome=='observer-failure' else 0)
                def cleanup(arguments,**kwargs):
                    self.assertFalse((output/'results/runner-results.json').exists(),'premature final result before cleanup')
                    cleanup_calls.append(arguments)
                    return subprocess.CompletedProcess(arguments,1,b'',b'No such container')
                argv=['run_native_idle','--primary','192.0.2.1','--secondary','192.0.2.2','--service-cert',str(cert),'--anchor',str(anchor),'--output','run' if outcome=='relative-output' else str(output)]
                with mock.patch.object(sys,'argv',argv),mock.patch.object(runner.subprocess,'Popen',side_effect=spawn),mock.patch.object(runner.subprocess,'run',side_effect=cleanup),mock.patch.object(runner.signal,'signal'),contextlib.redirect_stdout(io.StringIO()):
                    previous=Path.cwd()
                    try:
                        os.chdir(root)
                        if outcome in ('success','relative-output'):runner.main()
                        else:
                            with self.assertRaises((ValueError,RuntimeError)):runner.main()
                    finally:os.chdir(previous)
                self.assertEqual(len(cleanup_calls),3)
                report=json.loads((output/'results/runner-results.json').read_text())
                self.assertEqual(report['status'],'passed' if outcome in ('success','relative-output') else 'failed')
                self.assertEqual(report['source_integrity']['status'],'failed' if outcome=='source-tamper' else 'passed')
                self.assertEqual(report['public_input_integrity']['status'],'failed' if outcome in ('public-tamper','public-extra') else 'passed')

    def test_private_key_input_is_rejected_before_container_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);cert=root/'cert.pem';anchor=root/'anchor.conf'
            cert.write_text('-----BEGIN PRIVATE KEY-----\nfixture');anchor.write_text('public fixture')
            argv=['run_native_idle','--primary','192.0.2.1','--secondary','192.0.2.2','--service-cert',str(cert),'--anchor',str(anchor),'--output',str(root/'run')]
            with mock.patch.object(sys,'argv',argv),mock.patch.object(runner.subprocess,'Popen') as spawn:
                with self.assertRaises(ValueError):runner.main()
                spawn.assert_not_called()


if __name__ == '__main__':unittest.main()
