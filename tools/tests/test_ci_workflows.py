"""CI trust-boundary regressions: hosted runners, immutable actions, public artifacts."""
from pathlib import Path
import tempfile
import unittest

import yaml

ROOT=Path(__file__).resolve().parents[2]


class WorkflowPolicyTests(unittest.TestCase):
    def workflows(self):
        # BaseLoader preserves GitHub's literal `on` and boolean-like inputs.
        return [yaml.load(path.read_text(),Loader=yaml.BaseLoader)
                for path in (ROOT/'.github/workflows').glob('*.yml')]

    def test_untrusted_changes_run_on_hosted_workers_with_immutable_actions(self):
        for workflow in self.workflows():
            self.assertIn('pull_request',workflow['on'])
            self.assertIn('merge_group',workflow['on'])
            self.assertNotIn('pull_request_target',workflow['on'])
            self.assertEqual(workflow['permissions'],{'contents':'read'})
            for job in workflow['jobs'].values():
                self.assertEqual(job['runs-on'],'ubuntu-24.04')
                self.assertLessEqual(int(job['timeout-minutes']),60)
                for step in job['steps']:
                    if 'uses' in step:
                        self.assertRegex(step['uses'],r'^[A-Za-z0-9_./-]+@[0-9a-f]{40}$')
                    if step.get('uses','').startswith('actions/checkout@'):
                        self.assertEqual(step['with']['persist-credentials'],'false')

    def test_public_artifact_patterns_exclude_private_fixture_material(self):
        workflow=yaml.load((ROOT/'.github/workflows/rust-port.yml').read_text(),Loader=yaml.BaseLoader)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);work=root/'.validation/integration/run-example';work.mkdir(parents=True)
            public={'initial-results.json','failure.json','container-state.json','bind-secondary.log'}
            private={'config.json','bind-key.conf','tsig.key','ca.key','state.sealed','container-stderr.private.log'}
            for name in public|private:(work/name).write_text('fixture')
            uploads=[step['with'] for job in workflow['jobs'].values() for step in job['steps']
                     if step.get('uses','').startswith('actions/upload-artifact@')]
            self.assertEqual(len(uploads),3)
            for upload in uploads:
                self.assertEqual(upload['include-hidden-files'],'false')
                self.assertEqual(upload['if-no-files-found'],'error')
            mail=next(upload for upload in uploads if upload['name']=='secondary-mail-public-results')
            selected={file.name for pattern in mail['path'].splitlines() for file in root.glob(pattern)}
            self.assertTrue(public<=selected)
            self.assertFalse(private&selected)
            self.assertEqual(next(x for x in uploads if x['name']=='ccf-secondary-public-results')['path'],'.validation/ci-ccf-public/')

    def test_codeql_covers_current_production_languages_without_legacy_sdk(self):
        workflow=yaml.load((ROOT/'.github/workflows/codeql-analysis.yml').read_text(),Loader=yaml.BaseLoader)
        job=workflow['jobs']['analyze']
        self.assertEqual(set(job['strategy']['matrix']['language']),{'rust','cpp','python','javascript-typescript','actions'})
        init=next(step for step in job['steps'] if step.get('uses','').startswith('github/codeql-action/init@'))
        self.assertEqual(init['with']['build-mode'],'none')
        self.assertFalse(any('6.0.' in step.get('run','') for step in job['steps']))


if __name__=='__main__':unittest.main()
