from __future__ import annotations
import copy
import json
import importlib.util
import unittest
from pathlib import Path
spec = importlib.util.spec_from_file_location('release_gate', Path(__file__).resolve().parents[1] / 'app/release_ci_gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
ROOT = Path(__file__).resolve().parents[1]
SHA = 'a' * 40


def fixtures():
    run = {'id': 10, 'head_sha': SHA, 'head_branch': 'main', 'event': 'push',
           'path': '.github/workflows/ci.yml', 'status': 'completed', 'conclusion': 'success', 'run_attempt': 1}
    jobs = [{'name': name, 'run_id': 10, 'head_sha': SHA, 'status': 'completed', 'conclusion': 'success',
             'steps': [{'name': step, 'status': 'completed', 'conclusion': 'success'}
                       for step in ('Unit tests', 'Integration test', gate.CLEANUP)]}
            for name in sorted(gate.REQUIRED_JOBS)]
    return run, jobs


class ReleaseGateTests(unittest.TestCase):
    def test_exact_completed_main_push_with_cleanup_passes(self):
        r, j = fixtures(); self.assertTrue(gate.validate(r, j, SHA))

    def test_branch_pr_old_sha_and_tag_ci_cannot_authorize_release(self):
        r, j = fixtures()
        for field, value in [('event', 'pull_request'), ('head_branch', 'release/foo'), ('head_sha', 'b'*40), ('path', '.github/workflows/other.yml')]:
            changed = {**r, field: value}
            with self.subTest(field=field), self.assertRaises(gate.GateFailure): gate.validate(changed, j, SHA)

    def test_pending_ci_is_not_success(self):
        r, j = fixtures(); r.update(status='in_progress', conclusion=None)
        self.assertFalse(gate.validate(r, j, SHA))

    def test_failed_cancelled_skipped_and_missing_jobs_block(self):
        r, j = fixtures()
        for conclusion in ('failure', 'cancelled', 'skipped', None):
            with self.subTest(conclusion=conclusion), self.assertRaises(gate.GateFailure):
                gate.validate({**r, 'conclusion': conclusion}, j, SHA)
        with self.assertRaises(gate.GateFailure): gate.validate(r, j[:-1], SHA)

    def test_skipped_cleanup_cannot_hide_in_successful_job(self):
        r, j = fixtures()
        next(x for x in j if x['name'].startswith('macOS '))['steps'][-1]['conclusion'] = 'skipped'
        with self.assertRaises(gate.GateFailure): gate.validate(r, j, SHA)

    def test_newest_failed_run_cannot_fall_back_to_older_green(self):
        r, _ = fixtures(); newer = {**r, 'id': 11, 'conclusion': 'failure'}
        self.assertEqual(gate.latest_run([r, newer], SHA)['id'], 11)

    def test_polling_and_pagination_verify_exact_main(self):
        run, jobs = fixtures(); listing_calls = []
        def fetch(path):
            if path == 'git/ref/heads/main': return {'object': {'sha': SHA}}
            if path.startswith('actions/workflows'):
                listing_calls.append(path)
                return {'workflow_runs': [{**run, 'status': 'in_progress', 'conclusion': None} if len(listing_calls)==1 else run]}
            return {'total_count': len(jobs), 'jobs': jobs[:4] if path.endswith('page=1') else jobs[4:]}
        sleeps = []
        result = gate.wait('owner/repo', SHA, fetch=fetch, sleep=sleeps.append, clock=lambda: 0)
        self.assertTrue(result['verified']); self.assertEqual(sleeps, [15])

    def test_changed_main_or_rerun_blocks_publication(self):
        run, jobs = fixtures()
        for mode in ('main', 'rerun'):
            calls = []
            def fetch(path):
                calls.append(path)
                if path == 'git/ref/heads/main':
                    return {'object': {'sha': 'b'*40 if mode=='main' else SHA}}
                if path.startswith('actions/workflows'):
                    return {'workflow_runs': [{**run, 'run_attempt': 2} if mode=='rerun' and calls.count(path)>1 else run]}
                return {'total_count': len(jobs), 'jobs': jobs}
            with self.subTest(mode=mode), self.assertRaises(gate.GateFailure):
                gate.wait('owner/repo', SHA, fetch=fetch, sleep=lambda _: None, clock=lambda: 0)

    def test_no_ci_by_deadline_blocks(self):
        with self.assertRaises(gate.GateFailure):
            gate.wait('owner/repo', SHA, timeout=0, fetch=lambda _: None, clock=lambda: 1)

class PublisherWiringTests(unittest.TestCase):
    def test_publication_is_gated_and_shell_and_embedded_python_parse(self):
        import subprocess
        import re
        path = ROOT / '.github/workflows/verified-release.yml'
        if not path.exists():
            self.skipTest('Installed program layout excludes GitHub workflow files')
        workflow = json.loads(path.read_text())
        job = workflow['jobs']['publish']
        self.assertEqual(job['permissions']['actions'], 'read')
        steps = job['steps']
        gates = [i for i, s in enumerate(steps) if 'verify_release_ci.py' in s.get('run', '')]
        self.assertEqual(len(gates), 2)
        self.assertLess(gates[0], next(i for i,s in enumerate(steps) if s['name'].startswith('Build ZIP')))
        publish = steps[gates[-1]]['run']
        self.assertLess(publish.index('verify_release_ci.py'), publish.index('gh release create'))
        self.assertLess(publish.rindex('verify_release_ci.py'), publish.index('gh release edit'))
        self.assertNotIn('--method DELETE', publish)
        for step in steps:
            if 'run' not in step:
                continue
            run = step['run']
            subprocess.run(['bash', '-n'], input=run, text=True, check=True, capture_output=True)
            for code in re.findall(r"<<'PY'\n(.*?)\nPY", run, re.S):
                compile(code, '<release-workflow>', 'exec')
