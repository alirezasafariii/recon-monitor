#!/usr/bin/env python3
"""Release only an exact main commit with successful post-merge push CI."""
from __future__ import annotations
import argparse
import json
import os
import re
import time
import urllib.error
import urllib.request

REQUIRED_JOBS = {
    'Python 3.11', 'Python 3.13', 'Python 3.14',
    'macOS macos-latest Python 3.14', 'macOS macos-15-intel Python 3.14',
    'API shutdown (macOS)', 'Dashboard acceptance (native Safari)',
}
CLEANUP = 'Command cleanup without resource leaks'


class GateFailure(RuntimeError):
    pass


def latest_run(runs, sha):
    matching = [r for r in runs if r.get('head_sha') == sha and r.get('head_branch') == 'main'
                and r.get('event') == 'push' and r.get('path', '').split('@')[0] == '.github/workflows/ci.yml']
    return max(matching, key=lambda r: r['id']) if matching else None


def validate(run, jobs, sha):
    if latest_run([run], sha) is None:
        raise GateFailure('CI identity differs from release commit/main push')
    if run.get('status') != 'completed':
        return False
    if run.get('conclusion') != 'success':
        raise GateFailure('Post-merge CI failed or was cancelled/skipped')
    by_name = {}
    for j in jobs:
        name = j.get('name')
        if name in by_name:
            raise GateFailure('Duplicate CI job names')
        by_name[name] = j
        if j.get('run_id') != run['id'] or j.get('head_sha') != sha:
            raise GateFailure('Job identity differs from release CI')
        if j.get('status') != 'completed' or j.get('conclusion') != 'success':
            raise GateFailure('A CI job has not completed successfully')
    if not REQUIRED_JOBS <= set(by_name):
        raise GateFailure('Required CI jobs are missing')
    for name in REQUIRED_JOBS:
        if name.startswith('macOS '):
            steps = by_name[name].get('steps', [])
            for step_name in ('Unit tests', 'Integration test', CLEANUP):
                matches = [s for s in steps if s.get('name') == step_name]
                if len(matches) != 1 or matches[0].get('status') != 'completed' or matches[0].get('conclusion') != 'success':
                    raise GateFailure('Required macOS step was skipped or failed')
    return True


def api(repository, suffix):
    request = urllib.request.Request('https://api.github.com/repos/' + repository + '/' + suffix,
        headers={'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
                 'User-Agent': 'recon-monitor-release-gate', 'X-GitHub-Api-Version': '2022-11-28'})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise GateFailure('GitHub CI verification HTTP status ' + str(exc.code)) from None


def wait(repository, sha, timeout=1200, fetch=None, sleep=time.sleep, clock=time.monotonic):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise GateFailure('Invalid repository or full commit SHA')
    fetch = fetch or (lambda suffix: api(repository, suffix))
    deadline = clock() + timeout
    listing = 'actions/workflows/ci.yml/runs?branch=main&event=push&per_page=100'
    while clock() < deadline:
        if fetch('git/ref/heads/main')['object']['sha'] != sha:
            raise GateFailure('main moved; release aborted')
        run = latest_run(fetch(listing)['workflow_runs'], sha)
        if run and run.get('status') == 'completed':
            jobs = []
            page = 1
            while True:
                result = fetch(f"actions/runs/{run['id']}/jobs?filter=latest&per_page=100&page={page}")
                jobs.extend(result['jobs'])
                if len(jobs) >= result['total_count']:
                    break
                if not result['jobs']:
                    raise GateFailure('Incomplete CI job pagination')
                page += 1
            if validate(run, jobs, sha):
                current = latest_run(fetch(listing)['workflow_runs'], sha)
                if (current is None or current['id'] != run['id'] or current.get('run_attempt') != run.get('run_attempt')
                        or current.get('status') != 'completed' or current.get('conclusion') != 'success'):
                    raise GateFailure('CI changed during verification')
                if fetch('git/ref/heads/main')['object']['sha'] != sha:
                    raise GateFailure('main moved during verification')
                return {'commit': sha, 'ci_run': run['id'], 'ci_attempt': run.get('run_attempt'),
                        'required_jobs': sorted(REQUIRED_JOBS), 'verified': True}
        sleep(min(15, max(0, deadline - clock())))
    raise GateFailure('Timed out waiting for completed post-merge CI')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', required=True)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--timeout', type=int, default=1200)
    args = parser.parse_args()
    try:
        print(json.dumps(wait(args.repo, args.sha, args.timeout), sort_keys=True))
    except (GateFailure, OSError, ValueError, KeyError) as exc:
        # Never echo request headers or environment values.
        parser.exit(1, 'Release CI gate failed: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()
