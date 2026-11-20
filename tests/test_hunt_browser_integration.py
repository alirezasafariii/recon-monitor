from __future__ import annotations
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import test_hunt_agent as fixtures
import hunt_agent as agent
from core import ReconError

class HuntBrowserIntegrationTests(unittest.TestCase):
    setUp = fixtures.HuntAgentTests.setUp
    def browser_mission(self):
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\nENABLE_ACTIVE_MODULES="yes"\n')
        self.paths.policy.write_text(json.dumps({'targets': [{'name': 'example.test', 'roots': ['example.test'],
            'active': {'confirmation': 'I_AM_AUTHORIZED_FOR_ACTIVE_TESTING'}}]}))
        plan = self.paths.root / 'browser-plan.json'
        plan.write_text(json.dumps({'version': 1, 'target': 'example.test', 'tests': [
            {'id': 'one', 'family': 'reflected_xss', 'url': 'https://example.test/search',
             'input': {'kind': 'query', 'name': 'q'}}]}))
        return plan, agent.create_mission(self.paths, self.db, target='example.test', source_run='RUN-1',
            planner='rules', browser_plan=str(plan), browser_active=True, browser_verify=True)
    def test_browser_is_offered_after_analysis_and_before_cases(self):
        _, data = self.browser_mission()
        data['state']['analysis_id'] = 'AN-1'
        with patch('correlation_engine.investigation_queue', return_value=[]):
            actions = agent.actions_for(self.db, data)
        self.assertEqual(actions[0]['tool'], 'browser')
        with patch('xss_browser.run', return_value={'status': 'incomplete', 'report': 'fixture'}) as execute:
            result = agent.execute_action(self.paths, self.db, data, actions[0], 100)
        self.assertTrue(result['browser_incomplete'])
        self.assertTrue(execute.call_args.kwargs['verify'])
    def test_plan_mutation_refuses_browser_dispatch(self):
        plan, data = self.browser_mission()
        plan.write_text(plan.read_text().replace('/search', '/changed'))
        with patch('xss_browser.run') as execute, self.assertRaisesRegex(ReconError, 'plan changed'):
            agent.execute_action(self.paths, self.db, data, {'tool': 'browser'}, 100)
        execute.assert_not_called()

