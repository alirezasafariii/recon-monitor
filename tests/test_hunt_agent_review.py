"""Orchestration regressions: real offline case engines, synthetic live results."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import hunt_agent as agent
from core import AppPaths, utc_now
import test_investigation_case_workflow_v866 as fixtures


class HuntFinalReviewTests(unittest.TestCase):
    def setUp(self):
        temp,self.db=fixtures.InvestigationCaseWorkflowV866Tests().project()
        self.addCleanup(temp.cleanup); self.addCleanup(self.db.close)
        self.paths=AppPaths.from_root(Path(temp.name))
        self.paths.config.write_text('I_HAVE_AUTHORIZATION="yes"\n')
        self.paths.policy.write_text(json.dumps({'targets':[{'name':'example.com','roots':['example.com']}]}))
        self.db.execute("INSERT INTO run_targets(run_id,target,policy_hash,status,started_at,run_dir) VALUES('RUN-1','example.com','fixture','success',?,?)",(utc_now(),str(self.paths.output/'RUN-1')))
        self.data=agent.create_mission(self.paths,self.db,target='example.com',source_run='RUN-1',planner='rules',allow_live=True)
        from investigation_workflow import ensure_cluster_case
        case=ensure_cluster_case(self.db,analysis_id='AN-1',cluster_id=fixtures.SAMPLE_ITEM['cluster_id'],item=fixtures.SAMPLE_ITEM)
        self.cid=case['case_id']
        self.data['state'].update(analysis_id='AN-1',cases={self.cid:{}})
        agent.save(self.db,self.data,'ready')
        from safe_validation import create_validation_plan
        plan=create_validation_plan(self.paths,self.db,self.cid,requested_level='offline')
        self.plan=plan['plan_id']
        # A synthetic approval exercises ordering/status propagation only. The
        # real live executor and its family/scope gates are not invoked.
        self.db.execute("UPDATE validation_plans SET level='passive_live',status='approved',plan_json=? WHERE plan_id=?",(json.dumps({'requests':[{}]}),self.plan))

    def test_live_is_offered_only_after_successful_offline_validation(self):
        actions=agent.actions_for(self.db,self.data)
        self.assertNotIn('live:'+self.plan,[a['id'] for a in actions])
        self.data['steps']=[{'action_id':'validate:'+self.cid,'tool':'validate','status':'completed'}]
        self.assertIn('live:'+self.plan,[a['id'] for a in agent.actions_for(self.db,self.data)])

    def test_failed_offline_validation_does_not_offer_live(self):
        self.data['steps']=[{'action_id':'validate:'+self.cid,'tool':'validate','status':'failed'}]
        self.assertNotIn('live:'+self.plan,[a['id'] for a in agent.actions_for(self.db,self.data)])

    def run_with_live_result(self, status, result):
        import safe_validation
        original=safe_validation.execute_validation_plan
        def execute(paths,config,db,plan_id,**kwargs):
            if plan_id==self.plan:
                db.execute('UPDATE security_cases SET validation_state=?,validation_summary=? WHERE case_id=?',(result,'synthetic live outcome',self.cid))
                return {'run_id':'SYNTHETIC-LIVE','status':status,'result':result,'network_requests':1}
            return original(paths,config,db,plan_id,**kwargs)
        with patch.object(safe_validation,'execute_validation_plan',side_effect=execute),patch('socket.socket.connect',side_effect=AssertionError('unexpected target request')):
            output=agent.run_mission(self.paths,self.db,self.data['mission_id'])
        return output,agent.mission(self.db,self.data['mission_id'])

    def test_safety_stop_remains_a_gap_with_engine_status_preserved(self):
        output,stored=self.run_with_live_result('stopped_for_safety','stopped_for_safety')
        self.assertEqual(output['status'],'completed_with_gaps')
        live=next(s for s in stored['steps'] if s['tool']=='live')
        self.assertEqual(live['status'],'partial')
        self.assertEqual(live['result']['engine_status'],'stopped_for_safety')

    def test_later_live_case_state_is_not_overwritten_by_offline_validation(self):
        output,stored=self.run_with_live_result('completed','strengthened')
        self.assertEqual(output['status'],'completed')
        self.assertEqual([s['tool'] for s in stored['steps']],['validate','live','report'])
        self.assertEqual(self.db.one('SELECT validation_state FROM security_cases WHERE case_id=?',(self.cid,))[0],'strengthened')

if __name__=='__main__':unittest.main()
