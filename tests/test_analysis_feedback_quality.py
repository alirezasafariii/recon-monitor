from __future__ import annotations
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from core import AppPaths,Database,utc_now
from analysis_engine import _quality_snapshot,analysis_quality,calibration_report,run_analysis

class FeedbackQualityTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.paths=AppPaths.from_root(Path(temporary.name));self.paths.ensure()
        self.db=Database(self.paths.db);self.addCleanup(self.db.close)
        guard=patch('socket.socket.connect',side_effect=AssertionError('No network in quality tests'));guard.start();self.addCleanup(guard.stop)
        now=utc_now()
        self.db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('r','8.8.3','success',?,?,?,1)",(now,now,'example.test'))
    def alert(self,key,state='new',target='example.test'):
        alert,_,_=self.db.upsert_alert(target,key,'changed_js','HIGH',78,'Saved observation','/api/admin/export',{},'r')
        if state!='new': self.db.set_alert_status(alert,state,'test feedback')
        return alert
    def analyze(self,target='example.test'):
        return run_analysis(self.paths,self.db,'r',target)['analysis_id']
    def test_empty_feedback_is_unknown(self):
        value=_quality_snapshot(self.db,'empty','example.test')
        self.assertIsNone(value['precision_proxy']);self.assertIsNone(value['false_positive_proxy'])
        self.assertEqual(value['feedback_status'],'insufficient_feedback')
        for bucket in calibration_report(self.db)['buckets'].values():
            self.assertEqual(bucket['status'],'insufficient_feedback');self.assertIsNone(bucket['calibration_gap'])
    def test_unreviewed_analysis_is_unknown_and_reads_do_not_write(self):
        self.alert('new');analysis=self.analyze()
        before=self.db.one('SELECT COUNT(*) n FROM analysis_quality_snapshots')['n']
        for _ in range(2):
            value=analysis_quality(self.db,'example.test');self.assertEqual(value['analysis_id'],analysis)
            self.assertIsNone(value['precision_proxy']);self.assertEqual(value['source_run_id'],'r')
        self.assertEqual(before,self.db.one('SELECT COUNT(*) n FROM analysis_quality_snapshots')['n'])
        for bucket in calibration_report(self.db,'example.test')['buckets'].values():
            self.assertEqual(bucket['reviewed_count'],0);self.assertIsNone(bucket['observed_useful_rate'])
    def test_measured_zero_stays_zero(self):
        self.alert('noisy','false_positive');self.analyze()
        value=analysis_quality(self.db,'example.test')
        self.assertEqual(value['precision_proxy'],0);self.assertEqual(value['false_positive_proxy'],1)
        self.assertEqual(value['feedback_count'],1)
    def test_false_positive_denominator_remains_all_alerts(self):
        self.alert('useful','interesting');self.alert('noisy','ignored');self.alert('unreviewed')
        value=_quality_snapshot(self.db,'synthetic','example.test')
        self.assertEqual(value['precision_proxy'],.5);self.assertEqual(value['false_positive_proxy'],.333)
    def test_selected_target_does_not_use_other_target_feedback(self):
        self.alert('selected');selected=self.analyze()
        self.alert('other','interesting','other.test');self.analyze('other.test')
        value=analysis_quality(self.db,'example.test')
        self.assertEqual(value['analysis_id'],selected);self.assertEqual(value['alerts'],1);self.assertIsNone(value['precision_proxy'])
        self.assertEqual(analysis_quality(self.db,'other.test')['precision_proxy'],1)
    def test_failed_analysis_is_not_calibrated(self):
        self.alert('saved','interesting');analysis=self.analyze()
        self.db.execute("UPDATE analysis_runs SET status='failed' WHERE id=?",(analysis,))
        self.assertEqual(sum(bucket['count'] for bucket in calibration_report(self.db)['buckets'].values()),0)
    def test_replays_are_scored_results_not_unique_feedback(self):
        self.alert('saved','interesting');self.analyze();self.analyze()
        report=calibration_report(self.db,'example.test')
        self.assertEqual(sum(v['count'] for v in report['buckets'].values()),2)
        self.assertEqual(sum(v['reviewed_count'] for v in report['buckets'].values()),2)
        self.assertEqual(analysis_quality(self.db,'example.test')['feedback_count'],1)
if __name__=='__main__':unittest.main()
