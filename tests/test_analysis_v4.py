from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))

from analysis_engine import run_analysis, replay_analysis, calibration_report, _endpoint_schema
from core import AppPaths, Database, utc_now


class AnalysisV4Tests(unittest.TestCase):
    def make_db(self, td: str):
        paths=AppPaths.from_root(Path(td)); paths.ensure(); db=Database(paths.db)
        now=utc_now()
        db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('run1','4.0.0','success',?,?,?,1)",(now,now,'example.com'))
        details={"status_code":401,"semantic_changed":True,"endpoint_classification":{"primary_category":"admin","confidence":94},"method":"POST","body_fields":["accountId"],"content_type":"application/json"}
        alert_id,_,_=db.upsert_alert('example.com','key1','changed_js','HIGH',78,'Admin export deployed','/api/v3/admin/export/{accountId}',details,'run1')
        db.set_alert_status(alert_id,'interesting','useful')
        return paths,db,alert_id

    def test_schema_has_analysis_tables(self):
        with tempfile.TemporaryDirectory() as td:
            _,db,_=self.make_db(td)
            try:
                tables={row[0] for row in db.all("SELECT name FROM sqlite_master WHERE type='table'")}
                self.assertTrue({'analysis_runs','analysis_results','js_dataflows','endpoint_schemas','deployment_signatures'}.issubset(tables))
                self.assertEqual(db.meta_get('schema_version'),'16')
            finally: db.close()

    def test_hypothesis_evidence_and_endpoint_schema(self):
        with tempfile.TemporaryDirectory() as td:
            paths,db,alert_id=self.make_db(td)
            try:
                result=run_analysis(paths,db,'run1','example.com')
                self.assertEqual(result['alerts'],1)
                row=db.one("SELECT * FROM analysis_results WHERE analysis_id=? AND alert_id=?",(result['analysis_id'],alert_id))
                self.assertIn('authorization boundary',row['hypothesis'])
                against=json.loads(row['evidence_against_json'])
                self.assertTrue(any('401' in item['text'] for item in against))
                schema=json.loads(row['endpoint_schema_json'])
                self.assertIn('accountId',schema['object_identifiers'])
                self.assertEqual(schema['method'],'POST')
            finally: db.close()

    def test_replay_compares_previous_analysis(self):
        with tempfile.TemporaryDirectory() as td:
            paths,db,_=self.make_db(td)
            try:
                first=run_analysis(paths,db,'run1','example.com')
                second=replay_analysis(paths,db,'run1','example.com')
                self.assertNotEqual(first['analysis_id'],second['analysis_id'])
                self.assertIn('replay_comparison',second)
                self.assertEqual(second['replay_comparison']['previous_analysis_id'],first['analysis_id'])
            finally: db.close()

    def test_calibration_buckets(self):
        with tempfile.TemporaryDirectory() as td:
            paths,db,_=self.make_db(td)
            try:
                run_analysis(paths,db,'run1','example.com')
                report=calibration_report(db,'example.com')
                self.assertIn('80-100',report['buckets'])
                self.assertIn('status',report['buckets']['80-100'])
            finally: db.close()


    def test_legacy_null_endpoint_lists_do_not_crash(self):
        with tempfile.TemporaryDirectory() as td:
            paths=AppPaths.from_root(Path(td)); paths.ensure(); db=Database(paths.db)
            try:
                now=utc_now()
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) VALUES('legacy-run','4.0.0','success',?,?,?,1)",(now,now,'example.com'))
                legacy_shapes = [
                    {"diff_summary": {"added_endpoints": None}},
                    {"endpoint_classification": None, "diff_summary": {"added_endpoints": []}},
                    {"endpoint_classification": [None, {"primary_category": "admin", "confidence": 80}]},
                    {"diff_summary": {"added_endpoints": {"primary_category": "export", "confidence": 72}}},
                ]
                for index, details in enumerate(legacy_shapes, start=1):
                    db.upsert_alert('example.com',f'legacy-{index}','changed_js','MEDIUM',55,'Legacy alert',f'/api/legacy/{index}',details,'legacy-run')
                result=run_analysis(paths,db,'legacy-run','example.com')
                self.assertEqual(result['alerts'],len(legacy_shapes))
                self.assertEqual(db.one("SELECT COUNT(*) AS count FROM analysis_results WHERE analysis_id=?",(result['analysis_id'],))['count'],len(legacy_shapes))
            finally:
                db.close()

    def test_endpoint_schema_extracts_identifiers(self):
        schema=_endpoint_schema('/api/accounts/{accountId}/orders?format=csv',{'method':'GET','authentication':'bearer'})
        self.assertIn('accountId',schema['path_parameters'])
        self.assertIn('accountId',schema['object_identifiers'])
        self.assertIn('format',schema['query_parameters'])


if __name__=='__main__': unittest.main()
