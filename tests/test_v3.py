from __future__ import annotations

import io
import json
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'app'))
from core import AppPaths, Config, Database, TargetPolicy, normalize_url
from execution import BudgetManager, BudgetExceeded, WorkQueue, DatabaseWriter
from storage import ContentAddressedStore
from plugins import PluginManager
from evidence import build_evidence_export
from operations import BackupManager
from recon_monitor import Orchestrator
from session_auth import create_user, verify_user, create_session, parse_session
from api_server import create_token, authenticate


class LoggerStub:
    def info(self,*a,**k): pass
    warn=info; error=info


class Version3Tests(unittest.TestCase):
    def project(self):
        tmp=tempfile.TemporaryDirectory(); root=Path(tmp.name); paths=AppPaths.from_root(root); paths.ensure()
        (root/'config.env').write_text('I_HAVE_AUTHORIZATION="yes"\nDASHBOARD_AUTH_ENABLED="yes"\nDASHBOARD_AUTH_MODE="session"\n')
        (root/'policies').mkdir(exist_ok=True)
        (root/'policies/targets.json').write_text(json.dumps({'defaults':{},'targets':[{'name':'example.com','roots':['example.com']}] }))
        return tmp,paths,Database(paths.db)

    def test_url_canonicalization(self):
        self.assertEqual(normalize_url('HTTPS://Example.COM:443/a//b?utm_source=x&z=2&a=1#x'),'https://example.com/a/b?a=1&z=2')

    def test_budget_and_queue_resume(self):
        tmp,paths,db=self.project()
        try:
            policy=TargetPolicy.from_dict({'name':'example.com','roots':['example.com'],'limits':{'max_http_requests':100,'max_dns_queries':100,'max_download_mb':10,'max_new_assets':10}})
            budget=BudgetManager.create(db,'r','example.com',policy); self.assertEqual(budget.consume('http_requests',50),(50,100))
            with self.assertRaises(BudgetExceeded): budget.consume('http_requests',51)
            q=WorkQueue(db,'r','example.com','js'); self.assertEqual(q.run_item('x',lambda:{'ok':1}),{'ok':1}); self.assertTrue(q.completed('x'))
            self.assertEqual(q.run_item('x',lambda:(_ for _ in ()).throw(Exception('must not run'))),{'ok':1})
        finally: db.close();tmp.cleanup()

    def test_database_writer(self):
        tmp,paths,db=self.project(); db.close(); writer=DatabaseWriter(paths.db)
        try:
            writer.submit(lambda x:x.meta_set('writer_test','ok'))
            check=Database(paths.db); self.assertEqual(check.meta_get('writer_test'),'ok'); check.close()
        finally: writer.close();tmp.cleanup()

    def test_ignore_correlation_lifecycle(self):
        tmp,paths,db=self.project()
        try:
            rid=db.add_ignore_rule('*','new_url','analytics'); self.assertEqual(db.ignore_match('example.com','new_url','/analytics/x'),rid)
            incident=db.correlate_event('example.com','e1','new_url','https://api.example.com/x','Deployment','HIGH',80,'r',{}); self.assertGreater(incident,0)
            db.upsert_asset('example.com','api.example.com',['subfinder','dns'],'r')
            states=db.refresh_asset_lifecycle('example.com','r'); self.assertEqual(states['new'],1)
        finally: db.close();tmp.cleanup()

    def test_content_store_dedup(self):
        tmp,paths,db=self.project()
        try:
            store=ContentAddressedStore(paths,db); d1,p1,c1=store.put(b'abc'); d2,p2,c2=store.put(b'abc')
            self.assertEqual(d1,d2); self.assertEqual(p1,p2); self.assertTrue(c1); self.assertFalse(c2)
            self.assertEqual(int(db.one('SELECT reference_count FROM object_store WHERE sha256=?',(d1,))[0]),2)
        finally: db.close();tmp.cleanup()

    def test_plugins(self):
        tmp,paths,db=self.project()
        try:
            manager=PluginManager(paths,db); names={r['name'] for r in manager.list()}; self.assertIn('javascript',names)
        finally:db.close();tmp.cleanup()

    def test_session_rbac_and_api_token(self):
        tmp,paths,db=self.project()
        try:
            create_user(paths,'alice','very-secure-password','analyst'); ok,role=verify_user(paths,'alice','very-secure-password'); self.assertTrue(ok);self.assertEqual(role,'analyst')
            session=create_session(paths,'alice',role); parsed=parse_session(paths,f'recon_session={session.token}'); self.assertTrue(parsed and parsed.allows('viewer'));self.assertFalse(parsed.allows('admin'))
            token=create_token(db,'test','viewer'); self.assertTrue(authenticate(db,'Bearer '+token)[0])
        finally:db.close();tmp.cleanup()

    def test_evidence_manifest_integrity(self):
        tmp,paths,db=self.project()
        try:
            db.upsert_asset('example.com','api.example.com',['root'],'r')
            name,data=build_evidence_export(db,target='example.com',entity_type='asset',entity_value='api.example.com')
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                manifest=json.loads(z.read('MANIFEST.json')); expected=z.read('MANIFEST.sha256').decode().split()[0]
                import hashlib
                self.assertEqual(hashlib.sha256(z.read('MANIFEST.json')).hexdigest(),expected); self.assertIn('evidence.json',manifest['files'])
        finally:db.close();tmp.cleanup()

    def test_latest_pointer_migrates_legacy_directories(self):
        tmp,paths,db=self.project()
        try:
            target_dir=paths.output/'example.com'; run_dir=target_dir/'runs'/'run-1'; run_dir.mkdir(parents=True)
            (target_dir/'LATEST').mkdir(); (target_dir/'LATEST'/'legacy.txt').write_text('keep')

            # A second differently-cased directory can only exist on a
            # case-sensitive filesystem. Create it when the volume permits it.
            lowercase=target_dir/'latest'
            if not lowercase.exists():
                lowercase.mkdir(); (lowercase/'legacy-link.txt').write_text('keep')

            orchestrator=Orchestrator.__new__(Orchestrator); orchestrator.paths=paths; orchestrator.logger=LoggerStub()
            orchestrator._update_latest_pointers('example.com',run_dir)
            self.assertTrue((target_dir/'LATEST').is_file())
            self.assertEqual((target_dir/'LATEST').read_text().strip(),str(run_dir))

            conventional=target_dir/'latest'
            if conventional.is_symlink():
                link=conventional
            else:
                link=target_dir/'latest-run'
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.resolve(),run_dir.resolve())

            migrated=list(target_dir.glob('LATEST.legacy-*'))
            self.assertEqual(len(migrated),1); self.assertEqual((migrated[0]/'legacy.txt').read_text(),'keep')
            migrated_link=list(target_dir.glob('latest.legacy-*'))
            if migrated_link:
                self.assertEqual((migrated_link[0]/'legacy-link.txt').read_text(),'keep')
        finally: db.close();tmp.cleanup()

    def test_latest_pointer_uses_latest_run_when_names_collide(self):
        tmp,paths,db=self.project()
        try:
            target_dir=paths.output/'example.com'; run_dir=target_dir/'runs'/'run-1'; run_dir.mkdir(parents=True)
            orchestrator=Orchestrator.__new__(Orchestrator); orchestrator.paths=paths; orchestrator.logger=LoggerStub()
            with mock.patch.object(Orchestrator, '_pointer_names_collide', return_value=True):
                orchestrator._update_latest_pointers('example.com',run_dir)
            self.assertTrue((target_dir/'LATEST').is_file())
            self.assertTrue((target_dir/'latest-run').is_symlink())
            self.assertEqual((target_dir/'latest-run').resolve(),run_dir.resolve())
        finally: db.close();tmp.cleanup()

    def test_backup_verify(self):
        tmp,paths,db=self.project()
        try:
            manager=BackupManager(paths,db,LoggerStub()); result=manager.create(); self.assertTrue(manager.verify(result['backup_id'])['ok'])
        finally:db.close();tmp.cleanup()

if __name__=='__main__':unittest.main()
