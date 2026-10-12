import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('reconcile',Path(__file__).resolve().parents[1]/'tools/reconcile_katana_backlog.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
RUN='20261012-test'

def fixture(root, bad=False):
    current=root/'output/hollisterco.com/runs'/RUN/'current';current.mkdir(parents=True)
    (root/'policies').mkdir();(root/'policies/targets.json').write_text(json.dumps({'targets':[{'name':'hollisterco.com','roots':['hollisterco.com']}]}))
    entries={};claims=[]
    for origin in sorted(m.ORIGINS):
        name=m.digest(origin.encode())+'.json'
        old={'contract':'recon.katana.standard.frontier.v1','origin':origin,'binding':'test','items':[{'url':origin,'depth':0,'done':False}]}
        new={**old,'items':[{'url':origin,'depth':0,'done':True}]}
        entries['official/current/katana-frontier/'+name]=m.jsonbytes(old)
        entries['diagnostic/checkpoint/'+name]=m.jsonbytes(new)
        prefix='diagnostic/'+origin.split('//')[1]+'-01/'
        event={'contract':'recon.katana.standard.completion.v1','origin':origin,'stop_reason':'queue_exhausted',
          'attempted_requests':1,'failed_requests':0,'limited_requests':0,'pending_items':1 if bad else 0,'active_items':0}
        entries[prefix+'completion.jsonl']=(json.dumps(event)+'\n').encode()
        entries[prefix+'origins.txt']=(origin+'\n').encode()
        entries[prefix+'urls.txt']=(origin+'/new.js\n').encode()
        entries[prefix+'request-errors.jsonl']=b'';entries[prefix+'stderr.txt']=b''
        claims.append({'origin':origin,'outcome':'completed','done':1,'pending':0})
    entries['diagnostic/summary.json']=m.jsonbytes({'origins':claims})
    entries['official/run-manifest.json']=m.jsonbytes({'run_id':RUN,'target':'hollisterco.com'})
    entries['official/current/katana-batches.jsonl']=b'{"batch":1}\n'
    entries['official/current/katana-urls.txt']=b'https://community.hollisterco.com/\n'
    entries['official/current/katana-completed-origins.txt']=b'https://other.hollisterco.com\n'
    entries['official/current/katana-pending-origins.txt']=('https://community.hollisterco.com\n'+'\n'.join(sorted(m.ORIGINS))+'\n').encode()
    for name,data in entries.items():
        if name.startswith('official/'):
            dest=root/'output/hollisterco.com/runs'/RUN/name.removeprefix('official/');dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
    archive=root/'evidence.zip'
    with zipfile.ZipFile(archive,'w') as z:
        for name,data in entries.items():z.writestr(name,data)
    return current,archive

class ReconcileTests(unittest.TestCase):
    def test_dry_run_apply_idempotence_preserves_pending_and_raw(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);current,archive=fixture(root)
            before=(current/'katana-pending-origins.txt').read_bytes()
            report=m.reconcile(root,archive,RUN)
            self.assertEqual(report['new_unique_raw_urls'],2)
            self.assertEqual((current/'katana-pending-origins.txt').read_bytes(),before)
            with patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=1)):
                report=m.reconcile(root,archive,RUN,True)
            self.assertEqual(report['status'],'registered')
            self.assertEqual((current/'katana-pending-origins.txt').read_text(),'https://community.hollisterco.com\n')
            self.assertIn('community',(current/'katana-urls.txt').read_text())
            self.assertEqual(len(m.jsonlines((current/'katana-batches.jsonl').read_bytes())),3)
            self.assertEqual(m.reconcile(root,archive,RUN,True)['status'],'already_registered')
            self.assertFalse(report['manifest_and_database_updated'])

    def test_incomplete_event_changed_baseline_and_active_process_rejected(self):
        for mode in ['event','baseline','active']:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);current,archive=fixture(root,bad=mode=='event')
                if mode=='baseline':(current/'katana-urls.txt').write_text('changed')
                with patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=0)):
                    with self.assertRaises(ValueError):m.reconcile(root,archive,RUN,True)
                self.assertFalse(list(current.glob('katana-reconcile-*.json')))

    def test_failed_write_restores_all_original_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);current,archive=fixture(root)
            before={p:p.read_bytes() for p in current.rglob('*') if p.is_file()}
            real=m.atomic;failed=False
            def write(path,data,mode=0o600):
                nonlocal failed
                if path.name=='katana-urls.txt' and not failed:
                    failed=True;raise OSError('simulated write failure')
                return real(path,data,mode)
            with patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=1)),patch.object(m,'atomic',side_effect=write):
                with self.assertRaises(OSError):m.reconcile(root,archive,RUN,True)
            after={p:p.read_bytes() for p in current.rglob('*') if p.is_file()}
            self.assertEqual(after,before)

if __name__=='__main__':unittest.main()
