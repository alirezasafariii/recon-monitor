"""Register verified external Katana continuation evidence in a stopped run.

Does not edit database, manifest lifecycle, or checkpoint item completion flags.
Imports the producer's final documents and preserves all attempt artifacts.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from core import AppPaths, PolicySet, RunLock, Logger
from katana_completion import read_completion, origin_key, unique_fields

ORIGINS = {'https://giftcards.hollisterco.com', 'https://helpsurvey.hollisterco.com'}

def digest(data): return hashlib.sha256(data).hexdigest()
def parsed(data): return json.loads(data, object_pairs_hook=unique_fields)
def lines(data): return [x for x in data.decode().splitlines() if x.strip()]
def jsonlines(data): return [parsed(x) for x in lines(data)]
def jsonbytes(value): return (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode()

def atomic(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.katana-reconcile-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)

def reconcile(root, archive, run_id, apply=False):
    root=Path(root).resolve();archive=Path(archive).resolve()
    if Path(run_id).name!=run_id or run_id in {'.','..'}: raise ValueError('Invalid run ID')
    paths=AppPaths.from_root(root)
    run=root/'output/hollisterco.com/runs'/run_id
    current=run/'current'
    if not current.is_dir():raise ValueError('Run artifacts missing')
    ident=digest(archive.read_bytes())[:16]
    marker=current/f'katana-reconcile-{ident}.json'
    if marker.exists():return {'status':'already_registered','receipt':str(marker)}
    policy=PolicySet.load(paths).select('hollisterco.com')[0]
    writes={};expected={};removed=[]
    with zipfile.ZipFile(archive) as z:
        names=z.namelist()
        if len(names)!=len(set(names)):raise ValueError('Duplicate archive entries')
        if sum(info.file_size for info in z.infolist())>128*1024*1024 or any(info.file_size>(64 if info.filename=='official/run-manifest.json' else 20)*1024*1024 for info in z.infolist()):raise ValueError('Oversized artifact')
        manifest=parsed(z.read('official/run-manifest.json'))
        if manifest.get('run_id')!=run_id or manifest.get('target')!='hollisterco.com':raise ValueError('Manifest target/run mismatch')
        summary=parsed(z.read('diagnostic/summary.json'))
        claims={row['origin']:row for row in summary['origins']}
        if set(claims)!=ORIGINS or any(row['outcome']!='completed' or row['pending']!=0 for row in claims.values()):raise ValueError('Diagnostic not completed')
        base={}
        for name in ['katana-batches.jsonl','katana-urls.txt','katana-pending-origins.txt','katana-completed-origins.txt']:
            data=z.read('official/current/'+name);base[name]=data;expected[current/name]=data
        batches=jsonlines(base['katana-batches.jsonl'])
        number=max(row['batch'] for row in batches)
        all_urls=lines(base['katana-urls.txt'])
        counts={};added_attempts=[]
        with tempfile.TemporaryDirectory() as tmp:
            for origin in sorted(ORIGINS):
                if not policy.url_in_scope(origin):raise ValueError('Origin outside current policy')
                filename=digest(origin.encode())+'.json'
                official=current/'katana-frontier'/filename
                old_data=z.read('official/current/katana-frontier/'+filename)
                new_data=z.read('diagnostic/checkpoint/'+filename)
                old,new=parsed(old_data),parsed(new_data)
                for doc in (old,new):
                    if doc.get('contract')!='recon.katana.standard.frontier.v1' or doc.get('origin')!=origin:raise ValueError('Invalid frontier contract/origin')
                if new['binding']!=old['binding']:raise ValueError('Frontier binding mismatch')
                old_items={row['url']:row for row in old['items']}
                new_items={row['url']:row for row in new['items']}
                if len(new_items)!=len(new['items']) or not new_items or any(r.get('done') is not True for r in new_items.values()):raise ValueError('Final frontier not exhausted/unique')
                if len(new_items)!=claims[origin]['done']:raise ValueError('Summary count mismatch')
                for url,row in old_items.items():
                    if url not in new_items or {k:v for k,v in row.items() if k!='done'}!={k:v for k,v in new_items[url].items() if k!='done'}:raise ValueError('Original frontier item changed or removed')
                for url in new_items:
                    if not policy.url_in_scope(url):raise ValueError('Frontier URL outside current policy')
                prefix='diagnostic/'+origin.split('//')[1]+'-'
                attempts=sorted({n.split('/')[1] for n in names if n.startswith(prefix) and n.endswith('/completion.jsonl')})
                if not attempts:raise ValueError('Missing continuation events')
                for index, attempt in enumerate(attempts):
                    event=z.read('diagnostic/'+attempt+'/completion.jsonl')
                    path=Path(tmp)/'completion.jsonl';path.write_bytes(event)
                    detail=read_completion(path,[origin],returncode=0,timed_out=False)[origin_key(origin)]
                    if detail['status']=='unknown':raise ValueError('Invalid producer event')
                    if index==len(attempts)-1 and detail['status']!='completed':raise ValueError('Last event not complete')
                    if z.read('diagnostic/'+attempt+'/origins.txt').decode().strip()!=origin:raise ValueError('Attempt input mismatch')
                    raw=z.read('diagnostic/'+attempt+'/urls.txt');all_urls.extend(lines(raw))
                    number+=1
                    stem=f'katana-imported-{ident}-{number:03d}'
                    mapping={'completion.jsonl':stem+'-completion.jsonl','urls.txt':stem+'-urls.txt','request-errors.jsonl':stem+'-request-errors.jsonl','stderr.txt':stem+'-stderr.txt',
                        'completion.jsonl.provenance.jsonl':stem+'-completion.jsonl.provenance.jsonl','completion.jsonl.diagnostics.jsonl':stem+'-completion.jsonl.diagnostics.jsonl'}
                    for source,dest in mapping.items():
                        entry='diagnostic/'+attempt+'/'+source
                        if entry in names:writes[current/dest]=z.read(entry)
                    batch={'batch':number,'origins':1,'origin_urls':[origin], 'origin_completion':{origin_key(origin):detail},
                        'completion_artifact':mapping['completion.jsonl'],'completion_contract':'v1','completion_verified':detail['status']=='completed',
                        'request_errors_artifact':mapping['request-errors.jsonl'],'urls_artifact':mapping['urls.txt'],
                        'status':'completed' if detail['status']=='completed' else 'completion_unverified','stop_reason':detail['stop_reason'],
                        'frontier_checkpoint_enabled':True,'imported_external_continuation':True,'request_accounting':'producer_attempted_requests',
                        'attempted_requests':detail['counters']['attempted_requests'],'rate_limit':1,'crawl_seconds_per_origin':60,'lines':len(lines(raw))}
                    batches.append(batch);added_attempts.append(batch)
                expected[official]=old_data;writes[official]=new_data
                lock=official.with_suffix('.json.lock')
                if lock.exists():expected[lock]=lock.read_bytes();removed.append(lock)
                counts[origin]=len(new_items)
        urls=list(dict.fromkeys(all_urls))
        writes[current/'katana-urls.txt']=(''.join(u+'\n' for u in urls)).encode()
        writes[current/'katana-batches.jsonl']=(''.join(json.dumps(row,ensure_ascii=False)+'\n' for row in batches)).encode()
        completed=list(dict.fromkeys(lines(base['katana-completed-origins.txt'])+sorted(ORIGINS)))
        pending=[o for o in lines(base['katana-pending-origins.txt']) if o not in ORIGINS]
        writes[current/'katana-completed-origins.txt']=(''.join(o+'\n' for o in completed)).encode()
        writes[current/'katana-pending-origins.txt']=(''.join(o+'\n' for o in pending)).encode()
    for path,data in expected.items():
        if path.read_bytes()!=data:raise ValueError('Official evidence changed since snapshot: '+path.name)
    for path in writes:
        if path not in expected and path.exists():raise ValueError('Import artifact collision')
    report={'status':'prepared','run_id':run_id,'archive_sha256':digest(archive.read_bytes()),'completed_origins':counts,
        'imported_attempts':len(added_attempts),'producer_attempted_requests':sum(r['attempted_requests'] for r in added_attempts),
        'new_unique_raw_urls':len(set(urls)-set(lines(base['katana-urls.txt']))),'pending_origins':pending,
        'manifest_and_database_updated':False,'next_step':'normal resume to analyze imported URLs and regenerate report'}
    if not apply:return report
    result=subprocess.run(['pgrep','-x','katana'],capture_output=True,text=True)
    if result.returncode!=1:raise ValueError('Katana may be running; import stopped')
    with RunLock(paths.lock,Logger(paths,verbose=False)):
        for path,data in expected.items():
            if path.read_bytes()!=data:raise ValueError('Concurrent evidence change')
        backup=paths.backups/('katana-reconcile-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        backup.mkdir(parents=True,mode=0o700)
        originals={path:(path.read_bytes(),path.stat().st_mode&0o777) if path.exists() else None for path in {*writes,*removed,marker}}
        for path,value in originals.items():
            if value is not None:
                dest=backup/path.relative_to(root);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,dest)
        report.update(status='registered',backup=str(backup))
        atomic(backup/'plan.json',jsonbytes(report))
        try:
            for path,data in writes.items():atomic(path,data,originals[path][1] if originals[path] else 0o600)
            for path in removed:path.unlink()
            atomic(marker,jsonbytes(report))
        except BaseException:
            for path,value in originals.items():
                if value is None:path.unlink(missing_ok=True)
                else:atomic(path,*value)
            raise
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--archive',required=True);p.add_argument('--run',required=True);p.add_argument('--apply',action='store_true');a=p.parse_args()
    print(json.dumps(reconcile(a.root,a.archive,a.run,a.apply),ensure_ascii=False,indent=2))
