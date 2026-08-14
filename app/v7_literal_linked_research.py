from __future__ import annotations

import argparse, hashlib, json, os, urllib.error, urllib.request
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlparse

from raw_recon_corpus import ROOT

VERSION='1.0.0';RULE_VERSION='2026.08.14.6.32.v7.1'
SOURCE_RESEARCH=ROOT/'benchmarks/raw/sources/v7_literal_source_research.json';OUTPUT=ROOT/'benchmarks/raw/sources/v7_literal_linked_research.json';MAX_BYTES=3*1024*1024

def _sha(v:Any)->str:return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def _request(url:str,token:str|None)->tuple[int,Any,str|None]:
    h={'Accept':'application/vnd.github+json','User-Agent':'recon-monitor-analysis-632-v7-linked-research','X-GitHub-Api-Version':'2022-11-28'}
    if token:h['Authorization']=f'Bearer {token}'
    try:
        with urllib.request.urlopen(urllib.request.Request(url,headers=h),timeout=30) as r:
            raw=r.read(MAX_BYTES+1)
            if len(raw)>MAX_BYTES:return int(r.status),None,'linked snapshot too large'
            return int(r.status),json.loads(raw.decode()),None
    except urllib.error.HTTPError as exc:return int(exc.code),None,f'HTTP {exc.code}: '+exc.read().decode(errors='replace')[:1200]
    except Exception as exc:return 0,None,f'{type(exc).__name__}: {exc}'
def _route(ref:str)->tuple[str,str|None,str|None]:
    p=urlparse(ref);parts=[x for x in p.path.split('/') if x]
    if p.scheme!='https' or p.netloc.casefold()!='github.com' or len(parts)<4:return 'unsupported',None,None
    owner,repo,kind,ident=parts[:4];base=f'https://api.github.com/repos/{owner}/{repo}'
    if kind=='commit':return 'commit',f'{base}/commits/{ident}',None
    if kind=='pull' and ident.isdigit():return 'pull',f'{base}/pulls/{ident}',f'{base}/pulls/{ident}/files?per_page=100'
    if kind=='issues' and ident.isdigit():return 'issue',f'{base}/issues/{ident}',None
    if kind=='security' and len(parts)>=5 and parts[3]=='advisories':return 'repository_advisory',f'{base}/security-advisories/{parts[4]}',None
    return 'unsupported',None,None

def build(token:str|None=None)->dict[str,Any]:
    src=json.loads(SOURCE_RESEARCH.read_text());entries=[]
    if src.get('successful_snapshot_count')!=36 or src.get('scoring_executed') is not False:raise RuntimeError('v7 canonical research incomplete')
    for row in src.get('entries') or []:
        if not isinstance(row,Mapping):continue
        ref=str(row.get('upstream_repository_reference') or '');route,url,files_url=_route(ref);status,payload,error=(0,None,'unsupported upstream reference') if not url else _request(url,token)
        files_status=None;files_payload=None;files_error=None
        if status==403 and token and url:status,payload,error=_request(url,None)
        if files_url and status==200:
            files_status,files_payload,files_error=_request(files_url,token)
            if files_status==403 and token:files_status,files_payload,files_error=_request(files_url,None)
        combined={'primary':payload,'files':files_payload} if files_url else payload
        ok=status==200 and payload is not None and (not files_url or files_status==200)
        entries.append({'family':row.get('family'),'source_root':row.get('source_root'),'source_project':row.get('source_project'),'reference':ref,'route':route,'api_reference':url,'files_api_reference':files_url,'fetch_status':status,'fetch_error':error,'files_fetch_status':files_status,'files_fetch_error':files_error,'snapshot_payload':combined,'snapshot_sha256':_sha(combined) if ok else None,'successful':ok,'active_target_validation_performed':False,'detector_output_used':False,'admission_output_used':False,'ranking_output_used':False,'v6_first_blind_score_used':False,'v6_first_blind_case_errors_used':False,'scoring_executed':False})
    good=[x for x in entries if x['successful']];bad=[x for x in entries if not x['successful']]
    return {'version':VERSION,'rule_version':RULE_VERSION,'evaluation_kind':'fresh_blind_v7_passive_linked_upstream_research_unscored','collected_at':datetime.now(timezone.utc).isoformat(),'family_count':36,'successful_link_snapshot_count':len(good),'unresolved_link_snapshot_count':len(bad),'unresolved':[{'family':x['family'],'reference':x['reference'],'route':x['route'],'fetch_status':x['fetch_status'],'fetch_error':x['fetch_error'],'files_fetch_status':x['files_fetch_status'],'files_fetch_error':x['files_fetch_error']} for x in bad],'entries':entries,'active_target_validation_performed':False,'detector_output_used':False,'admission_output_used':False,'ranking_output_used':False,'v6_first_blind_score_used':False,'v6_first_blind_case_errors_used':False,'scoring_executed':False,'first_blind_consumed':False}
def main()->int:
    p=argparse.ArgumentParser();p.add_argument('--require-all',action='store_true');a=p.parse_args();r=build(os.environ.get('GITHUB_TOKEN'));OUTPUT.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');print(json.dumps({k:r[k] for k in ('family_count','successful_link_snapshot_count','unresolved_link_snapshot_count','scoring_executed')},sort_keys=True));return 1 if a.require_all and r['successful_link_snapshot_count']!=36 else 0
if __name__=='__main__':raise SystemExit(main())
