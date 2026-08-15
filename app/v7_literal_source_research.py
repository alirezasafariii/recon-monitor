from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urlparse

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION='2.0.2'
RULE_VERSION='2026.08.15.6.33.v7.unseen.capture.research.3'
SHORTLIST=ROOT/'benchmarks/raw/sources/v7_shortlist.json'
OUTPUT=ROOT/'benchmarks/raw/sources/v7_literal_source_research.json'
GHSA_RE=re.compile(r'^GHSA-[0-9a-z-]+$',re.I)
MAX_BYTES=2*1024*1024
URL_RE=re.compile(r"https://[^\s)\]>'\"]+")

def _sha(value:Any)->str:return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def _api_url(reference:str)->str|None:
 p=urlparse(reference)
 if p.scheme!='https' or p.netloc.casefold()!='github.com':return None
 x=[v for v in p.path.split('/') if v]
 if len(x)==2 and x[0].casefold()=='advisories' and GHSA_RE.fullmatch(x[1]):return f'https://api.github.com/advisories/{x[1]}'
 if len(x)>=4:
  owner,repo=x[0],x[1]
  if x[2]=='issues' and x[3].isdigit():return f'https://api.github.com/repos/{owner}/{repo}/issues/{x[3]}'
  if x[2]=='pull' and x[3].isdigit():return f'https://api.github.com/repos/{owner}/{repo}/pulls/{x[3]}'
  if x[2]=='commit' and x[3]:return f'https://api.github.com/repos/{owner}/{repo}/commits/{x[3]}'
  if len(x)>=5 and x[2]=='security' and x[3]=='advisories' and GHSA_RE.fullmatch(x[4]):return f'https://api.github.com/repos/{owner}/{repo}/security-advisories/{x[4]}'
 return None
def _request(url:str,token:str|None)->tuple[int,Any,str|None]:
 h={'Accept':'application/vnd.github+json','User-Agent':'recon-monitor-analysis-633-v7-unseen-passive-research','X-GitHub-Api-Version':'2022-11-28'}
 if token:h['Authorization']=f'Bearer {token}'
 try:
  with urllib.request.urlopen(urllib.request.Request(url,headers=h),timeout=30) as r:
   raw=r.read(MAX_BYTES+1)
   if len(raw)>MAX_BYTES:return int(r.status),None,'snapshot too large'
   return int(r.status),json.loads(raw.decode('utf-8')),None
 except urllib.error.HTTPError as exc:return int(exc.code),None,f'HTTP {exc.code}: '+exc.read().decode('utf-8',errors='replace')[:1500]
 except Exception as exc:return 0,None,f'{type(exc).__name__}: {exc}'
def _links(payload:Mapping[str,Any])->list[str]:
 out=set()
 for key in ('html_url','repository_advisory_url','source_code_location'):
  v=payload.get(key)
  if isinstance(v,str) and v.startswith('https://'):out.add(v)
 for v in payload.get('references') or []:
  if isinstance(v,str) and v.startswith('https://'):out.add(v)
 for m in URL_RE.findall(str(payload.get('body') or payload.get('description') or '')):out.add(m.rstrip('.,;:'))
 return sorted(out)
def build(token:str|None=None)->dict[str,Any]:
 freeze=assert_capture_source_freeze();shortlist=json.loads(SHORTLIST.read_text());rows=[dict(x) for x in shortlist.get('selected') or [] if isinstance(x,Mapping)]
 if len(rows)!=36:raise RuntimeError(f'expected 36 frozen v7 sources, got {len(rows)}')
 literal=set(freeze['literal_adjudication_required_families']);fallback=set(freeze['audit_fallback_families']);entries=[]
 for row in sorted(rows,key=lambda x:str(x.get('family') or '')):
  if row.get('v7_engine_seen') is not False:raise RuntimeError(f"{row.get('family')}: selected row is not explicitly engine-unseen")
  family=str(row.get('family') or '');root=str(row.get('source_root') or '').strip();ref=str(row.get('canonical_advisory_url') or row.get('repository_advisory_url') or row.get('source_code_location') or '').strip();api=_api_url(ref);resolution_basis='canonical_reference'
  if api is None and GHSA_RE.fullmatch(root):
   api=f'https://api.github.com/advisories/{root}';resolution_basis='frozen_ghsa_source_root_fallback'
  if not api:status,payload,error=0,None,'v7 canonical source and frozen source_root are not supported GitHub references'
  else:
   status,payload,error=_request(api,token)
   if status==403 and token:status,payload,error=_request(api,None)
  pm=payload if isinstance(payload,Mapping) else {};targeted=family in literal
  if isinstance(payload,Mapping) and GHSA_RE.fullmatch(root):
   observed=str(payload.get('ghsa_id') or '').strip()
   if observed and observed.casefold()!=root.casefold():raise RuntimeError(f'{family}: GHSA fallback/source identity drift {observed!r}!={root!r}')
  entries.append({'family':family,'source_root':root,'source_project':row.get('source_project'),'canonical_reference':ref,'github_api_reference':api,'source_resolution_basis':resolution_basis,'fetch_status':status,'fetch_error':error,'snapshot_payload':payload,'snapshot_sha256':_sha(payload) if payload is not None else None,'discovered_upstream_links':_links(pm),'has_body_or_description':bool(pm.get('body') or pm.get('description')),'audit_fallback_source':family in fallback,'family_literal_adjudication_required':targeted,'family_literal_adjudication_complete':False if targeted else True,'detector_output_used':False,'admission_output_used':False,'ranking_output_used':False,'scoring_executed':False})
 good=[x for x in entries if x['fetch_status']==200 and x['snapshot_payload'] is not None];bad=[x for x in entries if x not in good]
 if sorted(str(x['family']) for x in entries if x['family_literal_adjudication_required'])!=sorted(literal):raise RuntimeError('v7 literal-adjudication source set drift')
 return {'version':VERSION,'rule_version':RULE_VERSION,'evaluation_kind':'fresh_blind_v7_engine_unseen_passive_public_source_research_unscored','collected_at':datetime.now(timezone.utc).isoformat(),'family_count':36,'successful_snapshot_count':len(good),'successful_families':sorted(str(x['family']) for x in good),'unresolved_snapshot_count':len(bad),'unresolved_sources':[{k:x.get(k) for k in ('family','source_root','source_project','canonical_reference','github_api_reference','source_resolution_basis','fetch_status','fetch_error')} for x in bad],'ghsa_root_fallback_count':sum(x.get('source_resolution_basis')=='frozen_ghsa_source_root_fallback' for x in entries),'entries':entries,'engine_baseline_commit':freeze['engine_baseline_commit'],'source_assignment_commit':freeze['source_assignment_commit'],'source_shortlist_sha256':freeze['source_shortlist_sha256'],'audit_fallback_families':freeze['audit_fallback_families'],'audit_fallback_count':freeze['audit_fallback_count'],'literal_adjudication_required_families':freeze['literal_adjudication_required_families'],'literal_adjudication_required_count':freeze['literal_adjudication_required_count'],'active_target_validation_performed':False,'detector_output_used':False,'admission_output_used':False,'ranking_output_used':False,'v6_first_blind_score_used':False,'v6_first_blind_case_errors_used':False,'corpus_v1_labels_used':False,'corpus_v1_evidence_used':False,'corpus_v1_scores_used':False,'scoring_executed':False,'first_blind_consumed':False}
def main()->int:
 p=argparse.ArgumentParser();p.add_argument('--require-all',action='store_true');a=p.parse_args();r=build(os.environ.get('GITHUB_TOKEN'));OUTPUT.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'family_count':r['family_count'],'successful_snapshot_count':r['successful_snapshot_count'],'unresolved_snapshot_count':r['unresolved_snapshot_count'],'unresolved_sources':r['unresolved_sources'],'ghsa_root_fallback_count':r['ghsa_root_fallback_count'],'audit_fallback_count':r['audit_fallback_count'],'literal_adjudication_required_count':r['literal_adjudication_required_count'],'scoring_executed':False},sort_keys=True))
 return 1 if a.require_all and r['successful_snapshot_count']!=36 else 0
if __name__=='__main__':raise SystemExit(main())
