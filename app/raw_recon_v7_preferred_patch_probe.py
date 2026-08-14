from __future__ import annotations

import hashlib, json, os, urllib.error, urllib.request
from typing import Any, Mapping
from urllib.parse import urlparse

from raw_recon_corpus import ROOT
from raw_recon_v7_source_firewall import check_candidate, exposure_index
from v7_pre_score_condition_audit import audit_conditions
from v7_source_semantic_audit import audit_row

VERSION='1.0.0'; RULE_VERSION='2026.08.14.6.32.v7.14'
PR=ROOT/'benchmarks/raw/sources/v7_pr_supplement.json'; TARGETED=ROOT/'benchmarks/raw/sources/v7_targeted_supplement.json'; OUT=ROOT/'benchmarks/raw/sources/v7_candidates_patchable.json'

def _request(url:str,token:str|None)->tuple[int,Any,str|None]:
    h={'Accept':'application/vnd.github+json','User-Agent':'recon-monitor-analysis-632-v7-preferred-patch','X-GitHub-Api-Version':'2022-11-28'}
    if token:h['Authorization']=f'Bearer {token}'
    try:
        with urllib.request.urlopen(urllib.request.Request(url,headers=h),timeout=30) as r:return int(r.status),json.loads(r.read(5*1024*1024).decode()),None
    except urllib.error.HTTPError as e:return int(e.code),None,f'HTTP {e.code}: '+e.read().decode(errors='replace')[:1000]
    except Exception as e:return 0,None,f'{type(e).__name__}: {e}'

def _ref(row:Mapping[str,Any])->tuple[str,str,str]|None:
    value=str(row.get('upstream_repository_reference') or row.get('source_code_location') or '').strip();p=urlparse(value);parts=[x for x in p.path.split('/') if x]
    if p.scheme!='https' or p.netloc.casefold()!='github.com' or len(parts)<4:return None
    project=f'{parts[0]}/{parts[1]}'
    if project.casefold()!=str(row.get('source_project') or '').casefold():return None
    if parts[2]=='pull' and parts[3].isdigit():return 'pull',project,parts[3]
    if parts[2]=='commit' and parts[3]:return 'commit',project,parts[3]
    return None

def _patch(route:str,project:str,ident:str,token:str|None)->tuple[int,Any,str|None,str]:
    url=f'https://api.github.com/repos/{project}/pulls/{ident}/files?per_page=100' if route=='pull' else f'https://api.github.com/repos/{project}/commits/{ident}'
    s,p,e=_request(url,token)
    if s==403 and token:s,p,e=_request(url,None)
    return s,p,e,url

def _files(payload:Any,route:str)->list[dict[str,Any]]:
    if route=='pull' and isinstance(payload,list):return [dict(x) for x in payload if isinstance(x,Mapping)]
    if route=='commit' and isinstance(payload,Mapping):return [dict(x) for x in payload.get('files') or [] if isinstance(x,Mapping)]
    return []
def _lines(files:list[dict[str,Any]])->tuple[list[str],list[str],list[str],str]:
    add=[];rem=[];ctx=[];chunks=[]
    for row in files[:100]:
        fn=str(row.get('filename') or '');patch=str(row.get('patch') or '')
        if fn or patch:chunks.append(f'FILE {fn}\n{patch}'[:10000])
        for line in patch.splitlines():
            if line.startswith(('+++','---','@@')):continue
            if line.startswith('+') and line[1:].strip():add.append(line[1:].strip())
            elif line.startswith('-') and line[1:].strip():rem.append(line[1:].strip())
            elif line.startswith(' ') and line[1:].strip():ctx.append(line[1:].strip())
    return add[:400],rem[:400],ctx[:400],'\n'.join(chunks)[:120000]
def _sha(text:str)->str:return hashlib.sha256(text.encode()).hexdigest()
def _load(path):return json.loads(path.read_text())

def probe(token:str|None=None)->dict[str,Any]:
    pr=_load(PR);targeted=_load(TARGETED);pools={}
    for family in sorted(set((pr.get('candidates_by_family') or {}))|set((targeted.get('candidates_by_family') or {}))):
        rows=[]
        for src in (targeted,pr):
            for x in (src.get('candidates_by_family') or {}).get(family) or []:
                if isinstance(x,Mapping):rows.append(dict(x))
        pools[family]=rows
    if len(pools)!=36:raise RuntimeError(f'preferred pool must cover 36 family buckets, got {len(pools)}')
    prior=exposure_index();output={};diag={};calls=0
    for family in sorted(pools):
        kept=[];reasons=[]
        for row in pools[family]:
            fw=check_candidate(row,index=prior)
            if not fw['allowed']:reasons.append('firewall');continue
            ref=_ref(row)
            if not ref:reasons.append('no_patch_ref');continue
            route,project,ident=ref;s,p,e,api=_patch(route,project,ident,token);calls+=1
            if s!=200:reasons.append(f'patch_http_{s}');continue
            files=_files(p,route);added,removed,context,patch_text=_lines(files)
            if not files or not added or not patch_text:reasons.append('patch_has_no_added_fix');continue
            enriched=dict(row);enriched['patch_text']=patch_text;enriched['description']=(str(row.get('description') or '')+'\n\nUPSTREAM PATCH\n'+patch_text).strip()
            passed,hits,score=audit_row(family,enriched);signals,condition_hits=audit_conditions(family,enriched)
            if not passed:reasons.append('family_semantic');continue
            if not signals:reasons.append('condition_semantic');continue
            enriched.update({'family':family,'upstream_repository_reference':f'https://github.com/{project}/{route}/{ident}','patch_probe_passed':True,'patch_probe_version':VERSION,'patch_probe_rule_version':RULE_VERSION,'patch_api_reference':api,'patch_route':route,'patch_file_count':len(files),'patch_added_line_count':len(added),'patch_removed_line_count':len(removed),'patch_context_line_count':len(context),'patch_text_sha256':_sha(patch_text),'patch_added_lines':added,'patch_removed_lines':removed,'patch_context_lines':context,'source_family_audit_passed':True,'source_family_audit_group_hits':hits,'source_family_audit_score':score,'pre_score_expected_condition_signals':signals,'pre_score_condition_source_hits':condition_hits,'selection_uses_v6_score':False,'selection_uses_v6_case_errors':False,'scoring_executed':False,'active_target_validation_performed':False})
            kept=[enriched];break
        output[family]=kept;diag[family]={'input_count':len(pools[family]),'patchable_count':len(kept),'reasons':reasons}
    missing=sorted(f for f,r in output.items() if not r)
    return {'version':VERSION,'rule_version':RULE_VERSION,'evaluation_kind':'fresh_blind_v7_preferred_patch_feasibility_unscored','family_count':36,'candidates_by_family':output,'family_candidate_counts':{f:len(r) for f,r in output.items()},'families_without_candidates':missing,'diagnostics':diag,'patch_api_call_count':calls,'candidate_selection_uses_detector_scores':False,'candidate_selection_uses_admission_results':False,'candidate_selection_uses_ranking_results':False,'candidate_selection_uses_v6_first_blind_score':False,'candidate_selection_uses_v6_first_blind_case_errors':False,'active_target_validation_performed':False,'scoring_executed':False,'first_blind_consumed':False}
def main()->int:
    r=probe(os.environ.get('GITHUB_TOKEN'));OUT.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');print(json.dumps({'family_candidate_counts':r['family_candidate_counts'],'families_without_candidates':r['families_without_candidates'],'patch_api_call_count':r['patch_api_call_count']},sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
