from __future__ import annotations

import json
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v7_source_firewall import check_candidate, exposure_index

VERSION='1.0.0'; RULE_VERSION='2026.08.14.6.32.v7.17'
BASE=ROOT/'benchmarks/raw/sources/v7_candidates_patchable.json'
SUPPLEMENT=ROOT/'benchmarks/raw/sources/v7_missing5_supplement.json'
OUT=BASE


def _load(path):
    value=json.loads(path.read_text())
    if not isinstance(value,Mapping): raise RuntimeError(f'expected object: {path}')
    return dict(value)

def _key(row:Mapping[str,Any])->tuple[str,str,str]:
    return (str(row.get('source_root') or '').casefold(),str(row.get('source_project') or '').casefold(),str(row.get('upstream_repository_reference') or row.get('source_code_location') or '').casefold())

def merge()->dict[str,Any]:
    base=_load(BASE); sup=_load(SUPPLEMENT)
    for name,r in [('base',base),('supplement',sup)]:
        if r.get('scoring_executed') is not False: raise RuntimeError(f'{name} must remain unscored')
        if r.get('candidate_selection_uses_v6_first_blind_score') is not False or r.get('candidate_selection_uses_v6_first_blind_case_errors') is not False: raise RuntimeError(f'{name} contaminated by v6 result')
    pools={str(f):[dict(x) for x in rows if isinstance(x,Mapping)] for f,rows in (base.get('candidates_by_family') or {}).items()}
    if len(pools)!=36: raise RuntimeError(f'base patchable pool must cover 36 buckets, got {len(pools)}')
    prior=exposure_index()
    for family,rows in (sup.get('candidates_by_family') or {}).items():
        family=str(family); existing={_key(x) for x in pools.setdefault(family,[])}
        for raw in rows or []:
            if not isinstance(raw,Mapping): continue
            row=dict(raw)
            if row.get('patch_probe_passed') is not True or int(row.get('patch_added_line_count') or 0)<=0: continue
            if not row.get('pre_score_expected_condition_signals'): continue
            if not check_candidate(row,index=prior)['allowed']: continue
            if _key(row) in existing: continue
            pools[family].append(row); existing.add(_key(row))
    missing=sorted(f for f,rows in pools.items() if not rows)
    result=dict(base)
    result.update({
        'version':VERSION,'rule_version':RULE_VERSION,'evaluation_kind':'fresh_blind_v7_merged_patch_feasible_pool_unscored',
        'family_count':36,'candidates_by_family':pools,'family_candidate_counts':{f:len(rows) for f,rows in pools.items()},
        'families_without_candidates':missing,'patchable_family_count':36-len(missing),'final_five_supplement_merged':True,
        'candidate_selection_uses_detector_scores':False,'candidate_selection_uses_admission_results':False,'candidate_selection_uses_ranking_results':False,
        'candidate_selection_uses_v6_first_blind_score':False,'candidate_selection_uses_v6_first_blind_case_errors':False,
        'active_target_validation_performed':False,'scoring_executed':False,'first_blind_consumed':False,
    })
    return result

def main()->int:
    r=merge();OUT.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'patchable_family_count':r['patchable_family_count'],'families_without_candidates':r['families_without_candidates'],'family_candidate_counts':r['family_candidate_counts']},sort_keys=True))
    return 0 if not r['families_without_candidates'] else 2
if __name__=='__main__': raise SystemExit(main())
