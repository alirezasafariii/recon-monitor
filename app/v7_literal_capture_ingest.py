from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from v7_literal_capture_verify import ALLOWED_BASES, _canon, _id, _sha_json

VERSION='1.0.0'; RULE_VERSION='2026.08.14.6.32.v7.1'
PLAN=ROOT/'benchmarks/raw/sources/v7_literal_capture_plan.json'; SHORTLIST=ROOT/'benchmarks/raw/sources/v7_shortlist.json'
CAPTURES=ROOT/'benchmarks/raw/sources/v7_literal_captures.jsonl'; REPORT=ROOT/'benchmarks/raw/sources/v7_literal_capture_ingest_report.json'

def _sha(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()

def build(*,require_complete:bool=True)->tuple[list[dict[str,Any]],dict[str,Any]]:
    plan=json.loads(PLAN.read_text()); shortlist=json.loads(SHORTLIST.read_text()); selected={str(x.get('family') or ''):dict(x) for x in shortlist.get('selected') or [] if isinstance(x,Mapping)}
    if len(plan.get('requirements') or [])!=144 or len(selected)!=36 or set(selected)!=set(DETECTOR_SPECS):raise RuntimeError('v7 ingest requires sealed 144-plan and 36-family shortlist')
    if plan.get('scoring_executed') is not False or shortlist.get('scoring_executed') is not False:raise RuntimeError('v7 ingest requires unscored inputs')
    rows=[];missing=[];errors=[];seen_hashes=set()
    for req in plan['requirements']:
        family=str(req.get('family') or '');kind=str(req.get('case_kind') or '');cid=str(req.get('capture_id') or f'{family}/{kind}');rel=str(req.get('required_evidence_path') or '');path=ROOT/rel
        if not path.exists():missing.append(cid);continue
        digest=_sha(path)
        if digest in seen_hashes:errors.append(f'{cid}: reused evidence content');continue
        seen_hashes.add(digest);e=json.loads(path.read_text());src=selected.get(family)
        if not isinstance(e,Mapping) or src is None:errors.append(f'{cid}: invalid evidence/family');continue
        for key,wanted in [('family',family),('case_kind',kind),('source_root',src.get('source_root')),('source_project',src.get('source_project'))]:
            if _id(e.get(key))!=_id(wanted):errors.append(f'{cid}: evidence.{key} drift')
        raw=e.get('raw') if isinstance(e.get('raw'),Mapping) else None
        if not raw:errors.append(f'{cid}: raw missing');continue
        raw_sha=_sha_json(raw)
        if str(e.get('raw_sha256') or '').lower()!=raw_sha:errors.append(f'{cid}: raw hash invalid')
        adj=e.get('adjudication') if isinstance(e.get('adjudication'),Mapping) else {};basis=str(adj.get('basis') or '')
        if basis not in ALLOWED_BASES:errors.append(f'{cid}: unsupported adjudication basis')
        for field in ('detector_output_used','admission_output_used','ranking_output_used','v6_first_blind_score_used','v6_first_blind_case_errors_used'):
            if adj.get(field) is not False:errors.append(f'{cid}: adjudication.{field} must be false')
        signals=[str(x) for x in adj.get('expected_condition_signals') or [] if str(x)]
        if set(signals)-set(DETECTOR_SPECS[family].condition_signals):errors.append(f'{cid}: noncanonical condition')
        if kind=='positive' and not signals:errors.append(f'{cid}: positive signal missing')
        if kind!='positive' and signals:errors.append(f'{cid}: non-positive signal forbidden')
        snap=e.get('source_snapshot') if isinstance(e.get('source_snapshot'),Mapping) else {}
        rows.append({'family':family,'case_kind':kind,'source_root':src.get('source_root'),'source_project':src.get('source_project'),'source_date':e.get('captured_at'),'raw':dict(raw),'expected_condition_signals':signals,'provenance':{'literal_capture':True,'capture_reference':e.get('capture_reference'),'captured_at':e.get('captured_at'),'capture_method':e.get('capture_method'),'raw_sha256':raw_sha,'evidence_path':rel,'evidence_sha256':digest,'source_snapshot_sha256':snap.get('content_sha256'),'adjudication_basis':basis,'detector_output_used':False,'admission_output_used':False,'ranking_output_used':False,'v6_first_blind_score_used':False,'v6_first_blind_case_errors_used':False}})
    if require_complete and missing:errors.append(f'v7 evidence incomplete: {len(missing)} missing')
    if require_complete and len(rows)!=144:errors.append(f'v7 ingest valid rows must be 144: {len(rows)}')
    report={'version':VERSION,'rule_version':RULE_VERSION,'evaluation_kind':'fresh_blind_v7_literal_capture_ingest_unscored','plan_sha256':_sha(PLAN),'shortlist_sha256':_sha(SHORTLIST),'require_complete':require_complete,'valid_capture_count':len(rows),'missing_capture_count':len(missing),'missing_capture_ids':missing,'error_count':len(errors),'errors':errors,'passed':not errors,'detector_output_used':False,'admission_output_used':False,'ranking_output_used':False,'v6_first_blind_score_used':False,'v6_first_blind_case_errors_used':False,'scoring_executed':False,'first_blind_consumed':False}
    return rows,report

def main()->int:
    p=argparse.ArgumentParser();p.add_argument('--allow-incomplete',action='store_true');a=p.parse_args();rows,r=build(require_complete=not a.allow_incomplete);REPORT.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');
    if r['passed']:CAPTURES.write_text('\n'.join(_canon(x) for x in rows)+('\n' if rows else ''))
    print(json.dumps(r,indent=2,sort_keys=True));return 0 if r['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
