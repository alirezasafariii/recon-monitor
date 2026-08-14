from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from raw_recon_v4_corpus import V4_VALID_METHODS
from v7_capture_guard import assert_capture_source_freeze
from v7_literal_capture_plan import ALLOWED_CAPTURE_METHODS, EVIDENCE_ROOT, OUTPUT as PLAN

VARIANTS={'positive','near_miss','secure_negative','sparse_noisy'}
ALLOWED_BASES={'source_observation','upstream_regression','patched_control','source_log_or_trace','repository_test_fixture'}
ALLOWED_SNAPSHOT_ROLES={'canonical_source','linked_upstream_observation','patched_or_unaffected_control'}


def _canonical(value:Any)->str: return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def _sha(value:Any)->str: return hashlib.sha256(_canonical(value).encode()).hexdigest()

def _plan()->tuple[dict[tuple[str,str],dict[str,Any]],dict[str,Any]]:
    doc=json.loads(PLAN.read_text())
    if doc.get('scoring_executed') is not False or doc.get('first_blind_consumed') is not False: raise RuntimeError('v7 plan must remain unscored/unconsumed')
    rows={}
    for r in doc.get('requirements') or []:
        if isinstance(r,Mapping): rows[(str(r.get('family') or ''),str(r.get('case_kind') or ''))]=dict(r)
    if len(rows)!=144: raise RuntimeError(f'v7 plan must contain 144 requirements: {len(rows)}')
    return rows,doc

def _obj(row:Mapping[str,Any],key:str,path:Path)->dict[str,Any]:
    value=row.get(key)
    if not isinstance(value,Mapping) or not value: raise RuntimeError(f'{path}: {key} object required')
    return dict(value)


def _targeted_positive_confirmation(row:Mapping[str,Any], family:str, path:Path)->bool:
    adj=row.get('adjudication')
    if not isinstance(adj,Mapping): return False
    if adj.get('family_literal_confirmed') is not True: return False
    if str(adj.get('family_literal_family') or '').strip()!=family: return False
    if not str(adj.get('family_literal_confirmation_basis') or '').strip(): return False
    signals=[str(x).strip() for x in adj.get('family_literal_confirmation_signals') or [] if str(x).strip()]
    if not signals: return False
    return True


def _existing_positive_confirmed(family:str)->bool:
    plan,doc=_plan(); req=plan.get((family,'positive'))
    if not req: return False
    dest=(ROOT/str(req['required_evidence_path'])).resolve()
    if not dest.exists(): return False
    try: row=json.loads(dest.read_text())
    except Exception: return False
    return _targeted_positive_confirmation(row,family,dest)


def publish(capture_dir:Path)->dict[str,Any]:
    freeze=assert_capture_source_freeze()
    plan,plan_doc=_plan()
    if plan_doc.get('engine_baseline_commit')!=freeze['engine_baseline_commit']: raise RuntimeError('v7 plan engine baseline drift')
    if plan_doc.get('source_assignment_commit')!=freeze['source_assignment_commit']: raise RuntimeError('v7 plan source assignment drift')
    files=sorted(Path(capture_dir).rglob('*.json'))
    if not files: raise RuntimeError('no v7 capture JSON files')

    parsed=[]; seen=set()
    for path in files:
        row=json.loads(path.read_text()); family=str(row.get('family') or '').strip(); kind=str(row.get('case_kind') or '').strip(); key=(family,kind)
        if key not in plan or kind not in VARIANTS: raise RuntimeError(f'{path}: unknown v7 family/variant {family}/{kind}')
        if key in seen: raise RuntimeError(f'{path}: duplicate {family}/{kind}')
        seen.add(key); parsed.append((path,row,family,kind,plan[key]))

    # For targeted-fallback sources, a literal positive confirmation is a hard
    # prerequisite for publishing any other variant. It may be supplied in this
    # batch or already exist as immutable published evidence.
    batch_confirmed=set()
    for path,row,family,kind,req in parsed:
        if req.get('family_literal_adjudication_required') is True and kind=='positive':
            if not _targeted_positive_confirmation(row,family,path):
                raise RuntimeError(f'{path}: targeted fallback positive requires literal family confirmation')
            batch_confirmed.add(family)
    for path,row,family,kind,req in parsed:
        if req.get('family_literal_adjudication_required') is True and kind!='positive':
            if family not in batch_confirmed and not _existing_positive_confirmed(family):
                raise RuntimeError(f'{path}: targeted fallback requires confirmed positive family evidence before {kind}')

    written=[]; families=set()
    for path,row,family,kind,req in parsed:
        families.add(family)
        if str(row.get('source_root') or req['source_root']).casefold()!=str(req['source_root']).casefold(): raise RuntimeError(f'{path}: source_root drift')
        if str(row.get('source_project') or req['source_project']).casefold()!=str(req['source_project']).casefold(): raise RuntimeError(f'{path}: source_project drift')
        ref=str(row.get('capture_reference') or '').strip(); method=str(row.get('capture_method') or '').strip(); captured=str(row.get('captured_at') or '').strip()
        if not ref.startswith('https://'): raise RuntimeError(f'{path}: https capture_reference required')
        if not captured: raise RuntimeError(f'{path}: captured_at required')
        if method not in ALLOWED_CAPTURE_METHODS: raise RuntimeError(f'{path}: unsupported capture method {method}')
        raw=_obj(row,'raw',path); collector=_obj(row,'collector',path); snapshot=_obj(row,'source_snapshot',path); adj=_obj(row,'adjudication',path)
        if str(raw.get('method') or '').upper() not in V4_VALID_METHODS: raise RuntimeError(f'{path}: invalid raw.method')
        if not isinstance(raw.get('details',{}),Mapping): raise RuntimeError(f'{path}: raw.details must be object')
        if str(snapshot.get('reference') or '')!=ref or 'payload' not in snapshot: raise RuntimeError(f'{path}: snapshot binding invalid')
        role=str(snapshot.get('snapshot_role') or 'canonical_source')
        if role not in ALLOWED_SNAPSHOT_ROLES: raise RuntimeError(f'{path}: unsupported snapshot_role {role}')
        signals=[str(x) for x in adj.get('expected_condition_signals') or [] if str(x)]
        if kind=='positive' and not signals: raise RuntimeError(f'{path}: positive expected_condition_signals required')
        if kind!='positive' and signals: raise RuntimeError(f'{path}: non-positive cannot carry expected signals')
        if str(adj.get('basis') or '') not in ALLOWED_BASES: raise RuntimeError(f'{path}: unsupported adjudication basis')
        if not str(adj.get('notes') or '').strip(): raise RuntimeError(f'{path}: adjudication notes required')
        for field in ('detector_output_used','admission_output_used','ranking_output_used'):
            if adj.get(field) is not False: raise RuntimeError(f'{path}: adjudication.{field} must be false')
        for field in ('v6_first_blind_score_used','v6_first_blind_case_errors_used','corpus_v1_labels_used','corpus_v1_evidence_used','corpus_v1_scores_used'):
            if adj.get(field,False) is not False: raise RuntimeError(f'{path}: forbidden contamination flag {field}')
        if req.get('family_literal_adjudication_required') is True and kind=='positive' and not _targeted_positive_confirmation(row,family,path):
            raise RuntimeError(f'{path}: literal family confirmation missing')
        raw_sha=_sha(raw); snap_sha=_sha(snapshot['payload'])
        if req.get('source_snapshot_sha256') and snap_sha!=str(req['source_snapshot_sha256']):
            if role not in {'linked_upstream_observation','patched_or_unaffected_control'}:
                raise RuntimeError(f'{path}: snapshot differs from canonical without explicit linked/control role')
        evidence={
            'schema_version':'1.1','evaluation_kind':'fresh_blind_v7_literal_source_evidence','family':family,'case_kind':kind,
            'source_root':req['source_root'],'source_project':req['source_project'],'captured_at':captured,'capture_reference':ref,
            'capture_method':method,'collector':collector,
            'engine_baseline_commit':freeze['engine_baseline_commit'],'source_assignment_commit':freeze['source_assignment_commit'],
            'family_literal_adjudication_required':bool(req.get('family_literal_adjudication_required')),
            'source_snapshot':{'reference':ref,'retrieved_at':str(snapshot.get('retrieved_at') or captured),'payload':snapshot['payload'],'content_sha256':snap_sha,'snapshot_role':role},
            'adjudication':dict(adj),'raw':raw,'raw_sha256':raw_sha,'scoring_executed':False,'first_blind_consumed':False,
        }
        dest=(ROOT/str(req['required_evidence_path'])).resolve(); dest.relative_to(EVIDENCE_ROOT.resolve()); dest.parent.mkdir(parents=True,exist_ok=True)
        rendered=json.dumps(evidence,indent=2,sort_keys=True,ensure_ascii=False)+'\n'
        if dest.exists() and dest.read_text()!=rendered: raise RuntimeError(f'refusing to overwrite non-identical v7 evidence: {dest}')
        if not dest.exists(): dest.write_text(rendered)
        written.append(dest.relative_to(ROOT).as_posix())
    return {
        'published_capture_count':len(written),'families':sorted(families),'evidence_paths':sorted(written),
        'engine_baseline_commit':freeze['engine_baseline_commit'],'source_assignment_commit':freeze['source_assignment_commit'],
        'targeted_family_confirmed_in_batch':sorted(batch_confirmed),'scoring_executed':False,'first_blind_consumed':False,
        'v6_first_blind_score_used':False,'v6_first_blind_case_errors_used':False,
        'corpus_v1_labels_used':False,'corpus_v1_evidence_used':False,'corpus_v1_scores_used':False,
    }


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument('capture_dir',type=Path); a=p.parse_args(); print(json.dumps(publish(a.capture_dir),indent=2,sort_keys=True)); return 0

if __name__=='__main__': raise SystemExit(main())
