from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION='2.0.0'
RULE_VERSION='2026.08.15.6.33.v7.unseen.capture.plan.1'
SHORTLIST=ROOT/'benchmarks/raw/sources/v7_shortlist.json'
LABEL_SCHEMA=ROOT/'benchmarks/raw/sources/v7_literal_label_schema.json'
SOURCE_RESEARCH=ROOT/'benchmarks/raw/sources/v7_literal_source_research.json'
OUTPUT=ROOT/'benchmarks/raw/sources/v7_literal_capture_plan.json'
EVIDENCE_ROOT=ROOT/'benchmarks/raw/sources/v7_capture_evidence'
VARIANTS=('positive','near_miss','secure_negative','sparse_noisy')
ALLOWED_CAPTURE_METHODS=('http_exchange','cli_output','packet_or_log_capture','regression_test_output','repository_test_fixture','passive_source_snapshot')
PURPOSE={
 'positive':'Literal source-grounded observation proving the target condition from the frozen fresh source or its upstream regression/PoC. No detector-generated fixture.',
 'near_miss':'Independent source-grounded similar/confounding observation that does not satisfy the decisive condition. No mutation of the positive row.',
 'secure_negative':'Implemented fixed, patched, unaffected, or enforced-control observation showing the target condition absent. Recommendation text alone is forbidden.',
 'sparse_noisy':'Independent partial/noisy source observation insufficient for positive admission. No field deletion or mutation of another variant.',
}

def _sha(path:Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()
def _slug(value:Any)->str: return ''.join(ch if ch.isalnum() else '-' for ch in str(value or '').strip().casefold()).strip('-')

def build()->dict[str,Any]:
    freeze=assert_capture_source_freeze(); shortlist=json.loads(SHORTLIST.read_text()); labels=json.loads(LABEL_SCHEMA.read_text()); research=json.loads(SOURCE_RESEARCH.read_text())
    rows=[dict(x) for x in shortlist.get('selected') or [] if isinstance(x,Mapping)]; by_family={str(x.get('family') or ''):x for x in rows}
    if len(rows)!=36 or set(by_family)!=set(DETECTOR_SPECS): raise RuntimeError('v7 capture plan requires 36 frozen detector families')
    if labels.get('family_count')!=36 or labels.get('scoring_executed') is not False: raise RuntimeError('v7 label vocabulary invalid')
    if research.get('successful_snapshot_count')!=36 or research.get('unresolved_snapshot_count')!=0: raise RuntimeError('v7 canonical source research incomplete')
    for key in ('source_assignment_commit','engine_baseline_commit','source_shortlist_sha256'):
        expected=freeze['source_assignment_commit'] if key=='source_assignment_commit' else freeze['engine_baseline_commit'] if key=='engine_baseline_commit' else freeze['source_shortlist_sha256']
        if research.get(key)!=expected: raise RuntimeError(f'v7 source research {key} drift')
    research_by_family={str(x.get('family') or ''):x for x in research.get('entries') or [] if isinstance(x,Mapping)}
    requirements=[]; present=0; literal_required=[]; audit_fallback=[]
    for family in sorted(by_family):
        source=by_family[family]; snap=research_by_family.get(family) or {}
        if str(snap.get('source_root') or '').casefold()!=str(source.get('source_root') or '').casefold(): raise RuntimeError(f'{family}: source research root drift')
        if str(snap.get('source_project') or '').casefold()!=str(source.get('source_project') or '').casefold(): raise RuntimeError(f'{family}: source research project drift')
        targeted=snap.get('family_literal_adjudication_required') is True; fallback=snap.get('audit_fallback_source') is True
        if targeted: literal_required.append(family)
        if fallback: audit_fallback.append(family)
        for kind in VARIANTS:
            path=EVIDENCE_ROOT/f'{_slug(family)}--{_slug(kind)}.json'; exists=path.exists(); present+=int(exists)
            requirements.append({'capture_id':f'v7-{family}-{kind}','family':family,'case_kind':kind,'source_root':source.get('source_root'),'source_project':source.get('source_project'),
                'canonical_source_reference':source.get('canonical_advisory_url') or source.get('repository_advisory_url') or source.get('source_code_location'),
                'required_evidence_path':path.relative_to(ROOT).as_posix(),'evidence_present':exists,'evidence_sha256':_sha(path) if exists else None,'source_snapshot_sha256':snap.get('snapshot_sha256'),
                'variant_purpose':PURPOSE[kind],'allowed_capture_methods':list(ALLOWED_CAPTURE_METHODS),'source_snapshot_required':True,'raw_sha256_required':True,
                'independent_literal_observation_required':True,'synthetic_fixture_generation_forbidden':True,'cross_variant_mutation_forbidden':True,
                'detector_output_may_not_be_used':True,'admission_output_may_not_be_used':True,'ranking_output_may_not_be_used':True,
                'v6_first_blind_score_may_not_be_used':True,'v6_first_blind_case_errors_may_not_be_used':True,'corpus_v1_label_evidence_score_may_not_be_used':True,
                'engine_seen_source_forbidden':True,'audit_fallback_source':fallback,'family_literal_adjudication_required':targeted,
                'positive_family_confirmation_required_before_nonpositive_publish':targeted,'family_target_is_final_before_literal_evidence':False if targeted else True})
    if len(requirements)!=144: raise RuntimeError(f'v7 plan cardinality mismatch: {len(requirements)}')
    if sorted(literal_required)!=sorted(freeze['literal_adjudication_required_families']): raise RuntimeError('v7 literal-adjudication family set drift')
    if sorted(audit_fallback)!=sorted(freeze['audit_fallback_families']): raise RuntimeError('v7 audit-fallback family set drift')
    return {'version':VERSION,'rule_version':RULE_VERSION,'evaluation_kind':'fresh_blind_v7_engine_unseen_literal_capture_acquisition_plan_unscored',
        'engine_baseline_commit':freeze['engine_baseline_commit'],'source_assignment_commit':freeze['source_assignment_commit'],'source_shortlist_sha256':_sha(SHORTLIST),
        'label_schema_sha256':_sha(LABEL_SCHEMA),'source_research_sha256':_sha(SOURCE_RESEARCH),'family_count':36,'variant_count_per_family':4,'required_capture_count':144,
        'evidence_present_count':present,'evidence_missing_count':144-present,'all_evidence_present':present==144,'capture_methods_allowed':list(ALLOWED_CAPTURE_METHODS),
        'audit_fallback_families':sorted(audit_fallback),'audit_fallback_count':len(audit_fallback),'literal_adjudication_required_families':sorted(literal_required),
        'literal_adjudication_required_count':len(literal_required),'requirements':requirements,'detector_output_used':False,'admission_output_used':False,'ranking_output_used':False,
        'v6_first_blind_score_used':False,'v6_first_blind_case_errors_used':False,'corpus_v1_labels_used':False,'corpus_v1_evidence_used':False,'corpus_v1_scores_used':False,
        'scoring_executed':False,'first_blind_consumed':False}

def main()->int:
    r=build(); OUTPUT.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n'); print(json.dumps({k:r[k] for k in ('family_count','required_capture_count','evidence_present_count','evidence_missing_count','audit_fallback_count','literal_adjudication_required_count','scoring_executed')},sort_keys=True)); return 0

if __name__=='__main__': raise SystemExit(main())
