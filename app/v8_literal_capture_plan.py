from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT

VERSION='1.0.1'
RULE_VERSION='2026.08.14.6.32.v8.2'
SHORTLIST=ROOT/'benchmarks/raw/sources/v8_shortlist.json'
LABEL_SCHEMA=ROOT/'benchmarks/raw/sources/v8_literal_label_schema.json'
SOURCE_RESEARCH=ROOT/'benchmarks/raw/sources/v8_literal_source_research.json'
LINKED_RESEARCH=ROOT/'benchmarks/raw/sources/v8_literal_linked_research.json'
OUTPUT=ROOT/'benchmarks/raw/sources/v8_literal_capture_plan.json'
EVIDENCE_ROOT=ROOT/'benchmarks/raw/sources/v8_capture_evidence'
VARIANTS=('positive','near_miss','secure_negative','sparse_noisy')
ALLOWED_CAPTURE_METHODS=('http_exchange','cli_output','packet_or_log_capture','regression_test_output','repository_test_fixture','passive_source_snapshot')
PURPOSE={
 'positive':'Literal source-grounded observation proving the target condition from the fresh selected source or its upstream regression/PoC. No detector-generated fixture.',
 'near_miss':'Independent source-grounded similar/confounding observation that does not satisfy the decisive condition. No mutation of the positive row.',
 'secure_negative':'Implemented fixed, patched, unaffected, or enforced-control observation showing the target condition absent. Recommendation text alone is forbidden.',
 'sparse_noisy':'Independent partial/noisy source observation insufficient for positive admission. No field deletion or mutation of another variant.',
}

def _sha(path: Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()
def _slug(value: Any)->str: return ''.join(ch if ch.isalnum() else '-' for ch in str(value or '').strip().casefold()).strip('-')


def build()->dict[str,Any]:
    shortlist=json.loads(SHORTLIST.read_text());labels=json.loads(LABEL_SCHEMA.read_text());research=json.loads(SOURCE_RESEARCH.read_text());linked=json.loads(LINKED_RESEARCH.read_text())
    rows=[dict(x) for x in shortlist.get('selected') or [] if isinstance(x,Mapping)];by_family={str(x.get('family') or ''):x for x in rows}
    if len(rows)!=36 or set(by_family)!=set(DETECTOR_SPECS): raise RuntimeError('v8 capture plan requires 36 selected detector families')
    if shortlist.get('scoring_executed') is not False or shortlist.get('first_blind_consumed') is not False: raise RuntimeError('v8 shortlist must remain unscored')
    if shortlist.get('selection_uses_v6_first_blind_score') is not False or shortlist.get('selection_uses_v6_first_blind_case_errors') is not False: raise RuntimeError('v8 shortlist contaminated by v6 result')
    if not isinstance(shortlist.get('firewall'),Mapping) or shortlist['firewall'].get('passed') is not True: raise RuntimeError('v8 shortlist firewall must pass')
    if labels.get('family_count')!=36 or labels.get('scoring_executed') is not False: raise RuntimeError('v8 label vocabulary invalid')
    if research.get('successful_snapshot_count')!=36 or research.get('unresolved_snapshot_count')!=0: raise RuntimeError('v8 canonical source research incomplete')
    if linked.get('successful_link_snapshot_count')!=36 or linked.get('unresolved_link_snapshot_count')!=0: raise RuntimeError('v8 linked upstream research incomplete')
    research_by_family={str(x.get('family') or ''):x for x in research.get('entries') or [] if isinstance(x,Mapping)}
    linked_by_family={str(x.get('family') or ''):x for x in linked.get('entries') or [] if isinstance(x,Mapping)}
    requirements=[];present=0
    for family in sorted(by_family):
        source=by_family[family];snap=research_by_family.get(family) or {};link=linked_by_family.get(family) or {}
        if str(snap.get('source_root') or '').casefold()!=str(source.get('source_root') or '').casefold(): raise RuntimeError(f'{family}: source research root drift')
        if str(link.get('source_root') or '').casefold()!=str(source.get('source_root') or '').casefold(): raise RuntimeError(f'{family}: linked research root drift')
        for kind in VARIANTS:
            path=EVIDENCE_ROOT/f'{_slug(family)}--{_slug(kind)}.json';exists=path.exists();present+=int(exists)
            requirements.append({'capture_id':f'v8-{family}-{kind}','family':family,'case_kind':kind,'source_root':source.get('source_root'),'source_project':source.get('source_project'),'canonical_source_reference':source.get('canonical_advisory_url') or source.get('repository_advisory_url') or source.get('source_code_location'),'upstream_repository_reference':source.get('upstream_repository_reference'),'required_evidence_path':path.relative_to(ROOT).as_posix(),'evidence_present':exists,'evidence_sha256':_sha(path) if exists else None,'source_snapshot_sha256':snap.get('snapshot_sha256'),'linked_snapshot_sha256':link.get('snapshot_sha256'),'variant_purpose':PURPOSE[kind],'allowed_capture_methods':list(ALLOWED_CAPTURE_METHODS),'source_snapshot_required':True,'linked_snapshot_required':True,'raw_sha256_required':True,'independent_literal_observation_required':True,'synthetic_fixture_generation_forbidden':True,'cross_variant_mutation_forbidden':True,'detector_output_may_not_be_used':True,'admission_output_may_not_be_used':True,'ranking_output_may_not_be_used':True,'v6_first_blind_score_may_not_be_used':True,'v6_first_blind_case_errors_may_not_be_used':True})
    if len(requirements)!=144: raise RuntimeError(f'v8 plan cardinality mismatch: {len(requirements)}')
    return {'version':VERSION,'rule_version':RULE_VERSION,'evaluation_kind':'fresh_blind_v8_literal_capture_acquisition_plan_unscored','source_shortlist_sha256':_sha(SHORTLIST),'label_schema_sha256':_sha(LABEL_SCHEMA),'source_research_sha256':_sha(SOURCE_RESEARCH),'linked_research_sha256':_sha(LINKED_RESEARCH),'family_count':36,'variant_count_per_family':4,'required_capture_count':144,'evidence_present_count':present,'evidence_missing_count':144-present,'all_evidence_present':present==144,'capture_methods_allowed':list(ALLOWED_CAPTURE_METHODS),'requirements':requirements,'detector_output_used':False,'admission_output_used':False,'ranking_output_used':False,'v6_first_blind_score_used':False,'v6_first_blind_case_errors_used':False,'scoring_executed':False,'first_blind_consumed':False}


def main()->int:
    r=build();OUTPUT.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');print(json.dumps({k:r[k] for k in ('family_count','required_capture_count','evidence_present_count','evidence_missing_count','scoring_executed')},sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
