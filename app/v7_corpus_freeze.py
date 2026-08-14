from __future__ import annotations

import hashlib, json
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT

VERSION='1.0.0'; RULE_VERSION='2026.08.14.6.32.v7.15'
SRC=ROOT/'benchmarks/raw/sources'; FREEZE=SRC/'v7_corpus_freeze.json'; MANIFEST=SRC/'v7_freeze_manifest.sha256'
REQUIRED=[
 'benchmarks/raw/sources/v7_protocol.json','benchmarks/raw/sources/v7_candidates.json','benchmarks/raw/sources/v7_candidates_patchable.json',
 'benchmarks/raw/sources/v7_shortlist.json','benchmarks/raw/sources/v7_literal_source_research.json','benchmarks/raw/sources/v7_literal_linked_research.json',
 'benchmarks/raw/sources/v7_literal_label_schema.json','benchmarks/raw/sources/v7_literal_capture_plan.json','benchmarks/raw/sources/v7_literal_captures.jsonl',
 'benchmarks/raw/sources/v7_literal_capture_ingest_report.json','benchmarks/raw/sources/v7_literal_capture_verification.json',
 'benchmarks/raw/sources/v7_materialization_report.json','benchmarks/raw/sources/v7_validation_report.json','benchmarks/raw/analysis_raw_v7.jsonl',
 'app/analysis_632_evidence.py','app/researcher_logic.py','app/hypothesis_admission.py','app/family_detectors/execution.py','app/security_reasoning.py',
]

def _sha(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()
def _load(rel:str)->dict[str,Any]:
 p=ROOT/rel
 if not p.exists():raise RuntimeError(f'v7 freeze required input missing: {rel}')
 v=json.loads(p.read_text())
 if not isinstance(v,Mapping):raise RuntimeError(f'v7 freeze expected object: {rel}')
 return dict(v)
def _rel(path:Path)->str:return path.resolve().relative_to(ROOT.resolve()).as_posix()
def _unscored(name:str,doc:Mapping[str,Any])->None:
 if doc.get('scoring_executed') is not False:raise RuntimeError(f'{name} must remain unscored')
 if 'first_blind_consumed' in doc and doc.get('first_blind_consumed') is not False:raise RuntimeError(f'{name} cannot consume v7 First Blind')
 if doc.get('v6_first_blind_score_used',False) is not False or doc.get('v6_first_blind_case_errors_used',False) is not False:raise RuntimeError(f'{name} is contaminated by v6 result')

def build()->dict[str,Any]:
 if FREEZE.exists():raise RuntimeError('v7 corpus freeze already exists; do not mutate a sealed holdout')
 if (SRC/'v7_first_blind_consumption.json').exists() or (ROOT/'benchmarks/raw/results/analysis_raw_v7_first_blind.json').exists():raise RuntimeError('v7 First Blind state exists before corpus freeze')
 protocol=_load('benchmarks/raw/sources/v7_protocol.json'); shortlist=_load('benchmarks/raw/sources/v7_shortlist.json'); research=_load('benchmarks/raw/sources/v7_literal_source_research.json');linked=_load('benchmarks/raw/sources/v7_literal_linked_research.json');labels=_load('benchmarks/raw/sources/v7_literal_label_schema.json');plan=_load('benchmarks/raw/sources/v7_literal_capture_plan.json');ingest=_load('benchmarks/raw/sources/v7_literal_capture_ingest_report.json');verify=_load('benchmarks/raw/sources/v7_literal_capture_verification.json');material=_load('benchmarks/raw/sources/v7_materialization_report.json');validation=_load('benchmarks/raw/sources/v7_validation_report.json')
 for name,doc in [('protocol',protocol),('shortlist',shortlist),('research',research),('linked',linked),('labels',labels),('plan',plan),('ingest',ingest),('verify',verify),('material',material),('validation',validation)]:_unscored(name,doc)
 if len(shortlist.get('selected') or [])!=36 or shortlist.get('global_assignment_complete') is not True:raise RuntimeError('v7 shortlist incomplete')
 fw=shortlist.get('firewall') if isinstance(shortlist.get('firewall'),Mapping) else {}
 if fw.get('passed') is not True or int(fw.get('unique_root_count') or 0)!=36 or int(fw.get('unique_project_count') or 0)!=36:raise RuntimeError('v7 shortlist firewall/uniqueness invalid')
 if research.get('successful_snapshot_count')!=36 or research.get('unresolved_snapshot_count')!=0:raise RuntimeError('v7 canonical research incomplete')
 if linked.get('successful_link_snapshot_count')!=36 or linked.get('unresolved_link_snapshot_count')!=0:raise RuntimeError('v7 linked research incomplete')
 if labels.get('family_count')!=36:raise RuntimeError('v7 labels incomplete')
 if plan.get('required_capture_count')!=144 or plan.get('evidence_present_count')!=144 or plan.get('evidence_missing_count')!=0 or plan.get('all_evidence_present') is not True:raise RuntimeError('v7 plan not 144/144')
 if ingest.get('passed') is not True or ingest.get('valid_capture_count')!=144 or ingest.get('missing_capture_count')!=0 or ingest.get('error_count')!=0:raise RuntimeError('v7 ingest not clean 144/144')
 if verify.get('passed') is not True or verify.get('capture_count')!=144 or verify.get('evidence_count')!=144 or verify.get('unique_evidence_hash_count')!=144:raise RuntimeError('v7 evidence verifier not clean 144/144')
 if material.get('case_count')!=276 or material.get('single_case_count')!=144 or material.get('pair_case_count')!=72 or material.get('triad_case_count')!=60 or material.get('literal_single_capture_count')!=144 or material.get('fresh_raw_claim') is not True:raise RuntimeError('v7 materialization cardinality/claim invalid')
 if validation.get('passed') is not True or validation.get('case_count')!=276 or validation.get('literal_single_capture_count')!=144 or validation.get('label_leakage_count')!=0:raise RuntimeError('v7 strict validation failed')
 vfw=validation.get('source_firewall') if isinstance(validation.get('source_firewall'),Mapping) else {}
 if vfw.get('passed') is not True:raise RuntimeError('v7 validation firewall failed')
 protected:set[str]=set(REQUIRED)
 for pattern in ('app/v7_*.py','app/raw_recon_v7_*.py','tests/test_analysis_632*.py','.github/workflows/analysis-632-v7-*.yml'):
  for p in ROOT.glob(pattern):
   if p.is_file():protected.add(_rel(p))
 evidence=SRC/'v7_capture_evidence';files=sorted(p for p in evidence.glob('*.json') if p.is_file())
 if len(files)!=144:raise RuntimeError(f'v7 freeze requires exactly 144 evidence files: {len(files)}')
 manifest=verify.get('evidence_manifest') if isinstance(verify.get('evidence_manifest'),Mapping) else {}
 if len(manifest)!=144:raise RuntimeError('v7 verifier manifest cardinality invalid')
 for p in files:
  rel=_rel(p);expected=str(manifest.get(rel) or '')
  if not expected or _sha(p)!=expected:raise RuntimeError(f'v7 evidence hash/manifest mismatch: {rel}')
  protected.add(rel)
 hashes={rel:_sha(ROOT/rel) for rel in sorted(protected)}
 return {'version':VERSION,'rule_version':RULE_VERSION,'evaluation_status':'sealed_fresh_v7_unscored_holdout','case_count':276,'single_case_count':144,'pair_case_count':72,'triad_case_count':60,'literal_evidence_artifact_count':144,'family_count':36,'source_root_count':36,'source_project_count':36,'protected_sha256':hashes,'protected_count':len(hashes),'v6_first_blind_score_used':False,'v6_first_blind_case_errors_used':False,'scoring_executed':False,'first_blind_consumed':False,'first_blind_evaluator_frozen':False,'mutation_policy':'all Analysis 6.32 v7 holdout inputs, evidence, corpus, production calibration surface, evaluator and v7 workflows are immutable after this freeze'}
def write()->dict[str,Any]:
 r=build();FREEZE.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n');MANIFEST.write_text(''.join(f'{h}  {rel}\n' for rel,h in sorted(r['protected_sha256'].items())));return r
def main()->int:print(json.dumps(write(),sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
