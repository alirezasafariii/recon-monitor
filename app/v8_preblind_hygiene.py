from __future__ import annotations
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];APP=ROOT/"app";SOURCES=ROOT/"benchmarks/raw/sources";RESULTS=ROOT/"benchmarks/raw/results"
FORBIDDEN=['raw_recon_v8_collision_supplement.py', 'raw_recon_v8_merge_candidates.py', 'raw_recon_v8_merge_patchable.py', 'raw_recon_v8_missing5_fast_revalidate.py', 'raw_recon_v8_missing5_supplement.py', 'raw_recon_v8_missing5_supplement_v2.py', 'raw_recon_v8_pr_supplement.py', 'raw_recon_v8_preferred_patch_probe.py', 'raw_recon_v8_source_discovery_fast.py', 'raw_recon_v8_targeted_supplement.py', 'workspace_v8.py']
REQUIRED=['v8_benchmark_dataset.py', 'v8_benchmark_validate.py', 'v8_corpus_freeze.py', 'v8_freeze_verify.py', 'v8_literal_capture_ingest.py', 'v8_literal_capture_plan.py', 'v8_literal_capture_verify.py', 'v8_literal_evidence_publish.py', 'v8_literal_label_schema.py', 'v8_literal_linked_research.py', 'v8_literal_patch_capture.py', 'v8_literal_source_research.py', 'v8_pre_score_condition_audit.py', 'v8_preblind_verify.py', 'v8_source_semantic_audit.py', 'raw_recon_v8_patch_probe.py', 'raw_recon_v8_source_discovery.py', 'raw_recon_v8_source_selection.py', 'raw_recon_v8_source_firewall.py', 'v8_benchmark_evaluate.py', 'v8_first_blind_consume.py', 'v8_preblind_contract.py', 'v8_preblind_hygiene.py']
def _load(name):
 p=SOURCES/name
 return json.loads(p.read_text()) if p.exists() else None
def verify(require_artifacts:bool=False):
 errors=[]
 for name in FORBIDDEN:
  if (APP/name).exists():errors.append(f"forbidden stale v8 generated module: {name}")
 for name in REQUIRED:
  if not (APP/name).exists():errors.append(f"required v8 module missing: {name}")
 specs=(("v8_candidates.json","candidate_selection_uses_v7_first_blind_score","candidate_selection_uses_v7_first_blind_case_errors","candidate_selection_uses_v7_first_blind_error"),("v8_candidates_patchable.json","candidate_selection_uses_v7_first_blind_score","candidate_selection_uses_v7_first_blind_case_errors","candidate_selection_uses_v7_first_blind_error"),("v8_shortlist.json","selection_uses_v7_first_blind_score","selection_uses_v7_first_blind_case_errors","selection_uses_v7_first_blind_error"))
 for name,*keys in specs:
  value=_load(name)
  if value is None:
   if require_artifacts:errors.append(f"required v8 artifact missing: {name}")
   continue
  for key in keys:
   if value.get(key) is not False:errors.append(f"{name} must explicitly record {key}=false")
  if value.get("scoring_executed") is not False:errors.append(f"{name} must remain unscored")
 if (SOURCES/"v8_first_blind_consumption.json").exists():errors.append("v8 First Blind receipt already exists")
 if (RESULTS/"analysis_raw_v8_first_blind.json").exists():errors.append("v8 First Blind result already exists")
 return {"passed":not errors,"errors":errors,"forbidden_count":len(FORBIDDEN),"required_count":len(REQUIRED),"scoring_executed":False,"first_blind_consumed":False}
def main():
 import sys
 r=verify(require_artifacts="--require-artifacts" in sys.argv);print(json.dumps(r,indent=2,sort_keys=True));return 0 if r["passed"] else 1
if __name__=="__main__":raise SystemExit(main())
