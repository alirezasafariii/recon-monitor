from __future__ import annotations
from pathlib import Path
from typing import Any, Iterable, Mapping
from raw_recon_corpus import ROOT, prior_source_index
import raw_recon_v7_source_firewall as v7
VERSION="1.1.0"; RULE_VERSION="2026.08.15.6.33.v8.7"
V7_CORPUS=ROOT/"benchmarks/raw/analysis_raw_v7.jsonl"; V7_SOURCES=ROOT/"benchmarks/raw/sources"; V7_EVIDENCE=V7_SOURCES/"v7_capture_evidence"
_SKIP={"v7_first_blind_consumption.json","v7_pre_score_checkpoint.json","v7_evaluator_freeze.json","v7_corpus_freeze.json","v7_validation_report.json","v7_terminal_status.json"}
def _add_corpus(index:dict[str,set[str]],path:Path)->None:
 if not path.exists():return
 corpus=prior_source_index((path,));roots={v7.v6._identity(x) for x in corpus["roots"] if v7.v6._identity(x)};projects={v7.v6._identity(x) for x in corpus["projects"] if v7.v6._identity(x)};urls={v7.v6.canonical_url(x) for x in corpus["urls"] if v7.v6.canonical_url(x)}
 index["roots"].update(roots);index["projects"].update(projects);index["urls"].update(urls)
 for value in roots|urls:index["identifiers"].update(v7.v6._identifiers(value))
def exposure_index()->dict[str,set[str]]:
 index={key:set(values) for key,values in v7.exposure_index().items()};_add_corpus(index,V7_CORPUS)
 if V7_SOURCES.exists():
  for path in sorted(V7_SOURCES.glob("v7_*.json")):
   if path.name in _SKIP:continue
   value=v7.v6._read_json(path)
   if value is None:continue
   for row in v7.v6._walk_rows(value):v7.v6._add_row(index,row)
 if V7_EVIDENCE.exists():
  for path in sorted(V7_EVIDENCE.glob("*.json")):
   value=v7.v6._read_json(path)
   if value is None:continue
   for row in v7.v6._walk_rows(value):v7.v6._add_row(index,row)
 return index
def check_candidate(row:Mapping[str,Any],*,index:Mapping[str,set[str]]|None=None)->dict[str,Any]:
 prior=index if index is not None else exposure_index();check=dict(v7.v6.check_candidate(row,index=prior));check.update({"firewall_version":VERSION,"firewall_rule_version":RULE_VERSION,"prior_scope":"all_exposed_sources_and_provenance_v1_through_consumed_v7","selection_uses_v7_first_blind_score":False,"selection_uses_v7_first_blind_case_errors":False,"selection_uses_v7_first_blind_error":False,"scoring_executed":False});return check
def validate_shortlist(rows:Iterable[Mapping[str,Any]],*,required_count:int=36)->dict[str,Any]:
 candidates=[dict(row) for row in rows];prior=exposure_index();checks=[check_candidate(row,index=prior) for row in candidates];roots={v7.v6._identity(row.get("source_root")) for row in candidates if v7.v6._identity(row.get("source_root"))};projects={v7.v6._identity(row.get("source_project")) for row in candidates if v7.v6._identity(row.get("source_project"))};failed=[check for check in checks if not check["allowed"]];errors=[]
 if len(candidates)!=required_count:errors.append(f"shortlist count must be {required_count}: {len(candidates)}")
 if len(roots)!=required_count:errors.append(f"shortlist must contain {required_count} unique roots: {len(roots)}")
 if len(projects)!=required_count:errors.append(f"shortlist must contain {required_count} unique projects: {len(projects)}")
 if failed:errors.append(f"v8 fresh-source firewall rejected {len(failed)} candidate(s)")
 return {"passed":not errors,"errors":errors,"candidate_count":len(candidates),"unique_root_count":len(roots),"unique_project_count":len(projects),"rejected":failed,"firewall_version":VERSION,"firewall_rule_version":RULE_VERSION,"prior_scope":"all_exposed_sources_and_provenance_v1_through_consumed_v7","selection_uses_v7_first_blind_score":False,"selection_uses_v7_first_blind_case_errors":False,"selection_uses_v7_first_blind_error":False,"scoring_executed":False}
__all__=["VERSION","RULE_VERSION","exposure_index","check_candidate","validate_shortlist"]
