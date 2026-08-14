from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT

VERSION = "1.0.1"
RULE_VERSION = "2026.08.14.6.32.v7.12"
CANONICAL = ROOT / "benchmarks/raw/sources/v7_candidates.json"
FAST = ROOT / "benchmarks/raw/sources/v7_candidates_fast.json"
PR_SUPPLEMENT = ROOT / "benchmarks/raw/sources/v7_pr_supplement.json"
TARGETED_SUPPLEMENT = ROOT / "benchmarks/raw/sources/v7_targeted_supplement.json"


def _identity(row: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("source_root") or "").strip().casefold(),
        str(row.get("source_project") or "").strip().casefold(),
        str(row.get("canonical_advisory_url") or row.get("repository_advisory_url") or row.get("source_code_location") or "").strip().casefold(),
    )


def _load(path: Path) -> dict[str, Any]:
    if not path.exists(): return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping): raise RuntimeError(f"v7 candidate source must be a JSON object: {path}")
    return dict(value)


def _assert_clean(name: str, report: Mapping[str, Any]) -> None:
    if not report: return
    if report.get("scoring_executed") is not False: raise RuntimeError(f"{name}: candidate source must be unscored")
    for key in ("candidate_selection_uses_detector_scores","candidate_selection_uses_admission_results","candidate_selection_uses_ranking_results","candidate_selection_uses_v6_first_blind_score","candidate_selection_uses_v6_first_blind_case_errors"):
        if key in report and report.get(key) is not False: raise RuntimeError(f"{name}: forbidden contamination flag {key}")
    if report.get("active_target_validation_performed") is not False: raise RuntimeError(f"{name}: active target validation is forbidden")


def merge() -> dict[str, Any]:
    base=_load(CANONICAL); fast=_load(FAST); pr=_load(PR_SUPPLEMENT); targeted=_load(TARGETED_SUPPLEMENT)
    _assert_clean("canonical",base); _assert_clean("fast",fast); _assert_clean("pr_supplement",pr); _assert_clean("targeted_supplement",targeted)
    sources=[("canonical_advisory_discovery",base),("bounded_advisory_discovery",fast),("merged_security_pr_supplement",pr),("targeted_final_supplement",targeted)]
    family_names:set[str]=set()
    for _,report in sources:
        pools=report.get("candidates_by_family") if isinstance(report.get("candidates_by_family"),Mapping) else {}
        family_names.update(str(family) for family in pools)
    if len(family_names)!=36: raise RuntimeError(f"v7 merge expects 36 family buckets, got {len(family_names)}")
    merged:dict[str,list[dict[str,Any]]]={}; provenance_counts:dict[str,dict[str,int]]={}
    for family in sorted(family_names):
        rows=[]; seen=set(); counts={}
        for source_name,report in sources:
            pools=report.get("candidates_by_family") if isinstance(report.get("candidates_by_family"),Mapping) else {}; accepted=0
            for raw in pools.get(family) or []:
                if not isinstance(raw,Mapping): continue
                row=dict(raw); ident=_identity(row)
                if not ident[0] or not ident[1] or ident in seen: continue
                seen.add(ident); row["v7_candidate_pool_origin"]=source_name; row["selection_uses_v6_score"]=False; row["selection_uses_v6_case_errors"]=False; row["scoring_executed"]=False; row["active_target_validation_performed"]=False
                rows.append(row); accepted+=1
            counts[source_name]=accepted
        merged[family]=rows; provenance_counts[family]=counts
    result=dict(base); result.update({"version":VERSION,"rule_version":RULE_VERSION,"evaluation_kind":"fresh_blind_v7_unscored_merged_candidate_pool","family_count":36,"candidates_by_family":merged,"family_candidate_counts":{family:len(rows) for family,rows in merged.items()},"families_without_candidates":sorted(family for family,rows in merged.items() if not rows),"candidate_pool_provenance_counts":provenance_counts,"candidate_pool_sources":[name for name,_ in sources],"candidate_selection_uses_detector_scores":False,"candidate_selection_uses_admission_results":False,"candidate_selection_uses_ranking_results":False,"candidate_selection_uses_v6_first_blind_score":False,"candidate_selection_uses_v6_first_blind_case_errors":False,"active_target_validation_performed":False,"scoring_executed":False,"first_blind_consumed":False})
    return result


def main() -> int:
    report=merge(); CANONICAL.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"family_candidate_counts":report["family_candidate_counts"],"families_without_candidates":report["families_without_candidates"],"candidate_pool_sources":report["candidate_pool_sources"],"scoring_executed":report["scoring_executed"]},sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
