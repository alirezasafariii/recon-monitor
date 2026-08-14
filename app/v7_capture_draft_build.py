from __future__ import annotations

"""Build source-grounded V7 capture drafts without publishing or scoring them.

Drafts are generated only from frozen public source snapshots, exact parent/fix
source neighborhoods, and upstream test-control snippets. Targeted-discovery
families remain blocked until their positive family semantics are independently
adjudicated. No synthetic target fixture is created.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from raw_recon_corpus import ROOT
from v7_capture_guard import assert_capture_source_freeze

VERSION="1.0.0"
RULE_VERSION="2026.08.14.6.33.v7.drafts.1"
RESEARCH=ROOT/"benchmarks/raw/sources/v7_literal_source_research.json"
BOUNDARY=ROOT/"benchmarks/raw/sources/v7_boundary_evidence.json"
SNIPPETS=ROOT/"benchmarks/raw/sources/v7_source_snippet_candidates.json"
PLAN=ROOT/"benchmarks/raw/sources/v7_literal_capture_plan.json"
DRAFT_ROOT=ROOT/"benchmarks/raw/sources/v7_capture_drafts"
REPORT=ROOT/"benchmarks/raw/sources/v7_capture_drafts_report.json"


def text(v:Any)->str:return str(v or "").strip()
def slug(v:Any)->str:return ''.join(ch if ch.isalnum() else '-' for ch in text(v).casefold()).strip('-')
def now()->str:return datetime.now(timezone.utc).isoformat()

def base_capture(family:str,kind:str,source:Mapping[str,Any],reference:str,payload:Any,raw_details:Mapping[str,Any],basis:str,notes:str,signals:list[str]|None=None,role:str="linked_upstream_observation")->dict[str,Any]:
    return {
        "family":family,"case_kind":kind,"source_root":source.get("source_root"),"source_project":source.get("source_project"),
        "captured_at":now(),"capture_reference":reference,"capture_method":"repository_test_fixture" if kind=="near_miss" else "passive_source_snapshot",
        "collector":{"kind":"v7_public_source_literal_draft","version":VERSION,"third_party_code_executed":False,"target_contact_performed":False},
        "source_snapshot":{"reference":reference,"retrieved_at":now(),"snapshot_role":role,"payload":payload},
        "raw":{"method":"UNKNOWN","details":dict(raw_details)},
        "adjudication":{"basis":basis,"notes":notes,"expected_condition_signals":list(signals or []),"detector_output_used":False,"admission_output_used":False,"ranking_output_used":False,"v6_first_blind_score_used":False,"v6_first_blind_case_errors_used":False,"corpus_v1_labels_used":False,"corpus_v1_evidence_used":False,"corpus_v1_scores_used":False},
    }

def first_source_snippet(pack:Mapping[str,Any],side:str)->tuple[str,Mapping[str,Any]]|None:
    key="parent_snippets" if side=="parent" else "fix_snippets"
    for f in pack.get("files") or []:
        if not isinstance(f,Mapping):continue
        for s in f.get(key) or []:
            if isinstance(s,Mapping) and text(s.get("text")):
                return text(f.get("filename")),s
    return None

def first_control(pack:Mapping[str,Any])->tuple[str,Mapping[str,Any]]|None:
    for f in pack.get("files") or []:
        if not isinstance(f,Mapping):continue
        for s in f.get("upstream_test_control_candidates") or []:
            if isinstance(s,Mapping) and text(s.get("text")):
                return text(f.get("filename")),s
    return None

def write_draft(capture:Mapping[str,Any])->str:
    path=DRAFT_ROOT/f"{slug(capture['family'])}--{slug(capture['case_kind'])}.json";path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(capture,indent=2,sort_keys=True,ensure_ascii=False)+"\n")
    return path.relative_to(ROOT).as_posix()

def main()->int:
    freeze=assert_capture_source_freeze()
    research=json.loads(RESEARCH.read_text());boundary=json.loads(BOUNDARY.read_text());snippets=json.loads(SNIPPETS.read_text());plan=json.loads(PLAN.read_text())
    if plan.get("source_assignment_commit")!=freeze["source_assignment_commit"]:raise RuntimeError("plan assignment drift")
    research_by={text(x.get("family")):x for x in research.get("entries") or [] if isinstance(x,Mapping)}
    boundary_by={text(x.get("family")):x for x in boundary.get("sources") or [] if isinstance(x,Mapping)}
    snippet_by={text(x.get("family")):x for x in snippets.get("sources") or [] if isinstance(x,Mapping)}
    requirements=[x for x in plan.get("requirements") or [] if isinstance(x,Mapping)]
    if len(requirements)!=144:raise RuntimeError("V7 plan must contain 144 requirements")
    rows=[]
    for req in requirements:
        family=text(req.get("family"));kind=text(req.get("case_kind"));source=research_by[family];bound=boundary_by.get(family,{}) ;sp=snippet_by.get(family,{})
        targeted=bool(req.get("family_literal_adjudication_required"));capture=None;reason=None
        if kind=="sparse_noisy":
            snap=source.get("snapshot_payload") if isinstance(source.get("snapshot_payload"),Mapping) else {}
            versions=[]
            for v in bound.get("version_boundaries") or []:
                if isinstance(v,Mapping):versions.append({"ecosystem":v.get("ecosystem"),"package":v.get("package"),"vulnerable_version_range":v.get("vulnerable_version_range"),"patched_version":v.get("patched_version")})
            capture=base_capture(family,kind,source,text(source.get("canonical_reference")),snap,{"observation_kind":"partial_public_source_metadata","source_project":source.get("source_project"),"version_boundary_count":len(versions),"version_boundaries":versions[:3]},"source_observation","Partial public-source metadata only; intentionally insufficient as a positive condition.",role="canonical_source")
        elif kind in {"positive","secure_negative"}:
            side="parent" if kind=="positive" else "fix";item=first_source_snippet(sp,side)
            if item:
                filename,s=item;sha=text(sp.get("parent_sha" if side=="parent" else "fix_sha"));reference=f"https://github.com/{source.get('source_project')}/blob/{sha}/{filename}" if sha else text(source.get("canonical_reference"))
                details={"observation_kind":"exact_vulnerable_parent_source_neighborhood" if kind=="positive" else "exact_patched_source_neighborhood","source_file":filename,"revision_sha":sha,"line_start":s.get("line_start"),"line_end":s.get("line_end"),"source_excerpt":s.get("text"),"source_excerpt_sha256":s.get("text_sha256")}
                signals=["literal vulnerable-parent source neighborhood at an upstream fix boundary"] if kind=="positive" else []
                capture=base_capture(family,kind,source,reference,{"revision_sha":sha,"source_file":filename,"line_start":s.get("line_start"),"line_end":s.get("line_end"),"source_excerpt":s.get("text"),"source_excerpt_sha256":s.get("text_sha256")},details,"source_observation" if kind=="positive" else "patched_control","Exact source neighborhood from the vulnerable parent revision." if kind=="positive" else "Exact source neighborhood from the upstream fixed revision.",signals,role="linked_upstream_observation" if kind=="positive" else "patched_or_unaffected_control")
            else:reason="no exact parent/fix source snippet available"
        elif kind=="near_miss":
            item=first_control(sp)
            if item:
                filename,s=item;sha=text(sp.get("fix_sha"));reference=f"https://github.com/{source.get('source_project')}/blob/{sha}/{filename}" if sha else text(source.get("canonical_reference"))
                capture=base_capture(family,kind,source,reference,{"revision_sha":sha,"source_file":filename,"test_control_excerpt":s.get("text"),"test_control_excerpt_sha256":s.get("text_sha256"),"control_keyword_match":s.get("control_keyword_match")},{"observation_kind":"upstream_control_test_candidate","source_file":filename,"revision_sha":sha,"test_control_excerpt":s.get("text"),"control_keyword_match":s.get("control_keyword_match")},"repository_test_fixture","Independent upstream control-like test excerpt; must remain non-positive after adjudication.",role="patched_or_unaffected_control")
            else:reason="no upstream control-like test snippet available"
        else:reason="unsupported variant"
        if capture:
            path=write_draft(capture);status="blocked_targeted_family_adjudication" if targeted else "draft_ready_for_semantic_review"
            rows.append({"family":family,"case_kind":kind,"status":status,"draft_path":path,"block_reason":"literal family confirmation required before publish" if targeted else None})
        else:rows.append({"family":family,"case_kind":kind,"status":"blocked_missing_literal_source","draft_path":None,"block_reason":reason})
    counts={}
    for r in rows:counts[r["status"]]=counts.get(r["status"],0)+1
    report={"version":VERSION,"rule_version":RULE_VERSION,"evaluation_kind":"fresh_blind_v7_literal_capture_draft_build","planned_count":144,"status_counts":counts,"draft_count":sum(bool(r["draft_path"]) for r in rows),"missing_literal_source_count":sum(r["status"]=="blocked_missing_literal_source" for r in rows),"targeted_family_blocked_count":sum(r["status"]=="blocked_targeted_family_adjudication" for r in rows),"rows":rows,"engine_baseline_commit":freeze["engine_baseline_commit"],"source_assignment_commit":freeze["source_assignment_commit"],"scoring_executed":False,"first_blind_consumed":False,"third_party_code_executed":False,"target_contact_performed":False}
    REPORT.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n");print(json.dumps({k:report[k] for k in ('planned_count','draft_count','missing_literal_source_count','targeted_family_blocked_count','status_counts','scoring_executed')},sort_keys=True));return 0

if __name__=="__main__":raise SystemExit(main())
