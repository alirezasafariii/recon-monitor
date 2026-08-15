from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
SOURCES = ROOT / "benchmarks/raw/sources"
RESULTS = ROOT / "benchmarks/raw/results"

# Only generic holdout machinery is permitted to cross the v7 -> v8 code boundary.
# Source supplements, collision replacements, targeted URLs, workspaces, and any
# consumed/evaluation artifact logic are intentionally excluded.
TRANSLATE_MODULES = (
    "v7_benchmark_dataset.py",
    "v7_benchmark_validate.py",
    "v7_corpus_freeze.py",
    "v7_freeze_verify.py",
    "v7_literal_capture_ingest.py",
    "v7_literal_capture_plan.py",
    "v7_literal_capture_verify.py",
    "v7_literal_evidence_publish.py",
    "v7_literal_label_schema.py",
    "v7_literal_linked_research.py",
    "v7_literal_patch_capture.py",
    "v7_literal_source_research.py",
    "v7_pre_score_condition_audit.py",
    "v7_preblind_verify.py",
    "v7_source_semantic_audit.py",
    "raw_recon_v7_patch_probe.py",
    "raw_recon_v7_source_discovery.py",
    "raw_recon_v7_source_selection.py",
)

# These have v7 name-counterparts, but v8 versions are rebuilt independently
# below and therefore are legitimate v8 outputs rather than stale translations.
SPECIAL_V8_OUTPUTS = {
    "raw_recon_v8_source_firewall.py",
    "v8_benchmark_evaluate.py",
    "v8_first_blind_consume.py",
}

FORBIDDEN_V8_COUNTERPARTS = tuple(
    sorted(
        {
            src.name.replace("v7", "v8").replace("V7", "V8")
            for src in APP.glob("*v7*.py")
            if src.name not in TRANSLATE_MODULES
            and src.name.replace("v7", "v8").replace("V7", "V8") not in SPECIAL_V8_OUTPUTS
        }
    )
)


def _cleanup_stale_generated_v8() -> None:
    for name in FORBIDDEN_V8_COUNTERPARTS:
        path = APP / name
        if path.exists():
            path.unlink()


def _transform_v7_modules() -> list[str]:
    _cleanup_stale_generated_v8()
    generated: list[str] = []
    for name in TRANSLATE_MODULES:
        src = APP / name
        if not src.exists():
            raise RuntimeError(f"required v7 generic module missing: {name}")
        dst = APP / name.replace("v7", "v8").replace("V7", "V8")
        text = src.read_text(encoding="utf-8")
        text = text.replace("v7", "v8").replace("V7", "V8")
        dst.write_text(text, encoding="utf-8")
        generated.append(str(dst.relative_to(ROOT)))
    return generated


def _write_firewall() -> None:
    # Deliberately use v7 exposure/provenance, but skip v7 First Blind result,
    # receipt, terminal status, freeze and checkpoint artifacts. The v7 outcome
    # is never an input to source selection.
    text = r'''from __future__ import annotations
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
'''
    (APP / "raw_recon_v8_source_firewall.py").write_text(text, encoding="utf-8")


def _harden_selection_modules() -> None:
    for filename in ("raw_recon_v8_source_discovery.py", "raw_recon_v8_patch_probe.py", "raw_recon_v8_source_selection.py"):
        path = APP / filename
        text = path.read_text(encoding="utf-8")
        if "candidate_selection_uses_v7_first_blind_score" not in text:
            marker = '"candidate_selection_uses_v6_first_blind_case_errors": False,'
            if marker in text:
                text = text.replace(
                    marker,
                    marker + '\n        "candidate_selection_uses_v7_first_blind_score": False,\n        "candidate_selection_uses_v7_first_blind_case_errors": False,\n        "candidate_selection_uses_v7_first_blind_error": False,',
                )
        if filename == "raw_recon_v8_source_selection.py":
            if "selection_uses_v7_first_blind_score" not in text:
                marker = '"selection_uses_v6_first_blind_case_errors": False,'
                if marker not in text:
                    raise RuntimeError("v8 selection contamination output anchor missing")
                text = text.replace(
                    marker,
                    marker + '\n        "selection_uses_v7_first_blind_score": False,\n        "selection_uses_v7_first_blind_case_errors": False,\n        "selection_uses_v7_first_blind_error": False,',
                )
            contamination_anchor = 'raw_pools = raw.get("candidates_by_family")'
            guard = '''if raw.get("candidate_selection_uses_v7_first_blind_score") is not False or raw.get("candidate_selection_uses_v7_first_blind_case_errors") is not False or raw.get("candidate_selection_uses_v7_first_blind_error") is not False:\n        raise RuntimeError("v8 source discovery was contaminated by v7 First Blind outcome")\n    '''
            if "contaminated by v7 First Blind outcome" not in text:
                if contamination_anchor not in text:
                    raise RuntimeError("v8 selection contamination guard anchor missing")
                text = text.replace(contamination_anchor, guard + contamination_anchor, 1)
        elif filename == "raw_recon_v8_patch_probe.py":
            contamination_anchor = 'pools = source.get("candidates_by_family")'
            guard = '''if source.get("candidate_selection_uses_v7_first_blind_score") is not False or source.get("candidate_selection_uses_v7_first_blind_case_errors") is not False or source.get("candidate_selection_uses_v7_first_blind_error") is not False:\n        raise RuntimeError("v8 candidate pool contaminated by v7 First Blind outcome")\n    '''
            if "candidate pool contaminated by v7 First Blind outcome" not in text:
                if contamination_anchor not in text:
                    raise RuntimeError("v8 patch probe contamination guard anchor missing")
                text = text.replace(contamination_anchor, guard + contamination_anchor, 1)
        path.write_text(text, encoding="utf-8")


def _write_evaluator_and_consumer() -> None:
    src = (APP / "v6_benchmark_evaluate.py").read_text(encoding="utf-8")
    replacements = (
        ("from v6_benchmark_validate import validate_v6_corpus", "from v8_benchmark_validate import validate_v8_corpus"),
        ("from v6_freeze_verify import verify_freeze", "from v8_freeze_verify import verify_freeze"),
        ("validate_v6_corpus(", "validate_v8_corpus("),
        ("analysis_raw_v6.jsonl", "analysis_raw_v8.jsonl"),
        ("v6_shortlist.json", "v8_shortlist.json"),
        ("v6_protocol.json", "v8_protocol.json"),
        ("v6_corpus_freeze.json", "v8_corpus_freeze.json"),
        ("v6_evaluator_freeze.json", "v8_evaluator_freeze.json"),
        ("v6_first_blind_consumption.json", "v8_first_blind_consumption.json"),
        ("analysis_raw_v6_first_blind.json", "analysis_raw_v8_first_blind.json"),
        ("run_v6_benchmark", "run_v8_benchmark"),
        ("fresh_blind_v6", "fresh_blind_v8"),
        ("single_family_fresh_v6", "single_family_fresh_v8"),
        ("2_family_interference_v6", "2_family_interference_v8"),
        ("3_family_interference_v6", "3_family_interference_v8"),
        ("V6 ", "V8 "),
        ("v6 ", "v8 "),
        ('VERSION = "1.2.0"', 'VERSION = "1.0.0"'),
        ('RULE_VERSION = "2026.08.14.6.31.16"', 'RULE_VERSION = "2026.08.15.6.33.v8.8"'),
    )
    for old, new in replacements:
        src = src.replace(old, new)
    forbidden = ("single_family_fresh_v6", "2_family_interference_v6", "3_family_interference_v6", "run_v6_benchmark", "analysis_raw_v6.jsonl")
    if any(token in src for token in forbidden):
        raise RuntimeError("v8 evaluator contains stale v6 execution selector")
    for token in ("single_family_fresh_v8", "2_family_interference_v8", "3_family_interference_v8"):
        if token not in src:
            raise RuntimeError(f"v8 evaluator missing required case selector: {token}")
    (APP / "v8_benchmark_evaluate.py").write_text(src, encoding="utf-8")

    src = (APP / "v6_first_blind_consume.py").read_text(encoding="utf-8")
    replacements = (
        ("from v6_benchmark_evaluate import run_v6_benchmark", "from v8_benchmark_evaluate import run_v8_benchmark"),
        ("from v6_freeze_verify import verify_freeze", "from v8_freeze_verify import verify_freeze"),
        ("run_v6_benchmark()", "run_v8_benchmark()"),
        ("analysis_raw_v6.jsonl", "analysis_raw_v8.jsonl"),
        ("v6_shortlist.json", "v8_shortlist.json"),
        ("v6_protocol.json", "v8_protocol.json"),
        ("v6_corpus_freeze.json", "v8_corpus_freeze.json"),
        ("v6_evaluator_freeze.json", "v8_evaluator_freeze.json"),
        ("v6_benchmark_evaluate.py", "v8_benchmark_evaluate.py"),
        ("v6_first_blind_consumption.json", "v8_first_blind_consumption.json"),
        ("analysis_raw_v6_first_blind.json", "analysis_raw_v8_first_blind.json"),
        ("fresh_blind_v6", "fresh_blind_v8"),
        ("Analysis 6.31", "Analysis 6.33 v8"),
        ('RULE_VERSION = "2026.08.14.6.31.15"', 'RULE_VERSION = "2026.08.15.6.33.v8.9"'),
    )
    for old, new in replacements:
        src = src.replace(old, new)
    if "run_v6_benchmark" in src or "v6_first_blind_consumption.json" in src:
        raise RuntimeError("v8 consumer contains stale v6 path")
    (APP / "v8_first_blind_consume.py").write_text(src, encoding="utf-8")


def _fix_freeze_api() -> None:
    path = APP / "v8_freeze_verify.py"
    text = path.read_text(encoding="utf-8")
    if "def verify_freeze(" not in text:
        anchor = "def main()->int:"
        alias = "def verify_freeze(freeze_path=None, *, require_freeze:bool=False, require_evaluator_frozen:bool=False):\n if freeze_path is not None and Path(freeze_path).resolve()!=FREEZE.resolve():raise RuntimeError('non-canonical v8 corpus freeze path')\n return verify(require_freeze=require_freeze,require_evaluator_frozen=require_evaluator_frozen)\n\n"
        if anchor not in text:
            raise RuntimeError("v8 freeze verifier alias anchor missing")
        text = text.replace(anchor, alias + anchor, 1)
    path.write_text(text, encoding="utf-8")


def _write_contract() -> None:
    text = r'''from __future__ import annotations
import json
from raw_recon_corpus import ROOT
VERSION="1.1.0";RULE_VERSION="2026.08.15.6.33.v8.10";CORPUS=ROOT/"benchmarks/raw/analysis_raw_v8.jsonl";EVALUATOR=ROOT/"app/v8_benchmark_evaluate.py";EXPECTED={"single_family_fresh_v8":144,"2_family_interference_v8":72,"3_family_interference_v8":60};STALE=("single_family_fresh_v6","2_family_interference_v6","3_family_interference_v6","single_family_fresh_v7","2_family_interference_v7","3_family_interference_v7")
def inspect_evaluator():
 text=EVALUATOR.read_text(encoding="utf-8");errors=[]
 for mode in EXPECTED:
  if mode not in text:errors.append(f"evaluator missing {mode}")
 for mode in STALE:
  if mode in text:errors.append(f"evaluator contains stale selector {mode}")
 if "from v8_freeze_verify import verify_freeze" not in text:errors.append("evaluator freeze API import mismatch")
 return {"passed":not errors,"errors":errors}
def verify_materialized_contract():
 e=inspect_evaluator();errors=list(e["errors"]);counts={}
 if not CORPUS.exists():errors.append("v8 corpus missing")
 else:
  rows=[json.loads(x) for x in CORPUS.read_text(encoding="utf-8").splitlines() if x.strip()];counts={mode:sum(1 for row in rows if row.get("case_mode")==mode) for mode in EXPECTED}
  if len(rows)!=276:errors.append(f"v8 corpus cardinality {len(rows)} != 276")
  for mode,n in EXPECTED.items():
   if counts.get(mode)!=n:errors.append(f"{mode} cardinality {counts.get(mode)} != {n}")
  unknown=sorted({str(row.get("case_mode") or "") for row in rows}-set(EXPECTED))
  if unknown:errors.append(f"unexpected case modes: {unknown}")
 return {"version":VERSION,"rule_version":RULE_VERSION,"passed":not errors,"errors":errors,"counts":counts,"expected":EXPECTED,"scoring_executed":False}
def main():
 r=verify_materialized_contract();print(json.dumps(r,indent=2,sort_keys=True));return 0 if r["passed"] else 1
if __name__=="__main__":raise SystemExit(main())
'''
    (APP / "v8_preblind_contract.py").write_text(text, encoding="utf-8")


def _write_hygiene_guard() -> None:
    forbidden = list(FORBIDDEN_V8_COUNTERPARTS)
    required = [Path(path).name.replace("v7", "v8").replace("V7", "V8") for path in TRANSLATE_MODULES]
    required += ["raw_recon_v8_source_firewall.py", "v8_benchmark_evaluate.py", "v8_first_blind_consume.py", "v8_preblind_contract.py", "v8_preblind_hygiene.py"]
    text = f'''from __future__ import annotations\nimport json\nfrom pathlib import Path\nROOT=Path(__file__).resolve().parents[1];APP=ROOT/"app";SOURCES=ROOT/"benchmarks/raw/sources";RESULTS=ROOT/"benchmarks/raw/results"\nFORBIDDEN={forbidden!r}\nREQUIRED={required!r}\ndef _load(name):\n p=SOURCES/name\n return json.loads(p.read_text()) if p.exists() else None\ndef verify(require_artifacts:bool=False):\n errors=[]\n for name in FORBIDDEN:\n  if (APP/name).exists():errors.append(f"forbidden stale v8 generated module: {{name}}")\n for name in REQUIRED:\n  if not (APP/name).exists():errors.append(f"required v8 module missing: {{name}}")\n specs=(("v8_candidates.json","candidate_selection_uses_v7_first_blind_score","candidate_selection_uses_v7_first_blind_case_errors","candidate_selection_uses_v7_first_blind_error"),("v8_candidates_patchable.json","candidate_selection_uses_v7_first_blind_score","candidate_selection_uses_v7_first_blind_case_errors","candidate_selection_uses_v7_first_blind_error"),("v8_shortlist.json","selection_uses_v7_first_blind_score","selection_uses_v7_first_blind_case_errors","selection_uses_v7_first_blind_error"))\n for name,*keys in specs:\n  value=_load(name)\n  if value is None:\n   if require_artifacts:errors.append(f"required v8 artifact missing: {{name}}")\n   continue\n  for key in keys:\n   if value.get(key) is not False:errors.append(f"{{name}} must explicitly record {{key}}=false")\n  if value.get("scoring_executed") is not False:errors.append(f"{{name}} must remain unscored")\n if (SOURCES/"v8_first_blind_consumption.json").exists():errors.append("v8 First Blind receipt already exists")\n if (RESULTS/"analysis_raw_v8_first_blind.json").exists():errors.append("v8 First Blind result already exists")\n return {{"passed":not errors,"errors":errors,"forbidden_count":len(FORBIDDEN),"required_count":len(REQUIRED),"scoring_executed":False,"first_blind_consumed":False}}\ndef main():\n import sys\n r=verify(require_artifacts="--require-artifacts" in sys.argv);print(json.dumps(r,indent=2,sort_keys=True));return 0 if r["passed"] else 1\nif __name__=="__main__":raise SystemExit(main())\n'''
    (APP / "v8_preblind_hygiene.py").write_text(text, encoding="utf-8")


def _write_protocol() -> None:
    protocol = json.loads((SOURCES / "v7_protocol.json").read_text(encoding="utf-8"))
    value = json.loads(json.dumps(protocol).replace("v7", "v8").replace("V7", "V8"))
    value["scoring_executed"] = False
    value["first_blind_consumed"] = False
    value["v7_first_blind_score_used"] = False
    value["v7_first_blind_case_errors_used"] = False
    value["v7_first_blind_error_used"] = False
    (SOURCES / "v8_protocol.json").write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    generated = _transform_v7_modules()
    _write_firewall()
    _harden_selection_modules()
    _write_evaluator_and_consumer()
    _fix_freeze_api()
    _write_contract()
    _write_hygiene_guard()
    _write_protocol()
    print(json.dumps({
        "generated_module_count": len(generated),
        "translated_module_allowlist_count": len(TRANSLATE_MODULES),
        "forbidden_stale_counterpart_count": len(FORBIDDEN_V8_COUNTERPARTS),
        "special_rebuilt_output_count": len(SPECIAL_V8_OUTPUTS),
        "v8_firewall": "strict_v1_through_v7",
        "v8_evaluator_case_contract": "explicit_v8",
        "v7_first_blind_outcome_used_for_selection": False,
        "v7_target_data_copied": False,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
