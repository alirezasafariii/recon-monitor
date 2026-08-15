from __future__ import annotations
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
