from __future__ import annotations

import hashlib,json
from pathlib import Path
from typing import Any

from raw_recon_corpus import ROOT
from v8_freeze_verify import verify as verify_corpus_freeze

VERSION='1.0.0';RULE_VERSION='2026.08.14.6.32.v8.21'
FREEZE=ROOT/'benchmarks/raw/sources/v8_corpus_freeze.json';EVAL_FREEZE=ROOT/'benchmarks/raw/sources/v8_evaluator_freeze.json';EVALUATOR=ROOT/'app/v8_benchmark_evaluate.py';CONSUMER=ROOT/'app/v8_first_blind_consume.py';PROTOCOL=ROOT/'benchmarks/raw/sources/v8_protocol.json'
def _sha(p:Path)->str:return hashlib.sha256(p.read_bytes()).hexdigest()
def verify()->dict[str,Any]:
 errors=[];base=verify_corpus_freeze(require_freeze=True,require_evaluator_frozen=False)
 if not base.get('passed'):errors.extend(str(x) for x in base.get('errors') or [])
 if not EVAL_FREEZE.exists():errors.append('v8 evaluator freeze missing');f={}
 else:
  f=json.loads(EVAL_FREEZE.read_text())
  if f.get('first_blind_evaluator_frozen') is not True:errors.append('v8 evaluator freeze flag false')
  if f.get('scoring_executed') is not False or f.get('first_blind_consumed') is not False:errors.append('v8 evaluator freeze must be unscored/unconsumed')
  if f.get('v6_first_blind_score_used') is not False or f.get('v6_first_blind_case_errors_used') is not False:errors.append('v8 evaluator freeze contaminated by v6 result')
  for key,path in [('evaluator_sha256',EVALUATOR),('consumer_sha256',CONSUMER),('protocol_sha256',PROTOCOL),('corpus_freeze_sha256',FREEZE)]:
   expected=str(f.get(key) or '');actual=_sha(path) if path.exists() else ''
   if not expected or expected!=actual:errors.append(f'v8 preblind hash mismatch: {key}')
 receipt=ROOT/'benchmarks/raw/sources/v8_first_blind_consumption.json';result=ROOT/'benchmarks/raw/results/analysis_raw_v8_first_blind.json'
 if receipt.exists():errors.append('v8 First Blind receipt already exists')
 if result.exists():errors.append('v8 First Blind result already exists')
 return {'version':VERSION,'rule_version':RULE_VERSION,'passed':not errors,'errors':errors,'corpus_freeze':base,'evaluator_freeze_present':EVAL_FREEZE.exists(),'evaluator_frozen':f.get('first_blind_evaluator_frozen') is True if EVAL_FREEZE.exists() else False,'scoring_executed':False,'first_blind_consumed':False}
def main()->int:
 r=verify();print(json.dumps(r,indent=2,sort_keys=True));return 0 if r['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
