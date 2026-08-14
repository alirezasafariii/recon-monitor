from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from raw_recon_corpus import ROOT

VERSION='1.0.0'; RULE_VERSION='2026.08.14.6.32.v7.18'
FREEZE=ROOT/'benchmarks/raw/sources/v7_corpus_freeze.json'; MANIFEST=ROOT/'benchmarks/raw/sources/v7_freeze_manifest.sha256'; EVAL_FREEZE=ROOT/'benchmarks/raw/sources/v7_evaluator_freeze.json'; EVALUATOR=ROOT/'app/v7_benchmark_evaluate.py'; PROTOCOL=ROOT/'benchmarks/raw/sources/v7_protocol.json'

def _sha(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()
def _verify_eval(errors:list[str],freeze_path:Path)->dict[str,Any]:
 if not EVAL_FREEZE.exists():errors.append('v7 evaluator freeze missing');return {'present':False,'frozen':False}
 f=json.loads(EVAL_FREEZE.read_text())
 if f.get('first_blind_evaluator_frozen') is not True:errors.append('v7 evaluator not frozen')
 if f.get('scoring_executed') is not False or f.get('first_blind_consumed') is not False:errors.append('v7 evaluator freeze must remain unscored/unconsumed')
 for key,path in [('evaluator_sha256',EVALUATOR),('protocol_sha256',PROTOCOL),('corpus_freeze_sha256',freeze_path)]:
  expected=str(f.get(key) or '');actual=_sha(path) if path.exists() else ''
  if not expected or actual!=expected:errors.append(f'v7 evaluator freeze hash mismatch: {key}')
 return {'present':True,'frozen':f.get('first_blind_evaluator_frozen') is True,'evaluator_sha256':f.get('evaluator_sha256'),'protocol_sha256':f.get('protocol_sha256'),'corpus_freeze_sha256':f.get('corpus_freeze_sha256')}
def verify(*,require_freeze:bool=False,require_evaluator_frozen:bool=False)->dict[str,Any]:
 errors=[]
 if not FREEZE.exists():
  if require_freeze:errors.append('v7 corpus freeze required but missing')
  return {'verifier_version':VERSION,'verifier_rule_version':RULE_VERSION,'freeze_present':False,'passed':not errors,'errors':errors,'evaluator_freeze':{'present':False,'frozen':False}}
 freeze=json.loads(FREEZE.read_text())
 if freeze.get('evaluation_status')!='sealed_fresh_v7_unscored_holdout':errors.append('v7 freeze status invalid')
 if freeze.get('scoring_executed') is not False or freeze.get('first_blind_consumed') is not False:errors.append('v7 freeze must remain unscored/unconsumed')
 if freeze.get('v6_first_blind_score_used') is not False or freeze.get('v6_first_blind_case_errors_used') is not False:errors.append('v7 freeze contaminated by v6 result')
 protected=freeze.get('protected_sha256') if isinstance(freeze.get('protected_sha256'),dict) else {}
 if not protected:errors.append('v7 protected hash map empty')
 actual={}
 for rel,expected in sorted(protected.items()):
  path=ROOT/rel
  if not path.exists():errors.append(f'v7 protected path missing: {rel}');continue
  digest=_sha(path);actual[rel]=digest
  if digest!=str(expected):errors.append(f'v7 protected hash mismatch: {rel}')
 if not MANIFEST.exists():errors.append('v7 freeze manifest missing')
 else:
  parsed={}
  for line in MANIFEST.read_text().splitlines():
   if not line.strip():continue
   digest,rel=line.split(None,1);parsed[rel.strip()]=digest.strip()
  if parsed!={str(k):str(v) for k,v in protected.items()}:errors.append('v7 manifest differs from protected hash map')
 evaluator={'present':EVAL_FREEZE.exists(),'frozen':False}
 if require_evaluator_frozen or EVAL_FREEZE.exists():evaluator=_verify_eval(errors,FREEZE)
 return {'verifier_version':VERSION,'verifier_rule_version':RULE_VERSION,'freeze_present':True,'passed':not errors,'errors':errors,'protected_count':len(protected),'verified_count':len(actual),'evaluator_freeze':evaluator,'scoring_executed':freeze.get('scoring_executed'),'first_blind_consumed':freeze.get('first_blind_consumed')}
def main()->int:
 p=argparse.ArgumentParser();p.add_argument('--require-freeze',action='store_true');p.add_argument('--require-evaluator-frozen',action='store_true');a=p.parse_args();r=verify(require_freeze=a.require_freeze,require_evaluator_frozen=a.require_evaluator_frozen);print(json.dumps(r,indent=2,sort_keys=True));return 0 if r['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
