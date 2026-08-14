from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from raw_recon_corpus import ROOT

SCHEMA=ROOT/'benchmarks/raw/sources/v6_literal_label_schema.json'
PLAN=ROOT/'benchmarks/raw/sources/v6_literal_capture_plan.json'
OUT=ROOT/'benchmarks/raw/sources/v6_remaining_signal_index.json'

def main() -> int:
    schema=json.loads(SCHEMA.read_text(encoding='utf-8'))
    plan=json.loads(PLAN.read_text(encoding='utf-8'))
    families=sorted({str(r.get('family') or '') for r in plan.get('requirements') or [] if isinstance(r,Mapping) and not bool(r.get('evidence_present'))})
    vocab=schema.get('families') if isinstance(schema.get('families'),Mapping) else {}
    rows={family:{'condition_signals':list((vocab.get(family) or {}).get('condition_signals') or []),'blocking_controls':list((vocab.get(family) or {}).get('blocking_controls') or [])} for family in families}
    value={'evaluation_kind':'fresh_blind_v6_remaining_signal_index_unscored','remaining_family_count':len(families),'families':rows,'detector_output_used':False,'admission_output_used':False,'ranking_output_used':False,'scoring_executed':False,'first_blind_consumed':False}
    OUT.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps(value,indent=2,sort_keys=True))
    return 0

if __name__=='__main__': raise SystemExit(main())
