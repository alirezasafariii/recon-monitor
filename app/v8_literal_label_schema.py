from __future__ import annotations

import hashlib
import json

from family_detectors.registry import DETECTOR_SPECS
from raw_recon_corpus import ROOT

VERSION='1.0.0'
RULE_VERSION='2026.08.14.6.32.v8.1'
OUTPUT=ROOT/'benchmarks/raw/sources/v8_literal_label_schema.json'


def build() -> dict:
    families={}
    for family,spec in sorted(DETECTOR_SPECS.items()):
        families[family]={
            'condition_signals':sorted(spec.condition_signals),
            'blocking_controls':sorted(spec.blocking_controls),
            'override_signals':sorted(spec.override_signals),
            'schema_role':'canonical_vocabulary_only_not_target_adjudication',
        }
    payload={
        'version':VERSION,'rule_version':RULE_VERSION,'evaluation_kind':'fresh_blind_v8_pre_score_label_vocabulary',
        'family_count':len(families),'families':families,
        'adjudication_policy':'Source evidence decides condition presence; this schema only freezes accepted condition/control names. OWASP/WSTG/CWE/write-up logic never counts as target evidence.',
        'detector_output_used':False,'admission_output_used':False,'ranking_output_used':False,
        'v6_first_blind_score_used':False,'v6_first_blind_case_errors_used':False,
        'scoring_executed':False,'first_blind_consumed':False,
    }
    raw=json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
    payload['schema_content_sha256']=hashlib.sha256(raw).hexdigest()
    return payload


def main() -> int:
    r=build()
    if r['family_count']!=36: raise RuntimeError(f"expected 36 families, got {r['family_count']}")
    OUTPUT.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'family_count':r['family_count'],'scoring_executed':r['scoring_executed']},sort_keys=True))
    return 0


if __name__=='__main__': raise SystemExit(main())
