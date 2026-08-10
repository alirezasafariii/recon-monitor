from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "app"))

from analysis_benchmark import benchmark_file, family_compatibility, REAL_WORLD_CORPUS
from hypothesis_admission import FAMILY_ADMISSION_POLICIES

report = benchmark_file(REAL_WORLD_CORPUS)
held = report["partitions"]["held_out"]
rows = held["cases"]
errors = []
confusion = defaultdict(Counter)
for row in rows:
    if not row.get("rank_required") or row.get("top1_correct"):
        continue
    case = next(c for c in __import__('analysis_benchmark').load_golden_cases(REAL_WORLD_CORPUS) if c['id'] == row['id'])
    support = case.get('support', [])
    contradict = case.get('contradict', [])
    rankings = [family_compatibility(f, support, contradict) for f in FAMILY_ADMISSION_POLICIES]
    rankings.sort(key=lambda item: (float(item['score']), bool(item['assessment'].get('admitted')), str(item['family'])), reverse=True)
    target = next(x for x in rankings if x['family'] == row['family'])
    top = rankings[:5]
    confusion[row['family']][row['top1']] += 1
    errors.append({
        'id': row['id'],
        'case_kind': row['case_kind'],
        'family': row['family'],
        'predicted_top1': row['top1'],
        'expected_admitted': row['expected_admitted'],
        'target_score': target['score'],
        'target_state': target['assessment'].get('state'),
        'target_required_satisfied': target['assessment'].get('required_satisfied'),
        'target_required_missing': target['assessment'].get('required_missing'),
        'top5': [
            {
                'family': x['family'],
                'score': x['score'],
                'admitted': bool(x['assessment'].get('admitted')),
                'state': x['assessment'].get('state'),
                'required_satisfied': x['assessment'].get('required_satisfied'),
                'required_missing': x['assessment'].get('required_missing'),
                'blocking': x['assessment'].get('blocking_contradictions'),
            }
            for x in top
        ],
        'support_types': [str(x.get('type')) for x in support],
        'contradict_types': [str(x.get('type')) for x in contradict],
    })

print(json.dumps({
    'heldout_case_count': len(rows),
    'heldout_top1': report['metrics']['heldout_top1_accuracy'],
    'misrank_count': len(errors),
    'confusion': {k: dict(v) for k, v in sorted(confusion.items())},
    'errors': errors,
}, indent=2, sort_keys=True))
