from __future__ import annotations

import json
from pathlib import Path

from raw_recon_corpus import ROOT
from raw_recon_v7_source_discovery import discover

OUT = ROOT / 'benchmarks/raw/sources/v7_candidates_fast.json'


def main() -> int:
    report = discover(
        recent_reviewed_pages=2,
        recent_unreviewed_pages=3,
        targeted_reviewed_pages=1,
        targeted_unreviewed_pages=1,
        target_per_family=30,
    )
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({
        'family_count': report['family_count'],
        'families_without_candidates': report['families_without_candidates'],
        'families_without_semantic_candidates': report.get('families_without_semantic_candidates', []),
        'api_request_count': report.get('api_request_count'),
        'source_firewall_rejection_count': report.get('source_firewall_rejection_count'),
        'scoring_executed': report['scoring_executed'],
    }, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
