from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"

shortlist = (APP / "raw_recon_v2_shortlist.py").read_text(encoding="utf-8")
shortlist = (
    shortlist
    .replace("raw_recon_v2_corpus", "raw_recon_v3_corpus")
    .replace("v2_candidates.json", "v3_candidates.json")
    .replace("v2_shortlist.json", "v3_shortlist.json")
    .replace("Analysis 6.13 v2", "Analysis 6.15 v3")
    .replace("frozen 6.12 engine", "frozen 6.14 engine")
    .replace("pre-frozen engine", "pre-frozen engine")
)
shortlist = shortlist.replace('SHORTLIST_VERSION = "1.1.0"', 'SHORTLIST_VERSION = "1.0.0"')
# Analysis 6.14 added conservative raw-condition reconstruction for these three
# families, so all twenty source buckets now have a target-observable replay path.
shortlist = shortlist.replace(
    '    "secret_exposure",\n}',
    '    "secret_exposure",\n    "command_injection",\n    "race_condition",\n    "unrestricted_resource_consumption",\n}',
    1,
)
(APP / "raw_recon_v3_shortlist.py").write_text(shortlist, encoding="utf-8")

materializer = (APP / "raw_recon_v2_materialize.py").read_text(encoding="utf-8")
materializer = (
    materializer
    .replace("raw_recon_v2_corpus", "raw_recon_v3_corpus")
    .replace("validate_v2_corpus", "validate_v3_corpus")
    .replace("v2_shortlist.json", "v3_shortlist.json")
    .replace("analysis_raw_v2.jsonl", "analysis_raw_v3.jsonl")
    .replace("v2_materialization_report.json", "v3_materialization_report.json")
    .replace("Analysis 6.13 raw v2", "Analysis 6.15 raw v3")
    .replace("v2 materialization", "v3 materialization")
    .replace('return published[:10] if len(published) >= 10 else "2026-08-11"', 'return published[:10] if len(published) >= 10 else "2026-08-12"')
)
(APP / "raw_recon_v3_materialize.py").write_text(materializer, encoding="utf-8")

print("Analysis 6.15 collection helpers staged")
