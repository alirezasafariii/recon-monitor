from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
test_path = ROOT / "tests" / "test_specialized_static_collectors_v6240.py"
text = test_path.read_text(encoding="utf-8")
old = '''                aid="analysis-624-pipeline"; run="run-624-pipeline"; target="fixture.invalid"
                self._seed(db, aid, run, target)
                _static_candidates(db, aid, run, target)
'''
new = '''                aid="analysis-624-pipeline"; run="run-624-pipeline"; target="fixture.invalid"; now=utc_now()
                db.execute("INSERT INTO runs(id,version,status,started_at,finished_at,target_count) VALUES(?,?,?,?,?,?)", (run, "6.23.0", "success", now, now, 1))
                db.execute("INSERT INTO analysis_runs(id,source_run_id,target,engine_version,rule_version,mode,status,started_at,finished_at,summary_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (aid, run, target, "6.23.0", "2026.08.12.6.23", "analysis", "success", now, now, "{}"))
                self._seed(db, aid, run, target)
                _static_candidates(db, aid, run, target)
'''
if text.count(old) != 1:
    raise RuntimeError(f"6.24 pipeline fixture target drift: {text.count(old)}")
test_path.write_text(text.replace(old, new, 1), encoding="utf-8")

manifest = ROOT / "MANIFEST.sha256"
entries: list[str] = []
for line in manifest.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    _, rel = line.split("  ", 1)
    entries.append(rel.strip())
manifest.write_text(
    "\n".join(f"{hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()}  {rel}" for rel in sorted(set(entries))) + "\n",
    encoding="utf-8",
)
