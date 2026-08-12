from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 1) Correct the client-side end-to-end contract: multiple hypotheses from the
# same family may coexist. Near-misses stay hidden; a distinct decisive target
# observation must still promote with a family-specific condition signal.
test_path = ROOT / "tests" / "test_physical_raw_collector_client_side_v6190.py"
text = test_path.read_text(encoding="utf-8")
old = '''                hypotheses = db.all("SELECT bug_family,bug_variant,state,rule_ids_json FROM analysis_hypotheses WHERE analysis_id=?", (result["analysis_id"],))
                routed = {}
                for row in hypotheses:
                    family = str(row["bug_family"]); rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(CLIENT_SIDE_FAMILIES) and "raw-collector-client-side-v1" in rules:
                        routed[family] = row
                self.assertEqual(set(routed), set(CLIENT_SIDE_FAMILIES), hypotheses)
                for family, expected in CLIENT_SIDE_OBSERVATIONS.items():
                    self.assertEqual(str(routed[family]["bug_variant"]), expected.variant)
                    self.assertEqual(str(routed[family]["state"]), "promoted")
'''
new = '''                hypotheses = db.all("SELECT bug_family,bug_variant,state,endpoint,rule_ids_json,supporting_evidence_json FROM analysis_hypotheses WHERE analysis_id=?", (result["analysis_id"],))
                routed = {}
                for row in hypotheses:
                    family = str(row["bug_family"]); rules = json.loads(row["rule_ids_json"] or "[]")
                    if family in set(CLIENT_SIDE_FAMILIES) and "raw-collector-client-side-v1" in rules:
                        routed.setdefault(family, []).append(row)
                self.assertEqual(set(routed), set(CLIENT_SIDE_FAMILIES), hypotheses)
                for family, expected in CLIENT_SIDE_OBSERVATIONS.items():
                    family_rows = [row for row in routed[family] if str(row["bug_variant"]) == expected.variant]
                    self.assertTrue(family_rows, (family, routed[family]))
                    promoted_rows = [row for row in family_rows if str(row["state"]) == "promoted"]
                    self.assertTrue(promoted_rows, (family, [dict(row) for row in family_rows]))
                    condition_signals = set(get_detector_spec(family).condition_signals)
                    self.assertTrue(
                        any(
                            {str(item.get("type") or "") for item in json.loads(row["supporting_evidence_json"] or "[]")} & condition_signals
                            for row in promoted_rows
                        ),
                        (family, condition_signals, [dict(row) for row in promoted_rows]),
                    )
                # A postMessage handler using location.href may legitimately retain a separate
                # non-promoted Open Redirect hypothesis. The real redirect observation must
                # still promote independently with external-destination evidence.
                redirect_promoted = [row for row in routed["open_redirect"] if str(row["state"]) == "promoted"]
                self.assertTrue(any("/login?redirect=/home" in str(row["endpoint"]) for row in redirect_promoted), [dict(row) for row in routed["open_redirect"]])
                self.assertTrue(any(
                    "external_destination" in {str(item.get("type") or "") for item in json.loads(row["supporting_evidence_json"] or "[]")}
                    for row in redirect_promoted
                ), [dict(row) for row in redirect_promoted])
'''
if text.count(old) != 1:
    raise RuntimeError(f"expected one Analysis 6.19 routed-hypothesis block, found {text.count(old)}")
test_path.write_text(text.replace(old, new, 1), encoding="utf-8")

# 2) Make the historical physical-detector regression independently runnable.
# It previously relied on another discovered test mutating sys.path first.
physical_path = ROOT / "tests" / "test_physical_family_detectors_v690.py"
physical = physical_path.read_text(encoding="utf-8")
old_imports = '''import importlib
import unittest
from pathlib import Path

from analysis_standards import FAMILY_STANDARDS, STANDARDS_ENGINE_VERSION
'''
new_imports = '''import importlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_standards import FAMILY_STANDARDS, STANDARDS_ENGINE_VERSION
'''
if physical.count(old_imports) != 1:
    raise RuntimeError(f"expected one physical-detector import block, found {physical.count(old_imports)}")
physical_path.write_text(physical.replace(old_imports, new_imports, 1), encoding="utf-8")

# 3) Refresh only the manifest entries touched by this post-generation contract fix.
manifest = ROOT / "MANIFEST.sha256"
lines = manifest.read_text(encoding="utf-8").splitlines()
replacements = {
    "tests/test_physical_raw_collector_client_side_v6190.py": hashlib.sha256(test_path.read_bytes()).hexdigest(),
    "tests/test_physical_family_detectors_v690.py": hashlib.sha256(physical_path.read_bytes()).hexdigest(),
}
updated = []
seen: set[str] = set()
for line in lines:
    replaced = False
    for relative, digest in replacements.items():
        if line.endswith("  " + relative):
            updated.append(f"{digest}  {relative}")
            seen.add(relative)
            replaced = True
            break
    if not replaced:
        updated.append(line)
for relative, digest in replacements.items():
    if relative not in seen:
        updated.append(f"{digest}  {relative}")
manifest.write_text("\n".join(updated) + "\n", encoding="utf-8")
