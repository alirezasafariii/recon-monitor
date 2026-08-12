from pathlib import Path

path = Path("tests/test_physical_raw_collector_client_side_v6190.py")
text = path.read_text(encoding="utf-8")
old = '"SELECT bug_family,bug_variant,state,rule_ids_json FROM analysis_hypotheses WHERE analysis_id=?"'
new = '"SELECT bug_family,bug_variant,state,rule_ids_json,admission_json,supporting_evidence_json FROM analysis_hypotheses WHERE analysis_id=?"'
if text.count(old) != 1:
    raise RuntimeError(f"expected one hypothesis query, found {text.count(old)}")
text = text.replace(old, new, 1)
old_assert = '                    self.assertEqual(str(routed[family]["state"]), "promoted")'
new_assert = '                    self.assertEqual(str(routed[family]["state"]), "promoted", (family, dict(routed[family])))'
if text.count(old_assert) != 1:
    raise RuntimeError(f"expected one promotion assertion, found {text.count(old_assert)}")
text = text.replace(old_assert, new_assert, 1)
path.write_text(text, encoding="utf-8")
