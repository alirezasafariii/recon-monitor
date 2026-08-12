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
needle = '                result = run_analysis(paths, db, run_id, target)\n                hypothesis_rows = db.all('
diagnostic = '''                result = run_analysis(paths, db, run_id, target)\n                debug_row = db.one(\n                    "SELECT r.category,r.business_context,r.endpoint_schema_json,a.item,a.details_json FROM analysis_results r JOIN alerts a ON a.id=r.alert_id WHERE r.analysis_id=? AND a.item LIKE ?",\n                    (result["analysis_id"], "%redirect%"),\n                )\n                if debug_row:\n                    debug_schema = json.loads(debug_row["endpoint_schema_json"] or "{}")\n                    debug_details = json.loads(debug_row["details_json"] or "{}")\n                    debug_execution = execute_detector_intelligence(\n                        target=target,\n                        endpoint=str(debug_schema.get("endpoint") or debug_row["item"] or ""),\n                        method=str(debug_schema.get("method") or "UNKNOWN"),\n                        endpoint_schema=debug_schema,\n                        details=debug_details,\n                        category=str(debug_row["category"] or ""),\n                        business_context=str(debug_row["business_context"] or "general"),\n                    )\n                    print("DEBUG619_OPEN_REDIRECT_INPUT", json.dumps({"schema": debug_schema, "details": debug_details}, sort_keys=True))\n                    print("DEBUG619_OPEN_REDIRECT_PACKET", json.dumps(debug_execution.get("open_redirect", {}), sort_keys=True))\n                hypothesis_rows = db.all('''
if text.count(needle) != 1:
    raise RuntimeError(f"expected one run_analysis diagnostic insertion, found {text.count(needle)}")
text = text.replace(needle, diagnostic, 1)
path.write_text(text, encoding="utf-8")
