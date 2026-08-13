from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "tests" / "test_physical_raw_collector_exposure_headers_v6230.py"
text = path.read_text(encoding="utf-8")
old = '''        execution2, assessment2 = self._assessment("sensitive_caching", protected)
        support2 = {str(row.get("type") or "") for row in execution2["sensitive_caching"]["support"]}
        contradict2 = {str(row.get("type") or "") for row in execution2["sensitive_caching"]["contradict"]}
        self.assertNotIn("browser_cache_no_store_missing", support2)
        self.assertIn("no_store", contradict2)
        self.assertFalse(assessment2["admitted"], (assessment2, execution2["sensitive_caching"]))
'''
new = '''        execution2, assessment2 = self._assessment("sensitive_caching", protected)
        protected_packet = execution2.get("sensitive_caching", {"support": [], "contradict": []})
        support2 = {str(row.get("type") or "") for row in protected_packet["support"]}
        contradict2 = {str(row.get("type") or "") for row in protected_packet["contradict"]}
        self.assertNotIn("browser_cache_no_store_missing", support2)
        if protected_packet["support"] or protected_packet["contradict"]:
            self.assertIn("no_store", contradict2)
        self.assertFalse(assessment2["admitted"], (assessment2, protected_packet))
'''
if old not in text:
    raise SystemExit("safe-cache historical packet expectation marker missing")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
