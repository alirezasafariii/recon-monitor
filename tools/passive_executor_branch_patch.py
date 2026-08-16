from __future__ import annotations

from pathlib import Path
import hashlib


def replace_once(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one replacement, found {count}: {old[:80]!r}")
    return text.replace(old, new, 1)


executor = Path("app/validation_executor.py")
text = executor.read_text(encoding="utf-8")

if "from validation_runner import snapshot_validation_runner_dry_run" not in text:
    text = replace_once(
        text,
        "from validation_eligibility import snapshot_validation_eligibility\n",
        "from validation_eligibility import snapshot_validation_eligibility\n"
        "from validation_runner import snapshot_validation_runner_dry_run\n",
    )

if "http_budget_units_consumed = 0" not in text:
    text = replace_once(
        text,
        "    failed_5xx = 0\n\n    try:\n",
        "    failed_5xx = 0\n"
        "    http_budget_units_consumed = 0\n\n"
        "    try:\n",
    )

if "http_budget_units_consumed += 1" not in text:
    text = replace_once(
        text,
        '            budget.consume("http_requests", 1)\n'
        "            observation, state = safe_validation._perform_request(request, policy)\n",
        '            budget.consume("http_requests", 1)\n'
        "            http_budget_units_consumed += 1\n"
        "            observation, state = safe_validation._perform_request(request, policy)\n",
    )

if "fresh_dry_run = snapshot_validation_runner_dry_run(" not in text:
    text = replace_once(
        text,
        '    if str(fresh_decision.get("validation_level") or "") != "passive_live":\n'
        '        raise ReconError("Fresh Validation Eligibility no longer permits passive-live validation")\n\n'
        "    endpoint = _safe_contract_url(contract, policy)\n",
        '    if str(fresh_decision.get("validation_level") or "") != "passive_live":\n'
        '        raise ReconError("Fresh Validation Eligibility no longer permits passive-live validation")\n\n'
        "    fresh_dry_run = snapshot_validation_runner_dry_run(\n"
        "        ctx,\n"
        "        evidence_completion_plan=planner,\n"
        "        validation_eligibility=fresh_gate,\n"
        "        persist=False,\n"
        "    )\n"
        "    fresh_contract = _contract_by_id(fresh_dry_run, contract_id)\n"
        '    for key in ("hypothesis_id", "family", "validation_level", "planning_phase"):\n'
        '        if str(contract.get(key) or "") != str(fresh_contract.get(key) or ""):\n'
        '            raise ReconError(f"Fresh Validation Runner dry-run contract mismatch: {key}")\n'
        '    stored_surface = dict(contract.get("surface") or {})\n'
        '    fresh_surface = dict(fresh_contract.get("surface") or {})\n'
        "    if (\n"
        '        str(stored_surface.get("kind") or "") != str(fresh_surface.get("kind") or "")\n'
        '        or str(stored_surface.get("display") or "") != str(fresh_surface.get("display") or "")\n'
        "    ):\n"
        '        raise ReconError("Fresh Validation Runner dry-run contract surface mismatch")\n'
        "    contract = fresh_contract\n\n"
        "    endpoint = _safe_contract_url(contract, policy)\n",
    )

if '"http_budget_units_consumed": http_budget_units_consumed,' not in text:
    text = replace_once(
        text,
        '            "network_requests_executed": len(observations),\n'
        '            "budget_consumed": True,\n',
        '            "network_requests_executed": len(observations),\n'
        '            "http_budget_units_consumed": http_budget_units_consumed,\n'
        '            "budget_consumed": http_budget_units_consumed > 0,\n',
    )
    text = replace_once(
        text,
        '        "network_requests_executed": len(observations),\n'
        '        "budget_consumed": bool(observations),\n',
        '        "network_requests_executed": len(observations),\n'
        '        "http_budget_units_consumed": http_budget_units_consumed,\n'
        '        "budget_consumed": http_budget_units_consumed > 0,\n',
    )

executor.write_text(text, encoding="utf-8")


tests = Path("tests/test_validation_executor.py")
test_text = tests.read_text(encoding="utf-8")
marker = "    def test_cors_recipe_uses_only_allowlisted_safe_headers_and_methods(self):\n"
if "test_modified_dry_run_surface_is_rejected_before_transport" not in test_text:
    regression = """    def test_modified_dry_run_surface_is_rejected_before_transport(self):
        _, _, dry, contract_id = self.fx.make_artifacts(passive_plan())
        dry[\"contracts\"][0][\"surface\"][\"display\"] = \"https://api.example.test/tampered\"
        (self.fx.run_dir / \"validation-runner-dry-run.json\").write_text(
            json_dumps(dry, pretty=True) + \"\\n\",
            encoding=\"utf-8\",
        )
        with patch(\"validation_executor.safe_validation._perform_request\") as request:
            with self.assertRaisesRegex(ReconError, \"dry-run contract surface mismatch\"):
                self.fx.execute(contract_id)
        request.assert_not_called()
        self.assertEqual(self.fx.budget_used(), 0)

"""
    if marker not in test_text:
        raise SystemExit("test insertion marker not found")
    test_text = test_text.replace(marker, regression + marker, 1)
tests.write_text(test_text, encoding="utf-8")


manifest = Path("MANIFEST.sha256")
entries: dict[str, str] = {}
for raw in manifest.read_text(encoding="utf-8").splitlines():
    if not raw.strip():
        continue
    digest, rel = raw.split("  ", 1)
    entries[rel] = digest
for rel in (
    "app/recon_monitor.py",
    "app/validation_executor.py",
    "tests/test_validation_executor.py",
):
    entries[rel] = hashlib.sha256(Path(rel).read_bytes()).hexdigest()
manifest.write_text(
    "".join(f"{entries[rel]}  {rel}\n" for rel in sorted(entries)),
    encoding="utf-8",
)
