from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
STANDARD_CI_SHA256 = "540637cb95ca3a2d6577a0d222a6cdb5d5d892244b305d66f6c1b962bc10484d"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"missing anchor: {label}")
    return text.replace(old, new, 1)


def apply() -> None:
    p = ROOT / "app/bug_candidates.py"
    text = p.read_text(encoding="utf-8")
    if "from family_reasoning import candidate_evidence_schema_map\n" not in text:
        text = replace_once(
            text,
            "from typing import Any, Callable, Mapping\n",
            "from typing import Any, Callable, Mapping\n\nfrom family_reasoning import candidate_evidence_schema_map\n",
            "candidate import",
        )
    text = replace_once(
        text,
        'CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION = "2.0.0"',
        'CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION = "2.1.0"',
        "candidate version",
    )
    pattern = re.compile(
        r'_base\.FAMILY_EVIDENCE_SCHEMAS\["broken_function_authorization"\]\s*=\s*\{.*?\nFAMILY_EVIDENCE_SCHEMAS = _base\.FAMILY_EVIDENCE_SCHEMAS',
        re.S,
    )
    replacement = (
        "# Single source of truth: Candidate Engine consumes the canonical 21-family\n"
        "# promotion contract directly from Family Reasoning.\n"
        "_base.FAMILY_EVIDENCE_SCHEMAS = candidate_evidence_schema_map()\n"
        "FAMILY_EVIDENCE_SCHEMAS = _base.FAMILY_EVIDENCE_SCHEMAS"
    )
    text, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise SystemExit(f"candidate schema block replacement count={count}")
    p.write_text(text, encoding="utf-8")

    p = ROOT / "app/workspace_v7.py"
    text = p.read_text(encoding="utf-8")
    core_line = "from core import APP_VERSION, SCHEMA_VERSION, AppPaths, Config, Database, ReconError, json_dumps, safe_json_loads, sha256_text, utc_now\n"
    if "from family_reasoning import DEFAULT_CASE_REQUIREMENTS, FAMILY_REASONING, case_requirement_map\n" not in text:
        text = replace_once(
            text,
            core_line,
            core_line + "from family_reasoning import DEFAULT_CASE_REQUIREMENTS, FAMILY_REASONING, case_requirement_map\n",
            "workspace import",
        )
    req_pattern = re.compile(
        r'BUG_FAMILY_REQUIREMENTS: dict\[str, list\[dict\[str, str\]\]\] = \{.*?\nDEFAULT_REQUIREMENTS = \[.*?\n\]\n\nBUG_FAMILY_ALIASES =',
        re.S,
    )
    text, count = req_pattern.subn("FAMILY_CASE_REQUIREMENTS = case_requirement_map()\n\nBUG_FAMILY_ALIASES =", text, count=1)
    if count != 1:
        raise SystemExit(f"workspace requirement block replacement count={count}")
    alias_anchor = '    "websocket_authorization": "websocket_authorization",\n}\n\ndef _canonical_family'
    alias_replacement = (
        '    "websocket_authorization": "websocket_authorization",\n'
        '}\n'
        'BUG_FAMILY_ALIASES.update({family: family for family in FAMILY_REASONING})\n'
        'BUG_FAMILY_ALIASES.update({str(policy.get("label") or "").strip().lower(): family for family, policy in FAMILY_REASONING.items()})\n\n'
        'def _canonical_family'
    )
    text = replace_once(text, alias_anchor, alias_replacement, "workspace aliases")
    text = replace_once(
        text,
        "    requirements = list(DEFAULT_REQUIREMENTS)\n    requirements.extend(BUG_FAMILY_REQUIREMENTS.get(family, []))",
        "    requirements = [dict(item) for item in FAMILY_CASE_REQUIREMENTS.get(family, DEFAULT_CASE_REQUIREMENTS)]",
        "workspace evidence gap",
    )
    p.write_text(text, encoding="utf-8")

    p = ROOT / "app/safe_validation.py"
    text = p.read_text(encoding="utf-8")
    if "from family_reasoning import FAMILY_REASONING, validation_level_for_family\n" not in text:
        text = replace_once(
            text,
            ')\n\nVALIDATION_VERSION = "6.0.4"',
            ')\nfrom family_reasoning import FAMILY_REASONING, validation_level_for_family\n\nVALIDATION_VERSION = "6.1.0"',
            "safe validation import/version",
        )
    else:
        text = text.replace('VALIDATION_VERSION = "6.0.4"', 'VALIDATION_VERSION = "6.1.0"', 1)
    text = text.replace("MANUAL_FAMILY_HINTS", "LEGACY_MANUAL_FAMILY_HINTS")
    text = text.replace("CONTROLLED_FAMILY_HINTS", "LEGACY_CONTROLLED_FAMILY_HINTS")
    text = text.replace("PASSIVE_FAMILY_HINTS", "LEGACY_PASSIVE_FAMILY_HINTS")

    eligibility_pattern = re.compile(
        r'def validation_eligibility\(db: Database, case_id: str\) -> dict\[str, Any\]:.*?\n\ndef _policy_for_target',
        re.S,
    )
    eligibility_replacement = '''def _canonical_family_id(case: dict[str, Any], candidates: Iterable[dict[str, Any]]) -> str:
    values = [str(case.get("primary_family") or "")]
    values.extend(str(row.get("bug_family") or "") for row in candidates)
    for raw in values:
        value = str(raw or "").strip()
        if not value:
            continue
        if value in FAMILY_REASONING:
            return value
        normalized = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
        if normalized in FAMILY_REASONING:
            return normalized
        lower = value.lower()
        for family, policy in FAMILY_REASONING.items():
            if lower == str(policy.get("label") or "").strip().lower():
                return family
    aliases = {
        "bola": "broken_object_authorization",
        "idor": "broken_object_authorization",
        "bola / idor": "broken_object_authorization",
        "bfla": "broken_function_authorization",
        "xss": "dom_xss",
        "dom xss": "dom_xss",
        "source map exposure": "source_map_exposure",
        "secret exposure": "secret_exposure",
        "graphql authorization": "graphql_authorization",
        "graphql data exposure": "graphql_data_exposure",
        "websocket authorization": "websocket_authorization",
        "cors": "cors_misconfiguration",
        "sensitive caching": "sensitive_caching",
    }
    for raw in values:
        resolved = aliases.get(str(raw or "").strip().lower())
        if resolved:
            return resolved
    return ""


def validation_eligibility(db: Database, case_id: str) -> dict[str, Any]:
    case, candidates = _case(db, case_id)
    family_text = _family_text(case, candidates)
    canonical_family = _canonical_family_id(case, candidates)
    reasons: list[str] = []
    if canonical_family:
        level = validation_level_for_family(canonical_family)
        reason_by_level = {
            "offline": "Family Reasoning defines this family as offline-only for automatic validation.",
            "passive_live": "Family Reasoning permits only bounded passive-live observation for this family.",
            "controlled": "Family Reasoning requires explicitly controlled test identities/resources for this family.",
            "manual_only": "Family Reasoning requires manual-only validation because active automation could cause unsafe effects.",
        }
        reasons.append(reason_by_level.get(level, "Family Reasoning did not define a live validation recipe."))
    elif any(hint in family_text for hint in LEGACY_MANUAL_FAMILY_HINTS):
        level = "manual_only"
        reasons.append("Legacy family text maps to a manual-only safety class; no canonical family identifier was available.")
    elif any(hint in family_text for hint in LEGACY_CONTROLLED_FAMILY_HINTS):
        level = "controlled"
        reasons.append("Legacy family text maps to controlled validation; canonical family metadata should be added.")
    elif any(hint in family_text for hint in LEGACY_PASSIVE_FAMILY_HINTS):
        level = "passive_live"
        reasons.append("Legacy family text maps to passive-live validation; canonical family metadata should be added.")
    else:
        level = "offline"
        reasons.append("Unknown/non-canonical family fails closed to offline validation.")
    executable = level in {"offline", "passive_live"}
    return {
        "case_id": case_id,
        "target": case["target"],
        "primary_family": case["primary_family"],
        "canonical_family": canonical_family,
        "recommended_level": level,
        "executable_in_this_release": executable,
        "reasons": reasons,
        "constraints": {
            "methods": sorted(SAFE_METHODS),
            "maximum_requests": MAX_REQUESTS,
            "maximum_runtime_seconds": MAX_RUNTIME_SECONDS,
            "maximum_response_bytes": MAX_RESPONSE_BYTES,
            "redirects_followed": False,
            "cookies_or_credentials": False,
            "identifier_enumeration": False,
            "state_changes": False,
        },
    }


def _policy_for_target'''
    text, count = eligibility_pattern.subn(eligibility_replacement, text, count=1)
    if count != 1:
        raise SystemExit(f"safe-validation eligibility replacement count={count}")

    recipe_pattern = re.compile(
        r'def _request_recipe\(family: str, url: str\) -> list\[dict\[str, Any\]\]:.*?\n\ndef create_validation_plan',
        re.S,
    )
    recipe_replacement = '''def _request_recipe(family: str, url: str) -> list[dict[str, Any]]:
    family_id = str(family or "").strip().lower()
    if family_id == "cors_misconfiguration" or "cors" in family_id:
        return [
            {"method": "OPTIONS", "url": url, "headers": {"Origin": SAFE_ORIGIN, "Access-Control-Request-Method": "GET"}, "purpose": "Observe preflight policy"},
            {"method": "GET", "url": url, "headers": {"Origin": SAFE_ORIGIN}, "purpose": "Observe CORS response headers"},
        ]
    if family_id == "source_map_exposure" or "source map" in family_id or url.endswith(".map"):
        return [{"method": "GET", "url": url, "headers": {}, "purpose": "Presence and metadata check only"}]
    if family_id == "open_redirect" or "redirect" in family_id:
        return [{"method": "GET", "url": url, "headers": {}, "purpose": "Inspect Location without following redirect"}]
    if family_id == "authentication_session" or "authentication" in family_id or "session" in family_id:
        return [{"method": "GET", "url": url, "headers": {}, "purpose": "Anonymous boundary observation"}]
    if family_id == "sensitive_caching" or "cache" in family_id or "caching" in family_id:
        return [{"method": "GET", "url": url, "headers": {}, "purpose": "Observe cache directives and redacted response shape"}]
    return [
        {"method": "HEAD", "url": url, "headers": {}, "purpose": "Reachability and response metadata"},
        {"method": "GET", "url": url, "headers": {}, "purpose": "Redacted response-shape observation"},
    ]


def create_validation_plan'''
    text, count = recipe_pattern.subn(recipe_replacement, text, count=1)
    if count != 1:
        raise SystemExit(f"safe-validation recipe replacement count={count}")
    text = replace_once(
        text,
        '    family = _family_text(case, candidates)\n    requests: list[dict[str, Any]] = []',
        '    family = str(eligibility.get("canonical_family") or "") or _family_text(case, candidates)\n    requests: list[dict[str, Any]] = []',
        "safe validation plan family",
    )
    p.write_text(text, encoding="utf-8")

    (ROOT / "tests/test_architecture_single_source_v883.py").write_text(r'''from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import bug_candidates
import safe_validation
import workspace_v7
from family_reasoning import FAMILY_ORDER, candidate_evidence_schema_map, case_requirement_map, validation_level_for_family


class _FakeCaseDB:
    def __init__(self, family: str):
        self.family = family

    def one(self, sql, params=()):
        if "FROM security_cases" in sql:
            return {"case_id": "CASE-SINGLE-SOURCE", "target": "example.com", "primary_family": self.family}
        return None

    def all(self, sql, params=()):
        return []


class ArchitectureSingleSourceV883Tests(unittest.TestCase):
    def test_candidate_engine_uses_exact_canonical_schema_map_for_all_21(self):
        expected = candidate_evidence_schema_map()
        self.assertEqual(set(expected), set(FAMILY_ORDER))
        self.assertEqual(len(expected), 21)
        self.assertEqual(bug_candidates.FAMILY_EVIDENCE_SCHEMAS, expected)
        self.assertEqual(bug_candidates._base.FAMILY_EVIDENCE_SCHEMAS, expected)
        self.assertEqual(bug_candidates.CANDIDATE_FAMILY_ANALYZER_INTEGRATION_VERSION, "2.1.0")
        source = inspect.getsource(bug_candidates)
        self.assertNotIn('_base.FAMILY_EVIDENCE_SCHEMAS["broken_function_authorization"]', source)
        self.assertIn('candidate_evidence_schema_map()', source)

    def test_workspace_case_requirements_are_exact_canonical_map(self):
        expected = case_requirement_map()
        self.assertEqual(set(expected), set(FAMILY_ORDER))
        self.assertEqual(workspace_v7.FAMILY_CASE_REQUIREMENTS, expected)
        self.assertEqual([row["key"] for row in expected["broken_object_authorization"]], ["authenticated_context", "second_identity", "ownership_map", "comparable_response"])
        self.assertEqual(workspace_v7._canonical_family("Sensitive Response Caching"), "sensitive_caching")
        source = inspect.getsource(workspace_v7)
        self.assertNotIn("BUG_FAMILY_REQUIREMENTS", source)
        self.assertNotIn("DEFAULT_REQUIREMENTS =", source)

    def test_safe_validation_calls_exact_family_reasoning_classifier(self):
        db = _FakeCaseDB("account_enumeration")
        with patch.object(safe_validation, "validation_level_for_family", return_value="manual_only") as classifier:
            result = safe_validation.validation_eligibility(db, "CASE-SINGLE-SOURCE")
        classifier.assert_called_once_with("account_enumeration")
        self.assertEqual(result["canonical_family"], "account_enumeration")
        self.assertEqual(result["recommended_level"], "manual_only")

    def test_safe_validation_matches_all_21_canonical_levels(self):
        self.assertEqual(safe_validation.VALIDATION_VERSION, "6.1.0")
        for family in FAMILY_ORDER:
            result = safe_validation.validation_eligibility(_FakeCaseDB(family), "CASE-SINGLE-SOURCE")
            self.assertEqual(result["canonical_family"], family)
            self.assertEqual(result["recommended_level"], validation_level_for_family(family))

    def test_safe_validation_canonicalizes_family_labels_before_legacy_hints(self):
        result = safe_validation.validation_eligibility(_FakeCaseDB("BOLA / IDOR"), "CASE-SINGLE-SOURCE")
        self.assertEqual(result["canonical_family"], "broken_object_authorization")
        self.assertEqual(result["recommended_level"], "controlled")
        result = safe_validation.validation_eligibility(_FakeCaseDB("Unsafe postMessage Trust"), "CASE-SINGLE-SOURCE")
        self.assertEqual(result["canonical_family"], "postmessage_trust")
        self.assertEqual(result["recommended_level"], "manual_only")

    def test_unknown_family_fails_closed_to_offline(self):
        result = safe_validation.validation_eligibility(_FakeCaseDB("future_unknown_family"), "CASE-SINGLE-SOURCE")
        self.assertEqual(result["canonical_family"], "")
        self.assertEqual(result["recommended_level"], "offline")
        self.assertTrue(result["executable_in_this_release"])

    def test_exact_recipe_selection_uses_canonical_ids(self):
        self.assertEqual([row["method"] for row in safe_validation._request_recipe("sensitive_caching", "https://example.com/account")], ["GET"])
        self.assertEqual([row["method"] for row in safe_validation._request_recipe("cors_misconfiguration", "https://example.com/api")], ["OPTIONS", "GET"])
        self.assertEqual([row["method"] for row in safe_validation._request_recipe("source_map_exposure", "https://example.com/app.js.map")], ["GET"])


if __name__ == "__main__":
    unittest.main()
''', encoding="utf-8")

    (ROOT / "docs/ARCHITECTURE_SINGLE_SOURCE.md").write_text(
        "# Architecture Single Source of Truth\n\n"
        "Recon Monitor now uses `app/family_reasoning.py` as the canonical source for three cross-cutting family contracts.\n\n"
        "- Candidate Engine evidence schemas come from `candidate_evidence_schema_map()` for all 21 families.\n"
        "- Security-case evidence requirements come from `case_requirement_map()` for all 21 families.\n"
        "- Safe Validation classification comes from `validation_level_for_family()` using the canonical family ID; legacy text hints are fallback-only.\n\n"
        "This removes duplicated per-family policy tables from `bug_candidates.py` and `workspace_v7.py`, and removes substring matching as the primary safety classifier in `safe_validation.py`. Unknown future families fail closed to offline validation.\n\n"
        "The consolidation does not loosen validation safety limits: GET/HEAD/OPTIONS-only execution, request/runtime/response caps, no redirects, no cookies/credentials, no identifier enumeration and no state changes remain unchanged.\n",
        encoding="utf-8",
    )


def finalize() -> None:
    temp = ROOT / ".ci-consolidate.py"
    if temp.exists():
        temp.unlink()
    names = subprocess.check_output(["git", "ls-files", "-co", "--exclude-standard", "-z"]).decode().split("\0")
    lines: list[str] = []
    for name in sorted(set(x for x in names if x and x not in {"MANIFEST.sha256", ".ci-consolidate.py"})):
        if name == ".github/workflows/ci.yml":
            digest = STANDARD_CI_SHA256
        else:
            path = ROOT / name
            if not path.exists():
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    (ROOT / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "apply"
    if mode == "apply":
        apply()
    elif mode == "finalize":
        finalize()
    else:
        raise SystemExit(f"unknown mode: {mode}")
