from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
APP = ROOT / "app"
TESTS = ROOT / "tests"
DOCS = ROOT / "docs"


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"anchor not found in {path}: {old[:120]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def regex_once(path: Path, pattern: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"regex anchor not found in {path}: {pattern[:120]!r}")
    path.write_text(updated, encoding="utf-8")


ranking = '''from __future__ import annotations

from typing import Any, Iterable, Mapping

from hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission

RANKING_ENGINE_VERSION = "1.0.0"
RANKING_RULE_VERSION = "2026.08.10.6.5"


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, float(value)))


def admission_confidence(assessment: Mapping[str, Any]) -> float:
    """Probability-like confidence that the vulnerability condition is established.

    This is deliberately separate from family fit. A family-specific security control can
    make the vulnerability condition unlikely while simultaneously making the family
    classification more certain.
    """
    if assessment.get("admitted"):
        return 0.96
    state = str(assessment.get("state") or "")
    if state == "shadow_contradicted":
        return 0.04
    satisfied = len(assessment.get("required_satisfied") or [])
    missing = len(assessment.get("required_missing") or [])
    coverage = satisfied / max(1, satisfied + missing)
    if state == "shadow_partial":
        return round(min(0.28, 0.06 + 0.24 * coverage), 6)
    return 0.04


def family_compatibility(
    family: str,
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Rank how well evidence belongs to a vulnerability family, not whether it is vulnerable.

    Blocking contradictions are intentionally *not* subtracted from family fit. They are
    evidence that the relevant security control was observed for this family, and therefore
    belong in condition confidence / admission, not in family identity scoring.
    """
    support_items = [dict(item) for item in support]
    contradict_items = [dict(item) for item in (contradict or [])]
    assessment = assess_admission(family, support_items, contradict_items)
    policy = FAMILY_ADMISSION_POLICIES[family]
    required_count = max(1, len(policy.get("required", [])))
    satisfied_count = len(assessment.get("required_satisfied") or [])
    coverage = satisfied_count / required_count
    required_sources = max(1, int(policy.get("min_independent_sources", 1)))
    source_ratio = min(1.0, int(assessment.get("independent_sources") or 0) / required_sources)

    score = 0.68 * coverage + 0.14 * source_ratio
    if assessment.get("admitted"):
        score += 0.18
    score = _clamp(score)
    blocking = list(assessment.get("blocking_contradictions") or [])
    condition_confidence = admission_confidence(assessment)
    return {
        "family": family,
        "score": round(score, 6),
        "family_fit_score": round(score, 6),
        "coverage": round(coverage, 6),
        "source_ratio": round(source_ratio, 6),
        "condition_confidence": condition_confidence,
        "control_evidence": blocking,
        "assessment": assessment,
        "ranking_engine_version": RANKING_ENGINE_VERSION,
        "ranking_rule_version": RANKING_RULE_VERSION,
    }


def rank_families(
    support: Iterable[Mapping[str, Any]],
    contradict: Iterable[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    support_items = [dict(item) for item in support]
    contradict_items = [dict(item) for item in (contradict or [])]
    rows = [family_compatibility(family, support_items, contradict_items) for family in FAMILY_ADMISSION_POLICIES]
    rows.sort(
        key=lambda item: (
            float(item["family_fit_score"]),
            bool(item["assessment"].get("admitted")),
            float(item["coverage"]),
            float(item["source_ratio"]),
            str(item["family"]),
        ),
        reverse=True,
    )
    return rows
'''
(APP / "analysis_ranking.py").write_text(ranking, encoding="utf-8")

# Benchmark: shared ranking semantics + complete confusion observability.
p = APP / "analysis_benchmark.py"
replace_once(
    p,
    "from analysis_corpus import validate_corpus\nfrom hypothesis_admission import FAMILY_ADMISSION_POLICIES, assess_admission\n",
    "from analysis_corpus import validate_corpus\nfrom analysis_ranking import admission_confidence as _ranking_admission_confidence, family_compatibility as _ranking_family_compatibility, rank_families\nfrom hypothesis_admission import FAMILY_ADMISSION_POLICIES\n",
)
replace_once(p, 'BENCHMARK_ENGINE_VERSION = "3.0.0"', 'BENCHMARK_ENGINE_VERSION = "3.1.0"')
regex_once(
    p,
    r"def family_compatibility\(.*?\n\ndef _admission_confidence\(assessment: Mapping\[str, Any\]\) -> float:\n.*?\n\ndef evaluate_case",
    '''def family_compatibility(\n    family: str,\n    support: Iterable[Mapping[str, Any]],\n    contradict: Iterable[Mapping[str, Any]] | None = None,\n) -> dict[str, Any]:\n    # Backward-compatible benchmark API; implementation lives in analysis_ranking.\n    return _ranking_family_compatibility(family, support, contradict)\n\n\ndef _admission_confidence(assessment: Mapping[str, Any]) -> float:\n    return _ranking_admission_confidence(assessment)\n\n\ndef evaluate_case''',
)
replace_once(
    p,
    "    rankings = [family_compatibility(family, support, contradict) for family in FAMILY_ADMISSION_POLICIES]\n    rankings.sort(\n        key=lambda item: (\n            float(item[\"score\"]),\n            bool(item[\"assessment\"].get(\"admitted\")),\n            str(item[\"family\"]),\n        ),\n        reverse=True,\n    )\n",
    "    rankings = rank_families(support, contradict)\n",
)
replace_once(
    p,
    "    top1_family = rankings[0][\"family\"] if rankings else \"\"\n    confounder_leaks = [family for family in admitted_families if family in set(confounders)]\n",
    "    top1_family = rankings[0][\"family\"] if rankings else \"\"\n    top1_score = float(rankings[0][\"score\"]) if rankings else 0.0\n    top2_score = float(rankings[1][\"score\"]) if len(rankings) > 1 else 0.0\n    target_rank = next((index + 1 for index, item in enumerate(rankings) if item[\"family\"] == expected_family), 0)\n    closest_incorrect_family = next((item[\"family\"] for item in rankings if item[\"family\"] != expected_family), \"\")\n    confounder_leaks = [family for family in admitted_families if family in set(confounders)]\n",
)
replace_once(
    p,
    '        "top1": top1_family,\n        "top3": top,\n',
    '        "top1": top1_family,\n        "top3": top,\n        "top1_score": round(top1_score, 6),\n        "top2_score": round(top2_score, 6),\n        "top1_margin": round(max(0.0, top1_score - top2_score), 6),\n        "target_rank": target_rank,\n        "closest_incorrect_family": closest_incorrect_family,\n',
)
replace_once(
    p,
    "    confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))\n    for row in hard_rank:\n        confusion[row[\"family\"]][row[\"top1\"]] += 1\n\n    metrics = {\n",
    "    full_confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))\n    for row in labeled_rank:\n        full_confusion[row[\"family\"]][row[\"top1\"]] += 1\n    ranking_errors = [row for row in labeled_rank if not row[\"top1_correct\"]]\n\n    hard_confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))\n    for row in hard_rank:\n        hard_confusion[row[\"family\"]][row[\"top1\"]] += 1\n\n    metrics = {\n",
)
replace_once(
    p,
    '        "top1_accuracy": round(top1, 6),\n        "top3_accuracy": round(top3, 6),\n',
    '        "top1_accuracy": round(top1, 6),\n        "top3_accuracy": round(top3, 6),\n        "ranking_error_rate": round(1.0 - top1, 6),\n',
)
replace_once(
    p,
    '        "family_recall": family_recalls,\n        "hard_confusion_matrix": {family: dict(values) for family, values in sorted(confusion.items())},\n',
    '        "family_recall": family_recalls,\n        "confusion_matrix": {family: dict(values) for family, values in sorted(full_confusion.items())},\n        "ranking_errors": ranking_errors,\n        "hard_confusion_matrix": {family: dict(values) for family, values in sorted(hard_confusion.items())},\n',
)
replace_once(
    p,
    '        report["held_out_confusion_matrix"] = held_out.get("hard_confusion_matrix", {})\n        report["held_out_reliability_buckets"] = _reliability_buckets(held_out.get("cases", []))\n',
    '        report["held_out_confusion_matrix"] = held_out.get("confusion_matrix", {})\n        report["held_out_ranking_errors"] = held_out.get("ranking_errors", [])\n        report["held_out_reliability_buckets"] = _reliability_buckets(held_out.get("cases", []))\n',
)
replace_once(
    p,
    '        report["held_out_confusion_matrix"] = {}\n        report["held_out_reliability_buckets"] = []\n',
    '        report["held_out_confusion_matrix"] = {}\n        report["held_out_ranking_errors"] = []\n        report["held_out_reliability_buckets"] = []\n',
)

# Production family ranking: security controls falsify the condition, not the family identity.
p = APP / "security_reasoning.py"
replace_once(p, 'REASONING_ENGINE_VERSION = "6.4.0"', 'REASONING_ENGINE_VERSION = "6.5.0"')
replace_once(p, 'REASONING_RULE_VERSION = "2026.08.10.6.4"', 'REASONING_RULE_VERSION = "2026.08.10.6.5"')
replace_once(
    p,
    '    score = 12 + (18 if family == primary_family else 0) + len(matched_required) * 13 + len(matched_support) * 5 - missing_groups * 16 - len(matched_contradict) * 10\n',
    '    # A matched security control can falsify exploitability while still making the family identity more certain.\n    # Keep contradictions out of family-fit scoring; condition confidence is handled separately downstream.\n    score = 12 + (18 if family == primary_family else 0) + len(matched_required) * 13 + len(matched_support) * 5 - missing_groups * 16\n',
)
replace_once(
    p,
    '    return _clamp(score, 0, 96), {"matched_required": matched_required, "missing_required_groups": missing_groups, "matched_support": matched_support, "matched_contradict": matched_contradict}\n',
    '    return _clamp(score, 0, 96), {"matched_required": matched_required, "missing_required_groups": missing_groups, "matched_support": matched_support, "matched_contradict": matched_contradict, "contradictions_affect_family_fit": False}\n',
)

# Stack versions: ranking output semantics changed, admission policy itself did not.
for rel, old, new in (
    ("analysis_engine.py", 'ENGINE_VERSION = "6.4.0"', 'ENGINE_VERSION = "6.5.0"'),
    ("analysis_engine.py", 'RULE_VERSION = "2026.08.10.6.4"', 'RULE_VERSION = "2026.08.10.6.5"'),
    ("bug_candidates.py", 'CANDIDATE_ENGINE_VERSION = "6.4.0"', 'CANDIDATE_ENGINE_VERSION = "6.5.0"'),
    ("bug_candidates.py", 'CANDIDATE_RULE_VERSION = "2026.08.10.6.4"', 'CANDIDATE_RULE_VERSION = "2026.08.10.6.5"'),
):
    replace_once(APP / rel, old, new)

# Update tests that assert the current analysis/reasoning stack version.
for test in TESTS.glob("test_*.py"):
    text = test.read_text(encoding="utf-8")
    updated = text.replace('"6.4.0"', '"6.5.0"').replace('"3.0.0"', '"3.1.0"')
    if updated != text:
        test.write_text(updated, encoding="utf-8")

ranking_tests = '''from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_benchmark import BENCHMARK_ENGINE_VERSION, REAL_WORLD_CORPUS, benchmark_file
from analysis_ranking import RANKING_ENGINE_VERSION, admission_confidence, family_compatibility, rank_families
from hypothesis_admission import assess_admission
from security_reasoning import REASONING_ENGINE_VERSION, _family_score


class AnalysisRankingV650Tests(unittest.TestCase):
    def test_versions(self):
        self.assertEqual(RANKING_ENGINE_VERSION, "1.0.0")
        self.assertEqual(BENCHMARK_ENGINE_VERSION, "3.1.0")
        self.assertEqual(REASONING_ENGINE_VERSION, "6.5.0")

    def test_security_control_reduces_condition_not_family_fit(self):
        support = [
            {"type": "privileged_function", "source": "semantic", "source_group": "function_surface"},
            {"type": "state_change", "source": "endpoint_contract", "source_group": "operation_surface"},
        ]
        contradict = [
            {"type": "lower_privilege_denied", "source": "stored_behavior", "source_group": "authorization_behavior"},
        ]
        assessment = assess_admission("broken_function_authorization", support, contradict)
        self.assertFalse(assessment["admitted"])
        self.assertEqual(assessment["state"], "shadow_contradicted")
        self.assertEqual(admission_confidence(assessment), 0.04)

        bfla = family_compatibility("broken_function_authorization", support, contradict)
        business = family_compatibility("business_logic", support, contradict)
        self.assertGreater(bfla["family_fit_score"], business["family_fit_score"])
        self.assertEqual(bfla["control_evidence"], ["lower_privilege_denied"])
        self.assertEqual(rank_families(support, contradict)[0]["family"], "broken_function_authorization")

    def test_production_family_score_keeps_control_out_of_fit_penalty(self):
        support_types = {"privileged_function", "state_change"}
        controlled, reason = _family_score(
            "broken_function_authorization",
            "broken_function_authorization",
            support_types,
            {"confirmed_role_enforcement"},
            "admin state change",
        )
        uncontrolled, _ = _family_score(
            "broken_function_authorization",
            "broken_function_authorization",
            support_types,
            set(),
            "admin state change",
        )
        self.assertEqual(controlled, uncontrolled)
        self.assertEqual(reason["matched_contradict"], ["confirmed_role_enforcement"])
        self.assertFalse(reason["contradictions_affect_family_fit"])

    def test_development_ranking_has_no_known_top1_confusion(self):
        report = benchmark_file(REAL_WORLD_CORPUS)
        development = report["partitions"]["development"]
        self.assertEqual(development["metrics"]["top1_accuracy"], 1.0)
        self.assertEqual(development["ranking_errors"], [])

    def test_full_confusion_matrix_is_not_hard_only(self):
        report = benchmark_file(REAL_WORLD_CORPUS)
        held = report["partitions"]["held_out"]
        self.assertEqual(report["held_out_confusion_matrix"], held["confusion_matrix"])
        self.assertIn("held_out_ranking_errors", report)
        self.assertGreater(sum(sum(v.values()) for v in report["held_out_confusion_matrix"].values()), 0)


if __name__ == "__main__":
    unittest.main()
'''
(TESTS / "test_analysis_ranking_v650.py").write_text(ranking_tests, encoding="utf-8")

doc = '''# Analysis Engine 6.5 — Family-Fit / Condition-Confidence Separation

Analysis 6.5 fixes a ranking semantics bug discovered during 6.4 held-out diagnostics.

## Core rule

A contradiction can mean two very different things:

- **Condition evidence:** the target appears to enforce the expected security control, so the vulnerability condition is not established.
- **Family evidence:** the observation is still clearly about that vulnerability family.

Earlier ranking code subtracted blocking contradictions from family compatibility. This could make a secure negative for a precise family rank below a generic neighboring family. For example, a privileged state-changing function with an observed lower-privilege denial is still most naturally a function-authorization observation even though it should abstain from a BFLA finding.

6.5 therefore separates:

- `family_fit_score`: how well the evidence belongs to a vulnerability family;
- `condition_confidence`: how strongly the target evidence establishes the vulnerability condition.

Blocking controls affect `condition_confidence` and admission state, but not `family_fit_score`.

## Production alignment

`security_reasoning._family_score()` now follows the same epistemic rule. Matched family-specific controls remain visible in the ranking reason but are not subtracted from family fit. Exploitability, calibrated likelihood, falsification, and contradiction handling remain separate and continue to reduce vulnerability confidence where appropriate.

## Confusion observability

Benchmark Engine 3.1 adds a complete confusion matrix over all rank-required cases, plus per-case:

- target rank;
- Top-1/Top-2 scores;
- Top-1 margin;
- closest incorrect family;
- ranking error rows.

The held-out confusion matrix now uses this complete matrix instead of incorrectly reusing the hard-case-only matrix.

## Tuning discipline

The 6.5 rule was selected using the **development partition only**. Development baseline had one Top-1 confusion; the frozen rule removed it without changing admission semantics.

The existing 6.4 held-out partition was inspected during diagnosis and is therefore considered a **consumed diagnostic holdout** for future scientific claims. Its post-6.5 result remains useful as a regression audit, but it must not be presented as a new unbiased production-accuracy estimate. A future corpus revision should introduce fresh post-freeze source roots for an unbiased holdout estimate.
'''
(DOCS / "ANALYSIS_ENGINE_6_5_RANKING_CALIBRATION.md").write_text(doc, encoding="utf-8")

print("Analysis 6.5 patch applied")
