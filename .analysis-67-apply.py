from __future__ import annotations

from pathlib import Path


def replace_exact(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"expected patch anchor not found in {path}: {old[:120]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_exact(
    "app/security_reasoning.py",
    "from hypothesis_admission import hypothesis_summary, knowledge_for_family\n",
    "from hypothesis_admission import hypothesis_summary, knowledge_for_family\n"
    "from security_family_ranker import production_family_rankings\n",
)
replace_exact(
    "app/security_reasoning.py",
    'REASONING_ENGINE_VERSION = "6.5.0"\nREASONING_RULE_VERSION = "2026.08.10.6.5"\n',
    'REASONING_ENGINE_VERSION = "6.7.0"\nREASONING_RULE_VERSION = "2026.08.10.6.7"\n',
)
replace_exact(
    "app/security_reasoning.py",
    '''        rankings: list[dict[str, Any]] = []\n        for ranked_family in FAMILY_SCHEMAS:\n            score, reason = _family_score(ranked_family, family, support_types, contradict_types, text)\n            if score > 0:\n                rankings.append({"family": ranked_family, "label": FAMILY_SCHEMAS[ranked_family]["label"], "score": score, "reason": reason})\n        rankings.sort(key=lambda x: x["score"], reverse=True)\n        top3 = rankings[:3]\n''',
    '''        # Analysis 6.7: production ranking is family-specific. The legacy\n        # _family_score helper remains for compatibility/tests but is no longer\n        # used to rank live candidates. Each family reasoner scopes evidence to\n        # its own vocabulary, weights its own required groups, and suppresses\n        # known confounders only when its own decisive condition is absent.\n        labels = {name: str(value.get("label") or name) for name, value in FAMILY_SCHEMAS.items()}\n        rankings = production_family_rankings(support, contradict, labels)\n        top3 = rankings[:3]\n''',
)
replace_exact(
    "tests/test_analysis_ranking_v650.py",
    '        self.assertEqual(RANKING_ENGINE_VERSION, "1.0.0")\n',
    '        self.assertEqual(RANKING_ENGINE_VERSION, "2.0.0")\n',
)
replace_exact(
    "tests/test_analysis_ranking_v650.py",
    '        self.assertEqual(REASONING_ENGINE_VERSION, "6.5.0")\n',
    '        self.assertEqual(REASONING_ENGINE_VERSION, "6.7.0")\n',
)
