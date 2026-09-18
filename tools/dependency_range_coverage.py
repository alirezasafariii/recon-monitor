from __future__ import annotations

"""Audit dependency-advisory range coverage without changing runtime state."""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from dependency_version_ranges import range_expression_capability

DEFAULT_CATALOG = ROOT / "data" / "dependency_advisory_catalog.json"


def classify_range_syntax(expression: str, ecosystem: str = "") -> str:
    text = str(expression or "").strip()
    eco = str(ecosystem or "").strip().lower()
    if "||" in text:
        return "union"
    if eco == "maven" and re.fullmatch(r"\s*[\[(].*,.*[\])\]]\s*", text):
        return "maven_interval"
    if text.startswith("~>"):
        return "rubygems_pessimistic"
    if text.startswith("~="):
        return "pep440_compatible"
    if text.startswith("^"):
        return "caret"
    if text.startswith("~"):
        return "tilde"
    if re.fullmatch(r"\s*\S+\s+-\s+\S+\s*", text):
        return "hyphen"
    if re.search(r"(?:^|\.)[xX*](?:$|\s)", text):
        return "wildcard"
    comparator_count = len(re.findall(r"(?:^|[\s,])(<=|>=|!=|==|=|<|>)\s*", text))
    if comparator_count >= 2 or "," in text:
        return "comparator_conjunction"
    if comparator_count == 1:
        return "single_comparator"
    if text:
        return "bare_or_ecosystem_specific"
    return "empty"


def audit_catalog(payload: Mapping[str, Any], *, top: int = 30) -> dict[str, Any]:
    capability_counts: Counter[str] = Counter()
    ecosystem_counts: dict[str, Counter[str]] = defaultdict(Counter)
    syntax_counts: dict[str, Counter[str]] = defaultdict(Counter)
    unsupported_expressions: Counter[tuple[str, str]] = Counter()
    partial_expressions: Counter[tuple[str, str]] = Counter()

    total = 0
    advisories = payload.get("advisories")
    if not isinstance(advisories, list):
        advisories = []

    for advisory in advisories:
        if not isinstance(advisory, Mapping):
            continue
        ecosystem = str(advisory.get("ecosystem") or "").strip().lower() or "unknown"
        ranges = advisory.get("affected_ranges")
        if not isinstance(ranges, list):
            continue
        for raw_expression in ranges:
            expression = str(raw_expression or "").strip()
            if not expression:
                continue
            capability = range_expression_capability(expression, ecosystem)
            syntax = classify_range_syntax(expression, ecosystem)
            total += 1
            capability_counts[capability] += 1
            ecosystem_counts[ecosystem][capability] += 1
            syntax_counts[syntax][capability] += 1
            if capability == "none":
                unsupported_expressions[(ecosystem, expression)] += 1
            elif capability == "partial":
                partial_expressions[(ecosystem, expression)] += 1

    def render_counter(counter: Counter[tuple[str, str]]) -> list[dict[str, Any]]:
        return [
            {"ecosystem": ecosystem, "expression": expression, "count": count}
            for (ecosystem, expression), count in counter.most_common(max(1, top))
        ]

    supported = capability_counts["full"]
    partial = capability_counts["partial"]
    none = capability_counts["none"]
    positively_evaluable = supported + partial
    return {
        "total_range_count": total,
        "full_count": supported,
        "partial_count": partial,
        "none_count": none,
        "positive_match_evaluable_count": positively_evaluable,
        "positive_match_evaluable_ratio": (
            round(positively_evaluable / total, 6) if total else 0.0
        ),
        "full_coverage_ratio": round(supported / total, 6) if total else 0.0,
        "by_ecosystem": {
            key: dict(sorted(value.items()))
            for key, value in sorted(ecosystem_counts.items())
        },
        "by_syntax": {
            key: dict(sorted(value.items()))
            for key, value in sorted(syntax_counts.items())
        },
        "top_unsupported": render_counter(unsupported_expressions),
        "top_partial": render_counter(partial_expressions),
        "fail_closed": True,
        "catalog_miss_means_safe": False,
    }


def load_catalog(path: str | Path) -> dict[str, Any]:
    selected = Path(path)
    payload = json.loads(selected.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("Dependency advisory catalog must be a JSON object")
    return dict(payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit dependency advisory range matcher coverage"
    )
    parser.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    parser.add_argument("--top", type=int, default=30)
    parser.add_argument(
        "--require-full-ratio",
        type=float,
        default=0.0,
        help="Exit non-zero when full coverage ratio is below this value",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = audit_catalog(load_catalog(args.catalog), top=max(1, args.top))
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.require_full_ratio and report["full_coverage_ratio"] < args.require_full_ratio:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
