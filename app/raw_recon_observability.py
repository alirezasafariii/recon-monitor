from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Iterable, Mapping

OBSERVABILITY_ENGINE_VERSION = "1.0.0"
OBSERVABILITY_RULE_VERSION = "2026.08.11.6.12"


def canonical_raw(raw: Mapping[str, Any]) -> str:
    return json.dumps(dict(raw), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def analyze_variant_observability(cases: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Measure whether labels are distinguishable from the supplied raw artifacts.

    This module is diagnostic only. It never emits detector evidence, never changes
    admission, and never treats a label/provenance field as a target observation.
    """
    grouped: dict[str, dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for case in cases:
        root = str(case.get("source_root") or "")
        kind = str(case.get("case_kind") or "")
        if root and kind:
            grouped[root][kind] = case

    rows: list[dict[str, Any]] = []
    for root, variants in sorted(grouped.items()):
        positive = variants.get("positive")
        if not positive:
            continue
        positive_raw = positive.get("raw") if isinstance(positive.get("raw"), Mapping) else {}
        positive_canonical = canonical_raw(positive_raw)
        collisions: list[str] = []
        for kind in ("near_miss", "secure_negative", "sparse_noisy"):
            negative = variants.get(kind)
            if not negative:
                continue
            negative_raw = negative.get("raw") if isinstance(negative.get("raw"), Mapping) else {}
            if canonical_raw(negative_raw) == positive_canonical:
                collisions.append(kind)
        status = "collision_unidentifiable" if collisions else "raw_distinguishable"
        rows.append(
            {
                "source_root": root,
                "family": str(positive.get("family") or ""),
                "status": status,
                "exact_raw_collision_with": collisions,
                "expected_condition_signals": list((positive.get("expected") or {}).get("condition_signals") or [])
                if isinstance(positive.get("expected"), Mapping)
                else [],
            }
        )

    collision_rows = [row for row in rows if row["status"] == "collision_unidentifiable"]
    distinguishable_rows = [row for row in rows if row["status"] == "raw_distinguishable"]
    return {
        "observability_engine_version": OBSERVABILITY_ENGINE_VERSION,
        "rule_version": OBSERVABILITY_RULE_VERSION,
        "source_root_count": len(rows),
        "collision_root_count": len(collision_rows),
        "raw_distinguishable_root_count": len(distinguishable_rows),
        "collision_rate": round(len(collision_rows) / len(rows), 6) if rows else 0.0,
        "raw_distinguishable_rate": round(len(distinguishable_rows) / len(rows), 6) if rows else 0.0,
        "rows": rows,
        "epistemic_note": "Exact positive/negative raw collisions are not separable by a deterministic detector that only consumes the permitted raw artifact. They must remain abstentions unless additional target evidence is collected.",
    }
