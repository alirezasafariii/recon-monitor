from __future__ import annotations

from typing import Any, Mapping

from raw_recon_v4_source_audit import HARD_ANCHORS as V4_HARD_ANCHORS

AUDIT_VERSION = "1.0.0"
AUDIT_RULE_VERSION = "2026.08.13.6.29"

# v5 keeps the v4 semantic contract and only broadens wording where fresh
# advisories use equivalent, explicit vulnerability semantics. These phrases
# are source-text criteria only; they are not detector signals or target evidence.
HARD_ANCHORS = dict(V4_HARD_ANCHORS)
HARD_ANCHORS["business_logic"] = (
    (
        "business logic",
        "workflow",
        "payment status",
        "order status",
        "state transition",
        "price",
        "checkout",
        "sales quantity",
        "available stock",
    ),
    (
        "bypass",
        "without proper",
        "invalid",
        "unpaid",
        "skip",
        "incorrect",
        "invariant",
        "did not properly validate",
        "fails to verify",
        "failed to verify",
        "improper enforcement",
        "different payment",
        "exceeds the available stock",
    ),
)


def _text(row: Mapping[str, Any]) -> str:
    return (str(row.get("summary") or "") + "\n" + str(row.get("description") or "")).lower()


def audit_row(family: str, row: Mapping[str, Any]) -> tuple[bool, list[list[str]], int]:
    if family not in HARD_ANCHORS:
        raise KeyError(f"unknown v5 source-audit family: {family}")
    text = _text(row)
    group_hits: list[list[str]] = []
    score = 0
    for group in HARD_ANCHORS[family]:
        hits = sorted({term for term in group if term.lower() in text})
        group_hits.append(hits)
        if not hits:
            return False, group_hits, score
        score += 5 + len(hits)
    if str(row.get("repository_advisory_url") or ""):
        score += 2
    if str(row.get("source_code_location") or ""):
        score += 1
    if str(row.get("advisory_source_type") or "") == "reviewed":
        score += 1
    return True, group_hits, score
