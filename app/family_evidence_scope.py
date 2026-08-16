from __future__ import annotations

"""Family evidence namespace and cross-family quarantine.

This module is derived from the strongest isolation property of Analysis 6.33:
evidence explicitly scoped to one vulnerability family must never silently
satisfy another family. Legacy unscoped evidence remains accepted for backward
compatibility, while newly persisted hypothesis evidence is annotated with the
canonical family namespace.
"""

from typing import Any, Iterable, Mapping

FAMILY_EVIDENCE_SCOPE_VERSION = "1.0.0"
FAMILY_EVIDENCE_SCOPE_RULE_VERSION = "2026.08.16.1"


def scope_family_evidence(
    family: str,
    items: Iterable[Mapping[str, Any]],
    *,
    annotate_unscoped: bool,
    channel: str,
) -> dict[str, Any]:
    """Partition evidence into accepted and cross-family quarantined records.

    Explicit cross-family scope fails closed. Unscoped legacy records remain
    readable; callers at persistence boundaries should set ``annotate_unscoped``
    so all newly stored evidence receives a stable family namespace.
    """

    canonical_family = str(family or "").strip()
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for raw in items:
        item = dict(raw)
        existing_scope = str(item.get("family_scope") or "").strip()
        if existing_scope and existing_scope != canonical_family:
            quarantined = dict(item)
            quarantined["scope_rejection_reason"] = "cross_family_evidence"
            quarantined["expected_family_scope"] = canonical_family
            rejected.append(quarantined)
            continue
        if annotate_unscoped and canonical_family:
            item["family_scope"] = canonical_family
            item["evidence_namespace"] = f"family:{canonical_family}"
            item["evidence_scope_version"] = FAMILY_EVIDENCE_SCOPE_VERSION
            item["evidence_scope_rule_version"] = FAMILY_EVIDENCE_SCOPE_RULE_VERSION
            item.setdefault("evidence_scope_channel", str(channel or "unknown"))
        accepted.append(item)
    return {
        "family": canonical_family,
        "accepted": accepted,
        "rejected": rejected,
        "accepted_count": len(accepted),
        "rejected_count": len(rejected),
        "version": FAMILY_EVIDENCE_SCOPE_VERSION,
        "rule_version": FAMILY_EVIDENCE_SCOPE_RULE_VERSION,
        "channel": str(channel or "unknown"),
    }
