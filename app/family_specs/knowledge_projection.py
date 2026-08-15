from __future__ import annotations

"""Knowledge/retrieval projections from canonical family specifications.

These helpers translate immutable family specifications into the legacy
vulnerability-knowledge shapes. They never create target evidence and never
participate in admission or confirmation.
"""

from typing import Any

from .base import FamilyDetectionSpec


KNOWLEDGE_PROJECTION_VERSION = "1.0.0"


def taxonomy_projection(spec: FamilyDetectionSpec) -> dict[str, list[str]]:
    """Return a detached taxonomy copy for the legacy knowledge profile."""

    return {
        key: list(values)
        for key, values in spec.taxonomy().items()
    }


def writeup_knowledge_projection(spec: FamilyDetectionSpec) -> list[dict[str, Any]]:
    """Project curated write-up lessons into legacy retrieval documents.

    The projection intentionally emits no evidence ``type`` field. Signal hints
    are retrieval/classification vocabulary only, and every document is marked
    non-evidentiary.
    """

    docs: list[dict[str, Any]] = []
    for item in spec.standard.writeups:
        docs.append(
            {
                "id": item.id,
                "family": spec.family,
                "source": item.source,
                "ref": item.ref,
                "url": item.url,
                "principle": item.lesson,
                "signals": list(item.signal_hints),
                "tags": [
                    f"family-spec:{spec.family}",
                    f"relation:{item.relation}",
                ],
                "external": False,
                "relation": item.relation,
                "counts_as_target_evidence": False,
                "family_spec_version": spec.version,
                "knowledge_projection_version": KNOWLEDGE_PROJECTION_VERSION,
            }
        )
    return docs


def validate_knowledge_projection(spec: FamilyDetectionSpec) -> list[str]:
    """Return projection invariant violations for one canonical family."""

    errors: list[str] = []
    taxonomy = taxonomy_projection(spec)
    for key in ("owasp", "wstg", "cwe"):
        if not taxonomy.get(key):
            errors.append(f"{spec.family}:missing_{key}")

    docs = writeup_knowledge_projection(spec)
    if len(docs) != len(spec.standard.writeups):
        errors.append(f"{spec.family}:writeup_projection_count_mismatch")
    if any(bool(doc.get("counts_as_target_evidence")) for doc in docs):
        errors.append(f"{spec.family}:knowledge_projection_became_evidence")
    if any("type" in doc for doc in docs):
        errors.append(f"{spec.family}:knowledge_projection_emits_evidence_type")
    if {str(doc.get("id") or "") for doc in docs} != {
        item.id for item in spec.standard.writeups
    }:
        errors.append(f"{spec.family}:writeup_projection_id_drift")
    return errors
