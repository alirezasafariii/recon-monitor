from __future__ import annotations

"""Knowledge/retrieval projections from canonical family specifications.

These helpers translate immutable family specifications into the legacy
vulnerability-knowledge shapes. Standards and write-up lessons are explanatory
classification material only: they never create target evidence and never
participate in admission or confirmation.
"""

import re
from typing import Any

from .base import FamilyDetectionSpec


KNOWLEDGE_PROJECTION_VERSION = "1.1.0"


def taxonomy_projection(spec: FamilyDetectionSpec) -> dict[str, list[str]]:
    """Return a detached taxonomy copy for the legacy knowledge profile."""

    return {key: list(values) for key, values in spec.taxonomy().items()}


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")


def _standard_id(kind: str, ref: str) -> str:
    kind = str(kind).strip().lower()
    value = str(ref).strip()
    if kind == "owasp":
        match = re.search(r"\b(API\d+):(\d{4})\b", value, flags=re.I)
        if match:
            return f"owasp-{match.group(1).lower()}-{match.group(2)}"
        return f"owasp-{_slug(value)}"
    return _slug(value)


def _classification_signals(spec: FamilyDetectionSpec) -> list[str]:
    """Return canonical retrieval vocabulary without creating evidence."""

    values: set[str] = set()
    for group in spec.promotion_required:
        values.update(str(item) for item in group)
    for group in spec.confirmation_required:
        values.update(str(item) for item in group)
    values.update(str(item) for item in spec.blocking_contradictions)
    values.update(str(item) for item in spec.override_signals)
    for writeup in spec.standard.writeups:
        values.update(str(item) for item in writeup.signal_hints)
    return sorted(value for value in values if value)


def standard_knowledge_projection(spec: FamilyDetectionSpec) -> list[dict[str, Any]]:
    """Project OWASP/WSTG/CWE/CAPEC references as non-evidentiary documents."""

    docs: list[dict[str, Any]] = []
    signals = _classification_signals(spec)
    sources = {
        "owasp": "OWASP",
        "wstg": "OWASP WSTG",
        "cwe": "MITRE CWE",
        "capec": "MITRE CAPEC",
    }
    for kind, refs in taxonomy_projection(spec).items():
        for ref in refs:
            docs.append(
                {
                    "id": _standard_id(kind, ref),
                    "family": spec.family,
                    "source": sources.get(kind, kind.upper()),
                    "ref": str(ref),
                    "url": "",
                    "principle": spec.principle,
                    "signals": list(signals),
                    "tags": [f"family-spec:{spec.family}", f"standard:{kind}"],
                    "external": False,
                    "relation": "standard",
                    "counts_as_target_evidence": False,
                    "family_spec_version": spec.version,
                    "knowledge_projection_version": KNOWLEDGE_PROJECTION_VERSION,
                }
            )
    return docs


def writeup_knowledge_projection(spec: FamilyDetectionSpec) -> list[dict[str, Any]]:
    """Project curated real-world write-up lessons into retrieval documents."""

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
                "tags": [f"family-spec:{spec.family}", f"relation:{item.relation}"],
                "external": False,
                "relation": item.relation,
                "counts_as_target_evidence": False,
                "family_spec_version": spec.version,
                "knowledge_projection_version": KNOWLEDGE_PROJECTION_VERSION,
            }
        )
    return docs


def family_knowledge_projection(spec: FamilyDetectionSpec) -> list[dict[str, Any]]:
    """Return canonical standards + write-up retrieval knowledge for a family."""

    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for doc in [*standard_knowledge_projection(spec), *writeup_knowledge_projection(spec)]:
        doc_id = str(doc.get("id") or "")
        if not doc_id or doc_id in seen:
            continue
        seen.add(doc_id)
        result.append(doc)
    return result


def validate_knowledge_projection(spec: FamilyDetectionSpec) -> list[str]:
    """Return projection invariant violations for one canonical family."""

    errors: list[str] = []
    taxonomy = taxonomy_projection(spec)
    for key in ("owasp", "wstg", "cwe"):
        if not taxonomy.get(key):
            errors.append(f"{spec.family}:missing_{key}")

    writeups = writeup_knowledge_projection(spec)
    if len(writeups) != len(spec.standard.writeups):
        errors.append(f"{spec.family}:writeup_projection_count_mismatch")
    if {str(doc.get("id") or "") for doc in writeups} != {item.id for item in spec.standard.writeups}:
        errors.append(f"{spec.family}:writeup_projection_id_drift")

    docs = family_knowledge_projection(spec)
    if any(bool(doc.get("counts_as_target_evidence")) for doc in docs):
        errors.append(f"{spec.family}:knowledge_projection_became_evidence")
    if any("type" in doc for doc in docs):
        errors.append(f"{spec.family}:knowledge_projection_emits_evidence_type")
    if not any(str(doc.get("relation") or "") == "standard" for doc in docs):
        errors.append(f"{spec.family}:missing_standard_projection")
    return errors
