from __future__ import annotations

"""Immutable family specification contracts for the Analysis Brain.

The specification layer describes *how to reason about* a vulnerability family.
It never creates target evidence. Runtime admission still depends on stored
target observations supplied by the evidence pipeline.
"""

from dataclasses import dataclass
from typing import Any, Mapping


FAMILY_SPEC_FRAMEWORK_VERSION = "1.0.0"


@dataclass(frozen=True)
class MethodologyStep:
    id: str
    basis: tuple[str, ...]
    principle: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "basis": list(self.basis),
            "principle": self.principle,
        }


@dataclass(frozen=True)
class WriteupLesson:
    id: str
    source: str
    ref: str
    url: str
    relation: str
    lesson: str
    signal_hints: tuple[str, ...] = ()
    counts_as_target_evidence: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "ref": self.ref,
            "url": self.url,
            "relation": self.relation,
            "lesson": self.lesson,
            "signal_hints": list(self.signal_hints),
            "counts_as_target_evidence": False,
        }


@dataclass(frozen=True)
class FamilyStandardSpec:
    family: str
    version: str
    strategy: str
    principle: str
    owasp: tuple[str, ...]
    wstg: tuple[str, ...]
    cwe: tuple[str, ...]
    capec: tuple[str, ...]
    methodology: tuple[MethodologyStep, ...]
    surface_terms: tuple[str, ...]
    surface_fields: tuple[str, ...]
    confounders: tuple[str, ...]
    false_positive_checks: tuple[str, ...]
    writeups: tuple[WriteupLesson, ...]

    def __post_init__(self) -> None:
        if not self.family or not self.strategy or not self.principle:
            raise ValueError("family, strategy and principle are required")
        if not self.owasp:
            raise ValueError(f"{self.family}: OWASP grounding is required")
        if not self.wstg:
            raise ValueError(f"{self.family}: WSTG grounding is required")
        if not self.cwe:
            raise ValueError(f"{self.family}: CWE grounding is required")
        if not self.writeups:
            raise ValueError(f"{self.family}: at least one curated write-up is required")
        if any(item.counts_as_target_evidence for item in self.writeups):
            raise ValueError(f"{self.family}: external knowledge cannot count as target evidence")

    def taxonomy(self) -> dict[str, list[str]]:
        return {
            "owasp": list(self.owasp),
            "wstg": list(self.wstg),
            "cwe": list(self.cwe),
            "capec": list(self.capec),
        }


@dataclass(frozen=True)
class FamilyDetectionSpec:
    """Runtime projection of standards + the canonical evidence contract."""

    family: str
    version: str
    standard: FamilyStandardSpec
    label: str
    category: str
    promotion_required: tuple[frozenset[str], ...]
    min_independent_sources: int
    blocking_contradictions: frozenset[str]
    override_signals: frozenset[str]
    confirmation_required: tuple[frozenset[str], ...]
    case_requirements: tuple[Mapping[str, Any], ...]
    next_evidence: tuple[str, ...]
    validation_level: str
    reasoning_version: str
    reasoning_rule_version: str

    @property
    def strategy(self) -> str:
        return self.standard.strategy

    @property
    def principle(self) -> str:
        return self.standard.principle

    def taxonomy(self) -> dict[str, list[str]]:
        return self.standard.taxonomy()


def _groups(value: Any) -> tuple[frozenset[str], ...]:
    groups: list[frozenset[str]] = []
    for raw in value or ():
        groups.append(frozenset(str(item) for item in raw))
    return tuple(groups)


def compose_detection_spec(
    standard: FamilyStandardSpec,
    reasoning_contract: Mapping[str, Any],
    *,
    reasoning_version: str,
    reasoning_rule_version: str,
) -> FamilyDetectionSpec:
    """Compose a read-only detector view without duplicating admission policy."""

    if not reasoning_contract:
        raise ValueError(f"{standard.family}: missing reasoning contract")
    return FamilyDetectionSpec(
        family=standard.family,
        version=f"{standard.version}+reasoning",
        standard=standard,
        label=str(reasoning_contract.get("label") or standard.family),
        category=str(reasoning_contract.get("category") or "unknown"),
        promotion_required=_groups(reasoning_contract.get("promotion_required")),
        min_independent_sources=int(reasoning_contract.get("min_independent_sources", 1)),
        blocking_contradictions=frozenset(
            str(item) for item in reasoning_contract.get("blocking_contradictions", ())
        ),
        override_signals=frozenset(
            str(item) for item in reasoning_contract.get("override_signals", ())
        ),
        confirmation_required=_groups(reasoning_contract.get("confirmation_required")),
        case_requirements=tuple(
            dict(item)
            for item in reasoning_contract.get("case_requirements", ())
            if isinstance(item, Mapping)
        ),
        next_evidence=tuple(str(item) for item in reasoning_contract.get("next_evidence", ())),
        validation_level=str(reasoning_contract.get("validation_level") or "offline"),
        reasoning_version=str(reasoning_version or ""),
        reasoning_rule_version=str(reasoning_rule_version or ""),
    )
