from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from analysis_standards import FAMILY_STANDARDS
from hypothesis_admission import FAMILY_ADMISSION_POLICIES

DETECTOR_ENGINE_VERSION = "1.1.0"
DETECTOR_RULE_VERSION = "2026.08.12.6.19"


@dataclass(frozen=True)
class WriteupReference:
    ref: str
    url: str
    relation: str
    lesson: str
    source: str = "GitHub Security Lab"
    counts_as_target_evidence: bool = False


@dataclass(frozen=True)
class FamilyDetectorSpec:
    family: str
    strategy: str
    surface_terms: tuple[str, ...]
    surface_fields: tuple[str, ...]
    confounders: tuple[str, ...]
    wstg_ids: tuple[str, ...]
    owasp_ids: tuple[str, ...]
    cwe_ids: tuple[str, ...]
    writeups: tuple[WriteupReference, ...]
    principle: str
    required_groups: tuple[frozenset[str], ...]
    condition_signals: frozenset[str]
    blocking_controls: frozenset[str]
    override_signals: frozenset[str]

    @property
    def identity_signals(self) -> frozenset[str]:
        if len(self.required_groups) <= 1:
            return frozenset()
        return frozenset().union(*self.required_groups[:-1])

    @property
    def target_signal_allowlist(self) -> frozenset[str]:
        groups = frozenset().union(*self.required_groups) if self.required_groups else frozenset()
        return groups | self.blocking_controls | self.override_signals


def writeup(ref: str, url: str, relation: str, lesson: str, *, source: str = "GitHub Security Lab") -> WriteupReference:
    return WriteupReference(ref=ref, url=url, relation=relation, lesson=lesson, source=source)


def make_spec(
    *,
    family: str,
    strategy: str,
    surface_terms: Iterable[str],
    surface_fields: Iterable[str],
    confounders: Iterable[str],
    expected_wstg: Iterable[str],
    expected_cwe: Iterable[str],
    writeups: Iterable[WriteupReference],
) -> FamilyDetectorSpec:
    policy = FAMILY_ADMISSION_POLICIES[family]
    standards = FAMILY_STANDARDS[family]
    actual_wstg = tuple(str(x["id"]) for x in standards.get("wstg", []))
    actual_owasp = tuple(str(x["id"]) for x in standards.get("owasp", []))
    actual_cwe = tuple(str(x["id"]) for x in standards.get("cwe", []))
    expected_wstg = tuple(expected_wstg)
    expected_cwe = tuple(expected_cwe)
    if actual_wstg != expected_wstg:
        raise RuntimeError(f"{family}: detector/WSTG drift expected={expected_wstg} actual={actual_wstg}")
    if not actual_owasp:
        raise RuntimeError(f"{family}: detector/OWASP grounding is required")
    if actual_cwe != expected_cwe:
        raise RuntimeError(f"{family}: detector/CWE drift expected={expected_cwe} actual={actual_cwe}")
    required = tuple(frozenset(str(v) for v in group) for group in policy.get("required", []))
    condition = required[-1] if required else frozenset()
    blockers = frozenset(str(v) for v in policy.get("blocking_contradictions", set()))
    overrides = frozenset(str(v) for v in policy.get("override_signals", set()))
    refs = tuple(writeups)
    if not refs:
        raise RuntimeError(f"{family}: at least one primary or explicitly-adjacent write-up is required")
    if any(ref.counts_as_target_evidence for ref in refs):
        raise RuntimeError(f"{family}: external knowledge must never count as target evidence")
    return FamilyDetectorSpec(
        family=family,
        strategy=strategy,
        surface_terms=tuple(surface_terms),
        surface_fields=tuple(surface_fields),
        confounders=tuple(confounders),
        wstg_ids=actual_wstg,
        owasp_ids=actual_owasp,
        cwe_ids=actual_cwe,
        writeups=refs,
        principle=str(standards.get("principle") or ""),
        required_groups=required,
        condition_signals=condition | overrides,
        blocking_controls=blockers,
        override_signals=overrides,
    )


def annotate_target_evidence(spec: FamilyDetectorSpec, items: Iterable[Mapping[str, Any]], *, contradiction: bool = False) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    identity = spec.identity_signals
    condition = spec.condition_signals
    for raw in items:
        item = dict(raw)
        signal = str(item.get("type") or "")
        if contradiction:
            signal_class = "control" if signal in spec.blocking_controls else "contextual_control"
            counts = signal in spec.blocking_controls
        elif signal in condition:
            signal_class = "condition"
            counts = True
        elif signal in identity:
            signal_class = "identity"
            counts = True
        else:
            signal_class = "surface"
            counts = False
        item.update({
            "physical_detector_id": f"family-detector:{spec.family}",
            "physical_detector_version": DETECTOR_ENGINE_VERSION,
            "physical_detector_rule_version": DETECTOR_RULE_VERSION,
            "physical_detector_strategy": spec.strategy,
            "detector_signal_class": signal_class,
            "detector_counts_as_target_evidence": counts,
        })
        rows.append(item)
    return rows
